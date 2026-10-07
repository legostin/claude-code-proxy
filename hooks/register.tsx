import { atom, read, update } from 'claude-code'
import type { EngineInterface, Register, RenderElement, RenderInput } from 'claude-code'

import { describeRule, parseRules, ruleErrors, scriptsOf } from '../shared/rules.mjs'
import type { Rule } from '../shared/rules.mjs'
import type { ProxyFlow, ProxyRuleEntry, ProxyRules, ProxySetupTab, ProxyStatus, ProxyView } from '../types'
import {
  buildTree,
  clip,
  type FlowDetail,
  filterFlows,
  flattenTree,
  flowTable,
  flowUrl,
  formatDuration,
  formatSize,
  isTextual,
  languageOf,
  mergeFlows,
  parseEvent,
  parseFilter,
  prettyBody,
  splitLines,
  statusLabel,
  toCurl,
  treeIds,
  treeLeafLabel,
  truncate,
} from './flows'
import { encodeQr, qrRaster, qrSvg } from './qr'
import {
  androidGuide,
  BROWSER_CANDIDATES,
  type Browser,
  browserArgs,
  browserGuide,
  cliGuide,
  iosGuide,
  phoneAddress,
  proxyTargets,
  SETUP_TABS,
  type SetupFacts,
  setupCommands,
} from './setup'

// --- state ----------------------------------------------------------------------
// The atoms are written here too: the engine reads every state reference off
// this file's own consts.

const PANE = 'proxy'

const STOPPED: ProxyStatus = {
  phase: 'stopped',
  host: '127.0.0.1',
  port: 8899,
  addresses: [],
  lan: [],
  runDir: null,
  pid: null,
  ca: null,
  error: null,
}

const flowsAtom = atom({ plugin: 'proxy', key: 'flows' } as const, [] as ProxyFlow[])
const statusAtom = atom({ plugin: 'proxy', key: 'status' } as const, STOPPED)
const viewAtom = atom({ plugin: 'proxy', key: 'view' } as const, {
  mode: 'list',
  selectedId: null,
  setupTab: 'browser',
  layout: 'list',
} as ProxyView)
const filterAtom = atom({ plugin: 'proxy', key: 'filter' } as const, '')
const wantedAtom = atom({ plugin: 'proxy', key: 'wanted' } as const, false)
const nextIdAtom = atom({ plugin: 'proxy', key: 'nextId' } as const, 1)
const noticeAtom = atom({ plugin: 'proxy', key: 'notice' } as const, '')
/** Emulators this session pointed at the proxy, to point back on stop. */
const emulatorsAtom = atom({ plugin: 'proxy', key: 'emulators' } as const, [] as string[])
/** The tree view's open nodes, by TreeNode id. */
const expandedAtom = atom({ plugin: 'proxy', key: 'expanded' } as const, [] as string[])
/** The project's rules file as last read. */
const rulesAtom = atom({ plugin: 'proxy', key: 'rules' } as const, { file: null, entries: [], fileErrors: [] } as ProxyRules)

// Every function that takes `$` lives in this file: the engine follows `$`
// into functions of the hooks module itself, never across an import.

// --- the sidecar and the machine ------------------------------------------------

// The sidecar's life, the flow list's updates, and the actions the setup
// tabs run on this machine (simulators, emulators, a browser).



type Options = {
  port: number
  listen: 'local' | 'lan'
  noDecrypt: string
  maxFlows: number
  node: string
}

type Runtime = {
  pid: number | null
  isStopping: boolean
  pending: Map<number, ProxyFlow>
  isFlushScheduled: boolean
  stderr: string
}

// The running sidecar of this load of the module; a reload kills the child
// with the module, and session.start starts another while `wanted` holds.
let runtime: Runtime | null = null

async function dataDirOf($: EngineInterface): Promise<string> {
  const home = (await $.env.get('HOME')) ?? '/tmp'
  return `${home}/.claude/proxy-mod`
}

async function setupFacts($: EngineInterface, options: Options): Promise<SetupFacts> {
  const status = await read($, statusAtom)
  return {
    status: { ...status, port: status.phase === 'running' ? status.port : options.port },
    dataDir: await dataDirOf($),
    listen: options.listen,
  }
}

async function showStatus($: EngineInterface): Promise<void> {
  const status = await read($, statusAtom)
  const flows = await read($, flowsAtom)
  if (status.phase === 'running') $.ui.status(`⇄ proxy :${status.port} · ${flows.length}`)
  else if (status.phase === 'starting') $.ui.status('⇄ proxy: starting…')
  else if (status.phase === 'failed') $.ui.status('⇄ proxy: failed (/proxy)')
  else $.ui.status(undefined)
}

function describeFatal(code: string, message: string, options: Options): string {
  if (code === 'port-busy') {
    return `port ${options.port} is taken (another Claude session or another proxy). Change the Port option in /config, or stop that process: lsof -nP -iTCP:${options.port} -sTCP:LISTEN`
  }
  if (code === 'ca') return `could not create the certificates (openssl is needed): ${message}`
  return message
}

function scheduleFlush($: EngineInterface, rt: Runtime, options: Options): void {
  if (rt.isFlushScheduled) return
  rt.isFlushScheduled = true
  $.clock.after(200, () => {
    rt.isFlushScheduled = false
    void flush($, rt, options)
  })
}

async function flush($: EngineInterface, rt: Runtime, options: Options): Promise<void> {
  if (rt.pending.size === 0) return
  const updates = [...rt.pending.values()]
  rt.pending.clear()
  await update($, flowsAtom, list => mergeFlows(list ?? [], updates, options.maxFlows))
  const maxId = Math.max(...updates.map(flow => flow.id))
  await update($, nextIdAtom, n => Math.max(n ?? 1, maxId + 1))
  await showStatus($)
}

async function kill($: EngineInterface, pid: number): Promise<void> {
  await $.process.run(['kill', String(pid)]).catch(() => undefined)
}

function isRunning(): boolean {
  return runtime !== null
}

async function startProxy($: EngineInterface, options: Options): Promise<void> {
  if (runtime) return
  const rt: Runtime = { pid: null, isStopping: false, pending: new Map(), isFlushScheduled: false, stderr: '' }
  runtime = rt

  // A sidecar a previous load of this module started may still hold the port.
  const previous = await read($, statusAtom)
  if (previous.pid) {
    await kill($, previous.pid)
    await $.clock.sleep(300)
  }

  const host = options.listen === 'lan' ? '0.0.0.0' : '127.0.0.1'
  await update($, wantedAtom, () => true)
  await update($, statusAtom, (s): ProxyStatus => ({ ...STOPPED, lan: s?.lan ?? [], phase: 'starting', host, port: options.port }))
  await showStatus($)

  const stream = $.process.spawn({
    argv: [
      options.node,
      `${$.plugin.root}/sidecar/proxy.mjs`,
      '--port', String(options.port),
      '--host', host,
      '--data', await dataDirOf($),
      '--run', await $.session.id(),
      '--first-id', String(await read($, nextIdAtom)),
      '--no-decrypt', options.noDecrypt,
      '--rules', await rulesFileOf($),
      '--trust', await trustFileOf($),
    ],
  })

  void (async () => {
    let rest = ''
    let fatal: string | null = null
    try {
      for await (const chunk of stream) {
        if (chunk.stream === 'stderr') {
          rt.stderr = (rt.stderr + chunk.text).slice(-4000)
          continue
        }
        const split = splitLines(rest, chunk.text)
        rest = split.rest
        for (const line of split.lines) {
          const event = parseEvent(line)
          if (!event) continue
          if (event.t === 'ready') {
            rt.pid = event.pid
            if (rt.isStopping) {
              await kill($, event.pid)
              continue
            }
            await update($, statusAtom, (): ProxyStatus => ({
              phase: 'running',
              host: event.host,
              port: event.port,
              addresses: event.addresses,
              lan: event.lan ?? [],
              runDir: event.runDir,
              pid: event.pid,
              ca: event.ca,
              error: null,
            }))
            await showStatus($)
          } else if (event.t === 'rules') {
            // the file changed on disk (an edit, a git checkout): read it again
            await loadRules($)
          } else if (event.t === 'network') {
            // the Mac joined another network: the phone's address changed
            await update($, statusAtom, (s): ProxyStatus => ({ ...(s ?? STOPPED), lan: event.lan }))
          } else if (event.t === 'flow') {
            rt.pending.set(event.flow.id, event.flow)
            scheduleFlush($, rt, options)
          } else if (event.t === 'fatal') {
            fatal = describeFatal(event.code, event.message, options)
          } else if (event.t === 'log' && event.level === 'error') {
            $.ui.log(`proxy: ${event.message}`, { to: 'debug' })
          }
        }
      }
    } catch (error) {
      fatal = `could not start "${options.node}": ${error instanceof Error ? error.message : String(error)}. The proxy needs Node 18 or newer (the Node executable option in /config).`
    }
    if (runtime === rt) runtime = null
    // The module may be unloading as the child ends: what is left to record
    // is best effort.
    try {
      await flush($, rt, options)
      const tail = rt.stderr.trim().split('\n').slice(-3).join(' ⏎ ')
      await update($, statusAtom, (status): ProxyStatus => ({
        ...(status ?? STOPPED),
        phase: rt.isStopping ? 'stopped' : 'failed',
        pid: null,
        error: rt.isStopping ? null : (fatal ?? `the proxy exited unexpectedly${tail ? `: ${tail}` : ''}`),
      }))
      if (!rt.isStopping) await update($, wantedAtom, () => false)
      await showStatus($)
    } catch {
      // nothing left to tell
    }
  })()
}

async function stopProxy($: EngineInterface): Promise<void> {
  await update($, wantedAtom, () => false)
  await revertAndroid($)
  const rt = runtime
  const status = await read($, statusAtom)
  const pid = rt?.pid ?? status.pid
  if (rt) rt.isStopping = true
  if (pid) await kill($, pid)
  if (!rt) {
    await update($, statusAtom, (s): ProxyStatus => ({ ...(s ?? STOPPED), phase: 'stopped', pid: null, error: null }))
    await showStatus($)
  }
}

async function clearFlows($: EngineInterface): Promise<void> {
  await update($, flowsAtom, () => [])
  await showStatus($)
}

// --- what the disk holds about one flow ----------------------------------------

async function loadDetail($: EngineInterface, id: number): Promise<FlowDetail | null> {
  const status = await read($, statusAtom)
  const runDir = status.runDir ?? `${await dataDirOf($)}/flows/${await $.session.id()}`
  try {
    return JSON.parse(await $.fs.read(`${runDir}/${id}.json`)) as FlowDetail
  } catch {
    return null
  }
}

type LoadedBody = { text: string | null; note: string | null }

async function loadBody(
  $: EngineInterface,
  body: FlowDetail['req'],
  contentType: string | null,
): Promise<LoadedBody> {
  if (!body) return { text: null, note: null }
  const size = body.size
  const notes: string[] = []
  if (body.isTruncated) notes.push(`${body.stored} of ${size} bytes recorded`)
  if (body.encoding && !body.isDecoded) notes.push(`could not decode ${body.encoding}`)
  if (!isTextual(contentType)) {
    return { text: null, note: [`binary body (${contentType ?? 'unknown type'}), file: ${body.file}`, ...notes].join('; ') }
  }
  try {
    return { text: await $.fs.read(body.file), note: notes.length ? notes.join('; ') : null }
  } catch (error) {
    return { text: null, note: `could not read ${body.file}: ${error instanceof Error ? error.message : String(error)}` }
  }
}

// --- machine-side actions -----------------------------------------------------

async function say($: EngineInterface, text: string): Promise<void> {
  await update($, noticeAtom, () => text)
}

async function findBrowsers($: EngineInterface): Promise<{ browser: Browser; path: string }[]> {
  const home = (await $.env.get('HOME')) ?? ''
  const found: { browser: Browser; path: string }[] = []
  for (const browser of BROWSER_CANDIDATES) {
    for (const dir of ['/Applications', `${home}/Applications`]) {
      const path = `${dir}/${browser.app}`
      if (await $.fs.exists(path).catch(() => false)) {
        found.push({ browser, path })
        break
      }
    }
  }
  return found
}

async function launchBrowser($: EngineInterface, options: Options, slug: string): Promise<void> {
  const status = await read($, statusAtom)
  if (status.phase !== 'running' || !status.ca) return say($, 'Start the proxy first.')
  const found = (await findBrowsers($)).find(b => b.browser.slug === slug)
  if (!found) return say($, 'That browser is not in /Applications.')
  const facts = await setupFacts($, options)
  const ran = await $.process.run(['open', '-na', found.path, '--args', ...browserArgs(facts, found.browser)])
  await say(
    $,
    ran.exitCode === 0
      ? `${found.browser.name} started with a profile of its own; all of its traffic goes through :${status.port}.`
      : `Could not start ${found.browser.name}: ${ran.stderr.trim()}`,
  )
}

async function addCaToSimulators($: EngineInterface): Promise<void> {
  const status = await read($, statusAtom)
  if (!status.ca) return say($, 'There is no certificate yet: start the proxy.')
  const listed = await $.process.run(['xcrun', 'simctl', 'list', 'devices', 'booted', '-j']).catch(error => ({
    exitCode: 1,
    stdout: '',
    stderr: String(error),
  }))
  if (listed.exitCode !== 0) return say($, `xcrun simctl is not available: ${listed.stderr.trim() || 'Xcode is needed'}`)
  type Device = { udid: string; name: string; state: string }
  const devices = Object.values((JSON.parse(listed.stdout) as { devices: Record<string, Device[]> }).devices)
    .flat()
    .filter(device => device.state === 'Booted')
  if (devices.length === 0) return say($, 'No simulator is booted: boot one and press again.')
  const done: string[] = []
  const failed: string[] = []
  for (const device of devices) {
    const ran = await $.process.run(['xcrun', 'simctl', 'keychain', device.udid, 'add-root-cert', status.ca.path])
    if (ran.exitCode === 0) done.push(device.name)
    else failed.push(`${device.name}: ${ran.stderr.trim()}`)
  }
  await say(
    $,
    [done.length ? `CA added to: ${done.join(', ')}.` : '', failed.length ? `Failed: ${failed.join('; ')}` : '']
      .filter(Boolean)
      .join(' '),
  )
}

async function adb($: EngineInterface): Promise<string | null> {
  const onPath = await $.process.run(['adb', 'version']).catch(() => null)
  if (onPath?.exitCode === 0) return 'adb'
  const home = (await $.env.get('HOME')) ?? ''
  const sdk = `${home}/Library/Android/sdk/platform-tools/adb`
  return (await $.fs.exists(sdk).catch(() => false)) ? sdk : null
}

async function androidDevices($: EngineInterface, tool: string): Promise<string[]> {
  const ran = await $.process.run([tool, 'devices'])
  return ran.stdout
    .split('\n')
    .slice(1)
    .map(line => line.trim().split(/\s+/))
    .filter(parts => parts[1] === 'device')
    .map(parts => parts[0]!)
}

/**
 * Emulators reach this Mac's localhost as 10.0.2.2; a USB device reaches it
 * through `adb reverse`, so neither needs the LAN.
 */
async function pointAndroid($: EngineInterface): Promise<void> {
  const status = await read($, statusAtom)
  if (status.phase !== 'running') return say($, 'Start the proxy first.')
  const tool = await adb($)
  if (!tool) return say($, 'adb not found (neither on PATH nor in ~/Library/Android/sdk/platform-tools).')
  const serials = await androidDevices($, tool)
  if (serials.length === 0) return say($, 'No emulator or device is connected (adb devices lists none).')
  const done: string[] = []
  for (const serial of serials) {
    const isEmulator = serial.startsWith('emulator-')
    if (!isEmulator) await $.process.run([tool, '-s', serial, 'reverse', `tcp:${status.port}`, `tcp:${status.port}`])
    const target = isEmulator ? `10.0.2.2:${status.port}` : `127.0.0.1:${status.port}`
    const ran = await $.process.run([tool, '-s', serial, 'shell', 'settings', 'put', 'global', 'http_proxy', target])
    if (ran.exitCode === 0) done.push(serial)
  }
  await update($, emulatorsAtom, list => [...new Set([...(list ?? []), ...done])])
  await say($, done.length ? `Through the proxy now: ${done.join(', ')}. "Revert" or stopping the proxy points them back.` : 'Could not set the proxy.')
}

async function revertAndroid($: EngineInterface): Promise<void> {
  const serials = await read($, emulatorsAtom)
  if (serials.length === 0) return
  const tool = await adb($)
  const status = await read($, statusAtom)
  if (tool) {
    for (const serial of serials) {
      await $.process.run([tool, '-s', serial, 'shell', 'settings', 'put', 'global', 'http_proxy', ':0']).catch(() => null)
      if (!serial.startsWith('emulator-')) {
        await $.process.run([tool, '-s', serial, 'reverse', '--remove', `tcp:${status.port}`]).catch(() => null)
      }
    }
  }
  await update($, emulatorsAtom, () => [])
  await say($, `Android proxy reverted on: ${serials.join(', ')}.`)
}

async function openCaPageOnAndroid($: EngineInterface): Promise<void> {
  const tool = await adb($)
  if (!tool) return say($, 'adb not found.')
  const serials = await androidDevices($, tool)
  if (serials.length === 0) return say($, 'No emulator or device is connected.')
  for (const serial of serials) {
    await $.process.run([
      tool, '-s', serial, 'shell', 'am', 'start', '-a', 'android.intent.action.VIEW', '-d', 'http://claude.proxy/',
    ])
  }
  await say($, `Opened the CA page on ${serials.join(', ')} (the device must be using the proxy).`)
}

// --- the rules file ------------------------------------------------------------
//
// <project>/.claude/proxy-rules.json, which the sidecar applies (see
// shared/rules.mjs). A rule holding a script runs only once the script's
// SHA-256 is in <data>/trusted-scripts.json: a cloned project's rules file
// must not run code on this machine unasked.

async function rulesFileOf($: EngineInterface): Promise<string> {
  return `${await $.session.root()}/.claude/proxy-rules.json`
}

async function trustFileOf($: EngineInterface): Promise<string> {
  return `${await dataDirOf($)}/trusted-scripts.json`
}

async function sha256(text: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))
  return [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, '0')).join('')
}

async function readTrusted($: EngineInterface): Promise<Set<string>> {
  try {
    const data = JSON.parse(await $.fs.read(await trustFileOf($))) as { sha256?: unknown }
    return new Set(Array.isArray(data.sha256) ? data.sha256.filter((hash): hash is string => typeof hash === 'string') : [])
  } catch {
    return new Set()
  }
}

async function trustScripts($: EngineInterface, codes: readonly string[]): Promise<void> {
  if (codes.length === 0) return
  const trusted = await readTrusted($)
  for (const code of codes) trusted.add(await sha256(code))
  await $.fs.write(await trustFileOf($), `${JSON.stringify({ sha256: [...trusted] }, null, 2)}\n`)
}

async function readRulesText($: EngineInterface): Promise<{ file: string; text: string | null }> {
  const file = await rulesFileOf($)
  try {
    return { file, text: await $.fs.read(file) }
  } catch {
    return { file, text: null }
  }
}

/** Reads the rules file into the rules view's state, and answers it. */
async function loadRules($: EngineInterface): Promise<ProxyRules> {
  const { file, text } = await readRulesText($)
  const parsed = parseRules(text)
  const trusted = await readTrusted($)
  const entries: ProxyRuleEntry[] = []
  for (const { rule, errors } of parsed.rules) {
    let isUntrusted = false
    if (errors.length === 0) {
      for (const code of scriptsOf(rule)) if (!trusted.has(await sha256(code))) isUntrusted = true
    }
    entries.push({
      id: typeof rule?.id === 'string' ? rule.id : '?',
      name: typeof rule?.name === 'string' ? rule.name : null,
      description: typeof rule?.description === 'string' ? rule.description : null,
      enabled: rule?.enabled !== false,
      summary: errors.length ? '' : describeRule(rule),
      errors,
      isUntrusted,
    })
  }
  const value: ProxyRules = { file, entries, fileErrors: parsed.errors }
  await update($, rulesAtom, () => value)
  return value
}

/**
 * Rewrites the rules file's list through `change`, keeping the rest of the
 * file; `change` answers the new list, or a string saying why not.
 * Answers that reason, or null once written.
 */
async function editRules($: EngineInterface, change: (rules: Rule[]) => Rule[] | string): Promise<string | null> {
  const { file, text } = await readRulesText($)
  let data: { rules: Rule[] } & Record<string, unknown> = { rules: [] }
  if (text !== null && text.trim() !== '') {
    try {
      data = JSON.parse(text) as typeof data
    } catch {
      return `${file} is not valid JSON; fix it by hand first`
    }
    if (data === null || typeof data !== 'object' || !Array.isArray(data.rules)) return `${file} must hold {"rules": [...]}`
  }
  const next = change([...data.rules])
  if (typeof next === 'string') return next
  await $.fs.write(file, `${JSON.stringify({ ...data, rules: next }, null, 2)}\n`)
  await loadRules($)
  return null
}

async function toggleRule($: EngineInterface, id: string): Promise<void> {
  const failure = await editRules($, rules => rules.map(rule => (rule.id === id ? { ...rule, enabled: rule.enabled === false } : rule)))
  if (failure) await say($, failure)
}

async function moveRule($: EngineInterface, id: string, by: number): Promise<void> {
  const failure = await editRules($, rules => {
    const from = rules.findIndex(rule => rule.id === id)
    const to = Math.max(0, Math.min(rules.length - 1, from + by))
    if (from < 0 || from === to) return rules
    const [moved] = rules.splice(from, 1)
    rules.splice(to, 0, moved!)
    return rules
  })
  if (failure) await say($, failure)
}

async function allowRuleScripts($: EngineInterface, id: string): Promise<void> {
  const { text } = await readRulesText($)
  const rule = parseRules(text).rules.find(entry => entry.rule?.id === id)?.rule
  if (!rule) return
  await trustScripts($, scriptsOf(rule))
  await loadRules($)
  await say($, `Scripts of ${id} approved; the proxy runs them from now on.`)
}

// --- the pane -------------------------------------------------------------------




type PaneEvent = RenderInput<'Pane'>

const MAX_ROWS = 200
const BODY_LINES = 200
const BODY_CHARS = 20_000

const ERROR_HINTS: Record<string, string> = {
  'client-rejected-cert':
    'The client does not trust the proxy CA, or the app pins its certificates. Install and trust the CA (Setup), or add the host to "Hosts not to decrypt".',
  upstream: 'The proxy could not reach the server: DNS, the network, a refused connection or an untrusted server certificate.',
  'client-closed': 'The client closed the connection before the whole response arrived.',
  'tls-handshake': 'The TLS handshake with the client failed.',
  forbidden:
    "A client from the network tried to reach this Mac's localhost through the proxy. That is closed on purpose: in lan mode the proxy does not open local services to others.",
}

function statusColor(flow: ProxyFlow): string | undefined {
  if (flow.state === 'error') return 'error'
  if (flow.status === null) return 'subtle'
  if (flow.status >= 500) return 'error'
  if (flow.status >= 400) return 'warning'
  if (flow.status >= 300) return 'suggestion'
  return 'success'
}

function phaseLine(status: ProxyStatus, total: number, shown: number, hasFilter: boolean): string {
  const requests = `${total} ${total === 1 ? 'request' : 'requests'}`
  const counts = hasFilter ? `${shown} of ${requests} match` : requests
  switch (status.phase) {
    case 'running': {
      const lan = status.addresses.filter(a => a !== '127.0.0.1')
      const where = status.host === '0.0.0.0' && lan.length ? `${lan[0]}:${status.port}` : `127.0.0.1:${status.port}`
      return `● ${where} · ${counts}`
    }
    case 'starting':
      return `◌ starting on :${status.port}…`
    case 'failed':
      return `✕ not working · ${counts}`
    default:
      return `○ stopped · ${counts}`
  }
}

async function drawPane($: EngineInterface, e: PaneEvent, options: Options): Promise<RenderElement> {
  const view = await read($, viewAtom)
  if (view.mode === 'detail' && view.selectedId !== null) return drawDetail($, e, view.selectedId, options)
  if (view.mode === 'setup') return drawSetup($, e, view.setupTab, options)
  if (view.mode === 'rules') return drawRules($, e)
  return drawList($, e, options)
}

async function drawList($: EngineInterface, e: PaneEvent, options: Options): Promise<RenderElement> {
  const table = $.ui.resolve(e)
  const { Box, Text, Button } = table
  const Input = 'Input' in table ? table.Input : undefined
  const flows = await read($, flowsAtom)
  const status = await read($, statusAtom)
  const query = await read($, filterAtom)
  const parsed = parseFilter(query)
  const shown = filterFlows(flows, query).reverse()
  const isRunning = status.phase === 'running' || status.phase === 'starting'
  const view = await read($, viewAtom)
  const isTree = view.layout === 'tree'
  const expanded = await read($, expandedAtom)
  const tree = isTree ? buildTree(filterFlows(flows, query)) : []
  const treeRows = isTree ? flattenTree(tree, new Set(expanded)) : []
  const width = Math.max(30, e.props.bodyColumns)
  // status 4 + method 7 + gaps; size and time on the right
  const urlWidth = Math.max(12, width - 4 - 1 - 7 - 1 - 17)

  const open = (id: number) => update($, viewAtom, (v): ProxyView => ({ ...v, mode: 'detail', selectedId: id }))
  const toggleNode = (id: string) =>
    update($, expandedAtom, list => ((list ?? []).includes(id) ? (list ?? []).filter(x => x !== id) : [...(list ?? []), id]))
  const setLayout = (layout: 'list' | 'tree') => chooseLayout($, layout)

  const rules = await read($, rulesAtom)
  const rulesOn = rules.entries.filter(entry => entry.enabled && entry.errors.length === 0 && !entry.isUntrusted).length
  const flowCells = (flow: ProxyFlow, label: string, labelWidth: number) => [
    <Text color={statusColor(flow)}>{statusLabel(flow).padEnd(4)} </Text>,
    <Text bold>{flow.method.slice(0, 7).padEnd(7)} </Text>,
    <Box flexGrow={1}>
      <Button
        plain
        key={`open-${flow.id}`}
        label={truncate(flow.rules?.length ? `✎ ${label}` : label, labelWidth)}
        onPress={() => void open(flow.id)}
      />
    </Box>,
    <Text dimColor>
      {' '}
      {formatSize(flow.resSize).padStart(7)} {formatDuration(flow.durationMs).padStart(7)}
    </Text>,
  ]

  return (
    <Box flexDirection="column">
      <Text bold color={status.phase === 'running' ? 'success' : status.phase === 'failed' ? 'error' : 'subtle'}>
        {truncate(phaseLine(status, flows.length, shown.length, parsed.terms.length > 0), width)}
      </Text>
      <Box flexDirection="row" gap={1} flexWrap="wrap">
        <Button
          key="toggle"
          hotkey="s"
          variant={isRunning ? undefined : 'primary'}
          label={isRunning ? 'Stop' : 'Start'}
          onPress={() => void (isRunning ? stopProxy($) : startProxy($, options))}
        />
        <Text dimColor>View</Text>
        <Button
          key="layout-list"
          hotkey="l"
          variant={isTree ? undefined : 'primary'}
          label="List"
          onPress={() => void setLayout('list')}
        />
        <Button
          key="layout-tree"
          hotkey="t"
          variant={isTree ? 'primary' : undefined}
          label="Tree"
          onPress={() => void setLayout('tree')}
        />
        {isTree ? (
          <Button key="expand-all" hotkey="e" label="Expand all" onPress={() => void update($, expandedAtom, () => treeIds(tree))} />
        ) : null}
        {isTree ? (
          <Button key="collapse-all" hotkey="c" label="Collapse all" onPress={() => void update($, expandedAtom, () => [])} />
        ) : null}
        <Button
          key="rules"
          hotkey="r"
          label={`Rules (${rulesOn})`}
          onPress={() => void openRules($)}
        />
        <Button key="clear" hotkey="x" label="Clear" onPress={() => void clearFlows($)} />
        <Button
          key="setup"
          hotkey="n"
          label="Setup"
          onPress={() => void update($, viewAtom, (v): ProxyView => ({ ...v, mode: 'setup' }))}
        />
      </Box>
      {status.error ? <Text color="error">{status.error}</Text> : null}
      {Input ? (
        <Input
          key="filter"
          label="Filter "
          placeholder="method:POST status:4xx host:*.api.com type:json is:error -text"
          value={query}
          submitLabel="apply"
          onInput={value => void update($, filterAtom, () => value)}
          onSubmit={value => void update($, filterAtom, () => value)}
        />
      ) : null}
      {parsed.errors.length ? <Text color="warning">Not understood: {parsed.errors.join(', ')}</Text> : null}
      {shown.length === 0 ? (
        <Text dimColor>
          {flows.length > 0
            ? 'Nothing matches the filter.'
            : isRunning
              ? 'Waiting for requests. Setup (n) shows how to point a browser, a simulator or a phone here.'
              : 'The proxy is stopped. Start (s) runs it; Setup (n) shows how to connect clients.'}
        </Text>
      ) : null}
      {isTree
        ? treeRows.slice(0, MAX_ROWS).map(row => {
            const indent = '  '.repeat(row.depth)
            if (row.kind === 'flow') {
              return (
                <Box key={`leaf-${row.flow.id}`} flexDirection="row">
                  <Text>{indent}</Text>
                  {flowCells(row.flow, treeLeafLabel(row.flow), urlWidth - indent.length)}
                </Box>
              )
            }
            const { node } = row
            return (
              <Box key={`branch-${node.id}`} flexDirection="row">
                <Text>{indent}</Text>
                <Button
                  plain
                  key={`node:${node.id}`}
                  label={`${row.isOpen ? '▾' : '▸'} ${truncate(node.label, Math.max(10, width - indent.length - 24))}`}
                  onPress={() => void toggleNode(node.id)}
                />
                <Text dimColor> {node.count}</Text>
                {node.errors ? <Text color="error"> · {node.errors} failed</Text> : null}
              </Box>
            )
          })
        : shown.slice(0, MAX_ROWS).map(flow => (
            <Box key={`row-${flow.id}`} flexDirection="row">
              {flowCells(flow, flowUrl(flow), urlWidth)}
            </Box>
          ))}
      {(isTree ? treeRows.length : shown.length) > MAX_ROWS ? (
        <Text dimColor>
          …and {(isTree ? treeRows.length : shown.length) - MAX_ROWS} more rows; narrow the filter{isTree ? ' or collapse a node' : ''}.
        </Text>
      ) : null}
    </Box>
  )
}

async function drawDetail($: EngineInterface, e: PaneEvent, id: number, options: Options): Promise<RenderElement> {
  const table = $.ui.resolve(e)
  const { Box, Text, Button, Code } = table
  const flows = await read($, flowsAtom)
  const summary = flows.find(flow => flow.id === id)
  const detail = await loadDetail($, id)
  const flow = summary ?? detail
  const back = () => void update($, viewAtom, (v): ProxyView => ({ ...v, mode: 'list', selectedId: null }))

  if (!flow) {
    return (
      <Box flexDirection="column">
        <Button key="back" hotkey="b" label="← Back" onPress={back} />
        <Text color="warning">Request #{id} is gone (the list was cleared, or this is another session).</Text>
      </Box>
    )
  }

  const reqBody = detail ? await loadBody($, detail.req, detail.reqHeaders.find(([k]) => k.toLowerCase() === 'content-type')?.[1] ?? null) : null
  const resBody = detail ? await loadBody($, detail.res, flow.contentType) : null
  const url = detail?.url ?? flowUrl(flow)

  const headerRows = (headers: readonly [string, string][], prefix: string) =>
    headers.map(([name, value], i) => (
      <Box key={`${prefix}-${i}`} flexDirection="row">
        <Text color="claude">{name}: </Text>
        <Box flexShrink={1}>
          <Text>{value}</Text>
        </Box>
      </Box>
    ))

  const bodyBlock = (body: typeof reqBody, contentType: string | null, key: string) => {
    if (!body || (body.text === null && body.note === null)) return <Text dimColor>no body</Text>
    const pretty = body.text === null ? null : clip(prettyBody(body.text, contentType), BODY_LINES, BODY_CHARS)
    const language = languageOf(contentType)
    return (
      <Box flexDirection="column">
        {body.note ? <Text dimColor>{body.note}</Text> : null}
        {pretty && pretty.text.length > 0 ? (
          language ? (
            <Code source={pretty.text} language={language} wrap="wrap" />
          ) : (
            <Text>{pretty.text}</Text>
          )
        ) : pretty ? (
          <Text dimColor>empty body</Text>
        ) : null}
        {pretty?.isClipped ? <Text dimColor>…cut here; the whole body: {key === 'req-body' ? detail?.req?.file : detail?.res?.file}</Text> : null}
      </Box>
    )
  }

  const meta = [
    flow.status !== null ? `${flow.status}${detail?.statusMessage ? ` ${detail.statusMessage}` : ''}` : flow.state === 'error' ? 'failed' : 'in progress',
    formatDuration(flow.durationMs),
    `↑${formatSize(flow.reqSize)} ↓${formatSize(flow.resSize)}`,
    flow.contentType ?? '',
    flow.client ? `from ${flow.client}` : '',
    new Date(flow.ts).toLocaleTimeString(),
  ].filter(Boolean)

  return (
    <Box flexDirection="column">
      <Box flexDirection="row" gap={1}>
        <Button key="back" hotkey="b" label="← Back" onPress={back} />
        {detail && flow.kind === 'http' ? (
          <Button
            key="curl"
            hotkey="c"
            label="Copy as curl"
            onPress={press => void $.ui.copy({ text: toCurl(detail, reqBody?.text ?? null), surface: press.surface })}
          />
        ) : null}
        <Button key="url" hotkey="u" label="URL" onPress={press => void $.ui.copy({ text: url, surface: press.surface })} />
        <Button
          key="prompt"
          hotkey="p"
          variant="primary"
          label="To prompt"
          onPress={() =>
            void $.prompt.fill({
              text: `Captured request proxy #${flow.id}: ${flow.method} ${url} → ${statusLabel(flow)}. `,
              mode: 'insert',
            })
          }
        />
      </Box>
      <Text bold>
        #{flow.id} {flow.method} {url}
      </Text>
      <Text color={statusColor(flow)}>{meta.join(' · ')}</Text>
      {flow.error ? (
        <Box flexDirection="column">
          <Text color="error">{flow.error}</Text>
          {flow.errorCode && ERROR_HINTS[flow.errorCode] ? <Text dimColor>{ERROR_HINTS[flow.errorCode]}</Text> : null}
        </Box>
      ) : null}
      {detail?.ruleLog?.length ? (
        <Box flexDirection="column" marginTop={1}>
          <Text bold underline>Rules</Text>
          {detail.ruleLog.map((line, i) => (
            <Text key={`rule-log-${i}`} color="claude">
              ✎ {line}
            </Text>
          ))}
          <Text dimColor>Headers and bodies below are what the server got and what the client got.</Text>
        </Box>
      ) : null}
      {detail ? (
        <Box flexDirection="column" marginTop={1}>
          <Text bold underline>Request</Text>
          {headerRows(detail.reqHeaders, 'req')}
          {detail.req || flow.kind === 'http' ? bodyBlock(reqBody, detail.reqHeaders.find(([k]) => k.toLowerCase() === 'content-type')?.[1] ?? null, 'req-body') : null}
          <Box marginTop={1}>
            <Text bold underline>Response</Text>
          </Box>
          {detail.resHeaders.length ? headerRows(detail.resHeaders, 'res') : <Text dimColor>no headers yet</Text>}
          {flow.kind === 'http' ? bodyBlock(resBody, flow.contentType, 'res-body') : null}
        </Box>
      ) : (
        <Text dimColor>The details are not on disk yet.</Text>
      )}
    </Box>
  )
}

async function drawSetup($: EngineInterface, e: PaneEvent, tab: ProxySetupTab, options: Options): Promise<RenderElement> {
  const table = $.ui.resolve(e)
  const { Box, Text, Button, Markdown } = table
  const status = await read($, statusAtom)
  const notice = await read($, noticeAtom)
  const facts = await setupFacts($, options)
  const commands = setupCommands(facts)
  const isRunning = status.phase === 'running'

  const copy = (key: string) => (press: { surface: Parameters<EngineInterface['ui']['copy']>[0]['surface'] }) =>
    void $.ui.copy({ text: commands[key] ?? '', surface: press.surface }).then(result =>
      update($, noticeAtom, () => (result.isCopied ? 'Copied.' : 'Could not copy.')),
    )
  const run = (action: () => Promise<void>) => () => void action()

  let actions: RenderElement[] = []
  let guide = ''
  if (tab === 'browser') {
    const found = await findBrowsers($)
    guide = browserGuide(facts, found.map(f => f.browser))
    actions = found.map((f, i) => (
      <Button
        key={`browser-${f.browser.slug}`}
        hotkey={i === 0 ? 'o' : undefined}
        variant={i === 0 ? 'primary' : undefined}
        label={`Open ${f.browser.name}`}
        onPress={run(() => launchBrowser($, options, f.browser.slug))}
      />
    ))
  } else if (tab === 'ios') {
    guide = iosGuide(facts)
    actions = [
      <Button key="sim-ca" hotkey="a" variant="primary" label="CA → simulators" onPress={run(() => addCaToSimulators($))} />,
      <Button key="copy-sys-on" label="system proxy on" onPress={copy('sys-on')} />,
      <Button key="copy-sys-off" label="off" onPress={copy('sys-off')} />,
    ]
  } else if (tab === 'android') {
    guide = androidGuide(facts)
    const pointed = await read($, emulatorsAtom)
    actions = [
      <Button key="adb-on" hotkey="a" variant="primary" label="Android → proxy" onPress={run(() => pointAndroid($))} />,
      <Button key="adb-off" label={pointed.length ? `Revert (${pointed.length})` : 'Revert'} onPress={run(() => revertAndroid($))} />,
      <Button key="adb-ca" label="Open CA page" onPress={run(() => openCaPageOnAndroid($))} />,
      <Button key="copy-android-config" label="config snippet" onPress={copy('android-config')} />,
    ]
  } else {
    guide = cliGuide(facts)
    actions = [
      <Button key="copy-trust" label="trust CA" onPress={copy('trust')} />,
      <Button key="copy-sys-on" label="system proxy on" onPress={copy('sys-on')} />,
      <Button key="copy-sys-off" label="off" onPress={copy('sys-off')} />,
      <Button key="copy-env" label="env" onPress={copy('env')} />,
      <Button key="copy-curl" label="curl" onPress={copy('curl')} />,
    ]
  }

  const targets = proxyTargets(facts, tab)
  const remote = targets.find(target => target.isRemote)
  const phone = phoneAddress(facts)
  const isLocalOnly = options.listen !== 'lan'
  const others = facts.status.lan.filter(entry => !entry.isPrimary)
  const kindName = (kind: string) => (kind === 'vpn' ? 'VPN' : kind === 'virtual' ? 'virtual machines' : 'another network')
  const setListen = (value: 'lan' | 'local') => async () => {
    // the engine reloads the mod with the new option; the proxy restarts on it
    const result = await $.config.set({ key: 'proxy.listen', value })
    await say($, 'deny' in result && result.deny ? `Could not change Listen on: ${result.deny}` : value === 'lan' ? 'Listening on the network now.' : 'Listening on this Mac only now.')
  }

  // a phone scans this before any proxy setting: a plain request to the port
  // answers with the setup page
  const qrUrl = remote && phone && !isLocalOnly ? `http://${phone.address}:${facts.status.port}/` : null
  let qrBlock: RenderElement | null = null
  if (qrUrl) {
    const code = encodeQr(qrUrl)
    // Raster draws on the terminal alone (elsewhere it is an empty fragment)
    const isTerminal = e.surface === 'terminal'
    const raster = isTerminal && 'Raster' in table ? qrRaster(code) : null
    const picture =
      isTerminal && 'Raster' in table && raster ? (
        <table.Raster key="qr" columns={raster.columns} rows={raster.rows} cells={raster.cells} />
      ) : 'Svg' in table ? (
        <table.Svg source={qrSvg(code)} alt={`QR code for ${qrUrl}`} width={180} height={180} />
      ) : null
    qrBlock = (
      <Box flexDirection="row" gap={2} marginTop={1}>
        {picture}
        <Box flexDirection="column" flexShrink={1}>
          <Text bold>Scan with the {tab === 'ios' ? "iPhone's" : "phone's"} camera</Text>
          <Text color="claude">{qrUrl}</Text>
          <Text dimColor>
            {tab === 'ios'
              ? 'It opens the setup page: tap "iOS: download profile", then follow the steps below.'
              : 'It opens the setup page: tap "Android: download certificate", then follow the steps below.'}
          </Text>
          <Text dimColor>The phone only has to be on the same network; no proxy setting is needed for this page.</Text>
        </Box>
      </Box>
    )
  }

  return (
    <Box flexDirection="column">
      <Box flexDirection="row" gap={1} flexWrap="wrap">
        <Button
          key="back"
          hotkey="b"
          label="← List"
          onPress={() => void update($, viewAtom, (v): ProxyView => ({ ...v, mode: 'list' }))}
        />
        {SETUP_TABS.map(t => (
          <Button
            key={`tab-${t.tab}`}
            hotkey={t.hotkey}
            variant={t.tab === tab ? 'primary' : undefined}
            label={t.label}
            onPress={() => {
              void update($, noticeAtom, () => '')
              void update($, viewAtom, (v): ProxyView => ({ ...v, setupTab: t.tab }))
            }}
          />
        ))}
      </Box>
      <Box flexDirection="column" borderStyle="round" borderColor="claude" paddingX={1} marginTop={1}>
        <Text bold>Proxy settings to enter{isRunning ? '' : ' (once the proxy runs)'}</Text>
        {targets.map(target => (
          <Box key={`target-${target.client}`} flexDirection="row" flexWrap="wrap">
            <Text>{target.client.padEnd(18)} </Text>
            {target.host ? (
              <Text bold color={target.isRemote && isLocalOnly ? 'warning' : 'success'}>
                Server {target.host}  Port {target.port}
              </Text>
            ) : (
              <Text color="warning">no address a phone can reach</Text>
            )}
            <Text dimColor>  {target.how}</Text>
          </Box>
        ))}
        {remote && phone ? (
          <Text dimColor>
            {phone.address} is this Mac on {phone.label}
            {others.length ? `; not ${others.map(entry => `${entry.address} (${kindName(entry.kind)})`).join(', ')}` : ''}.
          </Text>
        ) : null}
        {remote ? (
          <Box flexDirection="row" gap={1} flexWrap="wrap">
            {phone ? (
              <Button
                key="copy-ip"
                hotkey="i"
                label={`copy ${phone.address}`}
                onPress={press =>
                  void $.ui.copy({ text: phone.address, surface: press.surface }).then(result =>
                    say($, result.isCopied ? `Copied ${phone.address}.` : 'Could not copy.'),
                  )
                }
              />
            ) : null}
            {isLocalOnly ? (
              <Text color="warning">Listen on is local: a phone cannot reach the proxy yet.</Text>
            ) : null}
            {isLocalOnly ? (
              <Button key="listen-lan" hotkey="l" variant="primary" label="Listen on LAN" onPress={() => void setListen('lan')()} />
            ) : (
              <Button key="listen-local" label="Back to this Mac only" onPress={() => void setListen('local')()} />
            )}
          </Box>
        ) : null}
      </Box>
      {status.ca ? (
        <Box flexDirection="column">
          <Text dimColor>CA: {status.ca.path}</Text>
          <Text dimColor>SHA-256: {status.ca.fingerprint256}</Text>
        </Box>
      ) : (
        <Text dimColor>The certificate is made the first time the proxy starts.</Text>
      )}
      {!isRunning ? (
        <Box flexDirection="row" gap={1}>
          <Text color="warning">The proxy is not running.</Text>
          <Button key="start" hotkey="s" variant="primary" label="Start" onPress={run(() => startProxy($, options))} />
        </Box>
      ) : null}
      {notice ? <Text color="success">{notice}</Text> : null}
      {actions.length ? (
        <Box flexDirection="row" gap={1} flexWrap="wrap" marginTop={1}>
          {actions}
        </Box>
      ) : null}
      {qrBlock}
      <Markdown key="guide" text={guide} />
    </Box>
  )
}

async function openRules($: EngineInterface): Promise<void> {
  await loadRules($)
  await update($, viewAtom, (v): ProxyView => ({ ...v, mode: 'rules' }))
}

async function drawRules($: EngineInterface, e: PaneEvent): Promise<RenderElement> {
  const { Box, Text, Button } = $.ui.resolve(e)
  const rules = await read($, rulesAtom)
  const flows = await read($, flowsAtom)
  const notice = await read($, noticeAtom)
  const hits = (id: string) => flows.filter(flow => flow.rules?.includes(id)).length
  const on = rules.entries.filter(entry => entry.enabled && entry.errors.length === 0 && !entry.isUntrusted).length
  const shownFile = rules.file?.replace(/^.*\/(\.claude\/proxy-rules\.json)$/, '$1') ?? '.claude/proxy-rules.json'

  return (
    <Box flexDirection="column">
      <Box flexDirection="row" gap={1} flexWrap="wrap">
        <Button key="back" hotkey="b" label="← List" onPress={() => void update($, viewAtom, (v): ProxyView => ({ ...v, mode: 'list' }))} />
        <Button key="rules-reload" hotkey="g" label="Reload" onPress={() => void loadRules($)} />
      </Box>
      <Text bold>
        Rules · {shownFile} · {rules.entries.length} {rules.entries.length === 1 ? 'rule' : 'rules'}, {on} on
      </Text>
      <Text dimColor>The first rule applies first; every matching rule that is on applies, in order, unless one says stop.</Text>
      {rules.fileErrors.map((error, i) => (
        <Text key={`file-error-${i}`} color="error">
          {error}
        </Text>
      ))}
      {notice ? <Text color="success">{notice}</Text> : null}
      {rules.entries.length === 0 && rules.fileErrors.length === 0 ? (
        <Box flexDirection="column" marginTop={1}>
          <Text>No rules yet. Ask Claude, for example:</Text>
          <Text dimColor>  "make GET /api/feed take 3 seconds"</Text>
          <Text dimColor>  "answer POST /login with a 500 and an error JSON"</Text>
          <Text dimColor>  "add an Authorization header to every request to api.example.com"</Text>
          <Text dimColor>  "send /v1/* to my local server on port 3000"</Text>
        </Box>
      ) : null}
      {rules.entries.map((entry, index) => {
        const isActive = entry.enabled && entry.errors.length === 0 && !entry.isUntrusted
        const count = hits(entry.id)
        return (
          <Box key={`rule-${entry.id}-${index}`} flexDirection="column" marginTop={1}>
            <Box flexDirection="row" gap={1} flexWrap="wrap">
              <Text dimColor>{String(index + 1).padStart(2)}.</Text>
              <Button
                plain
                key={`rule-toggle:${entry.id}`}
                label={entry.enabled ? '[on] ' : '[off]'}
                onPress={() => void toggleRule($, entry.id)}
              />
              <Text bold color={isActive ? undefined : 'subtle'}>
                {entry.name ?? entry.id}
              </Text>
              {entry.name ? <Text dimColor>({entry.id})</Text> : null}
              <Button plain key={`rule-up:${entry.id}`} label="↑" onPress={() => void moveRule($, entry.id, -1)} />
              <Button plain key={`rule-down:${entry.id}`} label="↓" onPress={() => void moveRule($, entry.id, 1)} />
              <Text dimColor>
                {count} {count === 1 ? 'hit' : 'hits'}
              </Text>
            </Box>
            {entry.description ? <Text>    {entry.description}</Text> : null}
            {entry.summary ? <Text dimColor>    {entry.summary}</Text> : null}
            {entry.errors.map((error, i) => (
              <Text key={`rule-error-${entry.id}-${i}`} color="error">
                {'    '}
                {error}
              </Text>
            ))}
            {entry.isUntrusted ? (
              <Box flexDirection="row" gap={1} flexWrap="wrap">
                <Text color="warning">    Its script is not approved yet, so the rule does not run.</Text>
                <Button key={`rule-trust:${entry.id}`} label="Allow script" onPress={() => void allowRuleScripts($, entry.id)} />
              </Box>
            ) : null}
          </Box>
        )
      })}
    </Box>
  )
}

// --- hooks ------------------------------------------------------------------------

const LIST_TOOL = 'mcp__proxy__list_requests'
const GET_TOOL = 'mcp__proxy__get_request'

const FILTER_HELP =
  'space-separated terms that must all hold, a leading "-" negates one: free text (substring of the URL), ' +
  'method:POST (or method:get,post), status:4xx | status:404 | status:>=400 | status:400-499, host:api.example.com | host:*.example.com, ' +
  'path:/v1/login, type:json|html|xml|js|css|img|font|media|text|form|ws|tunnel|other, is:error|ok|pending|tunnel|ws|https|rejected, client:192.168.'

const ACTION_TYPES = [
  'delay', 'throttle', 'setHeader', 'removeHeader', 'setQuery', 'removeQuery', 'mapRemote', 'replaceUrl',
  'setBody', 'replaceBody', 'mergeJson', 'respond', 'setStatus', 'fail', 'script',
]

const ACTION_SCHEMA = {
  type: 'object',
  description:
    'One step; its type and fields: delay {ms, msMax?} · throttle {bytesPerSecond} · setHeader {name, value} · removeHeader {name} · ' +
    'setQuery {name, value} (request) · removeQuery {name} (request) · mapRemote {scheme?, host?, port?, path?} (request: send elsewhere) · ' +
    'replaceUrl {pattern, with} (request) · setBody {text | json | file} · replaceBody {pattern, with} · mergeJson {json} (deep-merges into a JSON body) · ' +
    'respond {status, headers?, text | json | file} (request: answer without asking the server) · setStatus {status} (response) · ' +
    'fail {kind: reset | close | timeout} · script {code}. A replace pattern is re:<regex source> (every match, $1 works in with) or literal text. ' +
    'file is relative to the project root. script code is the body of async (req, res, ctx) => {}: in request it may change req.method, ' +
    'req.url, req.headers (lower-case names), req.body, or set req.respond = {status, headers, body}; in response it may change res.status, ' +
    'res.headers, res.body; req.json() and res.json() parse the bodies; a body may be set to an object. Prefer the other types to scripts.',
  properties: { type: { type: 'string', enum: ACTION_TYPES } },
  required: ['type'],
  additionalProperties: true,
}

const PATTERN_HELP = 'a glob (* any run, ? one character, case-insensitive, matched whole) or re:<JavaScript regex source>'

const RULE_SCHEMA = {
  type: 'object',
  properties: {
    id: { type: 'string', description: 'Unique in the file: 1-64 of letters, digits, ., _ and -.' },
    name: { type: 'string', description: 'A short title.' },
    description: { type: 'string', description: 'Why the rule exists, in one sentence the person reads.' },
    enabled: { type: 'boolean', description: 'false keeps the rule in the file without applying it.' },
    match: {
      type: 'object',
      description: `Every condition given must hold; no condition matches every request. Patterns are ${PATTERN_HELP}.`,
      properties: {
        url: { type: 'string', description: 'The full URL, e.g. https://api.example.com/v1/*' },
        host: { type: 'string', description: 'api.example.com, or *.example.com (which covers example.com too)' },
        path: { type: 'string', description: 'The path without the query, e.g. /v1/feed*' },
        methods: { type: 'array', items: { type: 'string' }, description: 'e.g. ["GET", "POST"]' },
        headers: { type: 'object', additionalProperties: { type: 'string' }, description: 'Request header name → pattern of its value' },
        query: { type: 'object', additionalProperties: { type: 'string' }, description: 'Query parameter → pattern of its value' },
        bodyContains: { type: 'string', description: 'Text the request body holds' },
        status: { type: 'string', description: 'Response only: 404, 4xx, >=400 or 500-599. A rule with it takes response steps only.' },
        contentType: { type: 'string', description: 'Response only: part of the response content type, e.g. json' },
      },
      additionalProperties: false,
    },
    request: { type: 'array', items: ACTION_SCHEMA, description: 'Steps on the request before it is sent, in order.' },
    response: { type: 'array', items: ACTION_SCHEMA, description: 'Steps on the response before the client gets it, in order.' },
    stop: { type: 'boolean', description: 'When this rule applies, the rules after it do not.' },
  },
  required: ['id'],
  additionalProperties: false,
}

async function rulesText($: EngineInterface): Promise<string> {
  const rules = await loadRules($)
  const flows = await read($, flowsAtom)
  const status = await read($, statusAtom)
  const lines = [
    `Rules file: ${rules.file}. ${rules.entries.length} rules; earlier rules apply first and every matching rule that is on chains.` +
      (status.phase === 'running' ? ' The proxy applies changes at once.' : ' The proxy is stopped; the rules apply once it runs.'),
    ...rules.fileErrors.map(error => `File error: ${error}`),
  ]
  rules.entries.forEach((entry, index) => {
    const hits = flows.filter(flow => flow.rules?.includes(entry.id)).length
    const state = entry.errors.length ? 'BROKEN' : entry.isUntrusted ? 'SCRIPT NOT APPROVED' : entry.enabled ? 'on' : 'off'
    lines.push(`${index + 1}. ${entry.id} [${state}]${entry.name ? ` ${entry.name}` : ''} · ${hits} hits`)
    if (entry.description) lines.push(`   ${entry.description}`)
    if (entry.summary) lines.push(`   ${entry.summary}`)
    for (const error of entry.errors) lines.push(`   error: ${error}`)
  })
  return lines.join('\n')
}

function optionsOf(raw: Record<string, unknown>): Options {
  const number = (value: unknown, fallback: number) => (Number.isFinite(Number(value)) && Number(value) > 0 ? Number(value) : fallback)
  return {
    port: number(raw.port, 8899),
    listen: raw.listen === 'lan' ? 'lan' : 'local',
    noDecrypt: typeof raw.noDecrypt === 'string' ? raw.noDecrypt : '',
    maxFlows: number(raw.maxFlows, 2000),
    node: typeof raw.node === 'string' && raw.node.trim() ? raw.node.trim() : 'node',
  }
}

async function statusText($: EngineInterface): Promise<string> {
  const status = await read($, statusAtom)
  const flows = await read($, flowsAtom)
  const lan = status.addresses.filter(a => a !== '127.0.0.1')
  switch (status.phase) {
    case 'running':
      return `Proxy is running on 127.0.0.1:${status.port}${status.host === '0.0.0.0' && lan.length ? ` and ${lan.map(a => `${a}:${status.port}`).join(', ')}` : ''}; ${flows.length} requests captured.`
    case 'starting':
      return `Proxy is starting on :${status.port}; ${flows.length} requests captured so far.`
    case 'failed':
      return `Proxy failed: ${(status.error ?? 'unknown error').replace(/\.+$/, '')}. ${flows.length} requests captured before that.`
    default:
      return `Proxy is stopped (the person starts it with /proxy). ${flows.length} requests captured earlier.`
  }
}

/** Shows the list or the tree, and remembers the choice for later sessions. */
async function chooseLayout($: EngineInterface, layout: 'list' | 'tree'): Promise<void> {
  await update($, viewAtom, (v): ProxyView => ({ ...v, mode: v?.mode === 'detail' ? 'list' : (v?.mode ?? 'list'), layout }))
  await $.store.set('layout', layout).catch(() => undefined)
}

async function openPane($: EngineInterface): Promise<void> {
  const opened = await $.ui.open({ id: PANE, title: 'Proxy', focus: true })
  if (!opened.isPlaced) $.ui.toast('proxy: the pane is waiting for room; widen the terminal')
}

export const register: Register = (on, raw) => {
  const options = optionsOf(raw as Record<string, unknown>)

  on('session.start', async ($, e, next) => {
    const started = await next(e)
    await $.command.register({
      name: 'proxy',
      description: 'HTTPS proxy: captured requests, filter, and setup for a browser, iOS and Android',
      argumentHint: '[start|stop|clear|setup|rules|status|tree|list]',
    })
    await $.tool.register({
      name: 'list_requests',
      description:
        'List the HTTP(S) requests captured by the Claude Code proxy the person runs with /proxy for their browser, iOS simulator/iPhone and Android emulator/phone. ' +
        'Returns the proxy status, then one line per request, oldest first: #id method status url response-size duration type, and the error if one. ' +
        'Status CERT means the client refused the proxy certificate. ' +
        `filter: ${FILTER_HELP}.`,
      inputSchema: {
        type: 'object',
        properties: {
          filter: { type: 'string', description: `Optional filter: ${FILTER_HELP}` },
          limit: { type: 'number', description: 'How many of the newest matching requests to list (default 50, at most 500).' },
        },
      },
    })
    await $.tool.register({
      name: 'get_request',
      description:
        'Show one captured request in full by its id from list_requests: URL, status, timing, client, error, request and response headers, and the decoded (gunzipped) text bodies, cut at max_body_chars.',
      inputSchema: {
        type: 'object',
        properties: {
          id: { type: 'number', description: 'The request id, the number after # in list_requests.' },
          max_body_chars: { type: 'number', description: 'Most characters of each body to include (default 20000).' },
        },
        required: ['id'],
      },
    })
    await $.tool.register({
      name: 'list_rules',
      description:
        "List the proxy's rules (<project>/.claude/proxy-rules.json): order (priority), id, on/off, what each does in words, errors, and how many captured requests each changed.",
      inputSchema: { type: 'object', properties: {} },
    })
    await $.tool.register({
      name: 'add_rule',
      description:
        "Add a rule to the proxy's rules engine. A rule changes matching requests before they are sent and their responses before the client gets them: " +
        'delays, throttling, headers, query, sending elsewhere, mocked answers, rewritten or merged bodies, status codes, failed connections, scripts. ' +
        'Rules live in <project>/.claude/proxy-rules.json; earlier rules apply first and every matching rule chains. It applies at once while the proxy runs. ' +
        'Prefer declarative steps; a script you add here is approved to run. Answers the rule in words. Ids of changed requests show in list_requests.',
      inputSchema: {
        type: 'object',
        properties: {
          rule: RULE_SCHEMA,
          position: { type: 'number', description: '1-based place in the order; the first applies first. Default: last.' },
        },
        required: ['rule'],
      },
    })
    await $.tool.register({
      name: 'update_rule',
      description:
        'Change a proxy rule by id: replace any of its fields (match, request and response are replaced whole), turn it on or off, or move it in the order. Answers the rule in words.',
      inputSchema: {
        type: 'object',
        properties: {
          id: { type: 'string', description: 'The rule to change.' },
          changes: { ...RULE_SCHEMA, required: [], description: 'Fields to set; the others stay.' },
          enabled: { type: 'boolean', description: 'Turn the rule on or off.' },
          position: { type: 'number', description: '1-based place to move it to; the first applies first.' },
        },
        required: ['id'],
      },
    })
    await $.tool.register({
      name: 'remove_rule',
      description: 'Remove a proxy rule by id.',
      inputSchema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'] },
    })
    await loadRules($).catch(() => undefined)
    const remembered = await $.store.get('layout').catch(() => undefined)
    if (remembered === 'tree' || remembered === 'list') {
      await update($, viewAtom, (v): ProxyView => ({ ...v, layout: remembered }))
    }
    // A reload of the module took the sidecar with it; bring it back.
    if (await read($, wantedAtom)) await startProxy($, options)
    return started
  })

  on('session.end', async ($, e, next) => {
    if (e.reason !== 'clear') {
      await revertAndroid($)
      await stopProxy($)
    }
    return next(e)
  })

  on('command.run', { command: 'proxy' }, async ($, e) => {
    const arg = e.args.trim().toLowerCase()
    switch (arg) {
      case 'start':
        await startProxy($, options)
        return { text: 'The proxy is starting. /proxy opens the pane.' }
      case 'stop':
        await stopProxy($)
        return { text: 'The proxy is stopped.' }
      case 'clear':
        await clearFlows($)
        return { text: 'The request list is cleared.' }
      case 'status':
        return { text: await statusText($) }
      case 'rules':
        await openRules($)
        await openPane($)
        return { text: 'The Proxy pane shows the rules.' }
      case 'tree':
      case 'list':
        await chooseLayout($, arg)
        await update($, viewAtom, (v): ProxyView => ({ ...v, mode: 'list' }))
        await openPane($)
        return { text: `The Proxy pane shows the requests as a ${arg}.` }
      case 'setup':
        await update($, viewAtom, (v): ProxyView => ({ ...v, mode: 'setup' }))
        await openPane($)
        return { text: 'Client setup is open in the Proxy pane.' }
      case '':
        await openPane($)
        await startProxy($, options)
        return { text: 'The Proxy pane is open.' }
      default:
        return { text: `Unknown "${arg}". /proxy [start|stop|clear|setup|rules|status|tree|list]` }
    }
  })

  on('ui.render', { component: 'Pane', requestId: PANE }, ($, e) => drawPane($, e, options))

  on('tool.call', { tool: 'mcp__proxy__list_rules' }, async $ => ({ result: await rulesText($) })).catch(() => ({
    deny: 'proxy: could not read the rules file; try again.',
  }))

  on('tool.call', { tool: 'mcp__proxy__add_rule' }, async ($, e) => {
    const rule = e.rule as Rule
    const errors = ruleErrors(rule)
    if (errors.length) return { result: `Not added:\n${errors.join('\n')}` }
    const failure = await editRules($, rules => {
      if (rules.some(other => other.id === rule.id)) return `A rule with the id ${rule.id} exists; choose another id or call update_rule.`
      const at = typeof e.position === 'number' ? Math.max(0, Math.min(rules.length, Math.floor(e.position) - 1)) : rules.length
      rules.splice(at, 0, rule)
      return rules
    })
    if (failure) return { result: `Not added: ${failure}` }
    await trustScripts($, scriptsOf(rule))
    await loadRules($)
    return { result: `Added ${rule.id}: ${describeRule(rule)}\n\n${await rulesText($)}` }
  }).catch(() => ({ deny: 'proxy: could not write the rules file; try again.' }))

  on('tool.call', { tool: 'mcp__proxy__update_rule' }, async ($, e) => {
    const id = String(e.id)
    let changed: Rule | undefined
    let problems: string[] = []
    const failure = await editRules($, rules => {
      const from = rules.findIndex(rule => rule.id === id)
      if (from < 0) return `No rule has the id ${id}.`
      const changes = (e.changes ?? {}) as Partial<Rule>
      const next: Rule = { ...rules[from]!, ...changes }
      if (typeof e.enabled === 'boolean') next.enabled = e.enabled
      problems = ruleErrors(next)
      if (problems.length) return 'invalid'
      if (next.id !== id && rules.some(rule => rule.id === next.id)) return `A rule with the id ${next.id} exists.`
      rules.splice(from, 1)
      const to = typeof e.position === 'number' ? Math.max(0, Math.min(rules.length, Math.floor(e.position) - 1)) : from
      rules.splice(to, 0, next)
      changed = next
      return rules
    })
    if (failure === 'invalid') return { result: `Not changed:\n${problems.join('\n')}` }
    if (failure || !changed) return { result: `Not changed: ${failure}` }
    await trustScripts($, scriptsOf(changed))
    await loadRules($)
    return { result: `Changed ${changed.id}: ${describeRule(changed)}\n\n${await rulesText($)}` }
  }).catch(() => ({ deny: 'proxy: could not write the rules file; try again.' }))

  on('tool.call', { tool: 'mcp__proxy__remove_rule' }, async ($, e) => {
    const id = String(e.id)
    const failure = await editRules($, rules => (rules.some(rule => rule.id === id) ? rules.filter(rule => rule.id !== id) : `No rule has the id ${id}.`))
    return { result: failure ? `Not removed: ${failure}` : `Removed ${id}.\n\n${await rulesText($)}` }
  }).catch(() => ({ deny: 'proxy: could not write the rules file; try again.' }))

  on('tool.call', { tool: LIST_TOOL }, async ($, e) => {
    const filter = typeof e.filter === 'string' ? e.filter : ''
    const limit = Math.min(500, Math.max(1, Math.floor(Number(e.limit) || 50)))
    const flows = await read($, flowsAtom)
    const parsed = parseFilter(filter)
    const matched = filterFlows(flows, filter)
    const shown = matched.slice(-limit)
    const lines = [
      await statusText($),
      parsed.errors.length ? `Unrecognised filter terms ignored: ${parsed.errors.join(', ')}.` : '',
      filter ? `${matched.length} match "${filter}"${matched.length > shown.length ? `, the newest ${shown.length} shown` : ''}.` : matched.length > shown.length ? `The newest ${shown.length} shown.` : '',
      shown.length ? flowTable(shown) : 'No requests.',
    ]
    return { result: lines.filter(Boolean).join('\n') }
  }).catch(() => ({ deny: 'proxy: could not read the captured requests; try again.' }))

  on('tool.call', { tool: GET_TOOL }, async ($, e) => {
    const id = Number(e.id)
    const maxChars = Math.max(200, Math.floor(Number(e.max_body_chars) || 20_000))
    const summary = (await read($, flowsAtom)).find(flow => flow.id === id)
    const detail = await loadDetail($, id)
    const flow = detail ?? summary
    if (!flow) return { result: `No captured request #${e.id}. Call list_requests for the ids.` }

    const out: string[] = []
    out.push(`#${flow.id} ${flow.method} ${detail?.url ?? flowUrl(flow)}`)
    out.push(
      `status: ${statusLabel(flow)}${detail?.statusMessage ? ` ${detail.statusMessage}` : ''} · state: ${flow.state} · ${formatDuration(flow.durationMs)} · sent ${formatSize(flow.reqSize)} · received ${formatSize(flow.resSize)} · ${new Date(flow.ts).toISOString()}${flow.client ? ` · client ${flow.client}` : ''}`,
    )
    if (flow.error) out.push(`error (${flow.errorCode ?? 'unknown'}): ${flow.error}`)
    if (!detail) {
      out.push('Headers and bodies are not on disk (yet).')
      return { result: out.join('\n') }
    }
    const section = async (title: string, headers: [string, string][], body: typeof detail.req, contentType: string | null) => {
      out.push('', `--- ${title} headers ---`, ...headers.map(([k, v]) => `${k}: ${v}`))
      const loaded = await loadBody($, body, contentType)
      if (loaded.text === null && loaded.note === null) return out.push(`--- ${title} body: none ---`)
      out.push(`--- ${title} body${loaded.note ? ` (${loaded.note})` : ''} ---`)
      if (loaded.text !== null) {
        const clipped = clip(prettyBody(loaded.text, contentType), Number.MAX_SAFE_INTEGER, maxChars)
        out.push(clipped.text)
        if (clipped.isClipped) out.push(`[cut at ${maxChars} characters; the whole body is in ${body?.file}]`)
      }
    }
    const reqType = detail.reqHeaders.find(([k]) => k.toLowerCase() === 'content-type')?.[1] ?? null
    await section('request', detail.reqHeaders, detail.req, reqType)
    await section('response', detail.resHeaders, detail.res, detail.contentType)
    return { result: out.join('\n') }
  }).catch(() => ({ deny: 'proxy: could not read that request from disk; try again.' }))
}
