import { atom, read, update } from 'claude-code'
import type { EngineInterface, Register, RenderElement, RenderInput } from 'claude-code'

import { describeRule, isTracked, matchesHostPattern, normalizeHostPattern, parseRules, ruleErrors, scriptsOf, wildcardFor } from '../shared/rules.mjs'
import type { Rule } from '../shared/rules.mjs'
import type {
  ProxyAndroidDevice,
  ProxyDevices,
  ProxyFlow,
  ProxyRuleEntry,
  ProxyRules,
  ProxySetupTab,
  ProxySimulator,
  ProxyStatus,
  ProxySystemProxy,
  ProxyTracking,
  ProxyView,
} from '../types'
import {
  asAdminScript,
  enableCommands,
  needsAdmin,
  parseBypass,
  parseProxyState,
  parseServiceOrder,
  restoreCommands,
} from '../shared/systemproxy.mjs'
import type { SystemProxyBackup } from '../shared/systemproxy.mjs'
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
/** The session's tracked domains; off or empty, every domain is tracked. */
const trackingAtom = atom({ plugin: 'proxy', key: 'tracking' } as const, { enabled: false, patterns: [] } as ProxyTracking)
/** Hosts that passed through untracked since the proxy started, with counts. */
const skippedAtom = atom({ plugin: 'proxy', key: 'skipped' } as const, {} as Record<string, number>)
const devicesAtom = atom({ plugin: 'proxy', key: 'devices' } as const, {
  simulators: [],
  simulatorError: null,
  avds: [],
  android: [],
  androidError: null,
} as ProxyDevices)
const systemProxyAtom = atom({ plugin: 'proxy', key: 'systemProxy' } as const, { isOn: false, service: null, isOurs: false } as ProxySystemProxy)
const caSimulatorsAtom = atom({ plugin: 'proxy', key: 'caSimulators' } as const, [] as string[])
const busyAtom = atom({ plugin: 'proxy', key: 'busy' } as const, '')
/** This mod's version, from its plugin.json: which copy the session runs. */
const versionAtom = atom({ plugin: 'proxy', key: 'version' } as const, '')
const macTrustAtom = atom({ plugin: 'proxy', key: 'macTrust' } as const, 'unknown' as 'unknown' | 'trusted' | 'untrusted')
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
  const isSystem = (await read($, systemProxyAtom)).isOn
  if (status.phase === 'running') $.ui.status(`⇄ proxy :${status.port} · ${flows.length}${isSystem ? ' · system proxy' : ''}`)
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
      '--tracking', await writeTrackingFile($),
      '--system-proxy-backup', await systemProxyBackupOf($),
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
          } else if (event.t === 'system-proxy') {
            const isOn = event.isOn
            await update($, systemProxyAtom, (now): ProxySystemProxy => ({ ...(now ?? { service: null, isOurs: false }), isOn }))
          } else if (event.t === 'skipped') {
            await update($, skippedAtom, () => event.hosts)
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
  // nothing may stay pointed at a proxy that is gone
  await disableSystemProxy($, true)
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

// --- the macOS system proxy -------------------------------------------------------------
//
// Turned on for the network service the default route leaves by, with Claude's
// hosts on its bypass list; what was there before is kept in a backup file,
// put back on stop, at the session's end, or by the sidecar if Claude Code
// dies. networksetup may want an administrator: then one macOS password dialog.

async function systemProxyBackupOf($: EngineInterface): Promise<string> {
  return `${await dataDirOf($)}/system-proxy-backup.json`
}

async function readSystemProxyBackup($: EngineInterface): Promise<SystemProxyBackup | null> {
  try {
    const text = await $.fs.read(await systemProxyBackupOf($))
    return text.trim() ? (JSON.parse(text) as SystemProxyBackup) : null
  } catch {
    return null
  }
}

/** Runs networksetup commands, as an administrator when it must; answers why not, or null. */
async function runNetworkCommands($: EngineInterface, commands: string[][]): Promise<string | null> {
  for (const argv of commands) {
    const ran = await $.process.run(argv).catch(error => ({ exitCode: 1, stdout: '', stderr: String(error) }))
    const output = `${ran.stdout}${ran.stderr}`
    if (ran.exitCode === 0 && !/\*\* Error/i.test(output)) continue
    if (!needsAdmin(output) && !/\*\* Error/i.test(output)) return output.trim() || `${argv[0]} failed`
    const admin = await $.process.run(['osascript', '-e', asAdminScript(commands)], { timeoutMs: 180_000 })
    return admin.exitCode === 0 ? null : admin.stderr.includes('-128') ? 'cancelled' : admin.stderr.trim() || 'the administrator dialog failed'
  }
  return null
}

async function defaultNetworkService($: EngineInterface): Promise<string | null> {
  const route = await $.process.run(['route', '-n', 'get', 'default']).catch(() => null)
  const device = /interface:\s*(\S+)/.exec(route?.stdout ?? '')?.[1]
  const order = parseServiceOrder((await $.process.run(['networksetup', '-listnetworkserviceorder'])).stdout)
  return order.find(service => service.device === device && !service.isDisabled)?.name ?? order.find(service => service.name === 'Wi-Fi')?.name ?? null
}

async function enableSystemProxy($: EngineInterface, options: Options): Promise<void> {
  const status = await read($, statusAtom)
  if (status.phase !== 'running') await startProxy($, options)
  const port = status.phase === 'running' ? status.port : options.port
  const service = await defaultNetworkService($)
  if (!service) return say($, 'Could not tell which network service this Mac uses.')
  const kept = await readSystemProxyBackup($)
  // a backup already there is the state before we first turned it on: keep that one
  const backup: SystemProxyBackup = kept ?? {
    service,
    port,
    previous: {
      web: parseProxyState((await $.process.run(['networksetup', '-getwebproxy', service])).stdout),
      secure: parseProxyState((await $.process.run(['networksetup', '-getsecurewebproxy', service])).stdout),
      bypass: parseBypass((await $.process.run(['networksetup', '-getproxybypassdomains', service])).stdout),
    },
  }
  await $.fs.write(await systemProxyBackupOf($), JSON.stringify(backup, null, 2))
  await update($, busyAtom, () => `Pointing ${service} at the proxy…`)
  const failure = await runNetworkCommands($, enableCommands(service, port, backup.previous.bypass))
  await update($, busyAtom, () => '')
  if (failure) {
    if (!kept) await $.fs.write(await systemProxyBackupOf($), '')
    return say($, `The system proxy is unchanged: ${failure}.`)
  }
  await update($, systemProxyAtom, (): ProxySystemProxy => ({ isOn: true, service, isOurs: true }))
  await showStatus($)
  await say($, `This Mac's ${service} now goes through the proxy. Claude's own traffic bypasses it; it goes back when the proxy stops.`)
}

async function disableSystemProxy($: EngineInterface, quiet = false): Promise<void> {
  const backup = await readSystemProxyBackup($)
  if (!backup) {
    if (!quiet) await say($, 'The system proxy was not turned on from here; switch it off in System Settings → Network → Details → Proxies.')
    return
  }
  const failure = await runNetworkCommands($, restoreCommands(backup))
  if (failure) {
    if (!quiet) await say($, `Could not put the system proxy back: ${failure}.`)
    return
  }
  await $.fs.write(await systemProxyBackupOf($), '')
  await update($, systemProxyAtom, (): ProxySystemProxy => ({ isOn: false, service: backup.service, isOurs: false }))
  await showStatus($)
  if (!quiet) await say($, `${backup.service} is back to its own proxy settings.`)
}

// --- this Mac's trust in the CA ------------------------------------------------------------
//
// Safari and native apps behind the system proxy need the CA in the keychain;
// the separate browser and the simulators do not.

async function checkMacTrust($: EngineInterface): Promise<void> {
  const ca = (await read($, statusAtom)).ca
  if (!ca) return
  const ran = await $.process.run(['security', 'verify-cert', '-c', ca.path]).catch(() => null)
  const output = `${ran?.stdout ?? ''}${ran?.stderr ?? ''}`
  await update($, macTrustAtom, () => (/successful/i.test(output) ? 'trusted' : /NOT_TRUSTED|failed/i.test(output) ? 'untrusted' : 'unknown'))
}

async function trustCaOnMac($: EngineInterface): Promise<void> {
  const ca = (await read($, statusAtom)).ca
  if (!ca) return say($, 'There is no certificate yet: start the proxy.')
  const home = (await $.env.get('HOME')) ?? ''
  await update($, busyAtom, () => 'Waiting for you to confirm in the macOS dialog…')
  try {
    const ran = await $.process.run(['security', 'add-trusted-cert', '-r', 'trustRoot', '-k', `${home}/Library/Keychains/login.keychain-db`, ca.path], {
      timeoutMs: 180_000,
    })
    await checkMacTrust($)
    await say($, ran.exitCode === 0 ? 'This Mac trusts the proxy CA now (login keychain).' : `The keychain refused: ${ran.stderr.trim() || 'cancelled'}`)
  } finally {
    await update($, busyAtom, () => '')
  }
}

// --- simulators, emulators, devices ------------------------------------------------------

function runtimeLabel(key: string): string {
  // com.apple.CoreSimulator.SimRuntime.iOS-18-2 → iOS 18.2
  const tail = key.split('.').pop() ?? key
  return tail.replace(/-(\d+)-(\d+)$/, ' $1.$2').replace(/-/g, ' ')
}

function runtimeRank(runtime: string): number {
  const match = /(\d+)\.(\d+)/.exec(runtime)
  return match ? Number(match[1]) * 100 + Number(match[2]) : 0
}

async function scanSimulators($: EngineInterface): Promise<void> {
  const ran = await $.process.run(['xcrun', 'simctl', 'list', 'devices', 'available', '-j'], { timeoutMs: 30_000 }).catch(error => ({
    exitCode: 1,
    stdout: '',
    stderr: String(error),
  }))
  if (ran.exitCode !== 0) {
    await update($, devicesAtom, (d): ProxyDevices => ({ ...d!, simulators: [], simulatorError: 'Xcode’s simctl is not available: install Xcode to use simulators.' }))
    return
  }
  type Listed = { udid: string; name: string; state: string; isAvailable?: boolean }
  const devices = (JSON.parse(ran.stdout) as { devices: Record<string, Listed[]> }).devices
  const simulators: ProxySimulator[] = []
  for (const [runtime, list] of Object.entries(devices)) {
    if (!/iOS/.test(runtime)) continue
    for (const device of list) simulators.push({ udid: device.udid, name: device.name, runtime: runtimeLabel(runtime), state: device.state })
  }
  simulators.sort(
    (a, b) =>
      Number(b.state === 'Booted') - Number(a.state === 'Booted') ||
      runtimeRank(b.runtime) - runtimeRank(a.runtime) ||
      Number(b.name.startsWith('iPhone')) - Number(a.name.startsWith('iPhone')) ||
      a.name.localeCompare(b.name),
  )
  await update($, devicesAtom, (d): ProxyDevices => ({ ...d!, simulators, simulatorError: null }))
}

async function androidTool($: EngineInterface, name: 'adb' | 'emulator'): Promise<string | null> {
  const onPath = await $.process.run([name, name === 'adb' ? 'version' : '-version']).catch(() => null)
  if (onPath?.exitCode === 0) return name
  const home = (await $.env.get('HOME')) ?? ''
  const sdk = (await $.env.get('ANDROID_HOME')) ?? `${home}/Library/Android/sdk`
  const path = name === 'adb' ? `${sdk}/platform-tools/adb` : `${sdk}/emulator/emulator`
  return (await $.fs.exists(path).catch(() => false)) ? path : null
}

async function scanAndroid($: EngineInterface): Promise<void> {
  const emulator = await androidTool($, 'emulator')
  const tool = await adb($)
  if (!emulator && !tool) {
    await update($, devicesAtom, (d): ProxyDevices => ({ ...d!, avds: [], android: [], androidError: 'The Android SDK was not found (looked on PATH and in ~/Library/Android/sdk).' }))
    return
  }
  const avds = emulator
    ? (await $.process.run([emulator, '-list-avds'])).stdout.split('\n').map(line => line.trim()).filter(line => line && !line.startsWith('INFO'))
    : []
  const android: ProxyAndroidDevice[] = []
  if (tool) {
    for (const serial of await androidDevices($, tool)) {
      const isEmulator = serial.startsWith('emulator-')
      const avd = isEmulator ? (await $.process.run([tool, '-s', serial, 'emu', 'avd', 'name'])).stdout.split('\n')[0]?.trim() || null : null
      android.push({ serial, avd, isEmulator })
    }
  }
  await update($, devicesAtom, (d): ProxyDevices => ({ ...d!, avds, android, androidError: null }))
}

async function installCaOnSimulator($: EngineInterface, udid: string): Promise<boolean> {
  const status = await read($, statusAtom)
  if (!status.ca) {
    await say($, 'There is no certificate yet: start the proxy.')
    return false
  }
  const ran = await $.process.run(['xcrun', 'simctl', 'keychain', udid, 'add-root-cert', status.ca.path], { timeoutMs: 60_000 })
  if (ran.exitCode !== 0) {
    await say($, `Could not add the CA: ${ran.stderr.trim() || 'simctl failed'}`)
    return false
  }
  await update($, caSimulatorsAtom, list => [...new Set([...(list ?? []), udid])])
  return true
}

/** Boots the simulator if needed, puts the CA in, points this Mac at the proxy, brings Simulator up. */
async function useSimulator($: EngineInterface, udid: string, options: Options): Promise<void> {
  const simulator = (await read($, devicesAtom)).simulators.find(sim => sim.udid === udid)
  const name = simulator?.name ?? 'the simulator'
  try {
    if ((await read($, statusAtom)).phase !== 'running') await startProxy($, options)
    if (simulator?.state !== 'Booted') {
      await update($, busyAtom, () => `Booting ${name}…`)
      await $.process.run(['xcrun', 'simctl', 'boot', udid], { timeoutMs: 120_000 })
    }
    await $.process.run(['open', '-a', 'Simulator', '--args', '-CurrentDeviceUDID', udid])
    await update($, busyAtom, () => `Waiting for ${name} to finish booting…`)
    await $.process.run(['xcrun', 'simctl', 'bootstatus', udid, '-b'], { timeoutMs: 240_000 })
    await update($, busyAtom, () => `Adding the CA to ${name}…`)
    if (!(await installCaOnSimulator($, udid))) return
    if (!(await read($, systemProxyAtom)).isOn) await enableSystemProxy($, options)
    await scanSimulators($)
    if ((await read($, systemProxyAtom)).isOn) await say($, `${name} is ready: the CA is in, and its traffic goes through the proxy.`)
  } finally {
    await update($, busyAtom, () => '')
  }
}

async function startAvd($: EngineInterface, avd: string, options: Options): Promise<void> {
  const emulator = await androidTool($, 'emulator')
  if (!emulator) return say($, 'The Android emulator was not found.')
  if ((await read($, statusAtom)).phase !== 'running') await startProxy($, options)
  const port = (await read($, statusAtom)).port || options.port
  const quote = (text: string) => `'${text.replace(/'/g, `'\\''`)}'`
  // the emulator outlives this call: started in the background, its traffic sent to the proxy from boot
  await $.process.run(['/bin/sh', '-c', `nohup ${quote(emulator)} -avd ${quote(avd)} -http-proxy http://127.0.0.1:${port} >/dev/null 2>&1 &`])
  await say($, `${avd} is starting with its traffic going through the proxy from boot.`)
  // once it is up, its browser opens the CA page: one tap installs the certificate
  const tool = await adb($)
  if (!tool) return
  try {
    await update($, busyAtom, () => `Waiting for ${avd} to boot…`)
    const adbq = quote(tool)
    const found = await $.process.run(
      [
        '/bin/sh',
        '-c',
        `for i in $(seq 1 90); do for s in $(${adbq} devices | awk '/^emulator-/{print $1}'); do ` +
          `n=$(${adbq} -s "$s" emu avd name 2>/dev/null | head -1 | tr -d '\\r'); [ "$n" = ${quote(avd)} ] && echo "$s" && exit 0; done; sleep 2; done; exit 1`,
      ],
      { timeoutMs: 200_000 },
    )
    const serial = found.stdout.trim()
    if (found.exitCode !== 0 || !serial) return say($, `${avd} did not come up in time; when it does, press Open CA page.`)
    await $.process.run([tool, '-s', serial, 'shell', 'while [ "$(getprop sys.boot_completed)" != 1 ]; do sleep 1; done'], { timeoutMs: 240_000 })
    await $.process.run([tool, '-s', serial, 'shell', 'am', 'start', '-a', 'android.intent.action.VIEW', '-d', 'http://claude.proxy/'])
    await scanAndroid($)
    await say($, `${avd} is up behind the proxy, and its browser shows the CA page: download the certificate, then install it in Settings → Security → Encryption & credentials.`)
  } finally {
    await update($, busyAtom, () => '')
  }
}

// --- tracked domains ------------------------------------------------------------------
//
// Per session: kept in $.state, in $.store under the session's id (so a
// --resume brings it back) and in a file the sidecar watches.

async function trackingFileOf($: EngineInterface): Promise<string> {
  return `${await dataDirOf($)}/sessions/${await $.session.id()}/tracking.json`
}

/** Writes the session's list where the sidecar reads it; answers the path. */
async function writeTrackingFile($: EngineInterface): Promise<string> {
  const file = await trackingFileOf($)
  const tracking = await read($, trackingAtom)
  await $.fs.write(file, `${JSON.stringify(tracking, null, 2)}\n`)
  return file
}

async function setTracking($: EngineInterface, change: (now: ProxyTracking) => ProxyTracking): Promise<ProxyTracking> {
  const next = await update($, trackingAtom, now => {
    const changed = change(now ?? { enabled: false, patterns: [] })
    return { enabled: changed.enabled, patterns: [...new Set(changed.patterns)] }
  })
  await $.store.set(`tracking:${await $.session.id()}`, next).catch(() => undefined)
  await writeTrackingFile($)
  return next
}

async function restoreTracking($: EngineInterface): Promise<void> {
  const saved = (await $.store.get(`tracking:${await $.session.id()}`).catch(() => undefined)) as ProxyTracking | undefined
  if (saved && typeof saved.enabled === 'boolean' && Array.isArray(saved.patterns)) {
    await update($, trackingAtom, () => ({ enabled: saved.enabled, patterns: saved.patterns.filter(p => typeof p === 'string') }))
  }
}

/** Adds what a person or Claude typed: answers the patterns taken and the ones refused. */
async function trackDomains(
  $: EngineInterface,
  texts: readonly string[],
  isTyped = true,
): Promise<{ added: string[]; refused: string[] }> {
  const added: string[] = []
  const refused: string[] = []
  // what a person types may hold several, split by spaces or commas; a tool's list holds one per item
  const items = isTyped ? texts.flatMap(t => t.split(/[\s,]+/)) : texts.map(t => t.trim())
  for (const text of items.filter(Boolean)) {
    const pattern = normalizeHostPattern(text)
    if (pattern) added.push(pattern)
    else refused.push(text)
  }
  if (added.length) await setTracking($, now => ({ enabled: true, patterns: [...now.patterns, ...added] }))
  return { added, refused }
}

async function untrackDomains($: EngineInterface, texts: readonly string[]): Promise<void> {
  const gone = new Set(texts.map(text => normalizeHostPattern(text) ?? text))
  await setTracking($, now => ({ ...now, patterns: now.patterns.filter(pattern => !gone.has(pattern)) }))
}

function trackingLine(tracking: ProxyTracking): string {
  return tracking.enabled && tracking.patterns.length
    ? `tracking ${tracking.patterns.length} ${tracking.patterns.length === 1 ? 'domain' : 'domains'}`
    : 'tracking every domain'
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

function phaseLine(status: ProxyStatus, total: number, shown: number, hasFilter: boolean, tracking: ProxyTracking): string {
  const requests = `${total} ${total === 1 ? 'request' : 'requests'}${tracking.enabled && tracking.patterns.length ? ` · ${trackingLine(tracking)}` : ''}`
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
  if (view.mode === 'domains') return drawDomains($, e)
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

  const tracking = await read($, trackingAtom)
  const rules = await read($, rulesAtom)
  const rulesOn = rules.entries.filter(entry => entry.enabled && entry.errors.length === 0 && !entry.isUntrusted).length
  // nothing captured yet: the one-press ways in, from what is on this Mac
  let quickStart: RenderElement | null = null
  if (flows.length === 0) {
    const browsers = await findBrowsers($)
    const devices = await read($, devicesAtom)
    const version = await read($, versionAtom)
    const simulator = devices.simulators[0]
    const avd = devices.avds.find(name => !devices.android.some(device => device.avd === name)) ?? devices.avds[0]
    const row = (label: string, action: RenderElement | null, hint: string) => (
      <Box key={`qs-row-${label}`} flexDirection="row" gap={1} flexWrap="wrap">
        <Text>{label.padEnd(13)}</Text>
        {action}
        <Text dimColor>{hint}</Text>
      </Box>
    )
    quickStart = (
      <Box flexDirection="column" borderStyle="round" borderColor="claude" paddingX={1} marginTop={1}>
        <Text bold>
          {isRunning ? 'Waiting for requests. Point a client here:' : 'Quick start'}
          {version ? `  · proxy ${version}` : ''}
        </Text>
        {!isRunning
          ? row('Proxy', <Button key="qs-start" variant="primary" label="Start" onPress={() => void startProxy($, options)} />, 'runs it on this Mac')
          : null}
        {row(
          'Browser',
          browsers[0] ? (
            <Button key="qs-browser" label={`Open ${browsers[0].browser.name}`} onPress={() => void launchBrowser($, options, browsers[0]!.browser.slug)} />
          ) : null,
          browsers[0] ? 'a separate window: all of its traffic lands here, localhost too' : 'no Chrome, Edge, Brave or Chromium in /Applications',
        )}
        {simulator
          ? row(
              'iOS Simulator',
              <Button key="qs-simulator" label={`Use ${simulator.name}`} onPress={() => void useSimulator($, simulator.udid, options)} />,
              'boots it, adds the CA, turns the system proxy on',
            )
          : null}
        {avd
          ? row('Android', <Button key="qs-avd" label={`Start ${avd}`} onPress={() => void startAvd($, avd, options)} />, 'starts the emulator behind the proxy')
          : null}
        {row('Phone', <Button key="qs-phone" label="Set up a phone" onPress={() => void openSetupTab($, 'ios', 'real')} />, 'the exact address and a QR code to scan')}
        {row(
          'Only your app',
          <Button key="qs-domains" label="Track domains" onPress={() => void update($, viewAtom, (v): ProxyView => ({ ...v, mode: 'domains' }))} />,
          'decrypt and record only its hosts; everything else passes through',
        )}
      </Box>
    )
  }

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
        {truncate(phaseLine(status, flows.length, shown.length, parsed.terms.length > 0, tracking), width)}
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
          key="domains"
          hotkey="d"
          label={tracking.enabled && tracking.patterns.length ? `Domains (${tracking.patterns.length})` : 'Domains: all'}
          onPress={() => void update($, viewAtom, (v): ProxyView => ({ ...v, mode: 'domains' }))}
        />
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
          onPress={() => void openSetupTab($, view.setupTab)}
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
      {shown.length === 0 && flows.length > 0 ? <Text dimColor>Nothing matches the filter.</Text> : null}
      {quickStart}
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
  let deviceBlock: RenderElement | null = null
  let usbBlock: RenderElement | null = null
  let guide = ''
  const devices = await read($, devicesAtom)
  const caSimulators = await read($, caSimulatorsAtom)
  const systemProxy = await read($, systemProxyAtom)
  const busy = await read($, busyAtom)
  const version = await read($, versionAtom)
  const hasDevices = tab === 'ios' || tab === 'android'
  const device = (await read($, viewAtom)).device ?? 'virtual'
  const showVirtual = !hasDevices || device === 'virtual'
  const showReal = hasDevices && device === 'real'
  const flows = await read($, flowsAtom)
  const systemProxyBlock = (
    <Box flexDirection="column" marginTop={1}>
      <Box flexDirection="row" gap={1} flexWrap="wrap">
        <Text bold>System proxy</Text>
        <Text color={systemProxy.isOn ? 'success' : 'subtle'}>
          {systemProxy.isOn ? `on${systemProxy.service ? ` (${systemProxy.service})` : ''}` : 'off'}
        </Text>
        <Button
          key="system-proxy"
          hotkey="m"
          variant={systemProxy.isOn ? undefined : 'primary'}
          label={systemProxy.isOn ? 'Turn off' : 'Turn on for this Mac'}
          onPress={run(() => (systemProxy.isOn ? disableSystemProxy($) : enableSystemProxy($, options)))}
        />
      </Box>
      <Text dimColor>
        Safari, native apps and the iOS Simulator use it. Claude Code is never decrypted: its hosts bypass the proxy and its own connections are
        tunnelled. It is put back when the proxy stops.
      </Text>
    </Box>
  )
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
    const sims = devices.simulators
    deviceBlock = (
      <Box flexDirection="column" marginTop={1}>
        <Box flexDirection="row" gap={1}>
          <Text bold>Simulators</Text>
          <Button plain dimColor key="sims-refresh" label="refresh" onPress={run(() => scanSimulators($))} />
        </Box>
        {devices.simulatorError ? <Text color="warning">{devices.simulatorError}</Text> : null}
        {!devices.simulatorError && sims.length === 0 ? <Text dimColor>No iOS simulators found: add one in Xcode → Window → Devices and Simulators.</Text> : null}
        {sims.slice(0, 10).map((sim, i) => {
          const isBooted = sim.state === 'Booted'
          const hasCa = caSimulators.includes(sim.udid)
          return (
            <Box key={`sim-${sim.udid}`} flexDirection="row" gap={1} flexWrap="wrap">
              <Text color={isBooted ? 'success' : 'subtle'}>{isBooted ? '●' : '○'}</Text>
              <Text>{sim.name}</Text>
              <Text dimColor>{sim.runtime}</Text>
              {hasCa ? <Text color="success">CA ✓</Text> : null}
              <Button
                key={`sim-use:${sim.udid}`}
                hotkey={i === 0 ? 'u' : undefined}
                variant={i === 0 ? 'primary' : undefined}
                label={isBooted ? (hasCa && systemProxy.isOn ? 'Open' : 'Use') : 'Boot & use'}
                onPress={run(() => useSimulator($, sim.udid, options))}
              />
            </Box>
          )
        })}
        {sims.length > 10 ? <Text dimColor>…and {sims.length - 10} more in Xcode.</Text> : null}
        <Text dimColor>Use boots it, puts the CA in, and turns the system proxy on: the simulator has no proxy setting of its own.</Text>
      </Box>
    )
    actions = [<Button key="sim-ca" label="CA → every booted simulator" onPress={run(() => addCaToSimulators($))} />]
  } else if (tab === 'android') {
    guide = androidGuide(facts)
    const pointed = await read($, emulatorsAtom)
    const usb = devices.android.filter(device => !device.isEmulator)
    deviceBlock = (
      <Box flexDirection="column" marginTop={1}>
        <Box flexDirection="row" gap={1}>
          <Text bold>Emulators</Text>
          <Button plain dimColor key="android-refresh" label="refresh" onPress={run(() => scanAndroid($))} />
        </Box>
        {devices.androidError ? <Text color="warning">{devices.androidError}</Text> : null}
        {!devices.androidError && devices.avds.length === 0 ? <Text dimColor>No emulators (AVDs) found: create one in Android Studio → Device Manager.</Text> : null}
        {devices.avds.map((avd, i) => {
          const running = devices.android.find(device => device.avd === avd)
          return (
            <Box key={`avd-${avd}`} flexDirection="row" gap={1} flexWrap="wrap">
              <Text color={running ? 'success' : 'subtle'}>{running ? '●' : '○'}</Text>
              <Text>{avd}</Text>
              {running ? <Text dimColor>{running.serial}</Text> : null}
              {running ? (
                <Button key={`avd-ca:${avd}`} label="Open CA page" onPress={run(() => openCaPageOnAndroid($))} />
              ) : (
                <Button
                  key={`avd-start:${avd}`}
                  hotkey={i === 0 ? 'u' : undefined}
                  variant={i === 0 ? 'primary' : undefined}
                  label="Start through the proxy"
                  onPress={run(() => startAvd($, avd, options))}
                />
              )}
            </Box>
          )
        })}
      </Box>
    )
    usbBlock = (
      <Box flexDirection="column" marginTop={1}>
        <Box flexDirection="row" gap={1} flexWrap="wrap">
          <Text bold>On USB</Text>
          <Button key="usb-on" variant="primary" label="Point USB phones at the proxy" onPress={run(() => pointAndroid($))} />
          <Button plain dimColor key="usb-off" label="revert" onPress={run(() => revertAndroid($))} />
        </Box>
        {usb.length === 0 ? <Text dimColor>No phone on USB (adb devices lists none); with USB debugging on, it shows here.</Text> : null}
        {usb.map(device => (
          <Box key={`usb-${device.serial}`} flexDirection="row" gap={1}>
            <Text>{device.serial}</Text>
            {pointed.includes(device.serial) ? <Text color="success">through the proxy (adb reverse)</Text> : null}
          </Box>
        ))}
        <Text dimColor>No Wi-Fi needed: adb reverse carries its traffic to this Mac.</Text>
      </Box>
    )
    actions = [
      <Button key="adb-on" hotkey="a" variant="primary" label="Android → proxy" onPress={run(() => pointAndroid($))} />,
      <Button key="adb-off" label={pointed.length ? `Revert (${pointed.length})` : 'Revert'} onPress={run(() => revertAndroid($))} />,
      <Button key="adb-ca" label="Open CA page" onPress={run(() => openCaPageOnAndroid($))} />,
      <Button key="copy-android-config" label="config snippet" onPress={copy('android-config')} />,
    ]
  } else {
    guide = cliGuide(facts)
    const macTrust = await read($, macTrustAtom)
    deviceBlock = (
      <Box flexDirection="row" gap={1} flexWrap="wrap" marginTop={1}>
        <Text bold>This Mac trusts the CA</Text>
        <Text color={macTrust === 'trusted' ? 'success' : 'subtle'}>{macTrust === 'trusted' ? 'yes ✓' : macTrust === 'untrusted' ? 'no' : '?'}</Text>
        {macTrust !== 'trusted' ? (
          <Button key="mac-trust" hotkey="t" variant="primary" label="Trust CA on this Mac" onPress={run(() => trustCaOnMac($))} />
        ) : null}
        <Text dimColor>Safari and native apps need it; the separate browser and the simulators do not.</Text>
      </Box>
    )
    actions = [
      <Button key="copy-trust" label="trust CA (command)" onPress={copy('trust')} />,
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
    // the row's key as /config names it for this install ("proxy.listen", or a marketplace's spelling)
    const rows = await $.config.list().catch(() => [])
    const key = rows.find(row => /(^|[.:@])listen$/.test(row.key) && JSON.stringify(row.provider ?? '').includes('proxy'))?.key ?? 'proxy.listen'
    const result = await $.config.set({ key, value })
    await say($, 'deny' in result && result.deny ? `Could not change Listen on: ${result.deny}` : value === 'lan' ? 'Listening on the network now.' : 'Listening on this Mac only now.')
  }

  // clients on the network: what each sent, and how often it refused our certificate
  const phoneClients = [...flows.reduce((byAddress, flow) => {
    if (!flow.client || flow.client === '127.0.0.1' || flow.client === '::1') return byAddress
    const entry = byAddress.get(flow.client) ?? { address: flow.client, count: 0, rejected: 0 }
    entry.count++
    if (flow.errorCode === 'client-rejected-cert') entry.rejected++
    byAddress.set(flow.client, entry)
    return byAddress
  }, new Map<string, { address: string; count: number; rejected: number }>()).values()]

  // a phone scans this before any proxy setting: a plain request to the port
  // answers with the setup page
  const qrUrl = remote && phone ? `http://${phone.address}:${facts.status.port}/` : null
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
          {isLocalOnly ? (
            <Text color="warning">Turn on Listen on LAN first: until then the phone cannot open it.</Text>
          ) : (
            <Text dimColor>The phone only has to be on the same network; no proxy setting is needed for this page.</Text>
          )}
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
            onPress={() => void openSetupTab($, t.tab)}
          />
        ))}
      </Box>
      {!isRunning ? (
        <Box flexDirection="row" gap={1} marginTop={1}>
          <Text color="warning">The proxy is not running.</Text>
          <Button key="start" hotkey="s" variant="primary" label="Start" onPress={run(() => startProxy($, options))} />
        </Box>
      ) : null}
      {notice ? <Text color="success">{notice}</Text> : null}
      {busy ? <Text color="claude">◌ {busy}</Text> : null}

      {hasDevices ? (
        <Box flexDirection="row" gap={1} marginTop={1}>
          <Button
            key="sub-virtual"
            hotkey="v"
            variant={device === 'virtual' ? 'primary' : undefined}
            label={tab === 'ios' ? 'Simulator' : 'Emulator'}
            onPress={() => void update($, viewAtom, (v): ProxyView => ({ ...v, device: 'virtual' }))}
          />
          <Button
            key="sub-real"
            hotkey="p"
            variant={device === 'real' ? 'primary' : undefined}
            label={tab === 'ios' ? 'iPhone / iPad' : 'Phone (USB / Wi-Fi)'}
            onPress={() => void update($, viewAtom, (v): ProxyView => ({ ...v, device: 'real' }))}
          />
        </Box>
      ) : null}

      {showVirtual ? (
      <Box flexDirection="column" marginTop={1}>
        <Text bold underline>
          {tab === 'browser' ? 'Separate browser' : tab === 'ios' ? 'Simulator' : tab === 'android' ? 'Emulator' : 'This Mac'}
        </Text>
        {tab === 'ios' ? systemProxyBlock : null}
        {deviceBlock}
        {tab === 'cli' ? systemProxyBlock : null}
        {targets
          .filter(target => !target.isRemote && tab !== 'ios' && tab !== 'browser')
          .map(target => (
            <Box key={`target-${target.client}`} flexDirection="row" flexWrap="wrap" gap={1}>
              <Text dimColor>{target.client}:</Text>
              <Text bold>
                Server {target.host}  Port {target.port}
              </Text>
              <Text dimColor>{target.how}</Text>
            </Box>
          ))}
        {actions.length ? (
          <Box flexDirection="row" gap={1} flexWrap="wrap" marginTop={1}>
            {actions}
          </Box>
        ) : null}
      </Box>
      ) : null}

      {showReal ? usbBlock : null}
      {showReal && remote ? (
        <Box flexDirection="column" borderStyle="round" borderColor="claude" paddingX={1} marginTop={1}>
          <Text bold>{tab === 'ios' ? 'iPhone / iPad' : 'Android phone over Wi-Fi'}</Text>
          {phone ? (
            <Box flexDirection="row" gap={1} flexWrap="wrap">
              <Text>Proxy to enter:</Text>
              <Text bold color={isLocalOnly ? 'warning' : 'success'}>
                Server {phone.address}  Port {facts.status.port}
              </Text>
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
            </Box>
          ) : (
            <Text color="warning">This Mac has no address a phone could reach: connect it to Wi-Fi or Ethernet, on the phone's network.</Text>
          )}
          {phone ? (
            <Text dimColor>
              {phone.address} is this Mac on {phone.label}
              {others.length ? `; not ${others.map(entry => `${entry.address} (${kindName(entry.kind)})`).join(', ')}` : ''}.
            </Text>
          ) : null}
          {phoneClients.map(client => (
            <Text key={`client-${client.address}`} color={client.rejected ? 'error' : 'success'}>
              {client.rejected
                ? `✕ ${client.address} refused the proxy certificate ${client.rejected}× : install the ${tab === 'ios' ? 'profile and turn on its trust' : 'certificate'} (steps below), or the app pins its certificates.`
                : `✓ Traffic is arriving from ${client.address}: ${client.count} ${client.count === 1 ? 'request' : 'requests'}.`}
            </Text>
          ))}
          {phone && !isLocalOnly && phoneClients.length === 0 ? <Text dimColor>Nothing from a phone yet: once its Wi-Fi proxy is set, its requests show here.</Text> : null}
          {isLocalOnly ? (
            <Box flexDirection="row" gap={1} flexWrap="wrap">
              <Text color="warning">Listen on is local: a phone cannot reach the proxy yet.</Text>
              <Button key="listen-lan" hotkey="l" variant="primary" label="Listen on LAN" onPress={() => void setListen('lan')()} />
            </Box>
          ) : null}
          {qrBlock}
          {!isLocalOnly ? <Button plain dimColor key="listen-local" label="back to this Mac only" onPress={() => void setListen('local')()} /> : null}
          <Text dimColor>Connecting a phone? Turn on Domains (d) to record only your app: its system services keep working.</Text>
        </Box>
      ) : null}

      <Box flexDirection="column" marginTop={1}>
        {status.ca ? (
          <Text dimColor>
            {version ? `proxy ${version} · ` : ''}CA {status.ca.path} · SHA-256 {status.ca.fingerprint256}
          </Text>
        ) : (
          <Text dimColor>The certificate is made the first time the proxy starts.</Text>
        )}
      </Box>
      <Markdown key="guide" text={guide} />
    </Box>
  )
}

async function drawDomains($: EngineInterface, e: PaneEvent): Promise<RenderElement> {
  const table = $.ui.resolve(e)
  const { Box, Text, Button } = table
  const Input = 'Input' in table ? table.Input : undefined
  const tracking = await read($, trackingAtom)
  const skipped = await read($, skippedAtom)
  const flows = await read($, flowsAtom)
  const notice = await read($, noticeAtom)
  const isOn = tracking.enabled && tracking.patterns.length > 0
  const hits = (pattern: string) => flows.filter(flow => matchesHostPattern(pattern, flow.host)).length
  const passed = Object.entries(skipped).sort((a, b) => b[1] - a[1])
  const passedTotal = passed.reduce((sum, [, count]) => sum + count, 0)
  const add = async (text: string) => {
    const { added, refused } = await trackDomains($, [text])
    await say($, [added.length ? `Tracking ${added.join(', ')}.` : '', refused.length ? `Not a host pattern: ${refused.join(', ')}.` : ''].filter(Boolean).join(' '))
  }

  return (
    <Box flexDirection="column">
      <Box flexDirection="row" gap={1} flexWrap="wrap">
        <Button key="back" hotkey="b" label="← List" onPress={() => void update($, viewAtom, (v): ProxyView => ({ ...v, mode: 'list' }))} />
        <Button
          key="tracking-toggle"
          hotkey="o"
          variant={tracking.enabled ? 'primary' : undefined}
          label={tracking.enabled ? 'Tracking list: on' : 'Tracking list: off'}
          onPress={() => void setTracking($, now => ({ ...now, enabled: !now.enabled }))}
        />
      </Box>
      <Text bold>Tracked domains · this session</Text>
      <Text dimColor>
        {isOn
          ? 'Only these are decrypted and recorded; every other connection passes through untouched and unrecorded.'
          : tracking.enabled
            ? 'The list is on but empty, so every domain is decrypted and recorded. Add a domain below.'
            : 'The list is off: every domain is decrypted and recorded.'}
      </Text>
      {Input ? (
        <Input
          key="track-add"
          label="Add "
          placeholder="app.example.com, *.example.com or re:^api\."
          submitLabel="track"
          value=""
          onSubmit={value => void add(value)}
        />
      ) : null}
      {notice ? <Text color="success">{notice}</Text> : null}
      {tracking.patterns.map(pattern => (
        <Box key={`tracked-${pattern}`} flexDirection="row" gap={1}>
          <Text color={tracking.enabled ? 'success' : 'subtle'}>{pattern}</Text>
          <Text dimColor>
            {hits(pattern)} {hits(pattern) === 1 ? 'request' : 'requests'}
          </Text>
          <Button plain key={`untrack:${pattern}`} label="remove" dimColor onPress={() => void untrackDomains($, [pattern])} />
        </Box>
      ))}
      <Box flexDirection="column" marginTop={1}>
        <Text bold>Passed through, not tracked</Text>
        {passed.length === 0 ? (
          <Text dimColor>{isOn ? 'Nothing yet.' : 'While the list is on, the hosts it leaves out show here with Track buttons.'}</Text>
        ) : (
          <Text dimColor>
            {passedTotal} {passedTotal === 1 ? 'connection' : 'connections'} to {passed.length} {passed.length === 1 ? 'host' : 'hosts'} since the proxy started
          </Text>
        )}
        {passed.slice(0, 15).map(([host, count]) => {
          const wildcard = wildcardFor(host)
          return (
            <Box key={`passed-${host}`} flexDirection="row" gap={1} flexWrap="wrap">
              <Text>{host}</Text>
              <Text dimColor>×{count}</Text>
              <Button plain key={`track:${host}`} label="track" onPress={() => void add(host)} />
              {wildcard && !tracking.patterns.includes(wildcard) ? (
                <Button plain key={`track:${wildcard}`} label={`track ${wildcard}`} onPress={() => void add(wildcard)} />
              ) : null}
            </Box>
          )
        })}
      </Box>
    </Box>
  )
}

async function openSetupTab($: EngineInterface, tab: ProxySetupTab, device?: 'virtual' | 'real'): Promise<void> {
  await update($, noticeAtom, () => '')
  await update($, viewAtom, (v): ProxyView => ({ ...v, mode: 'setup', setupTab: tab, device: device ?? v?.device }))
  // what is on this Mac now: the lists draw from the last look
  if (tab === 'ios') await scanSimulators($).catch(() => undefined)
  if (tab === 'android') await scanAndroid($).catch(() => undefined)
  if (tab === 'cli') await checkMacTrust($).catch(() => undefined)
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
  const version = await read($, versionAtom)
  const tracking = await read($, trackingAtom)
  const scope = tracking.enabled && tracking.patterns.length ? ` Only ${tracking.patterns.join(', ')} are decrypted and recorded (track_domains).` : ''
  return `${await phaseText($)}${scope}${version ? ` (proxy mod ${version})` : ''}`
}

async function phaseText($: EngineInterface): Promise<string> {
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
      argumentHint: '[start|stop|clear|setup|rules|track <domains>|untrack <domains>|status|tree|list]',
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
    await $.tool.register({
      name: 'track_domains',
      description:
        "Show or change the session's tracked domains. While the list is on and not empty, the proxy decrypts and records only these hosts; " +
        'every other connection passes through untouched and unrecorded (so a phone\'s system services keep working and the list stays clean). ' +
        'Patterns: app.example.com, *.example.com (covers example.com too), or re:<regex>; URLs are cut to their host. ' +
        'Answers the list and the untracked hosts the proxy has seen, busiest first. With no arguments it only answers.',
      inputSchema: {
        type: 'object',
        properties: {
          add: { type: 'array', items: { type: 'string' }, description: 'Patterns to track; adding turns the list on.' },
          remove: { type: 'array', items: { type: 'string' }, description: 'Patterns to stop tracking.' },
          set: { type: 'array', items: { type: 'string' }, description: 'Replace the whole list.' },
          enabled: { type: 'boolean', description: 'Turn the list on or off (off tracks every domain).' },
        },
      },
    })
    await restoreTracking($).catch(() => undefined)
    try {
      const manifest = JSON.parse(await $.fs.read(`${$.plugin.root}/.claude-plugin/plugin.json`)) as { version?: string }
      await update($, versionAtom, () => manifest.version ?? '')
    } catch {}
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
    const [first = '', ...rest] = e.args.trim().split(/\s+/)
    const arg = first.toLowerCase()
    switch (arg) {
      case 'track': {
        if (rest.length === 0) {
          await update($, viewAtom, (v): ProxyView => ({ ...v, mode: 'domains' }))
          await openPane($)
          return { text: 'Tracked domains are open in the Proxy pane.' }
        }
        const { added, refused } = await trackDomains($, rest)
        const tracking = await read($, trackingAtom)
        return {
          text: [
            added.length ? `Tracking ${tracking.patterns.join(', ')}; every other domain passes through unrecorded.` : '',
            refused.length ? `Not a host pattern: ${refused.join(', ')}.` : '',
          ].filter(Boolean).join(' '),
        }
      }
      case 'untrack': {
        if (rest.length === 0) {
          await setTracking($, now => ({ ...now, enabled: false }))
          return { text: 'The tracking list is off: every domain is decrypted and recorded.' }
        }
        await untrackDomains($, rest)
        const tracking = await read($, trackingAtom)
        return { text: tracking.patterns.length ? `Tracking ${tracking.patterns.join(', ')}.` : 'No tracked domains left: every domain is decrypted and recorded.' }
      }
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
        await openPane($)
        await openSetupTab($, (await read($, viewAtom)).setupTab)
        return { text: 'Client setup is open in the Proxy pane.' }
      case '':
        await openPane($)
        await startProxy($, options)
        // what the quick start offers: the simulators and emulators on this Mac
        void scanSimulators($).catch(() => undefined)
        void scanAndroid($).catch(() => undefined)
        return { text: 'The Proxy pane is open.' }
      default:
        return { text: `Unknown "${arg}". /proxy [start|stop|clear|setup|rules|track|untrack|status|tree|list]` }
    }
  })

  on('ui.render', { component: 'Pane', requestId: PANE }, ($, e) => drawPane($, e, options))

  on('tool.call', { tool: 'mcp__proxy__track_domains' }, async ($, e) => {
    const notes: string[] = []
    const list = (value: unknown) => (Array.isArray(value) ? value.map(String) : [])
    if (Array.isArray(e.set)) {
      const patterns = list(e.set).map(text => normalizeHostPattern(text))
      const refused = list(e.set).filter((_, i) => !patterns[i])
      await setTracking($, now => ({ enabled: now.enabled || patterns.length > 0, patterns: patterns.filter((p): p is string => !!p) }))
      if (refused.length) notes.push(`Not host patterns: ${refused.join(', ')}.`)
    }
    if (Array.isArray(e.add)) {
      const { refused } = await trackDomains($, list(e.add), false)
      if (refused.length) notes.push(`Not host patterns: ${refused.join(', ')}.`)
    }
    if (Array.isArray(e.remove)) await untrackDomains($, list(e.remove))
    if (typeof e.enabled === 'boolean') await setTracking($, now => ({ ...now, enabled: e.enabled as boolean }))
    const tracking = await read($, trackingAtom)
    const skipped = Object.entries(await read($, skippedAtom)).sort((a, b) => b[1] - a[1])
    const lines = [
      ...notes,
      tracking.enabled && tracking.patterns.length
        ? `The list is on: only ${tracking.patterns.join(', ')} are decrypted and recorded.`
        : tracking.enabled
          ? 'The list is on but empty: every domain is decrypted and recorded.'
          : `The list is off: every domain is decrypted and recorded.${tracking.patterns.length ? ` Kept for later: ${tracking.patterns.join(', ')}.` : ''}`,
      skipped.length
        ? `Passed through untracked since the proxy started: ${skipped.slice(0, 30).map(([host, count]) => `${host} ×${count}`).join(', ')}`
        : 'No untracked host has passed through yet.',
    ]
    return { result: lines.join('\n') }
  }).catch(() => ({ deny: 'proxy: could not change the tracked domains; try again.' }))

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
