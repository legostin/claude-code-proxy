import { atom, read, update } from 'claude-code'
import type { EngineInterface, Register, RenderElement, RenderInput } from 'claude-code'

import { describeRule, isTracked, matchesHostPattern, normalizeHostPattern, parseRules, ruleErrors, scriptsOf, wildcardFor } from '../shared/rules.mjs'
import type { Rule } from '../shared/rules.mjs'
import type {
  ProxyAndroidDevice,
  ProxyDevices,
  ProxyFlow,
  ProxyHealth,
  ProxyHeld,
  ProxyRuleEntry,
  ProxyRules,
  ProxySession,
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
  type FlowBody,
  type FlowDetail,
  filterFlows,
  flattenTree,
  flowTable,
  flowUrl,
  formatDuration,
  formatSize,
  grpcLabel,
  isTextual,
  languageOf,
  matchesFilter,
  mergeFlows,
  modelUrl,
  parseRecords,
  type SseRecord,
  findMatches,
  findWindow,
  sseLine,
  splitByMatches,
  streamNote,
  type WsRecord,
  wsLine,
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
import { DEVICE_CA, hasSystemCaCommand, isRootRefused, systemCaScript } from './android'
import { diffRequests } from './diff'
import { type AndroidFacts, diagnose, type DoctorAction, type DoctorFacts, findingsText } from './doctor'
import { toHar } from './har'
import { bodyForModel, busiestHosts, clipValue, jsonPath, splitBudget } from './model'
import { encodeQr, qrRaster, qrSvg } from './qr'
import {
  androidGuide,
  BROWSER_CANDIDATES,
  type Browser,
  browserArgs,
  browserGuide,
  cliGuide,
  iosGuide,
  MIN_NODE,
  newestNodeFirst,
  NODE_DOWNLOAD,
  nodeMajor,
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

const flowsAtom = atom({ plugin: 'wirepane', key: 'flows' } as const, [] as ProxyFlow[])
const statusAtom = atom({ plugin: 'wirepane', key: 'status' } as const, STOPPED)
const viewAtom = atom({ plugin: 'wirepane', key: 'view' } as const, {
  mode: 'list',
  selectedId: null,
  setupTab: 'browser',
  layout: 'list',
} as ProxyView)
const filterAtom = atom({ plugin: 'wirepane', key: 'filter' } as const, '')
const wantedAtom = atom({ plugin: 'wirepane', key: 'wanted' } as const, false)
const nextIdAtom = atom({ plugin: 'wirepane', key: 'nextId' } as const, 1)
const noticeAtom = atom({ plugin: 'wirepane', key: 'notice' } as const, '')
/** Emulators this session pointed at the proxy, to point back on stop. */
const emulatorsAtom = atom({ plugin: 'wirepane', key: 'emulators' } as const, [] as string[])
/** The tree view's open nodes, by TreeNode id. */
const expandedAtom = atom({ plugin: 'wirepane', key: 'expanded' } as const, [] as string[])
/** The proxy's tracked domains, which every attached session shares; off or empty, every domain is tracked. */
const trackingAtom = atom({ plugin: 'wirepane', key: 'tracking' } as const, { enabled: false, patterns: [] } as ProxyTracking)
/** Hosts that passed through untracked since the proxy started, with counts. */
const skippedAtom = atom({ plugin: 'wirepane', key: 'skipped' } as const, {} as Record<string, number>)
const devicesAtom = atom({ plugin: 'wirepane', key: 'devices' } as const, {
  simulators: [],
  simulatorError: null,
  avds: [],
  android: [],
  androidError: null,
} as ProxyDevices)
const systemProxyAtom = atom({ plugin: 'wirepane', key: 'systemProxy' } as const, { isOn: false, service: null, isOurs: false } as ProxySystemProxy)
const caSimulatorsAtom = atom({ plugin: 'wirepane', key: 'caSimulators' } as const, [] as string[])
const busyAtom = atom({ plugin: 'wirepane', key: 'busy' } as const, '')
/** This mod's version, from its plugin.json: which copy the session runs. */
const versionAtom = atom({ plugin: 'wirepane', key: 'version' } as const, '')
const macTrustAtom = atom({ plugin: 'wirepane', key: 'macTrust' } as const, 'unknown' as 'unknown' | 'trusted' | 'untrusted')
/** The project's rules file as last read. */
const rulesAtom = atom({ plugin: 'wirepane', key: 'rules' } as const, { file: null, entries: [], fileErrors: [] } as ProxyRules)
/** The sessions attached to the shared proxy. */
const sessionsAtom = atom({ plugin: 'wirepane', key: 'sessions' } as const, [] as ProxySession[])
/** Hosts the proxy passes through after they refused the certificate. */
const pinnedAtom = atom({ plugin: 'wirepane', key: 'pinned' } as const, [] as { client: string | null; host: string }[])
/** Exchanges held at a breakpoint now, until someone lets them go. */
const heldAtom = atom({ plugin: 'wirepane', key: 'held' } as const, [] as ProxyHeld[])
const healthAtom = atom({ plugin: 'wirepane', key: 'health' } as const, { checkedAt: null, findings: [], process: null } as ProxyHealth)

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
  /** Upstreams whose certificate is accepted unchecked: dev servers with self-signed ones. */
  insecureHosts: string
  /** An office's or a VPN's proxy every connection to a server goes through, and the hosts reached directly. */
  upstreamProxy: string
  upstreamBypass: string
}

type Runtime = {
  pid: number | null
  isStopping: boolean
  pending: Map<number, ProxyFlow>
  isFlushScheduled: boolean
  stderr: string
  /** This session's attach process (attach.mjs): killing it lets go of the shared proxy. */
  clientPid: number | null
  /** Stopping the proxy for every session, not only letting go of it. */
  isStoppingAll: boolean
  /** Settles once the event loop has ended and its last status is written. */
  done: Promise<void>
  /** The session this run attached for: a /clear starts another, whose state starts empty. */
  sessionId: string
  checkedAt: number
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
    return `port ${options.port} is taken (another Claude session or another proxy). Change Proxy port in /config, or stop that process: lsof -nP -iTCP:${options.port} -sTCP:LISTEN`
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
  if (runtime) {
    // running for a session a /clear ended: this one's state is empty, so attach again
    if (!runtime.isStopping && (await $.session.id()) !== runtime.sessionId) await reattach($, options)
    return
  }
  let markDone = () => {}
  const rt: Runtime = {
    pid: null,
    isStopping: false,
    pending: new Map(),
    isFlushScheduled: false,
    stderr: '',
    clientPid: null,
    isStoppingAll: false,
    done: new Promise<void>(resolve => (markDone = resolve)),
    sessionId: await $.session.id(),
    checkedAt: 0,
  }
  runtime = rt

  // A sidecar of the time before the shared proxy (Wirepane 0.7) may still hold the port; a shared one is attached to.
  const previous = await read($, statusAtom)
  if (previous.pid && !previous.isShared) {
    await kill($, previous.pid)
    await $.clock.sleep(300)
  }

  const node = await findNode($)
  if (!node) {
    runtime = null
    await update($, wantedAtom, () => false)
    await update($, statusAtom, (s): ProxyStatus => ({ ...(s ?? STOPPED), phase: 'failed', pid: null, error: NO_NODE, isNodeMissing: true }))
    await showStatus($)
    return
  }

  const host = options.listen === 'lan' ? '0.0.0.0' : '127.0.0.1'
  await update($, wantedAtom, () => true)
  await update($, statusAtom, (s): ProxyStatus => ({ ...STOPPED, lan: s?.lan ?? [], phase: 'starting', host, port: options.port }))
  await showStatus($)

  const stream = $.process.spawn({
    argv: [
      node,
      `${$.plugin.root}/sidecar/attach.mjs`,
      // this session's own
      '--session', await $.session.id(),
      '--project', await $.session.root(),
      '--rules', await rulesFileOf($),
      // the proxy's, when this session starts it
      '--port', String(options.port),
      '--host', host,
      '--data', await dataDirOf($),
      '--run', await $.session.id(),
      '--first-id', String(await read($, nextIdAtom)),
      '--no-decrypt', options.noDecrypt,
      '--insecure-hosts', options.insecureHosts,
      '--upstream-proxy', options.upstreamProxy,
      '--upstream-bypass', options.upstreamBypass,
      '--tracking', await trackingFileOf($),
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
          // a /clear began another session, its state empty: attach again, and the proxy tells it everything
          if (!rt.isStopping && Date.now() - rt.checkedAt > 1000) {
            rt.checkedAt = Date.now()
            if ((await $.session.id()) !== rt.sessionId) {
              void reattach($, options)
              break
            }
          }
          if (event.t === 'tick') continue
          if (event.t === 'stopping') {
            // stopped on purpose, by this session or another one: not a failure
            if (!rt.isStopping) await say($, 'The proxy was stopped from another session; /proxy starts it again.')
            rt.isStopping = true
            await update($, wantedAtom, () => false)
            continue
          }
          if (event.t === 'attached') {
            rt.clientPid = event.pid
            // a proxy this session started takes this session's tracked domains (restored by a --resume)
            if (event.isStarted) await writeTrackingFile($)
          } else if (event.t === 'ready') {
            rt.pid = event.pid
            if (rt.isStopping) {
              // stopping for everyone kills the proxy; a session leaving only lets go of it
              await kill($, rt.isStoppingAll || !rt.clientPid ? event.pid : rt.clientPid)
              continue
            }
            // another proxy run than the one this list came from: its requests follow
            const before = await read($, statusAtom)
            if (before.runDir && before.runDir !== event.runDir) await update($, flowsAtom, () => [])
            if (event.sessions) await update($, sessionsAtom, () => event.sessions ?? [])
            await update($, statusAtom, (): ProxyStatus => ({
              phase: 'running',
              host: event.host,
              port: event.port,
              addresses: event.addresses,
              lan: event.lan ?? [],
              runDir: event.runDir,
              control: event.control ?? null,
              isShared: event.isShared === true,
              proxyVersion: event.version,
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
          } else if (event.t === 'sessions') {
            await update($, sessionsAtom, () => event.sessions)
          } else if (event.t === 'tracking') {
            // the proxy's tracked domains, which every attached session shares
            const next: ProxyTracking = { enabled: event.enabled, patterns: event.patterns }
            await update($, trackingAtom, () => next)
            await $.store.set(`tracking:${await $.session.id()}`, next).catch(() => undefined)
          } else if (event.t === 'pinned') {
            await update($, pinnedAtom, list => [...(list ?? []).filter(p => !(p.client === event.client && p.host === event.host)), { client: event.client, host: event.host }])
          } else if (event.t === 'unpinned') {
            await update($, pinnedAtom, list => (list ?? []).filter(p => !(p.client === event.client && p.host === event.host)))
          } else if (event.t === 'held') {
            const { t, ...held } = event
            void t
            await update($, heldAtom, list => [...(list ?? []).filter(h => h.id !== held.id), held])
            $.ui.toast(`proxy: ${held.view.method} ${held.view.url.replace(/^https?:\/\//, '')} is held at a breakpoint`)
          } else if (event.t === 'released') {
            await update($, heldAtom, list => (list ?? []).filter(h => h.id !== event.id))
          } else if (event.t === 'cleared') {
            rt.pending.clear()
            await update($, flowsAtom, () => [])
            await showStatus($)
          } else if (event.t === 'fatal') {
            fatal = describeFatal(event.code, event.message, options)
          } else if (event.t === 'log' && event.source === 'attach') {
            // another version or other settings on the running proxy: the person should know
            await say($, `Wirepane: ${event.message}.`)
          } else if (event.t === 'log' && event.level === 'error') {
            $.ui.log(`proxy: ${event.message}`, { to: 'debug' })
          }
        }
      }
    } catch (error) {
      fatal = `could not start "${node}": ${error instanceof Error ? error.message : String(error)}. The proxy needs Node ${MIN_NODE} or newer.`
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
    markDone()
  })()
}

/** Lets go of the shared proxy and attaches again, for a session whose state started over; the proxy runs on. */
async function reattach($: EngineInterface, options: Options): Promise<void> {
  const old = runtime
  if (old) {
    old.isStopping = true
    if (old.clientPid) await kill($, old.clientPid)
    await old.done
  }
  await startProxy($, options)
}

/** Stops the proxy and starts it again once the old run has wound down (new settings, a new version). */
async function restartProxy($: EngineInterface, options: Options): Promise<void> {
  const old = runtime
  await stopProxy($)
  if (old) await old.done
  await startProxy($, options)
}

/** Stops the shared proxy for every session; answers how many others used it. */
async function stopProxy($: EngineInterface): Promise<number> {
  const me = await $.session.id()
  const others = (await read($, sessionsAtom)).filter(s => s.session !== me).length
  await update($, wantedAtom, () => false)
  await revertAndroid($)
  // nothing may stay pointed at a proxy that is gone
  await disableSystemProxy($, true)
  const rt = runtime
  const status = await read($, statusAtom)
  const pid = rt?.pid ?? status.pid
  if (rt) {
    rt.isStopping = true
    rt.isStoppingAll = true
  }
  // no proxy pid yet (it has not answered): letting go of it ends this run, and the proxy goes after its linger
  if (pid) await kill($, pid)
  else if (rt?.clientPid) await kill($, rt.clientPid)
  if (!rt) {
    await update($, statusAtom, (s): ProxyStatus => ({ ...(s ?? STOPPED), phase: 'stopped', pid: null, error: null }))
    await showStatus($)
  }
  await update($, sessionsAtom, () => [])
  return others
}

/** This session ends: the last one stops the proxy (the devices and the system proxy back first); the others only let go of it. */
async function leaveProxy($: EngineInterface): Promise<void> {
  const rt = runtime
  if (!rt) return
  const me = await $.session.id()
  const others = (await read($, sessionsAtom)).filter(s => s.session !== me)
  if (others.length === 0 || !(await read($, statusAtom)).isShared) {
    await stopProxy($)
    return
  }
  rt.isStopping = true
  if (rt.clientPid) await kill($, rt.clientPid)
}

/** The system proxy a proxy that died left pointing at nothing goes back as it was; a running proxy keeps it. */
async function repairLeftoverProxy($: EngineInterface): Promise<void> {
  const backup = await readSystemProxyBackup($)
  if (!backup) return
  const probe = await $.process.run(['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', '--noproxy', '*', '--max-time', '2', `http://127.0.0.1:${backup.port}/`])
  if (probe.stdout.trim() === '200') return
  await disableSystemProxy($, true)
  $.ui.toast('Wirepane put the system proxy back: a proxy that did not shut down had left it on.')
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
  if (body.view) {
    // gRPC and protobuf: the sidecar wrote what the wire format says, field by field
    try {
      const what = body.viewKind === 'grpc' ? 'gRPC messages' : 'protobuf'
      notes.unshift(`${what} decoded without a schema: field numbers, values, nested messages`)
      return { text: await $.fs.read(body.view), note: notes.join('; ') }
    } catch {}
  }
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

const NO_NODE =
  `Node.js ${MIN_NODE} or newer runs the proxy, and there is none on PATH or where Homebrew, Volta, nvm, fnm, mise, asdf, nodenv or MacPorts put it.`

/**
 * The Node that runs the sidecar: on PATH, or where a package or version
 * manager keeps it, since a Claude Code started from the Dock has a short
 * PATH. Each is asked its version; nvm's and fnm's newest come first.
 */
async function findNode($: EngineInterface): Promise<string | null> {
  const home = (await $.env.get('HOME')) ?? ''
  const managed: string[] = []
  for (const [dir, bin] of [
    [`${home}/.nvm/versions/node`, 'bin/node'],
    [`${home}/Library/Application Support/fnm/node-versions`, 'installation/bin/node'],
    [`${home}/.local/share/fnm/node-versions`, 'installation/bin/node'],
  ] as const) {
    const names = (await $.fs.list(dir).catch(() => [])).map(entry => entry.name)
    managed.push(...newestNodeFirst(names).map(version => `${dir}/${version}/${bin}`))
  }
  const candidates = [
    'node',
    '/opt/homebrew/bin/node',
    '/usr/local/bin/node',
    `${home}/.volta/bin/node`,
    ...managed,
    `${home}/.local/share/mise/shims/node`,
    `${home}/.asdf/shims/node`,
    `${home}/.nodenv/shims/node`,
    '/opt/local/bin/node',
  ]
  for (const candidate of candidates) {
    if (candidate !== 'node' && !(await $.fs.exists(candidate).catch(() => false))) continue
    const ran = await $.process.run([candidate, '--version']).catch(() => null)
    if (ran?.exitCode === 0 && nodeMajor(ran.stdout) >= MIN_NODE) return candidate
  }
  return null
}

async function findBrew($: EngineInterface): Promise<string | null> {
  for (const path of ['/opt/homebrew/bin/brew', '/usr/local/bin/brew']) {
    if (await $.fs.exists(path).catch(() => false)) return path
  }
  return null
}

/** Installs Node with Homebrew and starts the proxy on it; without Homebrew, opens the download page. */
async function installNode($: EngineInterface, options: Options): Promise<void> {
  const brew = await findBrew($)
  if (!brew) {
    await $.process.run(['open', NODE_DOWNLOAD]).catch(() => null)
    return
  }
  await update($, busyAtom, () => 'Installing Node.js: brew install node…')
  let ran: { exitCode: number | null; stdout: string; stderr: string }
  try {
    ran = await $.process.run([brew, 'install', 'node'], { timeoutMs: 600_000 }).catch(error => ({ exitCode: 1, stdout: '', stderr: String(error) }))
  } finally {
    await update($, busyAtom, () => '')
  }
  if (ran.exitCode !== 0) {
    const why = (ran.stderr || ran.stdout).trim().split('\n').slice(-2).join(' ⏎ ')
    await update($, statusAtom, (s): ProxyStatus => ({ ...(s ?? STOPPED), error: `brew install node failed${why ? `: ${why}` : ''}`, isNodeMissing: true }))
    return
  }
  await startProxy($, options)
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
  const pointed = await update($, emulatorsAtom, list => [...new Set([...(list ?? []), ...done])])
  await recordAndroid($, tool, status.port, pointed)
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
  await recordAndroid($, tool ?? 'adb', status.port, [])
  await say($, `Android proxy reverted on: ${serials.join(', ')}.`)
}

/** Which devices point at the proxy, on disk: a proxy whose last session vanished points them back itself. */
async function recordAndroid($: EngineInterface, tool: string, port: number, serials: readonly string[]): Promise<void> {
  await $.fs.write(`${await dataDirOf($)}/android-proxied.json`, serials.length ? JSON.stringify({ adb: tool, port, serials }) : '').catch(() => undefined)
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

/** Takes the rule out of the file; answers why not, or null once removed. */
async function removeRule($: EngineInterface, id: string): Promise<string | null> {
  return editRules($, rules => (rules.some(rule => rule.id === id) ? rules.filter(rule => rule.id !== id) : `No rule has the id ${id}.`))
}

/** The rules view's ✕ asks once more; this is its answer. */
async function confirmRemoveRule($: EngineInterface, id: string): Promise<void> {
  await update($, viewAtom, (v): ProxyView => ({ ...v, removing: null }))
  const failure = await removeRule($, id)
  await say($, failure ?? `Removed ${id}.`)
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
// The proxy's: one file it watches, shared by every attached session; each
// session keeps its last list in $.store under its id too, so a --resume
// that starts the proxy brings it back.

async function trackingFileOf($: EngineInterface): Promise<string> {
  return `${await dataDirOf($)}/tracking.json`
}

/** Writes the session's list where the proxy reads it; answers the path. */
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
    'The client does not trust the proxy CA, or the app pins its certificates. Install and trust the CA (Setup), or add the host to "Hosts never decrypted".',
  upstream: 'The proxy could not reach the server: DNS, the network, a refused connection or an untrusted server certificate.',
  'client-closed': 'The client closed the connection before the whole response arrived.',
  'tls-handshake': 'The TLS handshake with the client failed.',
  forbidden:
    "A client from the network tried to reach this Mac's localhost through the proxy. That is closed on purpose: in lan mode the proxy does not open local services to others.",
}

function statusColor(flow: ProxyFlow): string | undefined {
  if (flow.state === 'error') return 'error'
  // a gRPC call that failed answers HTTP 200: its trailers say how it went
  if (flow.grpcStatus) return 'error'
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
  if (view.mode === 'health') return drawHealth($, e, options)
  if (view.mode === 'held') return drawHeld($, e)
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

  const open = (id: number) => update($, viewAtom, (v): ProxyView => ({ ...v, mode: 'detail', selectedId: id, detailTab: undefined, detailSearch: '', detailMatch: 0 }))
  const toggleNode = (id: string) =>
    update($, expandedAtom, list => ((list ?? []).includes(id) ? (list ?? []).filter(x => x !== id) : [...(list ?? []), id]))
  const setLayout = (layout: 'list' | 'tree') => chooseLayout($, layout)

  const tracking = await read($, trackingAtom)
  const rules = await read($, rulesAtom)
  const rulesOn = rules.entries.filter(entry => entry.enabled && entry.errors.length === 0 && !entry.isUntrusted).length
  const problems = (await read($, healthAtom)).findings.filter(finding => finding.level === 'fail' || finding.level === 'warn').length
  const held = await read($, heldAtom)
  // nothing captured yet: the one-press ways in, from what is on this Mac
  // no Node to run the proxy on: install it, or download it without Homebrew
  let nodeOffer: RenderElement | null = null
  if (status.isNodeMissing) {
    const busy = await read($, busyAtom)
    const brew = busy ? null : await findBrew($)
    nodeOffer = (
      <Box flexDirection="row" gap={1} flexWrap="wrap">
        {busy ? <Text color="claude">◌ {busy}</Text> : null}
        {!busy && brew ? (
          <Button key="install-node" hotkey="i" variant="primary" label="Install Node.js" onPress={() => void installNode($, options)} />
        ) : null}
        {!busy && brew ? <Text dimColor>brew install node, then the proxy starts</Text> : null}
        {!busy && !brew ? (
          <Button key="download-node" hotkey="i" variant="primary" label="Download Node.js" onPress={() => void installNode($, options)} />
        ) : null}
        {!busy && !brew ? <Text dimColor>nodejs.org: install it, then press Start</Text> : null}
      </Box>
    )
  }

  let quickStart: RenderElement | null = null
  if (flows.length === 0) {
    const browsers = await findBrowsers($)
    const devices = await read($, devicesAtom)
    const version = await read($, versionAtom)
    const simulator = devices.simulators[0]
    const avd = devices.avds.find(name => !devices.android.some(device => device.avd === name)) ?? devices.avds[0]
    const row = (label: string, action: RenderElement | null, hint: string) => (
      <Box key={`qs-row-${label}`} flexDirection="row" gap={1}>
        <Text>{label.padEnd(13)}</Text>
        {action}
        <Box flexShrink={1}>
          <Text dimColor wrap="truncate-end">
            {hint}
          </Text>
        </Box>
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
          browsers[0] ? 'its own window, localhost too' : 'no Chrome, Edge, Brave or Chromium in /Applications',
        )}
        {simulator
          ? row(
              'iOS Simulator',
              <Button key="qs-simulator" label={`Use ${simulator.name}`} onPress={() => void useSimulator($, simulator.udid, options)} />,
              'boots, adds the CA, system proxy on',
            )
          : null}
        {avd
          ? row('Android', <Button key="qs-avd" label={`Start ${avd}`} onPress={() => void startAvd($, avd, options)} />, 'starts it behind the proxy')
          : null}
        {row('Phone', <Button key="qs-phone" label="Set up a phone" onPress={() => void openSetupTab($, 'ios', 'real')} />, 'its address and a QR code')}
        {row(
          'Only your app',
          <Button key="qs-domains" label="Track domains" onPress={() => void update($, viewAtom, (v): ProxyView => ({ ...v, mode: 'domains' }))} />,
          'record only its hosts',
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
      {(streamNote(flow) || formatSize(flow.resSize)).padStart(7)} {formatDuration(flow.durationMs).padStart(7)}
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
        <Button
          key="health"
          hotkey="h"
          label={problems ? `Health (${problems})` : 'Health'}
          onPress={() => void openHealth($, options)}
        />
        {held.length ? (
          <Button
            key="held"
            hotkey="w"
            variant="primary"
            label={`⏸ ${held.length} held`}
            onPress={() => void update($, viewAtom, (v): ProxyView => ({ ...v, mode: 'held' }))}
          />
        ) : null}
        <Button key="clear" hotkey="x" label="Clear" onPress={() => void clearFlows($)} />
        <Button
          key="setup"
          hotkey="n"
          label="Setup"
          onPress={() => void openSetupTab($, view.setupTab)}
        />
      </Box>
      {status.error ? <Text color="error">{status.error}</Text> : null}
      {nodeOffer}
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

const WS_SHOWN = 200
// how much of a body the find field searches
const FIND_CHARS = 2_000_000

/** A message typed in the pane, into a live WebSocket. */
async function sendFromPane($: EngineInterface, id: number, to: 'client' | 'server', text: string): Promise<void> {
  if (!text) return
  const answer = await control($, 'ws/send', { id, to, text })
  await say($, answer.error ? `Not sent: ${answer.error}.` : `Sent to the ${to}.`)
}

/** A JSON-lines log the sidecar keeps (WebSocket messages, server-sent events); empty when unreadable. */
async function readRecords<T>($: EngineInterface, file: string): Promise<T[]> {
  try {
    return parseRecords<T>(await $.fs.read(file))
  } catch {
    return []
  }
}

async function drawDetail($: EngineInterface, e: PaneEvent, id: number, options: Options): Promise<RenderElement> {
  const table = $.ui.resolve(e)
  const { Box, Text, Button, Code } = table
  const Input = 'Input' in table ? table.Input : undefined
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
  const messages = detail?.ws ? await readRecords<WsRecord>($, detail.ws.file) : []
  const notice = await read($, noticeAtom)
  const events = detail?.sse ? await readRecords<SseRecord>($, detail.sse.file) : []
  const lineWidth = Math.max(40, (e.props.bodyColumns ?? 100) - 4)
  const view = await read($, viewAtom)
  const reqType = detail?.reqHeaders.find(([k]) => k.toLowerCase() === 'content-type')?.[1] ?? null

  // the tabs: the request, the response, and a socket's messages or a stream's events
  type DetailTab = NonNullable<ProxyView['detailTab']>
  const tabs: { tab: DetailTab; label: string }[] = [
    { tab: 'request', label: 'Request' },
    { tab: 'response', label: flow.status !== null ? `Response · ${flow.status}` : 'Response' },
    ...(detail?.ws ? [{ tab: 'messages' as const, label: `Messages · ${streamNote(flow) || '0'}` }] : []),
    ...(detail?.sse ? [{ tab: 'events' as const, label: `Events · ${events.length}` }] : []),
  ]
  const fallback: DetailTab = detail?.ws ? 'messages' : detail?.sse ? 'events' : flow.state === 'error' && !detail?.resHeaders.length ? 'request' : 'response'
  const tab: DetailTab = tabs.some(t => t.tab === view.detailTab) ? view.detailTab! : fallback
  const setTab = (next: DetailTab) => () => void update($, viewAtom, (v): ProxyView => ({ ...v, detailTab: next, detailMatch: 0 }))

  // find: the tab as lines (headers, then the body as shown), every match, and the window around the current one
  const search = view.detailSearch ?? ''
  const headerLines = (headers: readonly [string, string][]) => headers.map(([name, value]) => `${name}: ${value}`)
  const bodyLines = (body: typeof reqBody, contentType: string | null) =>
    body?.text != null ? prettyBody(body.text.slice(0, FIND_CHARS), contentType).split('\n') : body?.note ? [body.note] : []
  const tabLines = !detail || !search
    ? []
    : tab === 'request'
      ? [...headerLines(detail.reqHeaders), '', ...bodyLines(reqBody, reqType)]
      : tab === 'response'
        ? [...headerLines(detail.resHeaders), '', ...bodyLines(resBody, flow.contentType), ...(detail.resTrailers?.length ? ['', 'trailers', ...headerLines(detail.resTrailers)] : [])]
        : tab === 'messages'
          ? messages.map((record, i) => wsLine(record, i + 1, 4000))
          : events.map((record, i) => sseLine(record, i + 1, 4000))
  const found = findMatches(tabLines, search)
  const current = found.length ? (((view.detailMatch ?? 0) % found.length) + found.length) % found.length : -1
  const currentMatch = current >= 0 ? found[current]! : null
  const shownLines = findWindow(tabLines.length, currentMatch?.line ?? null, BODY_LINES)
  const marksByLine = new Map<number, { match: (typeof found)[number]; n: number }[]>()
  found.forEach((match, n) => {
    if (match.line < shownLines.from || match.line >= shownLines.to) return
    marksByLine.set(match.line, [...(marksByLine.get(match.line) ?? []), { match, n }])
  })
  const step = (by: number) => () => void update($, viewAtom, (v): ProxyView => ({ ...v, detailMatch: (v.detailMatch ?? 0) + by }))

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
    grpcLabel(flow) ?? '',
    flow.httpVersion === '2' ? 'HTTP/2' : '',
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
          <Box flexDirection="row" gap={1}>
            {tabs.map((t, i) => (
              <Button key={`tab-${t.tab}`} hotkey={String(i + 1)} label={t.label} variant={t.tab === tab ? 'primary' : undefined} onPress={setTab(t.tab)} />
            ))}
          </Box>
          {Input ? (
            <Box flexDirection="row" gap={1}>
              <Box flexGrow={1}>
                <Input
                  key="find"
                  label="Find "
                  placeholder={tab === 'messages' ? 'text in the messages' : tab === 'events' ? 'text in the events' : `text in the ${tab}'s headers and body`}
                  value={search}
                  submitLabel="next"
                  onInput={value => void update($, viewAtom, (v): ProxyView => ({ ...v, detailSearch: value, detailMatch: 0 }))}
                  onSubmit={value =>
                    void update($, viewAtom, (v): ProxyView =>
                      value === (v.detailSearch ?? '') ? { ...v, detailMatch: (v.detailMatch ?? 0) + 1 } : { ...v, detailSearch: value, detailMatch: 0 },
                    )
                  }
                />
              </Box>
              {search && found.length > 1 ? <Button key="find-previous" hotkey="k" label="↑" onPress={step(-1)} /> : null}
              {search && found.length > 1 ? <Button key="find-next" hotkey="j" label="↓" onPress={step(1)} /> : null}
              {search ? <Button key="find-clear" label="✕" onPress={() => void update($, viewAtom, (v): ProxyView => ({ ...v, detailSearch: '', detailMatch: 0 }))} /> : null}
            </Box>
          ) : null}
          {search ? (
            found.length ? (
              <Text dimColor>
                {current + 1} of {found.length}
                {found.length >= 10_000 ? '+' : ''} · line {currentMatch!.line + 1}
                {found.length > 1 ? ' · j/↓ next, k/↑ previous, Enter next' : ''}
              </Text>
            ) : (
              <Text color="warning">Nothing matches "{search}" here.</Text>
            )
          ) : null}
          {search && found.length ? (
            <Box flexDirection="column" marginTop={1}>
              {shownLines.from > 0 ? <Text dimColor>…{shownLines.from} lines above</Text> : null}
              {tabLines.slice(shownLines.from, shownLines.to).map((text, i) => {
                const line = shownLines.from + i
                const marks = marksByLine.get(line) ?? []
                if (marks.length === 0) return <Text key={`find-line-${line}`}>{text || ' '}</Text>
                return (
                  <Text key={`find-line-${line}`}>
                    {splitByMatches(text, marks).map((piece, k) =>
                      piece.n === null ? (
                        piece.text
                      ) : (
                        <Text key={`find-mark-${line}-${k}`} backgroundColor={piece.n === current ? 'warning' : undefined} color={piece.n === current ? 'inverseText' : undefined} inverse={piece.n !== current}>
                          {piece.text}
                        </Text>
                      ),
                    )}
                  </Text>
                )
              })}
              {shownLines.to < tabLines.length ? <Text dimColor>…{tabLines.length - shownLines.to} lines below</Text> : null}
            </Box>
          ) : tab === 'request' ? (
            <Box flexDirection="column" marginTop={1}>
              {headerRows(detail.reqHeaders, 'req')}
              {detail.req || flow.kind === 'http' ? bodyBlock(reqBody, reqType, 'req-body') : null}
            </Box>
          ) : tab === 'response' ? (
            <Box flexDirection="column" marginTop={1}>
              {detail.resHeaders.length ? headerRows(detail.resHeaders, 'res') : <Text dimColor>no headers yet</Text>}
              {flow.kind === 'http' ? bodyBlock(resBody, flow.contentType, 'res-body') : null}
              {detail.resTrailers?.length ? (
                <Box flexDirection="column" marginTop={1}>
                  <Text bold>Trailers</Text>
                  {headerRows(detail.resTrailers, 'trailer')}
                </Box>
              ) : null}
            </Box>
          ) : null}
          {detail.ws && tab === 'messages' ? (
            <Box flexDirection="column" marginTop={1}>
              <Text dimColor>
                {streamNote(flow) || 'no messages yet'}
                {detail.ws.isMock ? ' · Wirepane plays the server' : ''}
                {detail.ws.close ? ` · closed ${detail.ws.close.code ?? ''} by ${detail.ws.close.by}` : ''} · → client to server, ← server to client
              </Text>
              {search ? null : (
                <Box flexDirection="column">
                  {messages.length > WS_SHOWN ? <Text dimColor>…the first {messages.length - WS_SHOWN} are in {detail.ws.file}</Text> : null}
                  {messages.slice(-WS_SHOWN).map((record, i, shown) => (
                    <Text key={`ws-${i}`} color={record.note ? 'warning' : record.dir === 'out' ? 'claude' : undefined}>
                      {wsLine(record, messages.length - shown.length + i + 1, lineWidth)}
                    </Text>
                  ))}
                  {messages.length === 0 ? <Text dimColor>No messages yet.</Text> : null}
                </Box>
              )}
              {Input && flow.state !== 'done' && flow.state !== 'error' ? (
                <Box flexDirection="column" marginTop={1}>
                  <Input
                    key="ws-to-server"
                    label="To the server "
                    placeholder="a message, as if the client sent it"
                    submitLabel="send"
                    value=""
                    onSubmit={text => void sendFromPane($, flow.id, 'server', text)}
                  />
                  <Input
                    key="ws-to-client"
                    label="To the client "
                    placeholder="a message, as if the server sent it"
                    submitLabel="send"
                    value=""
                    onSubmit={text => void sendFromPane($, flow.id, 'client', text)}
                  />
                  {notice ? <Text color="success">{notice}</Text> : null}
                </Box>
              ) : null}
            </Box>
          ) : null}
          {detail.sse && tab === 'events' && !search ? (
            <Box flexDirection="column" marginTop={1}>
              {events.length > WS_SHOWN ? <Text dimColor>…the first {events.length - WS_SHOWN} are in {detail.sse.file}</Text> : null}
              {events.slice(-WS_SHOWN).map((record, i, shown) => (
                <Text key={`sse-${i}`}>{sseLine(record, events.length - shown.length + i + 1, lineWidth)}</Text>
              ))}
              {events.length === 0 ? <Text dimColor>No events yet.</Text> : null}
            </Box>
          ) : null}
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
    // the row's key as /config names it for this install ("wirepane.listen", or a marketplace's spelling)
    const rows = await $.config.list().catch(() => [])
    const key = rows.find(row => /(^|[.:@])listen$/.test(row.key) && JSON.stringify(row.provider ?? '').includes('wirepane'))?.key ?? 'wirepane.listen'
    const result = await $.config.set({ key, value })
    await say($, 'deny' in result && result.deny ? `Could not change Proxy reachable from: ${result.deny}` : value === 'lan' ? 'Listening on the network now.' : 'Listening on this Mac only now.')
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
              <Text color="warning">The proxy is reachable from this Mac only: a phone cannot reach it yet.</Text>
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
  const view = await read($, viewAtom)
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
            {/* one row: a long name wraps in its own column, the controls stay put */}
            <Box flexDirection="row" gap={1}>
              <Text dimColor>{String(index + 1).padStart(2)}.</Text>
              <Button
                plain
                key={`rule-toggle:${entry.id}`}
                label={entry.enabled ? '[on] ' : '[off]'}
                onPress={() => void toggleRule($, entry.id)}
              />
              <Box flexShrink={1} flexGrow={1}>
                <Text bold color={isActive ? undefined : 'subtle'}>
                  {entry.name ?? entry.id}
                </Text>
              </Box>
              <Button plain key={`rule-up:${entry.id}`} label="↑" onPress={() => void moveRule($, entry.id, -1)} />
              <Button plain key={`rule-down:${entry.id}`} label="↓" onPress={() => void moveRule($, entry.id, 1)} />
              <Text dimColor>
                {count} {count === 1 ? 'hit' : 'hits'}
              </Text>
              {view.removing === entry.id ? null : (
                <Button
                  plain
                  key={`rule-remove:${entry.id}`}
                  label="✕"
                  onPress={() => void update($, viewAtom, (v): ProxyView => ({ ...v, removing: entry.id }))}
                />
              )}
            </Box>
            {view.removing === entry.id ? (
              <Box flexDirection="row" gap={1} flexWrap="wrap">
                <Text color="warning">    Remove {entry.id} from the rules file?</Text>
                <Button key={`rule-remove-confirm:${entry.id}`} label="Remove" onPress={() => void confirmRemoveRule($, entry.id)} />
                <Button
                  key={`rule-remove-keep:${entry.id}`}
                  label="Keep"
                  onPress={() => void update($, viewAtom, (v): ProxyView => ({ ...v, removing: null }))}
                />
              </Box>
            ) : null}
            {entry.description ? <Text>    {entry.description}</Text> : null}
            {entry.summary ? <Text dimColor>    {entry.name ? `${entry.id}: ` : ''}{entry.summary}</Text> : null}
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

// --- the doctor: what stands between the person and their traffic ----------------------
//
// The facts come from this Mac (networksetup, route, ps, lsof, adb, openssl)
// and from what the proxy saw; hooks/doctor.ts reads them into findings, each
// with its fix, and the Health view has a button for the fixes Wirepane can do.

async function run($: EngineInterface, argv: string[], timeoutMs = 5000): Promise<string> {
  const ran = await $.process.run(argv, { timeoutMs }).catch(() => null)
  return ran?.exitCode === 0 ? ran.stdout : ''
}

/** The CA's subject hash as Android names system CAs (`<hash>.0`). */
async function caHash($: EngineInterface): Promise<string | null> {
  const ca = (await read($, statusAtom)).ca
  if (!ca) return null
  const hash = (await run($, ['openssl', 'x509', '-inform', 'PEM', '-subject_hash_old', '-noout', '-in', ca.path])).trim()
  return /^[0-9a-f]{8}$/.test(hash) ? hash : null
}

async function androidFacts($: EngineInterface): Promise<AndroidFacts[]> {
  const tool = await adb($)
  if (!tool) return []
  const hash = await caHash($)
  const out: AndroidFacts[] = []
  for (const serial of await androidDevices($, tool).catch(() => [])) {
    const shell = async (...command: string[]) => (await run($, [tool, '-s', serial, 'shell', ...command])).trim()
    const sdk = Number(await shell('getprop', 'ro.build.version.sdk')) || null
    // Google APIs and AOSP images are userdebug and allow root; Google Play ones are user and do not
    const type = await shell('getprop', 'ro.build.type')
    const proxy = await shell('settings', 'get', 'global', 'http_proxy')
    out.push({
      serial,
      sdk,
      proxy: proxy && proxy !== 'null' && proxy !== ':0' ? proxy : null,
      isRootable: type === 'userdebug' || type === 'eng',
      hasSystemCa: hash ? (await shell(hasSystemCaCommand(hash))) === 'yes' : false,
    })
  }
  return out
}

const OTHER_PROXIES: [RegExp, string][] = [
  [/(^|\/)Charles$/, 'Charles'],
  [/(^|\/)Proxyman$/, 'Proxyman'],
  [/(^|\/)(mitmproxy|mitmdump|mitmweb)$/, 'mitmproxy'],
  [/HTTP Toolkit/, 'HTTP Toolkit'],
]

/** The web proxy the network service had before Wirepane took its place (an office's), as host:port. */
function previousProxyOf(
  backup: SystemProxyBackup | null,
  now: DoctorFacts['systemProxy'],
  port: number,
  autoProxyUrl: string | null,
  socks: { enabled: boolean; server: string; port: number } | null,
): string | null {
  const isOurs = (state: { server: string; port: number }) => /^(127\.0\.0\.1|localhost)$/.test(state.server) && state.port === port
  const candidates = [backup?.previous.secure, backup?.previous.web, now?.secure, now?.web]
  const found = candidates.find(state => state?.enabled && state.server && state.port && !isOurs(state))
  if (found) return `${found.server}:${found.port}`
  if (autoProxyUrl) return `pac+${autoProxyUrl}`
  if (socks?.enabled && socks.server && socks.port) return `socks5://${socks.server}:${socks.port}`
  return null
}

async function doctorFacts($: EngineInterface, options: Options): Promise<DoctorFacts> {
  const status = await read($, statusAtom)
  if (status.phase === 'running') await checkMacTrust($).catch(() => undefined)
  const service = await defaultNetworkService($).catch(() => null)
  const systemProxy = service
    ? {
        service,
        web: parseProxyState(await run($, ['networksetup', '-getwebproxy', service])),
        secure: parseProxyState(await run($, ['networksetup', '-getsecurewebproxy', service])),
      }
    : null
  // what else the network service routes through: a PAC file, a SOCKS proxy
  const autoProxy = service ? await run($, ['networksetup', '-getautoproxyurl', service]) : ''
  const autoProxyUrl = /^Enabled:\s*Yes/m.test(autoProxy) ? (/^URL:\s*(\S+)/m.exec(autoProxy)?.[1] ?? null) : null
  const socks = service ? parseProxyState(await run($, ['networksetup', '-getsocksfirewallproxy', service])) : null
  const route = /interface:\s*(\S+)/.exec(await run($, ['route', '-n', 'get', 'default']))?.[1] ?? ''
  const processes = (await run($, ['ps', '-axo', 'comm='])).split('\n').map(line => line.trim())
  const otherProxies = [...new Set(OTHER_PROXIES.filter(([pattern]) => processes.some(name => pattern.test(name))).map(([, name]) => name))]
  let portHolder: string | null = null
  let oldProxyPid: number | null = null
  if (status.phase === 'failed' && /port-busy|EADDRINUSE|in use/i.test(status.error ?? '')) {
    const lsof = await run($, ['lsof', '-nP', `-iTCP:${status.port}`, '-sTCP:LISTEN', '-Fcp'])
    const command = /^c(.+)$/m.exec(lsof)?.[1]
    const pid = /^p(\d+)$/m.exec(lsof)?.[1]
    portHolder = command ? `${command}${pid ? ` (pid ${pid})` : ''}` : null
    // a proxy of Wirepane 0.7 (each session its own, no --daemon) still running beside an updated plugin
    const args = pid ? await run($, ['ps', '-o', 'args=', '-p', pid]) : ''
    if (pid && /sidecar\/proxy\.mjs/.test(args) && !/--daemon/.test(args)) oldProxyPid = Number(pid)
  }
  return {
    status,
    flows: await read($, flowsAtom),
    tracking: await read($, trackingAtom),
    skipped: await read($, skippedAtom),
    macTrust: await read($, macTrustAtom),
    systemProxy,
    hasBackup: (await readSystemProxyBackup($)) !== null,
    upstreamProxy: options.upstreamProxy,
    previousProxy: previousProxyOf(await readSystemProxyBackup($), systemProxy, status.port, autoProxyUrl, socks),
    autoProxyUrl,
    vpn: /^(utun|ipsec|ppp|tun|tap)\d*/.test(route) ? route : null,
    otherProxies,
    portHolder,
    oldProxyPid,
    android: await androidFacts($),
    pinned: (await read($, pinnedAtom)).map(p => ({ client: p.client ?? '', host: p.host })),
  }
}

type ProcessInfo = NonNullable<ProxyHealth['process']>

async function processInfo($: EngineInterface): Promise<ProcessInfo | null> {
  const answer = (await control($, 'info', {})) as ControlAnswer & Partial<ProcessInfo> & { memory?: { rss: number } }
  if (answer.error || answer.pid === undefined) return null
  return {
    pid: answer.pid,
    version: answer.version ?? '',
    uptimeMs: answer.uptimeMs ?? 0,
    rss: answer.memory?.rss ?? 0,
    flows: answer.flows ?? 0,
    diskBytes: answer.diskBytes ?? 0,
    sessions: answer.sessions ?? [],
    websockets: answer.websockets ?? 0,
    pinned: answer.pinned ?? 0,
    isShared: answer.isShared ?? false,
  }
}

/** Looks again, keeps the findings for the Health view, and answers them. */
async function runDoctor($: EngineInterface, options: Options): Promise<ProxyHealth> {
  const findings = diagnose(await doctorFacts($, options))
  const health: ProxyHealth = { checkedAt: await $.clock.now(), findings, process: await processInfo($) }
  await update($, healthAtom, () => health)
  return health
}

function duration(ms: number): string {
  const minutes = Math.floor(ms / 60_000)
  return minutes >= 60 ? `${Math.floor(minutes / 60)} h ${minutes % 60} min` : `${minutes} min`
}

/** The proxy process in one line: pid, version, time up, memory, what it keeps, who uses it. */
async function processLine($: EngineInterface, info: ProcessInfo | null): Promise<string> {
  if (!info) return 'No proxy process answers.'
  const me = await $.session.id()
  const others = info.sessions.filter(s => s.session !== me)
  return (
    `Proxy process: pid ${info.pid}, Wirepane ${info.version || '?'}, up ${duration(info.uptimeMs)}, ${formatSize(info.rss)} of memory, ` +
    `${counted(info.flows, 'request')} kept (${formatSize(info.diskBytes)} on disk), ${counted(info.websockets, 'WebSocket')} open; ` +
    `${info.isShared ? `shared: this session${others.length ? ` and ${others.length} other${others.length === 1 ? '' : 's'} (${others.map(s => s.project.split('/').pop() || s.session.slice(0, 8)).join(', ')})` : ' alone'}` : 'this session’s own'}.`
  )
}

/** Carries out a finding's fix, then looks again. */
async function doFix($: EngineInterface, action: DoctorAction, options: Options): Promise<void> {
  switch (action.kind) {
    case 'start':
      await startProxy($, options)
      break
    case 'restore-system-proxy':
      await disableSystemProxy($)
      break
    case 'trust-mac':
      await trustCaOnMac($)
      break
    case 'track':
      await setTracking($, now => ({ enabled: true, patterns: [...now.patterns, ...action.patterns] }))
      break
    case 'insecure-host':
      await appendOption($, 'insecureHosts', action.host, options.insecureHosts)
      break
    case 'no-decrypt':
      await appendOption($, 'noDecrypt', action.host, options.noDecrypt)
      break
    case 'upstream':
      await setOption($, 'upstreamProxy', action.proxy.includes('://') || action.proxy.startsWith('pac+') ? action.proxy : `http://${action.proxy}`)
      break
    case 'android-system-ca':
      await androidSystemCa($, action.serial)
      break
    case 'setup':
      await openSetupTab($, action.tab)
      return
    case 'stop-old':
      await kill($, action.pid)
      await restartProxy($, options)
      break
  }
  await runDoctor($, options)
}

/** Adds a host to a comma-separated plugin option; the engine reloads the mod with it, and the proxy restarts on it. */
async function appendOption($: EngineInterface, name: 'insecureHosts' | 'noDecrypt', host: string, now: string): Promise<void> {
  const hosts = now.split(',').map(h => h.trim()).filter(Boolean)
  if (hosts.includes(host)) return
  await setOption($, name, [...hosts, host].join(','), `${host} added; the proxy restarts with it.`)
}

/** Sets one plugin option, by the key /config names it for this install. */
async function setOption($: EngineInterface, name: string, value: string, done = 'Set; the proxy restarts with it.'): Promise<void> {
  const rows = await $.config.list().catch(() => [])
  const key = rows.find(row => new RegExp(`(^|[.:@])${name}$`).test(row.key) && JSON.stringify(row.provider ?? '').includes('wirepane'))?.key ?? `wirepane.${name}`
  const result = await $.config.set({ key, value })
  await say($, 'deny' in result && result.deny ? `Could not change the setting: ${result.deny}` : done)
}

/** Puts the CA among an emulator's system CAs (an image that allows root), so every app trusts it until it reboots. */
async function androidSystemCa($: EngineInterface, serial: string): Promise<void> {
  const tool = await adb($)
  const ca = (await read($, statusAtom)).ca
  const hash = await caHash($)
  if (!tool || !ca || !hash) return say($, !tool ? 'adb not found.' : 'Start the proxy first (the CA comes with it).')
  await update($, busyAtom, () => `Putting the CA among ${serial}'s system CAs…`)
  try {
    const root = await $.process.run([tool, '-s', serial, 'root'], { timeoutMs: 20_000 })
    if (isRootRefused(`${root.stdout}${root.stderr}`)) {
      return say($, `${serial} runs a Google Play image, which refuses root: use a Google APIs image for apps without a network_security_config.`)
    }
    await $.process.run([tool, '-s', serial, 'wait-for-device'], { timeoutMs: 30_000 })
    await $.process.run([tool, '-s', serial, 'push', ca.path, DEVICE_CA], { timeoutMs: 20_000 })
    const ran = await $.process.run([tool, '-s', serial, 'shell', systemCaScript(hash)], { timeoutMs: 60_000 })
    const output = `${ran.stdout}${ran.stderr}`
    await say(
      $,
      /system CA in place/.test(output)
        ? `${serial} trusts the Wirepane CA in every app now, until it reboots. Restart the app you debug.`
        : `Could not put the CA in place on ${serial}: ${output.trim().split('\n').slice(-2).join(' ') || 'no answer'}`,
    )
  } finally {
    await update($, busyAtom, () => '')
  }
}

async function drawHealth($: EngineInterface, e: PaneEvent, options: Options): Promise<RenderElement> {
  const { Box, Text, Button } = $.ui.resolve(e)
  const health = await read($, healthAtom)
  const notice = await read($, noticeAtom)
  const busy = await read($, busyAtom)
  const status = await read($, statusAtom)
  const colors: Record<string, 'error' | 'warning' | 'success' | undefined> = { fail: 'error', warn: 'warning', ok: 'success', info: undefined }
  const marks: Record<string, string> = { fail: '✗', warn: '!', info: '•', ok: '✓' }
  const restart = async () => {
    await restartProxy($, options)
    await runDoctor($, options)
  }
  return (
    <Box flexDirection="column">
      <Box flexDirection="row" gap={1} flexWrap="wrap">
        <Button key="back" hotkey="b" label="← List" onPress={() => void update($, viewAtom, (v): ProxyView => ({ ...v, mode: 'list' }))} />
        <Button key="health-check" hotkey="g" label="Check again" onPress={() => void runDoctor($, options)} />
        {status.phase === 'running' ? <Button key="proxy-restart" label="Restart proxy" onPress={() => void restart()} /> : null}
        {health.process?.pinned ? (
          <Button key="pinned-retry" label={`Decrypt the ${health.process.pinned} passed-through hosts again`} onPress={() => void control($, 'pinned/clear', {}).then(() => runDoctor($, options))} />
        ) : null}
      </Box>
      <Text bold>Health{health.checkedAt ? ` · checked ${new Date(health.checkedAt).toLocaleTimeString()}` : ''}</Text>
      {busy ? <Text color="claude">{busy}</Text> : null}
      {notice ? <Text color="success">{notice}</Text> : null}
      <Text dimColor>{await processLine($, health.process)}</Text>
      {health.checkedAt === null ? <Text dimColor>Checking…</Text> : null}
      {health.findings.map((finding, i) => (
        <Box key={`finding-${i}`} flexDirection="column" marginTop={1}>
          <Box flexDirection="row" gap={1}>
            <Text color={colors[finding.level]}>{marks[finding.level]}</Text>
            <Box flexShrink={1} flexGrow={1}>
              <Text bold={finding.level === 'fail' || finding.level === 'warn'}>{finding.title}</Text>
            </Box>
            {finding.action && finding.label ? (
              <Button key={`fix-${i}`} label={finding.label} onPress={() => void doFix($, finding.action as DoctorAction, options)} />
            ) : null}
          </Box>
          {finding.detail ? <Text dimColor>  {finding.detail}</Text> : null}
          {finding.fix ? <Text>  {finding.fix}</Text> : null}
        </Box>
      ))}
    </Box>
  )
}

// --- breakpoints: what is held, and letting it go -----------------------------------------

type ResumeAnswer = ControlAnswer & { held?: number[] }

/** Lets a held exchange go: as it was, changed, answered by hand, or cut. */
async function resumeHeld($: EngineInterface, id: number, body: Record<string, unknown>): Promise<ResumeAnswer> {
  return (await control($, 'held/resume', { id, ...body })) as ResumeAnswer
}

async function drawHeld($: EngineInterface, e: PaneEvent): Promise<RenderElement> {
  const { Box, Text, Button, Code } = $.ui.resolve(e)
  const held = await read($, heldAtom)
  const notice = await read($, noticeAtom)
  const width = Math.max(40, (e.props.bodyColumns ?? 100) - 4)
  const act = async (id: number, body: Record<string, unknown>, words: string) => {
    const answer = await resumeHeld($, id, body)
    await say($, answer.error ? `Not let go: ${answer.error}.` : words)
  }
  return (
    <Box flexDirection="column">
      <Box flexDirection="row" gap={1}>
        <Button key="back" hotkey="b" label="← List" onPress={() => void update($, viewAtom, (v): ProxyView => ({ ...v, mode: 'list' }))} />
      </Box>
      <Text bold>Held at a breakpoint · {held.length}</Text>
      <Text dimColor>Each waits until you let it go (or its rule's time runs out). Claude changes one with resume_request.</Text>
      {notice ? <Text color="success">{notice}</Text> : null}
      {held.length === 0 ? <Text dimColor>Nothing is held. A rule with a breakpoint step holds what it matches.</Text> : null}
      {held.map(entry => (
        <Box key={`held-${entry.id}`} flexDirection="column" marginTop={1}>
          <Text bold>
            #{entry.id} {entry.phase === 'request' ? `${entry.view.method} ${entry.view.url}` : `${entry.view.status} for ${entry.view.method} ${entry.view.url}`}
          </Text>
          <Text dimColor>
            held {entry.phase === 'request' ? 'before it is sent' : 'before the client gets it'} · {entry.view.headers.length} headers
          </Text>
          {entry.view.body ? <Code source={truncate(entry.view.body, 2000)} language={/^\s*[[{]/.test(entry.view.body) ? 'json' : undefined} wrap="wrap" /> : null}
          <Box flexDirection="row" gap={1} flexWrap="wrap">
            <Button key={`held-go:${entry.id}`} variant="primary" label="Let it go" onPress={() => void act(entry.id, { action: 'continue' }, `#${entry.id} goes on as it was.`)} />
            <Button key={`held-cut:${entry.id}`} label="Cut it" onPress={() => void act(entry.id, { action: 'abort' }, `#${entry.id} is cut.`)} />
            <Button
              key={`held-ask:${entry.id}`}
              label="Ask Claude to change it"
              onPress={() =>
                void $.prompt.fill({
                  text: `Request #${entry.id} (${entry.view.method} ${truncate(entry.view.url, width)}) is held at the ${entry.phase} breakpoint. Change it with resume_request: `,
                  mode: 'insert',
                })
              }
            />
          </Box>
        </Box>
      ))}
    </Box>
  )
}

async function openHealth($: EngineInterface, options: Options): Promise<void> {
  await update($, viewAtom, (v): ProxyView => ({ ...v, mode: 'health' }))
  await runDoctor($, options)
}

// --- hooks ------------------------------------------------------------------------

const LIST_TOOL = 'mcp__wirepane__list_requests'
const GET_TOOL = 'mcp__wirepane__get_request'

const FILTER_HELP =
  'space-separated terms that must all hold, a leading "-" negates one: free text (substring of the URL), ' +
  'method:POST (or method:get,post), status:4xx | status:404 | status:>=400 | status:400-499, host:api.example.com | host:*.example.com, ' +
  'path:/v1/login, type:json|html|xml|js|css|img|font|media|text|form|grpc|ws|tunnel|other, is:error|ok|pending|tunnel|ws|https|h2|grpc|held|rejected|modified, client:192.168.'

const ACTION_TYPES = [
  'delay', 'throttle', 'setHeader', 'removeHeader', 'setQuery', 'removeQuery', 'mapRemote', 'replaceUrl',
  'setBody', 'replaceBody', 'mergeJson', 'respond', 'setStatus', 'fail', 'script', 'breakpoint',
]

const ACTION_SCHEMA = {
  type: 'object',
  description:
    'One step; its type and fields: delay {ms, msMax?} · throttle {bytesPerSecond} · setHeader {name, value} · removeHeader {name} · ' +
    'setQuery {name, value} (request) · removeQuery {name} (request) · mapRemote {scheme?, host?, port?, path?} (request: send elsewhere) · ' +
    'replaceUrl {pattern, with} (request) · setBody {text | json | file} · replaceBody {pattern, with} · mergeJson {json} (deep-merges into a JSON body) · ' +
    'respond {status, headers?, text | json | file} (request: answer without asking the server) · setStatus {status} (response) · ' +
    'fail {kind: reset | close | timeout} · script {code} · breakpoint {timeoutMs?} (holds the request or the response until the person, ' +
    'or Claude with resume_request, lets it go, changed or not; after timeoutMs, default 300000, it goes on as it was). ' +
    'A replace pattern is re:<regex source> (every match, $1 works in with) or literal text. ' +
    'file is relative to the project root. script code is the body of async (req, res, ctx) => {}: in request it may change req.method, ' +
    'req.url, req.headers (lower-case names), req.body, or set req.respond = {status, headers, body}; in response it may change res.status, ' +
    'res.headers, res.body; req.json() and res.json() parse the bodies; a body may be set to an object. Prefer the other types to scripts.',
  properties: { type: { type: 'string', enum: ACTION_TYPES } },
  required: ['type'],
  additionalProperties: true,
}

const MESSAGE_TYPES = ['replaceMessage', 'setMessage', 'mergeJson', 'drop', 'delay', 'reply', 'send', 'close', 'script']

const MESSAGE_STEP_SCHEMA = {
  type: 'object',
  description:
    'One step on WebSocket messages. Which messages: direction out (client → server) | in (server → client) | both (default), ' +
    'when: text the message holds, or re:<regex>; on: open runs it once as the socket opens (send, close, delay, script only). ' +
    'Types: replaceMessage {pattern, with} · setMessage {text | json | file} · mergeJson {json} · drop · delay {ms, msMax?} · ' +
    'reply {text | json | file} (answers the sender; the message goes no further) · send {to: client | server, text | json | file} (one more message) · ' +
    'close {code?, reason?} · script {code}: the body of async (msg, ctx) => {}, msg.text (change it), msg.json(), msg.drop = true, ' +
    'ctx.send(to, textOrObject), ctx.close(code, reason).',
  properties: {
    type: { type: 'string', enum: MESSAGE_TYPES },
    direction: { type: 'string', enum: ['out', 'in', 'both'] },
    on: { type: 'string', enum: ['message', 'open'] },
    when: { type: 'string' },
  },
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
    messages: {
      type: 'array',
      items: MESSAGE_STEP_SCHEMA,
      description:
        "Steps on a WebSocket's messages, in order; match then matches the upgrade request. With request [{type: respond, status: 101}] " +
        'Wirepane plays the WebSocket server itself (no server needed) and these steps answer.',
    },
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
    insecureHosts: typeof raw.insecureHosts === 'string' ? raw.insecureHosts : '',
    upstreamProxy: typeof raw.upstreamProxy === 'string' ? raw.upstreamProxy.trim() : '',
    upstreamBypass: typeof raw.upstreamBypass === 'string' ? raw.upstreamBypass : '',
  }
}

async function statusText($: EngineInterface): Promise<string> {
  const version = await read($, versionAtom)
  const tracking = await read($, trackingAtom)
  const scope = tracking.enabled && tracking.patterns.length ? ` Only ${tracking.patterns.join(', ')} are decrypted and recorded (track_domains).` : ''
  return `${await phaseText($)}${scope}${version ? ` (proxy mod ${version})` : ''}`
}

/** `1 request`, `3 requests`. */
function counted(n: number, noun: string): string {
  return `${n} ${noun}${n === 1 ? '' : 's'}`
}

async function phaseText($: EngineInterface): Promise<string> {
  const status = await read($, statusAtom)
  const flows = await read($, flowsAtom)
  const lan = status.addresses.filter(a => a !== '127.0.0.1')
  switch (status.phase) {
    case 'running':
      return `Proxy is running on 127.0.0.1:${status.port}${status.host === '0.0.0.0' && lan.length ? ` and ${lan.map(a => `${a}:${status.port}`).join(', ')}` : ''}; ${counted(flows.length, 'request')} captured.`
    case 'starting':
      return `Proxy is starting on :${status.port}; ${counted(flows.length, 'request')} captured so far.`
    case 'failed':
      return `Proxy failed: ${(status.error ?? 'unknown error').replace(/\.+$/, '')}. ${counted(flows.length, 'request')} captured before that.`
    default:
      return `Proxy is stopped (the person starts it with /proxy). ${counted(flows.length, 'request')} captured earlier.`
  }
}

/** Shows the list or the tree, and remembers the choice for later sessions. */
type ControlAnswer = { ok?: boolean; error?: string; open?: number[]; flows?: ProxyFlow[] }

// --- what the tools show Claude ---------------------------------------------------------

const PARTS = ['summary', 'headers', 'request', 'response', 'messages', 'all']

type RequestView = { part: string; budget: number; jsonPath?: string; from?: number; limit: number }

function contentTypeIn(headers: readonly [string, string][]): string | null {
  return headers.find(([k]) => k.toLowerCase() === 'content-type')?.[1] ?? null
}

/** One captured request as the tools show it, within `view.budget` characters of bodies; null when unknown. */
async function describeRequest($: EngineInterface, id: number, view: RequestView): Promise<string | null> {
  const summary = (await read($, flowsAtom)).find(flow => flow.id === id)
  const detail = await loadDetail($, id)
  const flow = detail ?? summary
  if (!flow) return null
  const out: string[] = []
  out.push(`#${flow.id} ${flow.method} ${detail?.url ?? flowUrl(flow)}${flow.replayOf ? ` (replay of #${flow.replayOf})` : ''}`)
  const protocol = flow.httpVersion
    ? ` · HTTP/${flow.httpVersion}${detail?.upstreamHttpVersion && detail.upstreamHttpVersion !== flow.httpVersion ? ` (server: HTTP/${detail.upstreamHttpVersion})` : ''}`
    : ''
  out.push(
    `status: ${statusLabel(flow)}${detail?.statusMessage ? ` ${detail.statusMessage}` : ''}${grpcLabel(flow) ? ` · ${grpcLabel(flow)}` : ''} · state: ${flow.state} · ${formatDuration(flow.durationMs)} · sent ${formatSize(flow.reqSize)} · received ${formatSize(flow.resSize)}${protocol} · ${new Date(flow.ts).toISOString()}${flow.client ? ` · client ${flow.client}` : ''}`,
  )
  if (flow.error) out.push(`error (${flow.errorCode ?? 'unknown'}): ${flow.error}`)
  if (!detail) {
    out.push('Headers and bodies are not on disk (yet).')
    return out.join('\n')
  }
  if (detail.ruleLog?.length) out.push(`rules: ${detail.ruleLog.join(' · ')}`)
  const held = (await read($, heldAtom)).find(h => h.id === id)
  if (held) {
    out.push(
      '',
      `--- HELD at the ${held.phase} breakpoint since ${new Date(held.since).toISOString()}: resume_request({ id: ${id} }) lets it go, with changes or not ---`,
      held.phase === 'request' ? `${held.view.method} ${held.view.url}` : `status ${held.view.status}`,
      ...held.view.headers.map(([k, v]) => `${k}: ${clipValue(v, 300)}`),
      '',
      held.view.body === null ? '(no body)' : bodyForModel(held.view.body, null, Math.min(view.budget, 8000)).text,
    )
  }
  if (view.part === 'summary') {
    out.push(`parts: get_request({ id: ${id}, part: 'headers' | 'request' | 'response'${detail.ws || detail.sse ? " | 'messages'" : ''} | 'all' })`)
    return out.join('\n')
  }
  const wants = (part: string) => view.part === 'all' || view.part === part
  const showReq = wants('request') || view.part === 'headers'
  const showRes = wants('response') || view.part === 'headers'
  const withBodies = view.part !== 'headers'
  const reqType = contentTypeIn(detail.reqHeaders)
  const req = showReq && withBodies ? await loadBody($, detail.req, reqType) : null
  const res = showRes && withBodies ? await loadBody($, detail.res, detail.contentType) : null
  const [reqBudget = 0, resBudget = 0] = splitBudget([req?.text?.length ?? 0, res?.text?.length ?? 0], view.budget)
  // json_path picks one part of the response body (of the request's, with part: 'request')
  const pathSide = view.jsonPath ? (view.part === 'request' ? 'request' : 'response') : null
  const section = (title: string, headers: readonly [string, string][], body: FlowBody | null, loaded: LoadedBody | null, contentType: string | null, budget: number) => {
    out.push('', `--- ${title} headers ---`, ...headers.map(([k, v]) => `${k}: ${clipValue(v, 300)}`))
    if (!withBodies) return
    if (!loaded || (loaded.text === null && loaded.note === null)) return void out.push(`--- ${title} body: none ---`)
    if (pathSide === title && loaded.text !== null) {
      let picked: ReturnType<typeof jsonPath>
      try {
        picked = jsonPath(JSON.parse(loaded.text), view.jsonPath!)
      } catch {
        picked = { error: 'the body is not JSON' }
      }
      if ('error' in picked) return void out.push(`--- ${title} body at ${view.jsonPath}: ${picked.error} ---`)
      const shown = bodyForModel(JSON.stringify(picked.value), 'application/json', view.budget)
      out.push(`--- ${title} body at ${view.jsonPath} ---`, shown.text)
      if (shown.isCut) out.push(`[cut at ${shown.text.length} characters; a deeper json_path, or max_chars, shows more]`)
      return
    }
    out.push(`--- ${title} body${loaded.note ? ` (${loaded.note})` : ''} ---`)
    if (loaded.text === null) return
    const shown = bodyForModel(loaded.text, contentType, Math.max(200, budget))
    out.push(shown.text)
    if (shown.isCut) out.push(`[cut at ${shown.text.length} of ${loaded.text.length} characters; json_path picks one part, max_chars shows more; the whole body: ${body?.file}]`)
  }
  if (showReq) section('request', detail.reqHeaders, detail.req, req, reqType, reqBudget)
  if (showRes) {
    section('response', detail.resHeaders, detail.res, res, detail.contentType, resBudget)
    if (detail.resTrailers?.length) out.push('', '--- response trailers ---', ...detail.resTrailers.map(([k, v]) => `${k}: ${v}`))
  }
  if (wants('messages')) {
    const page = <T,>(all: T[], line: (record: T, n: number, max: number) => string, what: string, file: string) => {
      const start = view.from === undefined ? Math.max(0, all.length - view.limit) : view.from - 1
      const shown = all.slice(start, start + view.limit)
      const max = Math.min(4000, Math.max(120, Math.floor(view.budget / Math.max(1, shown.length))))
      out.push('', `--- ${what}: ${all.length}${all.length > shown.length ? `, ${start + 1}-${start + shown.length} shown (from and limit page through them)` : ''} ---`)
      shown.forEach((record, i) => out.push(line(record, start + i + 1, max)))
      if (all.length === 0) out.push('none yet')
      out.push(`(all of them: ${file})`)
    }
    if (detail.ws) {
      const close = detail.ws.close ? `; closed ${detail.ws.close.code ?? ''}${detail.ws.close.reason ? ` "${detail.ws.close.reason}"` : ''} by ${detail.ws.close.by}` : ''
      out.push('', `WebSocket: ${streamNote(flow) || 'no messages'}${detail.ws.isMock ? '; Wirepane plays the server (a rule)' : ''}${close}. → is client to server, ← server to client.`)
      page(await readRecords<WsRecord>($, detail.ws.file), wsLine, 'messages', detail.ws.file)
    }
    if (detail.sse) page(await readRecords<SseRecord>($, detail.sse.file), sseLine, 'server-sent events', detail.sse.file)
  }
  return out.join('\n')
}

/** A request and its decoded bodies, for comparing and exporting; null when not on disk. */
async function exchangeOf($: EngineInterface, id: number): Promise<{ detail: FlowDetail; reqText: string | null; resText: string | null } | null> {
  const detail = await loadDetail($, id)
  if (!detail) return null
  const req = await loadBody($, detail.req, contentTypeIn(detail.reqHeaders))
  const res = await loadBody($, detail.res, detail.contentType)
  return { detail, reqText: req.text, resText: res.text }
}

const SEARCH_SCAN = 400

function snippet(text: string, at: number, length: number): string {
  const start = Math.max(0, at - 50)
  const part = text.slice(start, at + length + 50).replace(/\s+/g, ' ')
  return `${start > 0 ? '…' : ''}${part}${at + length + 50 < text.length ? '…' : ''}`
}

/** Where in a request the text is (case aside), with a little around it; null when nowhere. */
async function findIn($: EngineInterface, flow: ProxyFlow, text: string, where: string): Promise<{ where: string; snippet: string } | null> {
  const needle = text.toLowerCase()
  const look = (label: string, haystack: string | null | undefined) => {
    if (!haystack) return null
    const at = haystack.toLowerCase().indexOf(needle)
    return at < 0 ? null : { where: label, snippet: snippet(haystack, at, needle.length) }
  }
  if (where === 'url' || where === 'all') {
    const found = look('URL', flowUrl(flow))
    if (found || where === 'url') return found
  }
  const detail = await loadDetail($, flow.id)
  if (!detail) return null
  if (where === 'headers' || where === 'all') {
    const found =
      look('request headers', detail.reqHeaders.map(([k, v]) => `${k}: ${v}`).join('\n')) ??
      look('response headers', detail.resHeaders.map(([k, v]) => `${k}: ${v}`).join('\n'))
    if (found || where === 'headers') return found
  }
  const req = await loadBody($, detail.req, contentTypeIn(detail.reqHeaders))
  const res = await loadBody($, detail.res, detail.contentType)
  const found = look('request body', req.text) ?? look('response body', res.text)
  if (found) return found
  if (detail.ws) {
    const messages = await readRecords<WsRecord>($, detail.ws.file)
    for (let i = 0; i < messages.length; i++) {
      const hit = look(`message ${i + 1}`, messages[i]!.text ?? messages[i]!.view)
      if (hit) return hit
    }
  }
  if (detail.sse) {
    const events = await readRecords<SseRecord>($, detail.sse.file)
    for (let i = 0; i < events.length; i++) {
      const hit = look(`event ${i + 1}`, events[i]!.data)
      if (hit) return hit
    }
  }
  return null
}

// what curl sets itself, or what no longer holds for a body read back decoded
const REPLAY_SKIPPED = new Set(['host', 'content-length', 'connection', 'proxy-connection', 'keep-alive', 'transfer-encoding', 'te', 'upgrade', 'content-encoding'])
const HAR_MAX = 1000

/** Writes the captured requests (filtered) as a HAR file; answers what it did in words. */
async function exportHar($: EngineInterface, filter: string, file?: string): Promise<string> {
  const flows = filterFlows(await read($, flowsAtom), filter).filter(flow => flow.kind !== 'tunnel').slice(-HAR_MAX)
  if (flows.length === 0) return filter ? `No captured requests match "${filter}".` : 'No captured requests to write.'
  const exchanges = []
  for (const flow of flows) {
    const exchange = await exchangeOf($, flow.id)
    if (!exchange) continue
    const messages = exchange.detail.ws ? await readRecords<WsRecord>($, exchange.detail.ws.file) : undefined
    exchanges.push({ ...exchange, ...(messages ? { messages } : {}) })
  }
  const root = await $.session.root()
  const stamp = new Date(await $.clock.now()).toISOString().replace(/[:.]/g, '-').slice(0, 19)
  const path = file ? (file.startsWith('/') ? file : `${root}/${file}`) : `${root}/.claude/wirepane-${stamp}.har`
  await $.fs.write(path, `${JSON.stringify(toHar(exchanges, await read($, versionAtom)), null, 2)}\n`)
  return `Wrote ${exchanges.length} requests to ${path} (HAR 1.2: Chrome DevTools, Charles, Proxyman and HTTP Toolkit open it).`
}

/** A command to the running sidecar on its own port (curl, as the module has no network of its own). */
async function control($: EngineInterface, command: string, body: Record<string, unknown>): Promise<ControlAnswer> {
  const status = await read($, statusAtom)
  if (status.phase !== 'running' || !status.control) return { error: 'the proxy is not running (the person starts it with /proxy)' }
  const url = `http://127.0.0.1:${status.port}/__wirepane/${status.control.token}/${command}`
  const run = await $.process.run(['curl', '-sS', '--noproxy', '*', '--max-time', '10', '-X', 'POST', '--data-binary', '@-', url], {
    stdin: JSON.stringify(body),
  })
  try {
    return JSON.parse(run.stdout) as ControlAnswer
  } catch {
    return { error: run.stderr.trim() || 'no answer from the proxy' }
  }
}

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
      argumentHint: '[start|stop|restart|clear|setup|rules|doctor|track <domains>|untrack <domains>|export [file]|status|tree|list]',
    })
    await $.tool.register({
      name: 'list_requests',
      description:
        'List the HTTP(S) requests captured by Wirepane, the proxy the person runs with /proxy for their browser, iOS simulator/iPhone and Android emulator/phone. ' +
        'Returns the proxy status, then one line per request, oldest first: #id method status url (long ones cut) response-size duration type, ' +
        'WebSocket message counts, server-sent event counts, the rules that changed it and the error if one. ' +
        'Status CERT means the client refused the proxy certificate. To check for new requests, pass since: the newest id you saw. ' +
        `filter: ${FILTER_HELP}.`,
      inputSchema: {
        type: 'object',
        properties: {
          filter: { type: 'string', description: `Optional filter: ${FILTER_HELP}` },
          since: { type: 'number', description: 'Only requests after this id (the newest id of the last call).' },
          limit: { type: 'number', description: 'How many of the newest matching requests to list (default 50, at most 200).' },
        },
      },
    })
    await $.tool.register({
      name: 'get_request',
      description:
        'Show one captured request in full by its id from list_requests: URL, status, protocol, timing, client, error, request and response headers, ' +
        'the decoded (gunzipped) text bodies cut at max_body_chars, gRPC and protobuf bodies decoded without a schema, trailers (gRPC status), ' +
        "a WebSocket's messages both ways and a text/event-stream's events (newest 50; from and limit page through them).",
      inputSchema: {
        type: 'object',
        properties: {
          id: { type: 'number', description: 'The request id, the number after # in list_requests.' },
          part: {
            type: 'string',
            enum: PARTS,
            description: 'summary (the status line), headers (both sets), request, response, messages (WebSocket, server-sent events) or all (default).',
          },
          max_chars: { type: 'number', description: 'Characters of bodies (or messages) to show in all, shared by the request and the response (default 12000).' },
          json_path: { type: 'string', description: 'Show only this part of the JSON response body (of the request body with part: request), e.g. data.items[0].' },
          from: { type: 'number', description: 'WebSocket messages or server-sent events: the first one to show (1-based); default the newest.' },
          limit: { type: 'number', description: 'WebSocket messages or server-sent events: how many to show (default 50, at most 500).' },
        },
        required: ['id'],
      },
    })
    await $.tool.register({
      name: 'diagnose',
      description:
        "Check everything between the person and their traffic, and say how to fix each problem: the proxy and its process (sessions sharing it, memory), " +
        'the system proxy (left on by a dead proxy, held by Charles or Proxyman), a VPN, the Mac\'s trust in the CA, clients that refuse the CA (missing CA vs a pinned host), ' +
        'upstream failures (DNS, self-signed dev servers, closed ports), tracked domains that match nothing, Android emulators (proxy, system CA). ' +
        'Call it first when the person says nothing shows up, the app fails behind the proxy, or a phone cannot connect.',
      inputSchema: { type: 'object', properties: {} },
    })
    await $.tool.register({
      name: 'search_requests',
      description:
        'Find captured requests that hold some text (case aside) in their URL, headers, bodies, WebSocket messages or server-sent events, newest first, ' +
        'with the text in context: which request returned "invalid_token", which one sent a user id. Looks through the newest 400.',
      inputSchema: {
        type: 'object',
        properties: {
          text: { type: 'string' },
          where: { type: 'string', enum: ['url', 'headers', 'bodies', 'all'], description: 'Where to look (default all).' },
          filter: { type: 'string', description: `Only among requests matching this filter: ${FILTER_HELP}` },
          limit: { type: 'number', description: 'Most hits to answer (default 20).' },
        },
        required: ['text'],
      },
    })
    await $.tool.register({
      name: 'wait_for_request',
      description:
        'Wait until a request matching the filter ends (or starts, with until: start), then answer it: for "now tap Log in" moments, ' +
        'instead of calling list_requests again and again. Counts requests after since (default: the newest now).',
      inputSchema: {
        type: 'object',
        properties: {
          filter: { type: 'string', description: `The request to wait for: ${FILTER_HELP}` },
          timeout_s: { type: 'number', description: 'How long to wait (default 60, at most 300).' },
          until: { type: 'string', enum: ['end', 'start'] },
          since: { type: 'number', description: 'Count only requests after this id.' },
        },
      },
    })
    await $.tool.register({
      name: 'replay_request',
      description:
        'Send a captured HTTP request again through the proxy, as it was or changed (method, url, headers, body), and answer the new request ' +
        'with its response; it is recorded (marked as a replay) and the rules apply. It really is sent again: mind requests that pay, post or delete.',
      inputSchema: {
        type: 'object',
        properties: {
          id: { type: 'number' },
          method: { type: 'string' },
          url: { type: 'string' },
          headers: { type: 'object', additionalProperties: { type: ['string', 'null'] }, description: 'Headers to set; null removes one.' },
          body: { type: 'string', description: 'A new body, as text.' },
          json: { description: 'A new body, as JSON.' },
        },
        required: ['id'],
      },
    })
    await $.tool.register({
      name: 'diff_requests',
      description:
        'Compare two captured requests (the one that works and the one that does not): method, URL, query, headers, status and JSON bodies field by field.',
      inputSchema: {
        type: 'object',
        properties: { a: { type: 'number' }, b: { type: 'number' } },
        required: ['a', 'b'],
      },
    })
    await $.tool.register({
      name: 'export_har',
      description:
        'Write the captured requests (all, or those matching a filter, at most 1000) to a HAR 1.2 file, with bodies and WebSocket messages, ' +
        'for a teammate, a bug report, Chrome DevTools or another proxy. Answers the path.',
      inputSchema: {
        type: 'object',
        properties: {
          filter: { type: 'string', description: `Optional filter: ${FILTER_HELP}` },
          file: { type: 'string', description: 'Where to write it, relative to the project (default .claude/wirepane-<time>.har).' },
        },
      },
    })
    await $.tool.register({
      name: 'resume_request',
      description:
        'Let go of an exchange held at a breakpoint (a rule step {type: breakpoint} in request or response; list_requests shows it as HELD, get_request shows what is held). ' +
        'action continue (default) with optional changes: method, url, headers (null removes one), body or json (request phase); status, headers, body or json (response phase). ' +
        'action respond answers a held request without the server: respond {status, headers?, text | json}. action abort cuts the connection.',
      inputSchema: {
        type: 'object',
        properties: {
          id: { type: 'number' },
          action: { type: 'string', enum: ['continue', 'respond', 'abort'] },
          changes: {
            type: 'object',
            properties: {
              method: { type: 'string' },
              url: { type: 'string' },
              status: { type: 'number' },
              headers: { type: 'object', additionalProperties: { type: ['string', 'null'] } },
              body: { type: 'string' },
              json: {},
            },
          },
          respond: { type: 'object', properties: { status: { type: 'number' }, headers: { type: 'object' }, text: { type: 'string' }, json: {} } },
        },
        required: ['id'],
      },
    })
    await $.tool.register({
      name: 'send_ws_message',
      description:
        'Send a message into a live WebSocket the proxy records (its id from list_requests, kind ws, still open): to the client (as if the server said it) ' +
        'or to the server (as if the client did). Give text, json, or b64 for a binary message. The message shows in the log marked "sent by Claude".',
      inputSchema: {
        type: 'object',
        properties: {
          id: { type: 'number', description: 'The WebSocket request id.' },
          to: { type: 'string', enum: ['client', 'server'] },
          text: { type: 'string' },
          json: { description: 'Sent as JSON text.' },
          b64: { type: 'string', description: 'A binary message, base64.' },
        },
        required: ['id', 'to'],
      },
    })
    await $.tool.register({
      name: 'close_websocket',
      description: 'Close a live WebSocket the proxy records, both sides, with a close code (default 1000) and reason, to see how the app copes.',
      inputSchema: {
        type: 'object',
        properties: {
          id: { type: 'number', description: 'The WebSocket request id.' },
          code: { type: 'number', description: '1000 normal, 1001 going away, 1011 server error, 4000-4999 the app’s own.' },
          reason: { type: 'string' },
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
        'delays, throttling, headers, query, sending elsewhere, mocked answers, rewritten or merged bodies, status codes, failed connections, scripts; ' +
        "and a WebSocket's messages both ways (rewrite, drop, delay, answer, send more, close), up to a mock WebSocket server. Works on HTTP/1.1 and HTTP/2. " +
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
        "Show or change the proxy's tracked domains (one list for every session on this Mac). While the list is on and not empty, the proxy decrypts and records only these hosts; " +
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
    await repairLeftoverProxy($).catch(() => undefined)
    if (await read($, wantedAtom)) await startProxy($, options)
    return started
  })

  on('session.end', async ($, e, next) => {
    if (e.reason !== 'clear') await leaveProxy($)
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
      case 'stop': {
        const others = await stopProxy($)
        return { text: `The proxy is stopped${others ? `, for the ${others} other ${others === 1 ? 'session' : 'sessions'} that used it too` : ''}.` }
      }
      case 'clear':
        await clearFlows($)
        return { text: 'The request list is cleared.' }
      case 'status':
        return { text: await statusText($) }
      case 'export':
        return { text: await exportHar($, '', rest.join(' ').trim() || undefined) }
      case 'doctor':
      case 'health': {
        await openHealth($, options)
        await openPane($)
        const health = await read($, healthAtom)
        return { text: `${await processLine($, health.process)}\n\n${findingsText(health.findings)}` }
      }
      case 'restart':
        await restartProxy($, options)
        return { text: 'The proxy restarted.' }
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

  on('tool.call', { tool: 'mcp__wirepane__track_domains' }, async ($, e) => {
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

  on('tool.call', { tool: 'mcp__wirepane__list_rules' }, async $ => ({ result: await rulesText($) })).catch(() => ({
    deny: 'proxy: could not read the rules file; try again.',
  }))

  on('tool.call', { tool: 'mcp__wirepane__add_rule' }, async ($, e) => {
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

  on('tool.call', { tool: 'mcp__wirepane__update_rule' }, async ($, e) => {
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

  on('tool.call', { tool: 'mcp__wirepane__remove_rule' }, async ($, e) => {
    const id = String(e.id)
    const failure = await removeRule($, id)
    return { result: failure ? `Not removed: ${failure}` : `Removed ${id}.\n\n${await rulesText($)}` }
  }).catch(() => ({ deny: 'proxy: could not write the rules file; try again.' }))

  on('tool.call', { tool: 'mcp__wirepane__resume_request' }, async ($, e) => {
    const id = Number(e.id)
    const action = e.action === 'respond' || e.action === 'abort' ? e.action : 'continue'
    const answer = await resumeHeld($, id, { action, changes: e.changes, respond: e.respond })
    if (answer.error) return { result: `Not let go: ${answer.error}.${answer.held ? ` Held now: ${answer.held.length ? answer.held.map(h => `#${h}`).join(', ') : 'nothing'}.` : ''}` }
    const said = action === 'abort' ? 'cut' : action === 'respond' ? 'answered by hand' : e.changes ? 'let go with your changes' : 'let go as it was'
    return { result: `#${id} ${said}. wait_for_request({ filter: 'is:ok', since: ${id - 1} }) or get_request({ id: ${id} }) shows how it ended.` }
  }).catch(() => ({ deny: 'proxy: could not reach the proxy; try again.' }))

  on('tool.call', { tool: 'mcp__wirepane__send_ws_message' }, async ($, e) => {
    const body: Record<string, unknown> = { id: Number(e.id), to: e.to }
    if (typeof e.b64 === 'string') body.b64 = e.b64
    else if (e.json !== undefined) body.json = e.json
    else body.text = String(e.text ?? '')
    const answer = await control($, 'ws/send', body)
    if (answer.error) return { result: `Not sent: ${answer.error}.${answer.open ? ` Open WebSockets: ${answer.open.length ? answer.open.map(id => `#${id}`).join(', ') : 'none'}.` : ''}` }
    return { result: `Sent to the ${String(e.to)} on WebSocket #${Number(e.id)}. get_request shows it in the log, and what came back.` }
  }).catch(() => ({ deny: 'proxy: could not reach the proxy; try again.' }))

  on('tool.call', { tool: 'mcp__wirepane__close_websocket' }, async ($, e) => {
    const answer = await control($, 'ws/close', { id: Number(e.id), code: Number(e.code) || 1000, reason: String(e.reason ?? '') })
    if (answer.error) return { result: `Not closed: ${answer.error}.` }
    return { result: `Closing WebSocket #${Number(e.id)} with ${Number(e.code) || 1000} on both sides.` }
  }).catch(() => ({ deny: 'proxy: could not reach the proxy; try again.' }))

  on('tool.call', { tool: LIST_TOOL }, async ($, e) => {
    const filter = typeof e.filter === 'string' ? e.filter : ''
    const limit = Math.min(200, Math.max(1, Math.floor(Number(e.limit) || 50)))
    const since = Math.max(0, Math.floor(Number(e.since) || 0))
    const flows = await read($, flowsAtom)
    const tracking = await read($, trackingAtom)
    const parsed = parseFilter(filter)
    const matched = filterFlows(flows, filter).filter(flow => flow.id > since)
    const shown = matched.slice(-limit)
    const what = [filter ? `match "${filter}"` : '', since ? `came after #${since}` : ''].filter(Boolean).join(' and ')
    const hosts = busiestHosts(matched, 6)
    const isNoisy = !filter && !(tracking.enabled && tracking.patterns.length) && new Set(matched.map(flow => flow.host)).size > 6
    const lines = [
      await statusText($),
      parsed.errors.length ? `Unrecognised filter terms ignored: ${parsed.errors.join(', ')}.` : '',
      what ? `${matched.length} ${what}${matched.length > shown.length ? `, the newest ${shown.length} shown` : ''}.` : matched.length > shown.length ? `The newest ${shown.length} shown.` : '',
      isNoisy
        ? `Busiest hosts: ${hosts.map(([host, n]) => `${host} ×${n}`).join(', ')}. Narrow with filter (host:…, -host:…) or track_domains to record only the app's hosts.`
        : '',
      shown.length ? flowTable(shown) : 'No requests.',
      flows.length ? `Newest #${flows[flows.length - 1]!.id}: list_requests({ since: ${flows[flows.length - 1]!.id} }) lists only what comes after; wait_for_request waits for it.` : '',
    ]
    return { result: lines.filter(Boolean).join('\n') }
  }).catch(() => ({ deny: 'proxy: could not read the captured requests; try again.' }))

  on('tool.call', { tool: GET_TOOL }, async ($, e) => {
    const legacy = Number(e.max_body_chars)
    const view: RequestView = {
      part: typeof e.part === 'string' && PARTS.includes(e.part) ? e.part : 'all',
      budget: Math.max(500, Math.floor(Number(e.max_chars) || (legacy ? legacy * 2 : 12_000))),
      jsonPath: typeof e.json_path === 'string' && e.json_path.trim() ? e.json_path : undefined,
      from: e.from === undefined ? undefined : Math.max(1, Math.floor(Number(e.from) || 1)),
      limit: Math.min(500, Math.max(1, Math.floor(Number(e.limit) || 50))),
    }
    const text = await describeRequest($, Number(e.id), view)
    return { result: text ?? `No captured request #${e.id}. Call list_requests for the ids.` }
  }).catch(() => ({ deny: 'proxy: could not read that request from disk; try again.' }))

  on('tool.call', { tool: 'mcp__wirepane__diagnose' }, async $ => {
    const health = await runDoctor($, options)
    return { result: `${await processLine($, health.process)}\n\n${findingsText(health.findings)}` }
  }).catch(() => ({ deny: 'proxy: could not finish the checks; try again.' }))

  on('tool.call', { tool: 'mcp__wirepane__search_requests' }, async ($, e) => {
    const text = String(e.text ?? '')
    if (!text) return { result: 'Give text to look for.' }
    const where = ['url', 'headers', 'bodies', 'all'].includes(String(e.where)) ? String(e.where) : 'all'
    const limit = Math.min(100, Math.max(1, Math.floor(Number(e.limit) || 20)))
    const flows = filterFlows(await read($, flowsAtom), typeof e.filter === 'string' ? e.filter : '').reverse().slice(0, SEARCH_SCAN)
    const hits: string[] = []
    for (const flow of flows) {
      if (hits.length >= limit) break
      const found = await findIn($, flow, text, where)
      if (found) hits.push(`#${flow.id} ${flow.method} ${statusLabel(flow)} ${modelUrl(flow, 100)} · in ${found.where}: ${found.snippet}`)
    }
    const head = `${hits.length}${hits.length >= limit ? '+' : ''} of the ${flows.length} newest requests${e.filter ? ` matching "${String(e.filter)}"` : ''} hold "${text}" (${where === 'all' ? 'URL, headers, bodies, messages' : where}):`
    return { result: hits.length ? [head, ...hits, 'get_request({ id }) shows one in full.'].join('\n') : `None of the ${flows.length} newest requests hold "${text}".` }
  }).catch(() => ({ deny: 'proxy: could not search the captured requests; try again.' }))

  on('tool.call', { tool: 'mcp__wirepane__wait_for_request' }, async ($, e) => {
    const filter = typeof e.filter === 'string' ? e.filter : ''
    const until = e.until === 'start' ? 'start' : 'end'
    const seconds = Math.min(300, Math.max(1, Number(e.timeout_s) || 60))
    const flows = await read($, flowsAtom)
    const baseline = e.since !== undefined ? Math.max(0, Math.floor(Number(e.since) || 0)) : (flows[flows.length - 1]?.id ?? 0)
    const parsed = parseFilter(filter)
    const isWanted = (flow: ProxyFlow) => flow.id > baseline && (until === 'start' || flow.state === 'done' || flow.state === 'error') && matchesFilter(flow, parsed)
    const answer = (flow: ProxyFlow) => ({ result: `${flowTable([flow])}\nget_request({ id: ${flow.id} }) shows it in full.` })
    const deadline = (await $.clock.now()) + seconds * 1000
    for (;;) {
      const already = (await read($, flowsAtom)).find(isWanted)
      if (already) return answer(already)
      const left = deadline - (await $.clock.now())
      if (left <= 0) break
      const waited = await control($, 'flows/wait', { after: baseline, until, timeoutMs: Math.min(5000, left) })
      if (waited.error) return { result: `Cannot wait: ${waited.error}.` }
      const hit = (waited.flows ?? []).find(isWanted)
      if (hit) return answer(hit)
    }
    const newest = (await read($, flowsAtom)).at(-1)
    return {
      result: `Nothing${filter ? ` matching "${filter}"` : ''} ${until === 'start' ? 'started' : 'ended'} in ${seconds} s${newest && newest.id > baseline ? ` (${newest.id - baseline} other requests did; the newest #${newest.id})` : ''}. Check the app made the request, or widen the filter.`,
    }
  }).catch(() => ({ deny: 'proxy: could not wait for requests; try again.' }))

  on('tool.call', { tool: 'mcp__wirepane__replay_request' }, async ($, e) => {
    const id = Number(e.id)
    const detail = await loadDetail($, id)
    if (!detail || detail.kind !== 'http') return { result: `No HTTP request #${e.id} on disk to send again.` }
    const status = await read($, statusAtom)
    if (status.phase !== 'running' || !status.ca) return { result: 'The proxy is not running (the person starts it with /proxy).' }
    const headers = detail.reqHeaders.filter(([name]) => !REPLAY_SKIPPED.has(name.toLowerCase()))
    const changes: string[] = []
    if (e.headers && typeof e.headers === 'object') {
      for (const [name, value] of Object.entries(e.headers as Record<string, unknown>)) {
        const kept = headers.filter(([key]) => key.toLowerCase() !== name.toLowerCase())
        headers.splice(0, headers.length, ...kept)
        if (value !== null && value !== undefined) headers.push([name, String(value)])
        changes.push(value === null ? `header ${name} removed` : `header ${name}`)
      }
    }
    const method = typeof e.method === 'string' && e.method ? e.method.toUpperCase() : detail.method
    const url = typeof e.url === 'string' && e.url ? e.url : detail.url
    if (method !== detail.method) changes.push(`method ${method}`)
    if (url !== detail.url) changes.push('URL')
    let bodyFile = detail.req?.file ?? null
    if (e.json !== undefined || typeof e.body === 'string') {
      bodyFile = `${status.runDir ?? `${await dataDirOf($)}/flows/${await $.session.id()}`}/${id}.replay-${await $.clock.now()}.body`
      await $.fs.write(bodyFile, e.json !== undefined ? JSON.stringify(e.json) : String(e.body))
      changes.push('body')
    }
    const before = (await read($, flowsAtom)).at(-1)?.id ?? 0
    const run = await $.process.run(
      [
        'curl', '-sS', '-o', '/dev/null', '--max-time', '30',
        '--proxy', `http://127.0.0.1:${status.port}`, '--cacert', status.ca.path,
        // the proxy's token: curl descends from Claude, whose own traffic is otherwise never decrypted
        ...(status.control ? ['--proxy-header', `x-wirepane-control: ${status.control.token}`] : []),
        '-X', method, '-H', `x-wirepane-replay: ${id}`,
        ...headers.flatMap(([name, value]) => ['-H', `${name}: ${value}`]),
        ...(bodyFile && method !== 'GET' && method !== 'HEAD' ? ['--data-binary', `@${bodyFile}`] : []),
        url,
      ],
      { timeoutMs: 40_000 },
    )
    const isReplay = (flow: ProxyFlow) => flow.replayOf === id && flow.id > before && (flow.state === 'done' || flow.state === 'error')
    let replayed = (await read($, flowsAtom)).find(isReplay)
    if (!replayed) replayed = ((await control($, 'flows/wait', { after: before, timeoutMs: 5000 })).flows ?? []).find(isReplay)
    if (!replayed) return { result: `Sent #${id} again, but the proxy recorded no replay${run.stderr.trim() ? `: ${run.stderr.trim()}` : ''}.` }
    const shown = await describeRequest($, replayed.id, { part: 'response', budget: 3000, limit: 20 })
    return {
      result: `Replayed #${id} as #${replayed.id}${changes.length ? ` (changed: ${changes.join(', ')})` : ''}: ${statusLabel(replayed)} in ${formatDuration(replayed.durationMs)}.\n\n${shown ?? ''}`,
    }
  }).catch(() => ({ deny: 'proxy: could not send the request again; try again.' }))

  on('tool.call', { tool: 'mcp__wirepane__diff_requests' }, async ($, e) => {
    const a = await exchangeOf($, Number(e.a))
    const b = await exchangeOf($, Number(e.b))
    if (!a || !b) return { result: `No captured request #${!a ? e.a : e.b} on disk.` }
    return { result: [`#${a.detail.id} → #${b.detail.id}:`, ...diffRequests(a, b)].join('\n') }
  }).catch(() => ({ deny: 'proxy: could not compare those requests; try again.' }))

  on('tool.call', { tool: 'mcp__wirepane__export_har' }, async ($, e) => {
    return { result: await exportHar($, typeof e.filter === 'string' ? e.filter : '', typeof e.file === 'string' ? e.file : undefined) }
  }).catch(() => ({ deny: 'proxy: could not write the HAR file; try again.' }))
}
