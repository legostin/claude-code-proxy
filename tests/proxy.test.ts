import type { On } from 'claude-code'
import type { MockClock } from 'claude-code/testing'
import { expect, mock, test } from 'claude-code/testing'

import type { ProxyFlow } from '../types'

const HOME = '/home/tester'
const RUN_DIR = `${HOME}/.claude/proxy-mod/flows/session`
const CA_PATH = `${HOME}/.claude/proxy-mod/ca/ca.pem`

const READY = {
  t: 'ready',
  host: '127.0.0.1',
  port: 8899,
  addresses: ['127.0.0.1'],
  lan: [
    { address: '10.7.9.5', iface: 'en0', label: 'Wi-Fi (en0)', kind: 'lan', isPrimary: true },
    { address: '10.20.133.214', iface: 'utun8', label: 'utun8', kind: 'vpn', isPrimary: false },
  ],
  pid: 4242,
  runDir: RUN_DIR,
  ca: {
    path: CA_PATH,
    subject: 'CN=Wirepane CA (tester), O=Wirepane',
    fingerprint256: 'AB:CD',
    validTo: 'Jan  1 00:00:00 2029 GMT',
    spki: ['leafspki=', 'caspki='],
  },
}

function flow(id: number, extra: Partial<ProxyFlow> = {}): ProxyFlow {
  return {
    id,
    ts: 1_700_000_000_000,
    kind: 'http',
    method: 'GET',
    scheme: 'https',
    host: 'api.example.com',
    port: 443,
    path: `/v1/items/${id}`,
    status: 200,
    reqSize: 0,
    resSize: 2048,
    durationMs: 87,
    contentType: 'application/json',
    state: 'done',
    error: null,
    errorCode: null,
    client: '127.0.0.1',
    ...extra,
  }
}

let ruledFlow = false
const LOGIN = flow(2, { method: 'POST', path: '/v1/login', status: 401, reqSize: 17 })
const FLOWS = [flow(1), LOGIN, flow(3, { host: 'cdn.example.com', path: '/a.png', contentType: 'image/png' })]

const FILES: Record<string, string> = {
  [`${RUN_DIR}/2.json`]: JSON.stringify({
    ...LOGIN,
    url: 'https://api.example.com/v1/login',
    statusMessage: 'Unauthorized',
    reqHeaders: [
      ['Host', 'api.example.com'],
      ['Content-Type', 'application/json'],
    ],
    resHeaders: [['Content-Type', 'application/json']],
    req: { file: `${RUN_DIR}/2.req`, size: 17, stored: 17, isTruncated: false, encoding: null, isDecoded: false },
    res: { file: `${RUN_DIR}/2.res`, size: 30, stored: 30, isTruncated: false, encoding: 'gzip', isDecoded: true },
  }),
  [`${RUN_DIR}/2.req`]: '{"user":"tester"}',
  [`${RUN_DIR}/2.res`]: '{"error":"invalid_credentials"}',
}

/** Stands for node and the sidecar: answers spawn with READY and the flows. */
const ROOT = '/work/app'
const RULES_FILE = `${ROOT}/.claude/proxy-rules.json`
const TRUST_FILE = `${HOME}/.claude/proxy-mod/trusted-scripts.json`

/** Where Node is on the fake Mac: `--version` per path ("node" is the one on PATH), Homebrew, version folders. */
type FakeNode = { versions?: Record<string, string>; hasBrew?: boolean; dirs?: Record<string, string[]> }

const BREW = '/opt/homebrew/bin/brew'

function fakeMachine(on: On, clock: MockClock, extraFiles: Record<string, string> = {}, isQuiet = false, node: FakeNode = {}) {
  // the disk, fresh for each test: reads see what writes left
  const files: Record<string, string> = { ...FILES, ...extraFiles }
  const nodes: Record<string, string> = { ...(node.versions ?? { node: 'v22.11.0' }) }
  const spawned: (readonly string[])[] = []
  const killed: string[] = []
  let isKilled = false
  mock.env(on, { HOME })
  mock.store(on)
  on('process.spawn', async function* ($, e) {
    spawned.push(e.argv)
    const sent = isQuiet ? [] : FLOWS.map(f => (ruledFlow && f.id === 2 ? { ...f, rules: ['mock-login'] } : f))
    const skipped = { t: 'skipped', hosts: { 'gateway.icloud.com': 12, 'api.kolesa.kz': 3 } }
    const text = [READY, ...sent.map(f => ({ t: 'flow', flow: f })), skipped].map(event => `${JSON.stringify(event)}\n`).join('')
    // cut mid-line, as a pipe may
    yield { stream: 'stdout' as const, text: text.slice(0, 50) }
    yield { stream: 'stdout' as const, text: text.slice(50) }
    // Asleep on the mocked clock, which an act does not wait for.
    while (!isKilled) await clock.sleep(100)
    return { value: { code: null, signal: 'SIGTERM' } }
  })
  const ran: string[] = []
  on('process.run', async ($, e) => {
    if (e.argv[0] === 'kill') {
      killed.push(e.argv[1]!)
      isKilled = true
    }
    ran.push(e.argv.join(' '))
    const ok = (stdout: string) => ({ value: { exitCode: 0, stdout, stderr: '', isStdoutTruncated: false, isStderrTruncated: false } })
    const line = e.argv.join(' ')
    if (e.argv[1] === '--version' && /(^|\/)node$/.test(e.argv[0]!)) {
      const version = nodes[e.argv[0]!]
      return version ? ok(`${version}\n`) : { deny: `ENOENT: ${e.argv[0]}` }
    }
    if (line === `${BREW} install node`) {
      nodes['/opt/homebrew/bin/node'] = 'v24.9.0'
      return ok('')
    }
    if (line === 'xcrun simctl list devices available -j') return ok(JSON.stringify(SIMULATORS))
    if (line === 'route -n get default') return ok('   route to: default\n  interface: en0\n')
    if (line === 'networksetup -listnetworkserviceorder') return ok('(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n')
    if (line.startsWith('networksetup -getwebproxy') || line.startsWith('networksetup -getsecurewebproxy')) return ok('Enabled: No\nServer: \nPort: 0\n')
    if (line.startsWith('networksetup -getproxybypassdomains')) return ok('*.local\n169.254/16\n')
    if (line === 'emulator -list-avds') return ok('Pixel_8_API_35\nPixel_6\n')
    // the started emulator, found by its AVD name
    if (line.startsWith('/bin/sh -c for i in')) return ok('emulator-5556\n')
    if (line.startsWith('security verify-cert')) {
      return ok(ran.some(command => command.startsWith('security add-trusted-cert')) ? '...certificate verification successful.\n' : 'Cert Verify Result: CSSMERR_TP_NOT_TRUSTED\n')
    }
    if (line === 'adb devices') return ok('List of devices attached\nemulator-5554\tdevice\n')
    if (line === 'adb -s emulator-5554 emu avd name') return ok('Pixel_8_API_35\nOK\n')
    return ok('')
  })
  on('fs.read', async ($, e) => {
    const text = files[e.path]
    return text === undefined ? { deny: `ENOENT: ${e.path}` } : { value: text }
  })
  on('fs.write', async ($, e) => {
    files[e.path] = e.text
    return { value: undefined }
  })
  on('session.root', async () => ({ value: ROOT }))
  // Chrome is installed, and the Node and Homebrew the test names; nothing else is.
  on('fs.exists', async ($, e) => ({
    value: e.path === '/Applications/Google Chrome.app' || e.path in nodes || (node.hasBrew === true && e.path === BREW),
  }))
  on('fs.list', async ($, e) => {
    const names = node.dirs?.[e.path]
    return names ? { value: names.map(name => ({ name, kind: 'dir' as const, size: 0, mtimeMs: 0, isLink: false })) } : { deny: `ENOENT: ${e.path}` }
  })
  on('session.id', async () => ({ value: 'session' }))
  const configSets: [string, unknown][] = []
  on('config.set', async ($, e) => {
    configSets.push([e.key, e.value])
    return { value: e.value }
  })
  const statuses: (string | undefined)[] = []
  on('ui.status', async ($, e) => {
    statuses.push(e.text)
    return { value: undefined }
  })
  return { spawned, killed, statuses, configSets, files, ran }
}

// Each act waits for the sidecar loop the start left running to go quiet.
const SLOW = { timeoutMs: 20_000 }

const PANE = {
  component: 'Pane' as const,
  requestId: 'proxy',
  props: {
    title: 'Proxy',
    isFocused: true,
    bodyColumns: 100,
    placement: 'dock' as const,
    scroll: { offset: 0, bodyRows: 40 },
    view: {},
  },
  viewport: { columns: 160, rows: 48, isFullscreen: true },
}

for (const surface of ['terminal', 'desktop'] as const) {
  test(`${surface}: start lists the captured requests, newest first, and filters them`, SLOW, async ($, on) => {
    const clock = mock.clock(on)
    const machine = fakeMachine(on, clock)
    const ui = await $.ui.mount({ plugin: 'wirepane', surface, ...PANE })

    expect(await ui.find({ text: /stopped/ })).toBeDefined()
    await ui.press({ key: 'toggle' })
    await clock.advance(250)
    await ui.redraw()

    expect(machine.spawned).toHaveLength(1)
    const argv = machine.spawned[0]!
    expect(argv[0]).toBe('node')
    expect(argv[1]).toMatch(/sidecar\/proxy\.mjs$/)
    expect(argv).toContain('--no-decrypt')
    expect(argv[argv.indexOf('--data') + 1]).toBe(`${HOME}/.claude/proxy-mod`)

    expect(await ui.find({ text: /127\.0\.0\.1:8899 · 3 requests/ })).toBeDefined()
    const labels = (await Promise.all([1, 2, 3].map(id => ui.find({ key: `open-${id}` })))).map(row => row?.text)
    expect(labels).toEqual([
      'https://api.example.com/v1/items/1',
      'https://api.example.com/v1/login',
      'https://cdn.example.com/a.png',
    ])

    await ui.input({ key: 'filter', text: 'status:4xx', kind: 'change' })
    expect(await ui.find({ key: 'open-2' })).toBeDefined()
    expect(await ui.find({ key: 'open-1' })).toBeUndefined()
    expect(await ui.find({ text: /1 of 3 requests match/ })).toBeDefined()

    await ui.press({ key: 'toggle' })
    expect(machine.killed).toEqual(['4242'])
    await clock.advance(200)
    await ui.unmount()
  })

  test(`${surface}: a row opens its detail with headers and the decoded body`, SLOW, async ($, on) => {
    const clock = mock.clock(on)
    fakeMachine(on, clock)
    const ui = await $.ui.mount({ plugin: 'wirepane', surface, ...PANE })
    await ui.press({ key: 'toggle' })
    await clock.advance(250)
    await ui.redraw()

    await ui.press({ key: 'open-2' })
    expect(await ui.find({ text: /#2 POST https:\/\/api\.example\.com\/v1\/login/ })).toBeDefined()
    expect(await ui.find({ text: /401 Unauthorized/ })).toBeDefined()
    const body = await ui.find({ type: 'Code', text: /invalid_credentials/ })
    expect(String(body?.props.source)).toContain('"error": "invalid_credentials"')
    const sent = await ui.find({ type: 'Code', text: /tester/ })
    expect(String(sent?.props.language)).toBe('json')
    expect(await ui.find({ key: 'curl' })).toBeDefined()

    await ui.press({ key: 'back' })
    expect(await ui.find({ key: 'filter' })).toBeDefined()
    await ui.press({ key: 'toggle' })
    await clock.advance(200)
    await ui.unmount()
  })

  test(`${surface}: setup shows the tabs, the CA and each tab's actions`, SLOW, async ($, on) => {
    const clock = mock.clock(on)
    fakeMachine(on, clock)
    const ui = await $.ui.mount({ plugin: 'wirepane', surface, ...PANE })
    await ui.press({ key: 'toggle' })
    await clock.advance(250)
    await ui.press({ key: 'setup' })

    expect(await ui.find({ text: /SHA-256 AB:CD/ })).toBeDefined()
    expect(await ui.find({ type: 'Markdown', key: 'guide' })).toBeDefined()
    await ui.press({ key: 'tab-ios' })
    expect(await ui.find({ key: 'sim-ca' })).toBeDefined()
    await ui.press({ key: 'tab-android' })
    expect(await ui.find({ key: 'adb-on' })).toBeDefined()
    await ui.press({ key: 'tab-cli' })
    expect(await ui.find({ key: 'copy-trust' })).toBeDefined()
    await ui.press({ key: 'back' })
    await ui.press({ key: 'toggle' })
    await clock.advance(200)
    await ui.unmount()
  })
}

for (const surface of ['terminal', 'desktop'] as const) {
  test(`${surface}: setup names the exact address a phone enters, and switches to LAN`, SLOW, async ($, on) => {
    const clock = mock.clock(on)
    const machine = fakeMachine(on, clock)
    const ui = await $.ui.mount({ plugin: 'wirepane', surface, ...PANE })
    await ui.press({ key: 'toggle' })
    await clock.advance(250)
    await ui.press({ key: 'setup' })
    await ui.press({ key: 'tab-ios' })
    // the simulator needs no address typed: Use and the system proxy do it
    expect(await ui.find({ key: 'system-proxy' })).toBeDefined()
    await ui.press({ key: 'sub-real' })

    expect(await ui.find({ text: /Server 10\.7\.9\.5 {2}Port 8899/ })).toBeDefined()
    expect(await ui.find({ text: /not 10\.20\.133\.214 \(VPN\)/ })).toBeDefined()
    expect(await ui.find({ key: 'copy-ip' })).toBeDefined()
    await ui.press({ key: 'listen-lan' })
    expect(machine.configSets).toEqual([['wirepane.listen', 'lan']])

    await ui.press({ key: 'tab-android' })
    await ui.press({ key: 'sub-virtual' })
    expect(await ui.find({ text: /Server 10\.0\.2\.2 {2}Port 8899/ })).toBeDefined()
    await ui.press({ key: 'back' })
    await ui.press({ key: 'toggle' })
    await clock.advance(200)
    await ui.unmount()
  })

  test(`${surface}: the tree groups requests by host and path`, SLOW, async ($, on) => {
    const clock = mock.clock(on)
    fakeMachine(on, clock)
    const ui = await $.ui.mount({ plugin: 'wirepane', surface, ...PANE })
    await ui.press({ key: 'toggle' })
    await clock.advance(250)
    expect((await ui.find({ key: 'layout-list' }))?.props.variant).toBe('primary')
    await ui.press({ key: 'layout-tree' })
    expect((await ui.find({ key: 'layout-tree' }))?.props.variant).toBe('primary')
    expect((await ui.find({ key: 'layout-list' }))?.props.variant).toBeUndefined()

    const api = 'node:o:https://api.example.com'
    expect((await ui.find({ key: api }))?.text).toBe('▸ https://api.example.com')
    expect(await ui.find({ key: 'open-2' })).toBeUndefined()
    await ui.press({ key: api })
    expect((await ui.find({ key: api }))?.text).toBe('▾ https://api.example.com')
    await ui.press({ key: 'node:p:https://api.example.com/v1' })
    expect((await ui.find({ key: 'node:p:https://api.example.com/v1/items/1' }))?.text).toBe('▸ /items/1')
    await ui.press({ key: 'node:p:https://api.example.com/v1/login' })
    expect((await ui.find({ key: 'open-2' }))?.text).toBe('#2')
    expect(await ui.find({ text: /1 failed/ })).toBeDefined()

    await ui.press({ key: 'open-2' })
    expect(await ui.find({ text: /#2 POST https:\/\/api\.example\.com\/v1\/login/ })).toBeDefined()
    await ui.press({ key: 'back' })
    await ui.press({ key: 'expand-all' })
    for (const id of [1, 2, 3]) expect(await ui.find({ key: `open-${id}` })).toBeDefined()
    await ui.press({ key: 'collapse-all' })
    expect(await ui.find({ key: 'open-1' })).toBeUndefined()
    await ui.press({ key: 'layout-list' })
    expect((await ui.find({ key: 'open-1' }))?.text).toBe('https://api.example.com/v1/items/1')
    await ui.press({ key: 'toggle' })
    await clock.advance(200)
    await ui.unmount()
  })
}

for (const surface of ['terminal', 'desktop'] as const) {
  test(`${surface}: on LAN the phone tabs show a QR code of the setup address`, { ...SLOW, options: { listen: 'lan' } }, async ($, on) => {
    const clock = mock.clock(on)
    fakeMachine(on, clock)
    const ui = await $.ui.mount({ plugin: 'wirepane', surface, ...PANE })
    await ui.press({ key: 'toggle' })
    await clock.advance(250)
    await ui.press({ key: 'setup' })
    // the browser tab has no phone, so no code
    expect(await ui.find({ text: /Scan with/ })).toBeUndefined()
    for (const tab of ['ios', 'android']) {
      await ui.press({ key: `tab-${tab}` })
      await ui.press({ key: 'sub-real' })
      expect(await ui.find({ text: 'http://10.7.9.5:8899/' })).toBeDefined()
      expect(await ui.find(surface === 'terminal' ? { type: 'Raster', key: 'qr' } : { type: 'Svg' })).toBeDefined()
      expect(await ui.find({ key: 'listen-local' })).toBeDefined()
    }
    await ui.press({ key: 'back' })
    await ui.press({ key: 'toggle' })
    await clock.advance(200)
    await ui.unmount()
  })

  test(`${surface}: listening on this Mac only, the code shows with what to do first`, SLOW, async ($, on) => {
    const clock = mock.clock(on)
    fakeMachine(on, clock)
    const ui = await $.ui.mount({ plugin: 'wirepane', surface, ...PANE })
    await ui.press({ key: 'toggle' })
    await clock.advance(250)
    await ui.press({ key: 'setup' })
    await ui.press({ key: 'tab-ios' })
    // the simulator sub-tab is about the simulator: no phone here
    expect(await ui.find({ text: /Scan with/ })).toBeUndefined()
    await ui.press({ key: 'sub-real' })
    expect(await ui.find({ text: /Scan with/ })).toBeDefined()
    expect(await ui.find({ text: /Turn on Listen on LAN first/ })).toBeDefined()
    expect(await ui.find({ key: 'listen-lan' })).toBeDefined()
    await ui.press({ key: 'back' })
    await ui.press({ key: 'toggle' })
    await clock.advance(200)
    await ui.unmount()
  })
}

const SCRIPT_CODE = "res.body = 'scripted'"
const RULES = {
  rules: [
    { id: 'slow-feed', name: 'Slow feed', description: 'The feed takes its time', match: { path: '/v1/feed*' }, request: [{ type: 'delay', ms: 2000 }] },
    { id: 'mock-login', match: { methods: ['POST'], path: '/v1/login' }, request: [{ type: 'respond', status: 500, json: { error: 'down' } }] },
    { id: 'scripted', response: [{ type: 'script', code: SCRIPT_CODE }] },
    { id: 'broken', request: [{ type: 'nope' }] },
  ],
}

async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))
  return [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, '0')).join('')
}

for (const surface of ['terminal', 'desktop'] as const) {
  test(`${surface}: the rules view lists, toggles, reorders and approves rules`, SLOW, async ($, on) => {
    const clock = mock.clock(on)
    const machine = fakeMachine(on, clock, { [RULES_FILE]: JSON.stringify(RULES) })
    const ui = await $.ui.mount({ plugin: 'wirepane', surface, ...PANE })
    await ui.press({ key: 'rules' })

    expect(await ui.find({ text: /4 rules, 2 on/ })).toBeDefined()
    expect(await ui.find({ text: 'The feed takes its time' })).toBeDefined()
    expect(await ui.find({ text: /slow-feed: path \/v1\/feed\* → before sending: wait 2 s/ })).toBeDefined()
    expect(await ui.find({ text: /answer 500 with JSON \{"error":"down"\} without asking the server/ })).toBeDefined()
    expect(await ui.find({ text: /request\[0\]: type must be one of/ })).toBeDefined()
    expect(await ui.find({ text: /script is not approved/ })).toBeDefined()

    await ui.press({ key: 'rule-toggle:slow-feed' })
    const toggled = JSON.parse(machine.files[RULES_FILE]!) as typeof RULES
    expect(toggled.rules[0]).toMatchObject({ id: 'slow-feed', enabled: false })
    expect(await ui.find({ text: /4 rules, 1 on/ })).toBeDefined()

    await ui.press({ key: 'rule-down:slow-feed' })
    const moved = JSON.parse(machine.files[RULES_FILE]!) as typeof RULES
    expect(moved.rules.map(rule => rule.id)).toEqual(['mock-login', 'slow-feed', 'scripted', 'broken'])

    await ui.press({ key: 'rule-trust:scripted' })
    expect(JSON.parse(machine.files[TRUST_FILE]!)).toEqual({ sha256: [await sha256Hex(SCRIPT_CODE)] })
    expect(await ui.find({ key: 'rule-trust:scripted' })).toBeUndefined()
    expect(await ui.find({ text: /4 rules, 2 on/ })).toBeDefined()

    await ui.press({ key: 'back' })
    expect((await ui.find({ key: 'rules' }))?.text).toBe('Rules (2)')
    await ui.unmount()
  })
}

test('Claude adds, changes and removes rules through the tools', SLOW, async ($, on) => {
  const clock = mock.clock(on)
  const machine = fakeMachine(on, clock)
  const rule = { id: 'auth', match: { host: '*.example.com' }, request: [{ type: 'setHeader', name: 'Authorization', value: 'Bearer t' }] }

  const added = String((await $.tool.call({ tool: 'mcp__wirepane__add_rule', rule })).result)
  expect(added).toContain('Added auth: host *.example.com → before sending: set header Authorization: Bearer t')
  expect(JSON.parse(machine.files[RULES_FILE]!)).toEqual({ rules: [rule] })

  const invalid = String((await $.tool.call({ tool: 'mcp__wirepane__add_rule', rule: { id: 'x', request: [{ type: 'delay' }] } })).result)
  expect(invalid).toContain('Not added')
  expect(invalid).toContain('ms must be a number')
  const duplicate = String((await $.tool.call({ tool: 'mcp__wirepane__add_rule', rule })).result)
  expect(duplicate).toContain('exists')

  const scripted = { id: 'first', response: [{ type: 'script', code: 'res.status = 299' }] }
  await $.tool.call({ tool: 'mcp__wirepane__add_rule', rule: scripted, position: 1 })
  const both = JSON.parse(machine.files[RULES_FILE]!) as { rules: { id: string }[] }
  expect(both.rules.map(r => r.id)).toEqual(['first', 'auth'])
  // a script Claude adds is approved with it
  expect(JSON.parse(machine.files[TRUST_FILE]!).sha256).toEqual([await sha256Hex('res.status = 299')])

  const changed = String((await $.tool.call({ tool: 'mcp__wirepane__update_rule', id: 'auth', enabled: false, position: 1, changes: { name: 'Auth header' } })).result)
  expect(changed).toContain('Changed auth')
  const after = JSON.parse(machine.files[RULES_FILE]!) as { rules: { id: string; enabled?: boolean; name?: string }[] }
  expect(after.rules.map(r => r.id)).toEqual(['auth', 'first'])
  expect(after.rules[0]).toMatchObject({ enabled: false, name: 'Auth header' })

  const listed = String((await $.tool.call({ tool: 'mcp__wirepane__list_rules' })).result)
  expect(listed).toContain('1. auth [off] Auth header')
  expect(listed).toContain('2. first [on]')

  const removed = String((await $.tool.call({ tool: 'mcp__wirepane__remove_rule', id: 'auth' })).result)
  expect(removed).toContain('Removed auth.')
  expect((JSON.parse(machine.files[RULES_FILE]!) as { rules: unknown[] }).rules).toHaveLength(1)
})

test('a request a rule changed is marked in the list and explained in its detail', SLOW, async ($, on) => {
  const clock = mock.clock(on)
  const machine = fakeMachine(on, clock)
  machine.files[`${RUN_DIR}/2.json`] = JSON.stringify({ ...JSON.parse(FILES[`${RUN_DIR}/2.json`]!), ruleLog: ['mock-login: answer 500'] })
  ruledFlow = true
  try {
    const ui = await $.ui.mount({ plugin: 'wirepane', surface: 'terminal', ...PANE })
    await ui.press({ key: 'toggle' })
    await clock.advance(250)
    await ui.redraw()
    expect((await ui.find({ key: 'open-2' }))?.text).toBe('✎ https://api.example.com/v1/login')
    await ui.press({ key: 'open-2' })
    expect(await ui.find({ text: /✎ mock-login: answer 500/ })).toBeDefined()
    await ui.press({ key: 'back' })
    await ui.input({ key: 'filter', text: 'rule:mock-login', kind: 'change' })
    expect(await ui.find({ key: 'open-1' })).toBeUndefined()
    expect(await ui.find({ key: 'open-2' })).toBeDefined()
    await ui.press({ key: 'toggle' })
    await clock.advance(200)
    await ui.unmount()
  } finally {
    ruledFlow = false
  }
})

const TRACKING_FILE = `${HOME}/.claude/proxy-mod/sessions/session/tracking.json`

for (const surface of ['terminal', 'desktop'] as const) {
  test(`${surface}: the domains view tracks what you add and offers what passed through`, SLOW, async ($, on) => {
    const clock = mock.clock(on)
    const machine = fakeMachine(on, clock)
    const ui = await $.ui.mount({ plugin: 'wirepane', surface, ...PANE })
    await ui.press({ key: 'toggle' })
    await clock.advance(250)
    expect(machine.spawned[0]).toContain('--tracking')
    expect((await ui.find({ key: 'domains' }))?.text).toBe('Domains: all')
    await ui.press({ key: 'domains' })
    expect(await ui.find({ text: /The list is off/ })).toBeDefined()

    await ui.input({ key: 'track-add', text: 'https://App.Example.com/v1/feed?x=1', kind: 'submit' })
    expect(JSON.parse(machine.files[TRACKING_FILE]!)).toEqual({ enabled: true, patterns: ['app.example.com'] })
    expect(await ui.find({ text: /Only these are decrypted and recorded/ })).toBeDefined()
    expect(await ui.find({ text: 'app.example.com' })).toBeDefined()

    // what passed through, busiest first, one press to track it
    expect(await ui.find({ text: 'gateway.icloud.com' })).toBeDefined()
    expect(await ui.find({ text: /15 connections to 2 hosts/ })).toBeDefined()
    await ui.press({ key: 'track:*.kolesa.kz' })
    expect(JSON.parse(machine.files[TRACKING_FILE]!).patterns).toEqual(['app.example.com', '*.kolesa.kz'])

    await ui.press({ key: 'untrack:app.example.com' })
    await ui.press({ key: 'tracking-toggle' })
    expect(JSON.parse(machine.files[TRACKING_FILE]!)).toEqual({ enabled: false, patterns: ['*.kolesa.kz'] })
    await ui.press({ key: 'back' })
    expect((await ui.find({ key: 'domains' }))?.text).toBe('Domains: all')
    await ui.press({ key: 'toggle' })
    await clock.advance(200)
    await ui.unmount()
  })
}

test('Claude tracks domains through the tool, and sees what passed through', SLOW, async ($, on) => {
  const clock = mock.clock(on)
  const machine = fakeMachine(on, clock)
  const ui = await $.ui.mount({ plugin: 'wirepane', surface: 'terminal', ...PANE })
  await ui.press({ key: 'toggle' })
  await clock.advance(250)
  const answer = String((await $.tool.call({ tool: 'mcp__wirepane__track_domains', add: ['*.kolesa.kz', 'not a host!'] })).result)
  expect(answer).toContain('Not host patterns: not a host!.')
  expect(answer).toContain('only *.kolesa.kz are decrypted and recorded')
  expect(answer).toContain('gateway.icloud.com ×12, api.kolesa.kz ×3')
  expect(JSON.parse(machine.files[TRACKING_FILE]!)).toEqual({ enabled: true, patterns: ['*.kolesa.kz'] })
  const listed = String((await $.tool.call({ tool: 'mcp__wirepane__list_requests' })).result)
  expect(listed).toContain('Only *.kolesa.kz are decrypted and recorded')
  const off = String((await $.tool.call({ tool: 'mcp__wirepane__track_domains', enabled: false })).result)
  expect(off).toContain('The list is off')
  await ui.press({ key: 'toggle' })
  await clock.advance(200)
  await ui.unmount()
})

const SIMULATORS = {
  devices: {
    'com.apple.CoreSimulator.SimRuntime.iOS-17-5': [{ udid: 'SIM-15', name: 'iPhone 15', state: 'Shutdown', isAvailable: true }],
    'com.apple.CoreSimulator.SimRuntime.iOS-18-2': [
      { udid: 'SIM-16PRO', name: 'iPhone 16 Pro', state: 'Shutdown', isAvailable: true },
      { udid: 'SIM-16', name: 'iPhone 16', state: 'Booted', isAvailable: true },
    ],
    'com.apple.CoreSimulator.SimRuntime.watchOS-11-2': [{ udid: 'WATCH', name: 'Apple Watch', state: 'Shutdown', isAvailable: true }],
  },
}
const BACKUP_FILE = `${HOME}/.claude/proxy-mod/system-proxy-backup.json`

for (const surface of ['terminal', 'desktop'] as const) {
  test(`${surface}: a simulator is booted, given the CA and put behind the system proxy in one press`, SLOW, async ($, on) => {
    const clock = mock.clock(on)
    const machine = fakeMachine(on, clock)
    const ui = await $.ui.mount({ plugin: 'wirepane', surface, ...PANE })
    await ui.press({ key: 'toggle' })
    await clock.advance(250)
    await ui.press({ key: 'setup' })
    await ui.press({ key: 'tab-ios' })

    // booted first, then the newest runtime; no watches
    const rows = await ui.findAll({ type: 'Button' })
    const simKeys = rows.map(row => row.key).filter(key => key?.startsWith('sim-use:'))
    expect(simKeys).toEqual(['sim-use:SIM-16', 'sim-use:SIM-16PRO', 'sim-use:SIM-15'])
    expect((await ui.find({ key: 'sim-use:SIM-16PRO' }))?.text).toBe('Boot & use')
    expect((await ui.find({ key: 'system-proxy' }))?.text).toBe('Turn on for this Mac')

    await ui.press({ key: 'sim-use:SIM-16PRO' })
    const did = machine.ran.join('\n')
    expect(did).toContain('xcrun simctl boot SIM-16PRO')
    expect(did).toContain('open -a Simulator --args -CurrentDeviceUDID SIM-16PRO')
    expect(did).toContain('xcrun simctl bootstatus SIM-16PRO -b')
    expect(did).toContain(`xcrun simctl keychain SIM-16PRO add-root-cert ${READY.ca.path}`)
    expect(did).toContain('networksetup -setwebproxy Wi-Fi 127.0.0.1 8899')
    expect(did).toContain('networksetup -setsecurewebproxy Wi-Fi 127.0.0.1 8899')
    expect(did).toMatch(/networksetup -setproxybypassdomains Wi-Fi \*\.local 169\.254\/16 .*\*\.anthropic\.com/)
    expect(JSON.parse(machine.files[BACKUP_FILE]!)).toMatchObject({ service: 'Wi-Fi', previous: { bypass: ['*.local', '169.254/16'] } })
    expect(await ui.find({ text: /on \(Wi-Fi\)/ })).toBeDefined()
    expect(await ui.find({ text: 'CA ✓' })).toBeDefined()

    // off puts back exactly what was there
    await ui.press({ key: 'system-proxy' })
    expect(machine.ran.join('\n')).toContain('networksetup -setwebproxystate Wi-Fi off')
    expect(machine.ran.join('\n')).toContain('networksetup -setproxybypassdomains Wi-Fi *.local 169.254/16')
    expect(machine.files[BACKUP_FILE]).toBe('')
    await ui.press({ key: 'back' })
    await ui.press({ key: 'toggle' })
    await clock.advance(200)
    await ui.unmount()
  })

  test(`${surface}: emulators are listed and started through the proxy`, SLOW, async ($, on) => {
    const clock = mock.clock(on)
    const machine = fakeMachine(on, clock)
    const ui = await $.ui.mount({ plugin: 'wirepane', surface, ...PANE })
    await ui.press({ key: 'toggle' })
    await clock.advance(250)
    await ui.press({ key: 'setup' })
    await ui.press({ key: 'tab-android' })
    expect(await ui.find({ key: 'avd-ca:Pixel_8_API_35' })).toBeDefined()
    expect(await ui.find({ text: 'emulator-5554' })).toBeDefined()
    await ui.press({ key: 'avd-start:Pixel_6' })
    const did = machine.ran.join('\n')
    expect(did).toContain("nohup 'emulator' -avd 'Pixel_6' -http-proxy http://127.0.0.1:8899")
    // once it has booted, its browser opens the CA page
    expect(did).toContain('adb -s emulator-5556 shell while [ "$(getprop sys.boot_completed)" != 1 ]; do sleep 1; done')
    expect(did).toContain('adb -s emulator-5556 shell am start -a android.intent.action.VIEW -d http://claude.proxy/')
    expect(await ui.find({ text: /Pixel_6 is up behind the proxy/ })).toBeDefined()
    await ui.press({ key: 'back' })
    await ui.press({ key: 'toggle' })
    await clock.advance(200)
    await ui.unmount()
  })
}

test('the macOS tab trusts the CA in one press', SLOW, async ($, on) => {
  const clock = mock.clock(on)
  const machine = fakeMachine(on, clock)
  const ui = await $.ui.mount({ plugin: 'wirepane', surface: 'terminal', ...PANE })
  await ui.press({ key: 'toggle' })
  await clock.advance(250)
  await ui.press({ key: 'setup' })
  await ui.press({ key: 'tab-cli' })
  expect(await ui.find({ text: 'no' })).toBeDefined()
  await ui.press({ key: 'mac-trust' })
  expect(machine.ran.join('\n')).toContain(`security add-trusted-cert -r trustRoot -k ${HOME}/Library/Keychains/login.keychain-db ${READY.ca.path}`)
  expect(await ui.find({ text: 'yes ✓' })).toBeDefined()
  expect(await ui.find({ key: 'mac-trust' })).toBeUndefined()
  await ui.press({ key: 'back' })
  await ui.press({ key: 'toggle' })
  await clock.advance(200)
  await ui.unmount()
})

test('an empty list offers the one-press ways in', SLOW, async ($, on) => {
  const clock = mock.clock(on)
  const machine = fakeMachine(on, clock, {}, true)
  const ui = await $.ui.mount({ plugin: 'wirepane', surface: 'terminal', ...PANE })
  expect(await ui.find({ key: 'qs-start' })).toBeDefined()
  await ui.press({ key: 'toggle' })
  await clock.advance(250)
  // the simulators are known once a tab has looked
  await ui.press({ key: 'setup' })
  await ui.press({ key: 'tab-ios' })
  await ui.press({ key: 'back' })
  expect(await ui.find({ text: /Waiting for requests/ })).toBeDefined()
  expect((await ui.find({ key: 'qs-browser' }))?.text).toBe('Open Google Chrome')
  expect((await ui.find({ key: 'qs-simulator' }))?.text).toBe('Use iPhone 16')
  await ui.press({ key: 'qs-browser' })
  expect(machine.ran.join('\n')).toContain('open -na /Applications/Google Chrome.app --args')
  await ui.press({ key: 'qs-phone' })
  expect((await ui.find({ key: 'sub-real' }))?.props.variant).toBe('primary')
  expect(await ui.find({ text: /Scan with the iPhone's camera/ })).toBeDefined()
  await ui.press({ key: 'back' })
  await ui.press({ key: 'toggle' })
  await clock.advance(200)
  await ui.unmount()
})

test('stopping the proxy puts the system proxy back', SLOW, async ($, on) => {
  const clock = mock.clock(on)
  const machine = fakeMachine(on, clock)
  const ui = await $.ui.mount({ plugin: 'wirepane', surface: 'terminal', ...PANE })
  await ui.press({ key: 'toggle' })
  await clock.advance(250)
  await ui.press({ key: 'setup' })
  await ui.press({ key: 'tab-cli' })
  await ui.press({ key: 'system-proxy' })
  expect(machine.files[BACKUP_FILE]).toContain('"service": "Wi-Fi"')
  await ui.press({ key: 'back' })
  await ui.press({ key: 'toggle' })
  expect(machine.ran.join('\n')).toContain('networksetup -setsecurewebproxystate Wi-Fi off')
  expect(machine.files[BACKUP_FILE]).toBe('')
  expect(machine.spawned[0]).toContain('--system-proxy-backup')
  await clock.advance(200)
  await ui.unmount()
})

test('without node on PATH, the newest Node 18 or newer is found where version managers keep it', SLOW, async ($, on) => {
  const clock = mock.clock(on)
  const nvm = `${HOME}/.nvm/versions/node`
  const machine = fakeMachine(on, clock, {}, false, {
    // Homebrew's is too old; nvm has a newer one
    versions: { '/opt/homebrew/bin/node': 'v16.20.2', [`${nvm}/v18.20.4/bin/node`]: 'v18.20.4', [`${nvm}/v22.11.0/bin/node`]: 'v22.11.0' },
    dirs: { [nvm]: ['v18.20.4', 'v9.11.2', 'v22.11.0'] },
  })
  const ui = await $.ui.mount({ plugin: 'wirepane', surface: 'terminal', ...PANE })
  await ui.press({ key: 'toggle' })
  await clock.advance(250)
  await ui.redraw()
  expect(machine.spawned).toHaveLength(1)
  expect(machine.spawned[0]![0]).toBe(`${nvm}/v22.11.0/bin/node`)
  await ui.press({ key: 'toggle' })
  await clock.advance(200)
  await ui.unmount()
})

test('with no Node at all, the pane offers to install it with Homebrew and then starts', SLOW, async ($, on) => {
  const clock = mock.clock(on)
  const machine = fakeMachine(on, clock, {}, false, { versions: {}, hasBrew: true })
  const ui = await $.ui.mount({ plugin: 'wirepane', surface: 'terminal', ...PANE })
  await ui.press({ key: 'toggle' })
  await clock.advance(250)
  await ui.redraw()
  expect(machine.spawned).toHaveLength(0)
  expect(await ui.find({ text: /Node\.js 18 or newer/ })).toBeDefined()
  expect(await ui.find({ key: 'download-node' })).toBeUndefined()

  await ui.press({ key: 'install-node' })
  await clock.advance(250)
  await ui.redraw()
  expect(machine.ran).toContain(`${BREW} install node`)
  expect(machine.spawned).toHaveLength(1)
  expect(machine.spawned[0]![0]).toBe('/opt/homebrew/bin/node')
  expect(await ui.find({ text: /127\.0\.0\.1:8899 · 3 requests/ })).toBeDefined()
  expect(await ui.find({ key: 'install-node' })).toBeUndefined()
  await ui.press({ key: 'toggle' })
  await clock.advance(200)
  await ui.unmount()
})

test('with no Node and no Homebrew, the pane opens the Node.js download', SLOW, async ($, on) => {
  const clock = mock.clock(on)
  const machine = fakeMachine(on, clock, {}, false, { versions: {} })
  const ui = await $.ui.mount({ plugin: 'wirepane', surface: 'terminal', ...PANE })
  await ui.press({ key: 'toggle' })
  await clock.advance(250)
  await ui.redraw()
  expect(machine.spawned).toHaveLength(0)
  expect(await ui.find({ key: 'install-node' })).toBeUndefined()
  await ui.press({ key: 'download-node' })
  expect(machine.ran).toContain('open https://nodejs.org/en/download')
  await ui.unmount()
})

test('the tools list and show captured requests for the model', SLOW, async ($, on) => {
  const clock = mock.clock(on)
  fakeMachine(on, clock)
  const ui = await $.ui.mount({ plugin: 'wirepane', surface: 'terminal', ...PANE })
  await ui.press({ key: 'toggle' })
  await clock.advance(250)

  const listed = await $.tool.call({ tool: 'mcp__wirepane__list_requests', filter: 'method:POST' })
  const listText = String(listed.result)
  expect(listText).toContain('Proxy is running on 127.0.0.1:8899; 3 requests captured.')
  expect(listText).toContain('1 match "method:POST"')
  expect(listText).toContain('#2  POST    401  https://api.example.com/v1/login')
  expect(listText).not.toContain('#1 ')

  const shown = await $.tool.call({ tool: 'mcp__wirepane__get_request', id: 2 })
  const showText = String(shown.result)
  expect(showText).toContain('#2 POST https://api.example.com/v1/login')
  expect(showText).toContain('status: 401 Unauthorized')
  expect(showText).toContain('--- request headers ---\nHost: api.example.com')
  expect(showText).toContain('{\n  "user": "tester"\n}')
  expect(showText).toContain('"error": "invalid_credentials"')

  const missing = await $.tool.call({ tool: 'mcp__wirepane__get_request', id: 99 })
  expect(String(missing.result)).toContain('No captured request #99')
  await ui.press({ key: 'toggle' })
  await clock.advance(200)
  await ui.unmount()
})
