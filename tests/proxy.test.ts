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
  pid: 4242,
  runDir: RUN_DIR,
  ca: {
    path: CA_PATH,
    subject: 'CN=Claude Code Proxy CA (tester), O=Claude Code Proxy',
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
function fakeMachine(on: On, clock: MockClock) {
  const spawned: (readonly string[])[] = []
  const killed: string[] = []
  let isKilled = false
  mock.env(on, { HOME })
  on('process.spawn', async function* ($, e) {
    spawned.push(e.argv)
    const text = [READY, ...FLOWS.map(f => ({ t: 'flow', flow: f }))].map(event => `${JSON.stringify(event)}\n`).join('')
    // cut mid-line, as a pipe may
    yield { stream: 'stdout' as const, text: text.slice(0, 50) }
    yield { stream: 'stdout' as const, text: text.slice(50) }
    // Asleep on the mocked clock, which an act does not wait for.
    while (!isKilled) await clock.sleep(100)
    return { value: { code: null, signal: 'SIGTERM' } }
  })
  on('process.run', async ($, e) => {
    if (e.argv[0] === 'kill') {
      killed.push(e.argv[1]!)
      isKilled = true
    }
    return { value: { exitCode: 0, stdout: '', stderr: '', isStdoutTruncated: false, isStderrTruncated: false } }
  })
  on('fs.read', async ($, e) => {
    const text = FILES[e.path]
    return text === undefined ? { deny: `ENOENT: ${e.path}` } : { value: text }
  })
  // Chrome is installed; nothing else is.
  on('fs.exists', async ($, e) => ({ value: e.path === '/Applications/Google Chrome.app' }))
  on('session.id', async () => ({ value: 'session' }))
  const statuses: (string | undefined)[] = []
  on('ui.status', async ($, e) => {
    statuses.push(e.text)
    return { value: undefined }
  })
  return { spawned, killed, statuses }
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
    const ui = await $.ui.mount({ plugin: 'proxy', surface, ...PANE })

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
    const ui = await $.ui.mount({ plugin: 'proxy', surface, ...PANE })
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
    const ui = await $.ui.mount({ plugin: 'proxy', surface, ...PANE })
    await ui.press({ key: 'toggle' })
    await clock.advance(250)
    await ui.press({ key: 'setup' })

    expect(await ui.find({ text: /SHA-256: AB:CD/ })).toBeDefined()
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

test('the tools list and show captured requests for the model', SLOW, async ($, on) => {
  const clock = mock.clock(on)
  fakeMachine(on, clock)
  const ui = await $.ui.mount({ plugin: 'proxy', surface: 'terminal', ...PANE })
  await ui.press({ key: 'toggle' })
  await clock.advance(250)

  const listed = await $.tool.call({ tool: 'mcp__proxy__list_requests', filter: 'method:POST' })
  const listText = String(listed.result)
  expect(listText).toContain('Proxy is running on 127.0.0.1:8899; 3 requests captured.')
  expect(listText).toContain('1 match "method:POST"')
  expect(listText).toContain('#2  POST    401  https://api.example.com/v1/login')
  expect(listText).not.toContain('#1 ')

  const shown = await $.tool.call({ tool: 'mcp__proxy__get_request', id: 2 })
  const showText = String(shown.result)
  expect(showText).toContain('#2 POST https://api.example.com/v1/login')
  expect(showText).toContain('status: 401 Unauthorized')
  expect(showText).toContain('--- request headers ---\nHost: api.example.com')
  expect(showText).toContain('{\n  "user": "tester"\n}')
  expect(showText).toContain('"error": "invalid_credentials"')

  const missing = await $.tool.call({ tool: 'mcp__proxy__get_request', id: 99 })
  expect(String(missing.result)).toContain('No captured request #99')
  await ui.press({ key: 'toggle' })
  await clock.advance(200)
  await ui.unmount()
})
