import { describe, expect, test } from 'claude-code/testing'

import { diagnose, type DoctorFacts, findingsText } from '../hooks/doctor'
import type { ProxyFlow } from '../types'

function flow(id: number, extra: Partial<ProxyFlow> = {}): ProxyFlow {
  return {
    id,
    ts: 0,
    kind: 'http',
    method: 'GET',
    scheme: 'https',
    host: 'api.example.com',
    port: 443,
    path: '/',
    status: 200,
    reqSize: 0,
    resSize: 0,
    durationMs: 10,
    contentType: null,
    state: 'done',
    error: null,
    errorCode: null,
    client: '127.0.0.1',
    ...extra,
  }
}

const refused = (id: number, host: string, client = '127.0.0.1') =>
  flow(id, { kind: 'tunnel', host, status: null, state: 'error', errorCode: 'client-rejected-cert', error: 'refused', client })

function facts(extra: Partial<DoctorFacts> = {}): DoctorFacts {
  return {
    status: { phase: 'running', host: '127.0.0.1', port: 8899, addresses: [], lan: [], runDir: null, pid: 1, ca: null, error: null },
    flows: [flow(1)],
    tracking: { enabled: false, patterns: [] },
    skipped: {},
    macTrust: 'trusted',
    systemProxy: { service: 'Wi-Fi', web: { enabled: true, server: '127.0.0.1', port: 8899 }, secure: { enabled: true, server: '127.0.0.1', port: 8899 } },
    hasBackup: true,
    vpn: null,
    otherProxies: [],
    portHolder: null,
    android: [],
    pinned: [],
    ...extra,
  }
}

const titles = (f: DoctorFacts) => diagnose(f).map(finding => `${finding.level}: ${finding.title}`)

describe('the doctor', () => {
  test('all well reads as checks that hold', () => {
    expect(titles(facts())).toEqual(['ok: The proxy runs on port 8899', 'ok: Mac apps and the iOS Simulator go through Wirepane (Wi-Fi)'])
  })

  test('a system proxy left pointing at a stopped proxy is the worst, with a way back', () => {
    const found = diagnose(facts({ status: { ...facts().status, phase: 'stopped' } }))
    expect(found[0]!.level).toBe('fail')
    expect(found[0]!.title).toContain('no proxy runs: Mac apps and the iOS Simulator have no internet')
    expect(found[0]!.action).toEqual({ kind: 'restore-system-proxy' })
  })

  test('another proxy holding the system proxy is named by its port', () => {
    const other = facts({ systemProxy: { service: 'Wi-Fi', web: { enabled: true, server: '127.0.0.1', port: 9090 }, secure: { enabled: false, server: '', port: 0 } } })
    expect(titles(other)).toContain("warn: Wi-Fi sends web traffic to 127.0.0.1:9090 (Proxyman's port), not to Wirepane")
  })

  test('a port taken says by whom', () => {
    const busy = facts({ status: { ...facts().status, phase: 'failed', error: 'port-busy: EADDRINUSE' }, portHolder: 'Charles (pid 812)' })
    expect(titles(busy)[0]).toBe('fail: Port 8899 is taken by Charles (pid 812)')
  })

  test('a client refusing every host lacks the CA; one host among working ones pins', () => {
    const phone = facts({ flows: [refused(1, 'a.example.com', '10.0.0.5'), refused(2, 'b.example.com', '10.0.0.5')] })
    const [first] = diagnose(phone)
    expect(first!.title).toBe('the device at 10.0.0.5 refuses the Wirepane CA for every host (a.example.com, b.example.com)')
    expect(first!.fix).toContain('Certificate Trust Settings')
    const pinning = facts({ flows: [flow(1), refused(2, 'pinned.example.com')] })
    const warning = diagnose(pinning).find(f => f.title.startsWith('pinned.example.com'))!
    expect(warning.title).toBe('pinned.example.com refuses the Wirepane CA while other hosts work: the app pins its certificate')
    expect(warning.action).toEqual({ kind: 'no-decrypt', host: 'pinned.example.com' })
  })

  test('upstream failures are told apart: names, dev certificates, closed ports', () => {
    const failing = facts({
      flows: [
        flow(1, { host: 'internal.corp', status: null, state: 'error', errorCode: 'upstream', error: 'ENOTFOUND: getaddrinfo ENOTFOUND internal.corp' }),
        flow(2, { host: 'dev.local', port: 8443, status: null, state: 'error', errorCode: 'upstream', error: 'DEPTH_ZERO_SELF_SIGNED_CERT: self-signed certificate' }),
        flow(3, { host: 'localhost', port: 3000, scheme: 'http', status: null, state: 'error', errorCode: 'upstream', error: 'ECONNREFUSED: connect ECONNREFUSED 127.0.0.1:3000' }),
      ],
    })
    const found = diagnose(failing)
    expect(found.find(f => f.title === 'internal.corp does not resolve from this Mac')).toBeDefined()
    expect(found.find(f => f.title.startsWith('dev.local:8443 shows a certificate'))!.action).toEqual({ kind: 'insecure-host', host: 'dev.local' })
    expect(found.find(f => f.title === 'Nothing answers at localhost:3000')!.detail).toContain('is the dev server running')
  })

  test("the upstream proxy's sign-in failures are told once, whatever the host", () => {
    const proxyError = (id: number, host: string, error: string) => flow(id, { host, status: null, state: 'error', errorCode: 'upstream', error })
    const found = diagnose(
      facts({
        upstreamProxy: 'http://OFFICE%5Calice:pw@proxy.corp:8080',
        flows: [
          proxyError(1, 'a.example', 'EUPSTREAMPROXY: the upstream proxy http://proxy.corp:8080 answered 407 to CONNECT a.example:443: it refused the credentials'),
          proxyError(2, 'b.example', 'EUPSTREAMPROXY: the upstream proxy http://proxy.corp:8080 answered 407 to CONNECT b.example:443: it refused the credentials'),
          proxyError(3, 'c.example', 'EUPSTREAMPROXY: the upstream proxy http://proxy.corp:8080 wants Kerberos sign-in, which Wirepane cannot do: run a helper'),
        ],
      }),
    )
    expect(found.filter(f => f.title === 'The upstream proxy refused the credentials')).toHaveLength(1)
    expect(found.find(f => f.title.startsWith('The upstream proxy takes only Kerberos'))!.fix).toContain('Px')
    expect(found.find(f => f.title.startsWith('Servers are reached through'))!.title).toBe('Servers are reached through the upstream proxy http://…@proxy.corp:8080')
  })

  test('tracked domains that match nothing say what passed instead', () => {
    const off = facts({ flows: [], tracking: { enabled: true, patterns: ['app.example.com'] }, skipped: { 'api.example.org': 12, 'gateway.icloud.com': 3 } })
    expect(findingsText(diagnose(off))).toContain('api.example.org ×12, gateway.icloud.com ×3')
  })

  test('a rootable emulator is offered the system CA; a VPN and other proxies are named', () => {
    const found = diagnose(
      facts({
        vpn: 'utun4',
        otherProxies: ['Charles'],
        android: [{ serial: 'emulator-5554', sdk: 34, proxy: '10.0.2.2:8899', isRootable: true, hasSystemCa: false }],
      }),
    )
    expect(found.find(f => f.action?.kind === 'android-system-ca')!.title).toBe('emulator-5554: apps trust user CAs only with a network_security_config')
    expect(found.find(f => f.title === "A VPN carries this Mac's traffic (utun4)")).toBeDefined()
    expect(found.find(f => f.title === 'Other proxy apps run: Charles')).toBeDefined()
  })

  test("a network's own proxy (an office's) is offered as the upstream proxy", () => {
    const office = facts({
      previousProxy: 'proxy.corp.example:8080',
      flows: [flow(1, { host: 'intranet.corp.example', status: null, state: 'error', errorCode: 'upstream', error: 'ETIMEDOUT: connect ETIMEDOUT' })],
    })
    const found = diagnose(office).find(f => f.action?.kind === 'upstream')!
    expect(found.title).toBe('This network had its own proxy (proxy.corp.example:8080), which Wirepane does not go through')
    expect(found.level).toBe('warn')
    expect(found.action).toEqual({ kind: 'upstream', proxy: 'proxy.corp.example:8080' })
    const using = diagnose(facts({ upstreamProxy: 'http://alice:pw@proxy.corp.example:8080' }))
    expect(using.find(f => f.title.startsWith('Servers are reached through the upstream proxy'))!.title).toBe('Servers are reached through the upstream proxy http://…@proxy.corp.example:8080')
    const pac = diagnose(facts({ previousProxy: 'pac+http://wpad.corp/proxy.pac', autoProxyUrl: 'http://wpad.corp/proxy.pac' }))
    expect(pac.find(f => f.action?.kind === 'upstream')!.action).toEqual({ kind: 'upstream', proxy: 'pac+http://wpad.corp/proxy.pac' })
    expect(pac.find(f => f.title.includes('automatic proxy configuration on'))!.level).toBe('warn')
  })

  test('a Wirepane proxy from before 0.8 holding the port is offered a way out', () => {
    const busy = facts({ status: { ...facts().status, phase: 'failed', error: 'port-busy: EADDRINUSE' }, portHolder: 'node (pid 61068)', oldProxyPid: 61068 })
    const [first] = diagnose(busy)
    expect(first!.title).toBe('Port 8899 is held by a Wirepane proxy from before 0.8 (pid 61068), which another session may still use')
    expect(first!.action).toEqual({ kind: 'stop-old', pid: 61068 })
  })

  test('a Google Play emulator, which refuses root, is told what works instead', () => {
    const found = diagnose(facts({ android: [{ serial: 'emulator-5554', sdk: 37, proxy: null, isRootable: false, hasSystemCa: false }] }))
    const play = found.find(f => f.title.startsWith('emulator-5554 runs a Google Play image'))!
    expect(play.fix).toContain('debug-overrides')
    expect(found.some(f => f.action?.kind === 'android-system-ca')).toBe(false)
  })
})
