// node --test sidecar/proxy.spec.mjs
// Runs the sidecar against local upstreams and drives it with curl.

import assert from 'node:assert/strict'
import { execFile, spawn } from 'node:child_process'
import { X509Certificate } from 'node:crypto'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import http from 'node:http'
import https from 'node:https'
import { networkInterfaces, tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { after, before, describe, test } from 'node:test'
import { gzipSync } from 'node:zlib'

import { caCommonName, createLeafFactory, ensureCA } from './certs.mjs'
import { rankAddresses } from './network.mjs'

const here = dirname(fileURLToPath(import.meta.url))

function curl(args) {
  return new Promise(resolve => {
    execFile('curl', ['-sS', '--noproxy', '', '--max-time', '10', ...args], (error, stdout, stderr) =>
      resolve({ code: error?.code ?? 0, stdout, stderr }),
    )
  })
}

function listen(server) {
  return new Promise(resolve => server.listen(0, () => resolve(server.address().port)))
}

function startSidecar(dataDir, extra = []) {
  const child = spawn(process.execPath, [join(here, 'proxy.mjs'), '--port', '0', '--data', dataDir, '--run', 'spec', ...extra], {
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  const flows = new Map()
  const events = []
  const waiters = []
  let buffer = ''
  child.stdout.on('data', chunk => {
    buffer += chunk
    let newline
    while ((newline = buffer.indexOf('\n')) >= 0) {
      const event = JSON.parse(buffer.slice(0, newline))
      buffer = buffer.slice(newline + 1)
      events.push(event)
      if (event.t === 'flow') flows.set(event.flow.id, event.flow)
      for (const waiter of [...waiters]) waiter()
    }
  })
  const waitFor = (predicate, label) =>
    new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`timed out waiting for ${label}`)), 8000)
      const check = () => {
        const found = predicate()
        if (found) {
          clearTimeout(timer)
          waiters.splice(waiters.indexOf(check), 1)
          resolve(found)
        }
      }
      waiters.push(check)
      check()
    })
  return { child, flows, events, waitFor }
}

describe('sidecar', () => {
  let dataDir
  let sidecar
  let ready
  let httpPort
  let httpsPort
  let proxy
  const servers = []

  before(async () => {
    dataDir = await mkdtemp(join(tmpdir(), 'proxy-spec-'))

    const plain = http.createServer((req, res) => {
      if (req.url === '/json') {
        res.writeHead(200, { 'content-type': 'application/json', 'content-encoding': 'gzip' })
        return res.end(gzipSync(JSON.stringify({ hello: 'world' })))
      }
      let body = ''
      req.on('data', c => (body += c))
      req.on('end', () => {
        res.writeHead(201, { 'content-type': 'text/plain' })
        res.end(`echo:${body}`)
      })
    })
    servers.push(plain)
    httpPort = await listen(plain)

    // The upstream's certificate comes from a CA of its own, which the
    // sidecar does not trust: hence --insecure-upstream.
    const upstreamCA = await ensureCA(join(dataDir, 'upstream'))
    const upstreamContext = await createLeafFactory(upstreamCA).get('localhost')
    const secure = https.createServer(
      { SNICallback: (name, done) => done(null, upstreamContext) },
      (req, res) => {
        res.writeHead(200, { 'content-type': 'text/html' })
        res.end('<h1>secure</h1>')
      },
    )
    servers.push(secure)
    httpsPort = await listen(secure)

    sidecar = startSidecar(join(dataDir, 'proxy'), ['--insecure-upstream', '--first-id', '7'])
    ready = await sidecar.waitFor(() => sidecar.events.find(e => e.t === 'ready'), 'ready')
    proxy = `http://127.0.0.1:${ready.port}`
  })

  after(async () => {
    sidecar?.child.kill()
    for (const server of servers) server.close()
    await rm(dataDir, { recursive: true, force: true })
  })

  test('keeps the CA name within the 64 characters X.509 allows', () => {
    const long = caCommonName('Mac-1759823044-runner-with-a-very-long-machine-name.local.example')
    assert.ok(long.length <= 64, long)
    assert.match(long, /^Wirepane CA \(Mac-1759823044-runner-with-a-ver[\w-]*\)$/)
    assert.equal(caCommonName('MacBook-Pro.local'), 'Wirepane CA (MacBook-Pro)')
    assert.equal(caCommonName(''), 'Wirepane CA (local)')
  })

  test('puts the Wi-Fi address a phone should use first, VPN and VM bridges last', () => {
    const v4 = (address, extra = {}) => ({ address, family: 'IPv4', internal: false, ...extra })
    const ranked = rankAddresses(
      {
        lo0: [v4('127.0.0.1', { internal: true })],
        utun8: [v4('10.20.133.214')],
        bridge100: [v4('192.168.139.3')],
        en0: [{ address: 'fe80::1', family: 'IPv6', internal: false }, v4('10.7.9.5')],
        en8: [v4('169.254.61.132')],
      },
      'en0',
      { en0: 'Wi-Fi', bridge0: 'Thunderbolt Bridge' },
    )
    assert.deepEqual(
      ranked.map(a => [a.address, a.kind, a.isPrimary]),
      [
        ['10.7.9.5', 'lan', true],
        ['192.168.139.3', 'virtual', false],
        ['10.20.133.214', 'vpn', false],
      ],
    )
    assert.equal(ranked[0].label, 'Wi-Fi (en0)')
    // the default route through a VPN does not make the VPN the phone's address
    assert.equal(rankAddresses({ utun3: [v4('10.8.0.2')], en0: [v4('192.168.1.20')] }, 'utun3', { en0: 'Wi-Fi' })[0].address, '192.168.1.20')
    // nothing a phone could reach: no primary
    assert.equal(rankAddresses({ utun3: [v4('10.8.0.2')] }, 'utun3').some(a => a.isPrimary), false)
  })

  test('reports where it listens and its CA', () => {
    assert.ok(Array.isArray(ready.lan))
    assert.ok(ready.lan.every(a => typeof a.address === 'string' && typeof a.label === 'string'))
    assert.equal(ready.host, '127.0.0.1')
    assert.ok(ready.port > 0)
    assert.match(ready.ca.fingerprint256, /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/)
    assert.equal(ready.ca.spki.length, 2)
  })

  test('records a plain HTTP exchange and decodes its gzip body', async () => {
    const out = await curl(['-x', proxy, `http://127.0.0.1:${httpPort}/json`, '--compressed'])
    assert.equal(out.stdout, '{"hello":"world"}')
    const flow = await sidecar.waitFor(
      () => [...sidecar.flows.values()].find(f => f.path === '/json' && f.state === 'done'),
      'json flow',
    )
    assert.ok(flow.id >= 7)
    assert.equal(flow.status, 200)
    assert.equal(flow.contentType, 'application/json')
    const detail = JSON.parse(await readFile(join(ready.runDir, `${flow.id}.json`), 'utf8'))
    assert.equal(detail.res.isDecoded, true)
    assert.equal(await readFile(detail.res.file, 'utf8'), '{"hello":"world"}')
  })

  test('records a request body', async () => {
    const out = await curl(['-x', proxy, '-d', 'ping=1', `http://127.0.0.1:${httpPort}/echo`])
    assert.equal(out.stdout, 'echo:ping=1')
    const flow = await sidecar.waitFor(
      () => [...sidecar.flows.values()].find(f => f.path === '/echo' && f.state === 'done'),
      'echo flow',
    )
    assert.equal(flow.method, 'POST')
    assert.equal(flow.status, 201)
    const detail = JSON.parse(await readFile(join(ready.runDir, `${flow.id}.json`), 'utf8'))
    assert.equal(await readFile(detail.req.file, 'utf8'), 'ping=1')
  })

  test('decrypts HTTPS for a client that trusts its CA', async () => {
    const out = await curl(['-x', proxy, '--cacert', ready.ca.path, `https://localhost:${httpsPort}/page`])
    assert.equal(out.stdout, '<h1>secure</h1>', out.stderr)
    const flow = await sidecar.waitFor(
      () => [...sidecar.flows.values()].find(f => f.path === '/page' && f.state === 'done'),
      'https flow',
    )
    assert.equal(flow.scheme, 'https')
    assert.equal(flow.host, 'localhost')
    assert.equal(flow.port, httpsPort)
  })

  test('says so when the client refuses its certificate', async () => {
    const out = await curl(['-x', proxy, `https://localhost:${httpsPort}/refused`])
    assert.notEqual(out.code, 0)
    const flow = await sidecar.waitFor(
      () => [...sidecar.flows.values()].find(f => f.errorCode === 'client-rejected-cert'),
      'rejected flow',
    )
    assert.equal(flow.kind, 'tunnel')
    assert.equal(flow.host, 'localhost')
  })

  test('answers 502 and records the error when the upstream is down', async () => {
    const closed = http.createServer()
    const port = await listen(closed)
    closed.close()
    const out = await curl(['-x', proxy, '-o', '/dev/null', '-w', '%{http_code}', `http://127.0.0.1:${port}/down`])
    assert.equal(out.stdout, '502')
    const flow = await sidecar.waitFor(
      () => [...sidecar.flows.values()].find(f => f.path === '/down' && f.state === 'error'),
      'down flow',
    )
    assert.equal(flow.errorCode, 'upstream')
    assert.match(flow.error, /ECONNREFUSED/)
  })

  test('serves its CA and setup page to direct requests', async () => {
    const der = await new Promise((resolve, reject) =>
      http.get(`${proxy}/ca.crt`, res => {
        const chunks = []
        res.on('data', c => chunks.push(c))
        res.on('end', () => resolve(Buffer.concat(chunks)))
      }).on('error', reject),
    )
    assert.equal(new X509Certificate(der).fingerprint256, ready.ca.fingerprint256)
    const page = await curl([`${proxy}/`])
    assert.match(page.stdout, /Wirepane/)
    const magic = await curl(['-x', proxy, 'http://claude.proxy/ca.mobileconfig'])
    assert.match(magic.stdout, /com\.apple\.security\.root/)
  })

  test('tunnels hosts it must not decrypt', async () => {
    const tunnelled = startSidecar(join(dataDir, 'proxy'), ['--no-decrypt', '*.localhost,localhost'])
    const tunnelReady = await tunnelled.waitFor(() => tunnelled.events.find(e => e.t === 'ready'), 'ready')
    try {
      const out = await curl(['-k', '-x', `http://127.0.0.1:${tunnelReady.port}`, `https://localhost:${httpsPort}/x`])
      assert.equal(out.stdout, '<h1>secure</h1>', out.stderr)
      const flow = await tunnelled.waitFor(
        () => [...tunnelled.flows.values()].find(f => f.kind === 'tunnel' && f.state === 'done'),
        'tunnel flow',
      )
      assert.equal(flow.note, 'no-decrypt')
      assert.ok(flow.resSize > 0)
    } finally {
      tunnelled.child.kill()
    }
  })

  test('refuses this machine\'s loopback to clients from the network', async t => {
    const lan = Object.values(networkInterfaces()).flat().find(a => a && a.family === 'IPv4' && !a.internal)?.address
    if (!lan) return t.skip('no LAN address to send from')
    const open = startSidecar(join(dataDir, 'proxy'), ['--host', '0.0.0.0'])
    const openReady = await open.waitFor(() => open.events.find(e => e.t === 'ready'), 'ready')
    try {
      const via = ['--interface', lan, '-x', `http://${lan}:${openReady.port}`]
      const refused = await curl([...via, '-o', '/dev/null', '-w', '%{http_code}', `http://127.0.0.1:${httpPort}/json`])
      assert.equal(refused.stdout, '403')
      const byName = await curl([...via, '-o', '/dev/null', '-w', '%{http_code}', `http://localhost:${httpPort}/json`])
      assert.equal(byName.stdout, '403')
      const flow = await open.waitFor(
        () => [...open.flows.values()].find(f => f.errorCode === 'forbidden' && f.state === 'error'),
        'forbidden flow',
      )
      assert.equal(flow.client, lan)
      // the same request from this machine still goes through
      const local = await curl(['-x', `http://127.0.0.1:${openReady.port}`, `http://127.0.0.1:${httpPort}/json`, '--compressed'])
      assert.equal(local.stdout, '{"hello":"world"}')
    } finally {
      open.child.kill()
    }
  })

  test('records only the tracked domains, and passes the rest through untouched', async () => {
    const trackingFile = join(dataDir, 'tracking.json')
    await writeFile(trackingFile, JSON.stringify({ enabled: true, patterns: ['localhost'] }))
    const tracked = startSidecar(join(dataDir, 'proxy'), ['--tracking', trackingFile, '--insecure-upstream'])
    const trackedReady = await tracked.waitFor(() => tracked.events.find(e => e.t === 'ready'), 'ready')
    const via = `http://127.0.0.1:${trackedReady.port}`
    const recorded = path => [...tracked.flows.values()].filter(f => f.path.startsWith(path))
    try {
      assert.deepEqual(tracked.events.find(e => e.t === 'tracking'), { t: 'tracking', enabled: true, patterns: ['localhost'] })

      // 127.0.0.1 is not on the list: answered, never recorded
      assert.equal((await curl(['-x', via, `http://127.0.0.1:${httpPort}/echo`, '-d', 'a'])).stdout, 'echo:a')
      const skipped = await tracked.waitFor(() => tracked.events.findLast(e => e.t === 'skipped' && e.hosts['127.0.0.1']), 'skipped')
      assert.equal(skipped.hosts['127.0.0.1'], 1)

      // localhost is: recorded, and HTTPS to it decrypted
      assert.equal((await curl(['-x', via, `http://localhost:${httpPort}/echo`, '-d', 'b'])).stdout, 'echo:b')
      assert.equal((await curl(['-x', via, '--cacert', trackedReady.ca.path, `https://localhost:${httpsPort}/tracked`])).stdout, '<h1>secure</h1>')
      await tracked.waitFor(() => recorded('/tracked').some(f => f.state === 'done'), 'tracked flow')
      assert.equal(recorded('/echo').length, 1)

      // the list changes while running: localhost now passes as a plain tunnel
      const loads = tracked.events.filter(e => e.t === 'tracking').length
      await writeFile(trackingFile, JSON.stringify({ enabled: true, patterns: ['*.example.com'] }))
      await tracked.waitFor(() => tracked.events.filter(e => e.t === 'tracking').length > loads, 'tracking reload')
      const before = tracked.flows.size
      // the client sees the server's own certificate, so -k: nothing was decrypted
      assert.equal((await curl(['-k', '-x', via, `https://localhost:${httpsPort}/quiet`])).stdout, '<h1>secure</h1>')
      await tracked.waitFor(() => tracked.events.findLast(e => e.t === 'skipped' && e.hosts.localhost), 'skipped localhost')
      assert.equal(tracked.flows.size, before)

      // switched off, the list tracks everything again
      await writeFile(trackingFile, JSON.stringify({ enabled: false, patterns: ['*.example.com'] }))
      await tracked.waitFor(() => tracked.events.findLast(e => e.t === 'tracking')?.enabled === false, 'tracking off')
      assert.equal((await curl(['-x', via, `http://127.0.0.1:${httpPort}/echo`, '-d', 'c'])).stdout, 'echo:c')
      await tracked.waitFor(() => recorded('/echo').length === 2, 'recorded again')
    } finally {
      tracked.child.kill()
    }
  })

  test('fails fast when the port is taken', async () => {
    const second = spawn(process.execPath, [join(here, 'proxy.mjs'), '--port', String(ready.port), '--data', join(dataDir, 'proxy')], {
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let out = ''
    second.stdout.on('data', c => (out += c))
    const code = await new Promise(resolve => second.on('close', resolve))
    assert.equal(code, 3)
    assert.equal(JSON.parse(out.trim().split('\n').at(-1)).code, 'port-busy')
  })
})
