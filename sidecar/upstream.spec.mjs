// node --test sidecar/upstream.spec.mjs
// An upstream proxy (an office's, a VPN's): every connection Wirepane makes to
// a server goes through it, but for the hosts it bypasses.

import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import http from 'node:http'
import http2 from 'node:http2'
import https from 'node:https'
import net from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, before, describe, test } from 'node:test'

import { createLeafFactory, ensureCA } from './certs.mjs'
import { curl, listen, startSidecar } from './spec-kit.mjs'

describe('an upstream proxy', () => {
  let dataDir
  let sidecar
  let ready
  let proxy
  let plainPort
  let securePort
  let h2Port
  const seen = []
  const servers = []

  before(async () => {
    dataDir = await mkdtemp(join(tmpdir(), 'proxy-upstream-'))
    const plain = http.createServer((req, res) => res.end(`plain ${req.url}`))
    servers.push(plain)
    plainPort = await listen(plain)
    const upstreamCA = await ensureCA(join(dataDir, 'upstream-ca'))
    const context = await createLeafFactory(upstreamCA).get('localhost')
    const secure = https.createServer({ SNICallback: (name, done) => done(null, context) }, (req, res) => res.end(`secure ${req.url}`))
    servers.push(secure)
    securePort = await listen(secure)
    const h2 = http2.createSecureServer({ SNICallback: (name, done) => done(null, context) }, (req, res) => res.end(`h2 ${req.url} ${req.httpVersion}`))
    servers.push(h2)
    h2Port = await listen(h2)

    // the office proxy: CONNECT tunnels and absolute-form requests, with Basic auth
    const office = http.createServer((req, res) => {
      seen.push({ kind: 'request', url: req.url, auth: req.headers['proxy-authorization'] ?? null })
      const url = new URL(req.url)
      const headers = { ...req.headers }
      delete headers['proxy-authorization']
      const out = http.request({ host: url.hostname.endsWith('.test') ? '127.0.0.1' : url.hostname, port: url.port, path: `${url.pathname}${url.search}`, method: req.method, headers }, answer => {
        res.writeHead(answer.statusCode, answer.headers)
        answer.pipe(res)
      })
      req.pipe(out)
    })
    office.on('connect', (req, socket, head) => {
      seen.push({ kind: 'connect', target: req.url, auth: req.headers['proxy-authorization'] ?? null })
      const [host, port] = req.url.split(':')
      const out = net.connect(Number(port), host.endsWith('.test') ? '127.0.0.1' : host, () => {
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n')
        if (head.length) out.write(head)
        out.pipe(socket)
        socket.pipe(out)
      })
      out.on('error', () => socket.destroy())
      socket.on('error', () => out.destroy())
    })
    servers.push(office)
    const officePort = await listen(office)

    sidecar = startSidecar(join(dataDir, 'proxy'), [
      '--insecure-upstream',
      '--upstream-proxy', `http://alice:s3cret@127.0.0.1:${officePort}`,
      '--upstream-bypass', 'direct.test',
    ])
    ready = await sidecar.waitFor(() => sidecar.events.find(e => e.t === 'ready'), 'ready')
    proxy = `http://127.0.0.1:${ready.port}`
  })

  after(async () => {
    sidecar?.child.kill()
    for (const server of servers) {
      server.closeAllConnections?.()
      server.close()
    }
    await rm(dataDir, { recursive: true, force: true })
  })

  const basic = `Basic ${Buffer.from('alice:s3cret').toString('base64')}`

  test('plain HTTP goes to it in absolute form, with the credentials', async () => {
    assert.equal((await curl(['-x', proxy, `http://app.test:${plainPort}/via`])).stdout, 'plain /via')
    const request = seen.find(s => s.kind === 'request' && s.url.endsWith('/via'))
    assert.equal(request.url, `http://app.test:${plainPort}/via`)
    assert.equal(request.auth, basic)
  })

  test('HTTPS goes through its CONNECT, and is still decrypted and recorded', async () => {
    const out = await curl(['-x', proxy, '--cacert', ready.ca.path, `https://secure.test:${securePort}/tls`])
    assert.equal(out.stdout, 'secure /tls', out.stderr)
    assert.ok(seen.some(s => s.kind === 'connect' && s.target === `secure.test:${securePort}` && s.auth === basic))
    const flow = await sidecar.flow(f => f.path === '/tls' && f.state === 'done', 'the recorded https flow')
    assert.equal(flow.status, 200)
  })

  test('HTTP/2 to the server goes through it too', async () => {
    const out = await curl(['--http2', '-x', proxy, '--cacert', ready.ca.path, '-w', ' %{http_version}', `https://two.test:${h2Port}/two`])
    assert.equal(out.stdout, 'h2 /two 2.0 2', out.stderr)
    assert.ok(seen.some(s => s.kind === 'connect' && s.target === `two.test:${h2Port}`))
  })

  test("this Mac's own addresses, and the hosts named, are reached directly", async () => {
    const before = seen.length
    assert.equal((await curl(['-x', proxy, `http://localhost:${plainPort}/local`])).stdout, 'plain /local')
    assert.equal((await curl(['-x', proxy, '--resolve', `direct.test:${plainPort}:127.0.0.1`, `http://direct.test:${plainPort}/named`])).code, 0)
    assert.deepEqual(seen.slice(before), [])
  })
})

describe('an upstream proxy that refuses', () => {
  test('says so in the flow', async () => {
    const dataDir = await mkdtemp(join(tmpdir(), 'proxy-upstream-407-'))
    const refusing = http.createServer((req, res) => {
      res.writeHead(407, { 'proxy-authenticate': 'Basic realm="office"' })
      res.end()
    })
    refusing.on('connect', (req, socket) => socket.end('HTTP/1.1 407 Proxy Authentication Required\r\n\r\n'))
    const port = await listen(refusing)
    const target = http.createServer((req, res) => res.end('never'))
    const targetPort = await listen(target)
    const sidecar = startSidecar(join(dataDir, 'proxy'), ['--upstream-proxy', `http://127.0.0.1:${port}`])
    try {
      const ready = await sidecar.waitFor(() => sidecar.events.find(e => e.t === 'ready'), 'ready')
      const out = await curl(['-x', `http://127.0.0.1:${ready.port}`, '-w', '%{http_code}', '-o', '/dev/null', '--cacert', ready.ca.path, `https://far.test:${targetPort}/x`])
      assert.equal(out.stdout, '502')
      const flow = await sidecar.flow(f => f.path === '/x' && f.state === 'error', 'the refused flow')
      assert.match(flow.error, /upstream proxy .*407/)
    } finally {
      sidecar.child.kill()
      refusing.close()
      target.close()
      await rm(dataDir, { recursive: true, force: true })
    }
  })
})

/** A SOCKS5 server (RFC 1928) wanting alice:s3cret (RFC 1929); *.test names go to this machine. */
function socksServer(seen) {
  return net.createServer(socket => {
    let stage = 'greeting'
    let buffer = Buffer.alloc(0)
    socket.on('error', () => {})
    socket.on('data', function onData(chunk) {
      buffer = Buffer.concat([buffer, chunk])
      if (stage === 'greeting' && buffer.length >= 2 + buffer[1]) {
        const methods = [...buffer.subarray(2, 2 + buffer[1])]
        buffer = buffer.subarray(2 + buffer[1])
        if (!methods.includes(2)) return socket.end(Buffer.from([5, 255]))
        socket.write(Buffer.from([5, 2]))
        stage = 'auth'
      }
      if (stage === 'auth' && buffer.length >= 2 && buffer.length >= 3 + buffer[1] + buffer[2 + buffer[1]]) {
        const user = buffer.subarray(2, 2 + buffer[1]).toString()
        const password = buffer.subarray(3 + buffer[1], 3 + buffer[1] + buffer[2 + buffer[1]]).toString()
        buffer = buffer.subarray(3 + buffer[1] + buffer[2 + buffer[1]])
        if (user !== 'alice' || password !== 's3cret') return socket.end(Buffer.from([1, 1]))
        socket.write(Buffer.from([1, 0]))
        stage = 'request'
      }
      if (stage === 'request' && buffer.length >= 5 && buffer[3] === 3 && buffer.length >= 7 + buffer[4]) {
        const host = buffer.subarray(5, 5 + buffer[4]).toString()
        const port = buffer.readUInt16BE(5 + buffer[4])
        seen.push(`${host}:${port}`)
        stage = 'open'
        socket.off('data', onData)
        const out = net.connect(port, host.endsWith('.test') ? '127.0.0.1' : host, () => {
          socket.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]))
          out.pipe(socket)
          socket.pipe(out)
        })
        out.on('error', () => socket.end(Buffer.from([5, 5, 0, 1, 0, 0, 0, 0, 0, 0])))
      }
    })
  })
}

describe('a SOCKS5 upstream, and a PAC file that chooses', () => {
  let dataDir
  let securePort
  let plainPort
  let socksPort
  const seen = []
  const servers = []

  before(async () => {
    dataDir = await mkdtemp(join(tmpdir(), 'proxy-socks-'))
    const upstreamCA = await ensureCA(join(dataDir, 'upstream-ca'))
    const context = await createLeafFactory(upstreamCA).get('localhost')
    const secure = https.createServer({ SNICallback: (name, done) => done(null, context) }, (req, res) => res.end(`secure ${req.url}`))
    servers.push(secure)
    securePort = await listen(secure)
    const plain = http.createServer((req, res) => res.end(`plain ${req.url}`))
    servers.push(plain)
    plainPort = await listen(plain)
    const socks = socksServer(seen)
    servers.push(socks)
    socksPort = await listen(socks)
  })

  after(async () => {
    for (const server of servers) {
      server.closeAllConnections?.()
      server.close()
    }
    await rm(dataDir, { recursive: true, force: true })
  })

  test('HTTPS and plain HTTP go through SOCKS5 with its credentials, the proxy resolving the names', async () => {
    const sidecar = startSidecar(join(dataDir, 'socks'), ['--insecure-upstream', '--upstream-proxy', `socks5://alice:s3cret@127.0.0.1:${socksPort}`])
    try {
      const ready = await sidecar.waitFor(() => sidecar.events.find(e => e.t === 'ready'), 'ready')
      const proxy = `http://127.0.0.1:${ready.port}`
      const tls = await curl(['-x', proxy, '--cacert', ready.ca.path, `https://far.test:${securePort}/socks-tls`])
      assert.equal(tls.stdout, 'secure /socks-tls', tls.stderr)
      const plain = await curl(['-x', proxy, `http://far.test:${plainPort}/socks-plain`])
      assert.equal(plain.stdout, 'plain /socks-plain', plain.stderr)
      assert.ok(seen.includes(`far.test:${securePort}`))
      assert.ok(seen.includes(`far.test:${plainPort}`))
    } finally {
      sidecar.child.kill()
    }
  })

  test('a SOCKS5 proxy that refuses the credentials says so', async () => {
    const sidecar = startSidecar(join(dataDir, 'socks-bad'), ['--upstream-proxy', `socks5://alice:wrong@127.0.0.1:${socksPort}`])
    try {
      const ready = await sidecar.waitFor(() => sidecar.events.find(e => e.t === 'ready'), 'ready')
      await curl(['-x', `http://127.0.0.1:${ready.port}`, '--cacert', ready.ca.path, `https://far.test:${securePort}/nope`])
      const flow = await sidecar.flow(f => f.path === '/nope' && f.state === 'error', 'the refused flow')
      assert.match(flow.error, /refused the credentials/)
    } finally {
      sidecar.child.kill()
    }
  })

  test('a PAC file sends *.test through SOCKS and the rest direct', async () => {
    const pacServer = http.createServer((req, res) => {
      res.writeHead(200, { 'content-type': 'application/x-ns-proxy-autoconfig' })
      res.end(`function FindProxyForURL(url, host) {
        if (shExpMatch(host, "*.test")) return "SOCKS5 alice:s3cret@127.0.0.1:${socksPort}; DIRECT";
        return "DIRECT";
      }`)
    })
    servers.push(pacServer)
    const pacPort = await listen(pacServer)
    const sidecar = startSidecar(join(dataDir, 'pac'), ['--insecure-upstream', '--upstream-proxy', `pac+http://127.0.0.1:${pacPort}/proxy.pac`])
    try {
      const ready = await sidecar.waitFor(() => sidecar.events.find(e => e.t === 'ready'), 'ready')
      const proxy = `http://127.0.0.1:${ready.port}`
      const before = seen.length
      const viaPac = await curl(['-x', proxy, '--cacert', ready.ca.path, `https://pac.test:${securePort}/via-pac`])
      assert.equal(viaPac.stdout, 'secure /via-pac', viaPac.stderr)
      assert.ok(seen.slice(before).includes(`pac.test:${securePort}`))
      // a host the file sends DIRECT never meets the SOCKS proxy
      const direct = await curl(['-x', proxy, '--cacert', ready.ca.path, '--resolve', `direct.example:${securePort}:127.0.0.1`, `https://localhost:${securePort}/direct`])
      assert.equal(direct.stdout, 'secure /direct', direct.stderr)
      assert.ok(!seen.slice(before).some(s => s.startsWith('localhost')))
    } finally {
      sidecar.child.kill()
    }
  })
})
