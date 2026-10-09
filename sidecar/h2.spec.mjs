// node --test sidecar/h2.spec.mjs
// HTTP/2 and gRPC through the sidecar: curl --http2, and a Node HTTP/2
// client through the proxy's CONNECT.

import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import http2 from 'node:http2'
import https from 'node:https'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, before, describe, test } from 'node:test'

import { createLeafFactory, ensureCA } from './certs.mjs'
import { curl, grpcCall, h2Through, listen, pbString, startSidecar } from './spec-kit.mjs'
import http from 'node:http'
import { once } from 'node:events'

describe('HTTP/2', () => {
  let dataDir
  let sidecar
  let ready
  let proxy
  let h2Port
  let h1Port
  let rulesFile
  let slowPort
  let slowClosed = null
  let pickyContext
  let cookies = null
  const servers = []
  const seen = []

  before(async () => {
    dataDir = await mkdtemp(join(tmpdir(), 'proxy-h2-'))
    const upstreamCA = await ensureCA(join(dataDir, 'upstream'))
    const context = await createLeafFactory(upstreamCA).get('localhost')
    pickyContext = context

    // an upstream that speaks HTTP/2 only, with a gRPC service
    const h2 = http2.createSecureServer({ SNICallback: (name, done) => done(null, context) })
    h2.on('stream', (stream, headers) => {
      seen.push({ path: headers[':path'], te: headers.te, host: headers[':authority'] })
      const chunks = []
      stream.on('data', chunk => chunks.push(chunk))
      stream.on('end', () => {
        const path = headers[':path']
        if (path === '/cookies') {
          stream.respond({ ':status': 200 })
          return stream.end(JSON.stringify(headers.cookie ?? null))
        }
        if (path === '/hello') {
          stream.respond({ ':status': 200, 'content-type': 'text/plain' })
          return stream.end(`h2 says hello to ${headers['user-agent']?.split('/')[0]}`)
        }
        if (path === '/pkg.Greeter/Say') {
          const body = Buffer.concat(chunks)
          const name = body.subarray(5 + 2).toString()
          stream.respond({ ':status': 200, 'content-type': 'application/grpc' }, { waitForTrailers: true })
          stream.on('wantTrailers', () => stream.sendTrailers({ 'grpc-status': '0' }))
          const reply = pbString(1, `hi ${name}`)
          const head = Buffer.alloc(5)
          head.writeUInt32BE(reply.length, 1)
          return stream.end(Buffer.concat([head, reply]))
        }
        if (path === '/pkg.Greeter/Missing') {
          // trailers-only: the status in the one header block
          return stream.respond(
            { ':status': 200, 'content-type': 'application/grpc', 'grpc-status': '5', 'grpc-message': 'no such greeter' },
            { endStream: true },
          )
        }
        stream.respond({ ':status': 404 })
        stream.end()
      })
    })
    servers.push(h2)
    h2Port = await listen(h2)

    // an upstream that speaks HTTP/1.1 only
    const h1 = https.createServer({ SNICallback: (name, done) => done(null, context) }, (req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain', connection: 'keep-alive' })
      res.end(`h1 upstream got ${req.httpVersion}`)
    })
    servers.push(h1)
    h1Port = await listen(h1)

    // an endless stream (server-sent events), and what the server saw of the cookies
    const slow = https.createServer({ SNICallback: (name, done) => done(null, context) }, (req, res) => {
      if (req.url === '/cookies') return res.end(JSON.stringify(req.headers.cookie ?? null))
      res.writeHead(200, { 'content-type': 'text/event-stream' })
      res.write('data: first\n\n')
      const timer = setInterval(() => res.write('data: more\n\n'), 50)
      res.on('close', () => {
        clearInterval(timer)
        slowClosed = Date.now()
      })
    })
    servers.push(slow)
    slowPort = await listen(slow)
    void http

    rulesFile = join(dataDir, 'rules.json')
    await writeFile(
      rulesFile,
      JSON.stringify({
        rules: [
          { id: 'mock-h2', match: { path: '/mocked' }, request: [{ type: 'respond', status: 202, json: { mocked: true } }] },
          { id: 'tag-h2', match: { path: '/hello' }, response: [{ type: 'setHeader', name: 'x-tagged', value: 'yes' }] },
        ],
      }),
    )
    sidecar = startSidecar(join(dataDir, 'proxy'), ['--insecure-upstream', '--rules', rulesFile])
    ready = await sidecar.waitFor(() => sidecar.events.find(e => e.t === 'ready'), 'ready')
    proxy = `http://127.0.0.1:${ready.port}`
  })

  after(async () => {
    sidecar?.child.kill()
    for (const server of servers) server.close()
    await rm(dataDir, { recursive: true, force: true })
  })

  test('speaks HTTP/2 to a client that offers it and to an upstream that does', async () => {
    const out = await curl(['--http2', '-x', proxy, '--cacert', ready.ca.path, '-D', '-', '-w', '\n%{http_version}', `https://localhost:${h2Port}/hello`])
    assert.match(out.stdout, /h2 says hello to curl\n2$/, out.stderr)
    // rules apply on HTTP/2 like anywhere
    assert.match(out.stdout, /x-tagged: yes/)
    const flow = await sidecar.flow(f => f.path === '/hello' && f.state === 'done', 'h2 flow')
    assert.equal(flow.httpVersion, '2')
    assert.equal(flow.status, 200)
    assert.deepEqual(flow.rules, ['tag-h2'])
    assert.equal(seen.find(s => s.path === '/hello').host, `localhost:${h2Port}`)
  })

  test('an HTTP/2 client reaches an upstream that speaks HTTP/1.1 only', async () => {
    const out = await curl(['--http2', '-x', proxy, '--cacert', ready.ca.path, '-w', '\n%{http_version}', `https://localhost:${h1Port}/old`])
    assert.equal(out.stdout, 'h1 upstream got 1.1\n2', out.stderr)
    const flow = await sidecar.flow(f => f.path === '/old' && f.state === 'done', 'h1 upstream flow')
    assert.equal(flow.httpVersion, '2')
  })

  test('a client that offers HTTP/1.1 only keeps HTTP/1.1', async () => {
    const out = await curl(['--http1.1', '-x', proxy, '--cacert', ready.ca.path, '-w', '\n%{http_version}', `https://localhost:${h1Port}/one`])
    assert.equal(out.stdout, 'h1 upstream got 1.1\n1.1', out.stderr)
    const flow = await sidecar.flow(f => f.path === '/one' && f.state === 'done', 'h1 flow')
    assert.equal(flow.httpVersion, '1.1')
  })

  test('a rule answers an HTTP/2 request itself', async () => {
    const out = await curl(['--http2', '-x', proxy, '--cacert', ready.ca.path, '-w', '\n%{http_code} %{http_version}', `https://localhost:${h2Port}/mocked`])
    assert.equal(out.stdout, '{"mocked":true}\n202 2', out.stderr)
  })

  test('a gRPC call passes with its trailers, and its record decodes the messages', async () => {
    const session = await h2Through(ready.port, 'localhost', h2Port, await readFile(ready.ca.path))
    try {
      const reply = await grpcCall(session, '/pkg.Greeter/Say', pbString(1, 'wirepane'))
      assert.equal(reply.headers[':status'], 200)
      assert.deepEqual(reply.trailers?.['grpc-status'], '0')
      assert.equal(reply.body.subarray(7).toString(), 'hi wirepane')
      assert.equal(seen.find(s => s.path === '/pkg.Greeter/Say').te, 'trailers')
    } finally {
      session.close()
    }
    const flow = await sidecar.flow(f => f.path === '/pkg.Greeter/Say' && f.state === 'done', 'grpc flow')
    assert.equal(flow.contentType, 'application/grpc')
    assert.equal(flow.grpcStatus, 0)
    const detail = JSON.parse(await readFile(join(dataDir, 'proxy', 'flows', 'spec', `${flow.id}.json`), 'utf8'))
    assert.deepEqual(detail.resTrailers, [['grpc-status', '0']])
    assert.match(await readFile(detail.res.view, 'utf8'), /1: "hi wirepane"/)
    assert.match(await readFile(detail.req.view, 'utf8'), /1: "wirepane"/)
  })

  test('a gRPC call that fails counts as failed, with its message', async () => {
    const session = await h2Through(ready.port, 'localhost', h2Port, await readFile(ready.ca.path))
    try {
      const reply = await grpcCall(session, '/pkg.Greeter/Missing', pbString(1, 'nobody'))
      assert.equal(reply.headers['grpc-status'], '5')
    } finally {
      session.close()
    }
    const flow = await sidecar.flow(f => f.path === '/pkg.Greeter/Missing' && f.state === 'done', 'failed grpc flow')
    assert.equal(flow.grpcStatus, 5)
    assert.equal(flow.grpcMessage, 'no such greeter')
  })

  test('a client that cancels a stream lets go of the server, and the record says so', async () => {
    const session = await h2Through(ready.port, 'localhost', slowPort, await readFile(ready.ca.path))
    try {
      const stream = session.request({ ':method': 'GET', ':path': '/endless' })
      await new Promise(resolve => stream.once('data', resolve))
      stream.close(http2.constants.NGHTTP2_CANCEL)
      const flow = await sidecar.flow(f => f.path === '/endless' && f.state === 'error', 'the cancelled flow')
      assert.equal(flow.errorCode, 'client-closed')
      for (let i = 0; i < 40 && slowClosed === null; i++) await new Promise(resolve => setTimeout(resolve, 50))
      assert.ok(slowClosed !== null, 'the server saw its response closed')
    } finally {
      session.close()
    }
  })

  test("an HTTP/2 client's cookie crumbs reach the server as one cookie header", async () => {
    const session = await h2Through(ready.port, 'localhost', h2Port, await readFile(ready.ca.path))
    try {
      const stream = session.request({ ':method': 'GET', ':path': '/cookies', cookie: ['a=1', 'b=2'] })
      let body = ''
      stream.on('data', chunk => (body += chunk))
      await new Promise(resolve => stream.on('end', resolve))
      assert.equal(JSON.parse(body), 'a=1; b=2')
    } finally {
      session.close()
    }
  })

  test('a stream the server refuses is sent once more, on a fresh session', async () => {
    // an upstream that refuses the second stream of every session (REFUSED_STREAM)
    const streams = new WeakMap()
    let refused = 0
    const picky = http2.createSecureServer({ SNICallback: (name, done) => done(null, pickyContext) })
    picky.on('stream', stream => {
      stream.on('error', () => {})
      const n = (streams.get(stream.session) ?? 0) + 1
      streams.set(stream.session, n)
      if (n === 2) {
        refused += 1
        return stream.close(http2.constants.NGHTTP2_REFUSED_STREAM)
      }
      stream.respond({ ':status': 200 })
      stream.end(`stream ${n}`)
    })
    const pickyPort = await listen(picky)
    try {
      const first = await curl(['--http2', '-x', proxy, '--cacert', ready.ca.path, `https://localhost:${pickyPort}/one`])
      assert.equal(first.stdout, 'stream 1', first.stderr)
      const second = await curl(['--http2', '-x', proxy, '--cacert', ready.ca.path, '-w', ' %{http_code}', `https://localhost:${pickyPort}/two`])
      assert.equal(second.stdout, 'stream 1 200', second.stderr)
      assert.equal(refused, 1)
    } finally {
      picky.close()
    }
  })

  test('plain HTTP/2 (h2c, prior knowledge) through CONNECT: gRPC to a local service, recorded', async () => {
    // a plain-text gRPC service, as local development runs one
    const plain = http2.createServer()
    plain.on('stream', (stream, headers) => {
      stream.on('error', () => {})
      const chunks = []
      stream.on('data', chunk => chunks.push(chunk))
      stream.on('end', () => {
        stream.respond({ ':status': 200, 'content-type': 'application/grpc' }, { waitForTrailers: true })
        stream.on('wantTrailers', () => stream.sendTrailers({ 'grpc-status': '0' }))
        const reply = pbString(1, `plain ${headers[':scheme']}`)
        const head = Buffer.alloc(5)
        head.writeUInt32BE(reply.length, 1)
        stream.end(Buffer.concat([head, reply]))
      })
    })
    const plainPort = await listen(plain)
    try {
      const req = http.request({ host: '127.0.0.1', port: ready.port, method: 'CONNECT', path: `localhost:${plainPort}` })
      req.end()
      const [, tunnel] = await once(req, 'connect')
      const session = http2.connect(`http://localhost:${plainPort}`, { createConnection: () => tunnel })
      session.on('error', () => {})
      try {
        const reply = await grpcCall(session, '/pkg.Local/Say', pbString(1, 'dev'))
        assert.equal(reply.trailers?.['grpc-status'], '0')
        assert.equal(reply.body.subarray(7).toString(), 'plain http')
      } finally {
        session.close()
      }
      const flow = await sidecar.flow(f => f.path === '/pkg.Local/Say' && f.state === 'done', 'the h2c flow')
      assert.equal(flow.scheme, 'http')
      assert.equal(flow.httpVersion, '2')
      assert.equal(flow.grpcStatus, 0)
    } finally {
      plain.close()
    }
  })

  test('an h2c client reaches a plain server that speaks HTTP/1.1 only', async () => {
    const old = http.createServer((req, res) => res.end(`h1 plain got ${req.httpVersion}`))
    const oldPort = await listen(old)
    try {
      const req = http.request({ host: '127.0.0.1', port: ready.port, method: 'CONNECT', path: `localhost:${oldPort}` })
      req.end()
      const [, tunnel] = await once(req, 'connect')
      const session = http2.connect(`http://localhost:${oldPort}`, { createConnection: () => tunnel })
      session.on('error', () => {})
      try {
        const stream = session.request({ ':method': 'GET', ':path': '/plain-old' })
        let body = ''
        stream.on('data', chunk => (body += chunk))
        await once(stream, 'end')
        assert.equal(body, 'h1 plain got 1.1')
      } finally {
        session.close()
      }
    } finally {
      old.close()
    }
  })
})
