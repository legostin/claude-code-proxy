// node --test sidecar/ws.spec.mjs
// WebSockets through the sidecar: each message recorded, rules on messages,
// a mock server, and messages sent into a live connection.

import assert from 'node:assert/strict'
import { once } from 'node:events'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import http from 'node:http'
import https from 'node:https'
import net from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, before, describe, test } from 'node:test'
import tls from 'node:tls'

import { createLeafFactory, ensureCA } from './certs.mjs'
import { curl, listen, startSidecar } from './spec-kit.mjs'
import { acceptKey, closePayload, encodeFrame, FrameReader, MessageAssembler, OP, parseClose } from './websocket.mjs'

/** A WebSocket server: echoes text, answers JSON with JSON, closes on "close-me". */
function attachEcho(server, seen) {
  server.on('upgrade', (req, socket) => {
    seen.push({ path: req.url, extensions: req.headers['sec-websocket-extensions'] ?? null, auth: req.headers.authorization ?? null })
    socket.write(
      `HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${acceptKey(req.headers['sec-websocket-key'])}\r\n\r\n`,
    )
    const send = (opcode, text) => socket.write(encodeFrame({ opcode, payload: Buffer.from(text) }))
    const assembler = new MessageAssembler(message => {
      const text = message.data.toString()
      seen.push({ got: text })
      if (message.opcode === OP.ping) return socket.write(encodeFrame({ opcode: OP.pong, payload: message.data }))
      if (message.opcode === OP.close) return socket.end(encodeFrame({ opcode: OP.close, payload: message.data }))
      if (text === 'close-me') return socket.end(encodeFrame({ opcode: OP.close, payload: closePayload(4000, 'bye') }))
      if (text.startsWith('{')) return send(OP.text, JSON.stringify({ from: 'server', echoed: JSON.parse(text) }))
      send(OP.text, `echo: ${text}`)
    })
    const reader = new FrameReader(frame => assembler.frame(frame))
    socket.on('data', chunk => reader.push(chunk))
    socket.on('error', () => {})
  })
}

/** A WebSocket client through the proxy: by CONNECT (ws:// or wss://) or by an absolute-form request. */
async function wsClient({ proxyPort, url, ca, how = 'connect', headers = {} }) {
  const target = new URL(url)
  const port = Number(target.port) || (target.protocol === 'wss:' ? 443 : 80)
  let socket
  if (how === 'absolute') {
    socket = net.connect({ host: '127.0.0.1', port: proxyPort })
    await once(socket, 'connect')
  } else {
    const req = http.request({ host: '127.0.0.1', port: proxyPort, method: 'CONNECT', path: `${target.hostname}:${port}` })
    req.end()
    ;[, socket] = await once(req, 'connect')
    if (target.protocol === 'wss:') {
      socket = tls.connect({ socket, servername: target.hostname, ca, ALPNProtocols: ['http/1.1'] })
      await once(socket, 'secureConnect')
    }
  }
  const requestTarget = how === 'absolute' ? url : `${target.pathname}${target.search}`
  const extra = Object.entries(headers).map(([k, v]) => `${k}: ${v}\r\n`).join('')
  socket.write(
    `GET ${requestTarget} HTTP/1.1\r\nHost: ${target.host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n` +
      `Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n` +
      `Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n${extra}\r\n`,
  )
  const messages = []
  const waiters = []
  let head = null
  let buffer = Buffer.alloc(0)
  const assembler = new MessageAssembler(message => {
    messages.push({ opcode: message.opcode, text: message.data.toString(), close: message.opcode === OP.close ? parseClose(message.data) : null })
    waiters.forEach(check => check())
  })
  const reader = new FrameReader(frame => assembler.frame(frame))
  socket.on('data', chunk => {
    if (head !== null) return reader.push(chunk)
    buffer = Buffer.concat([buffer, chunk])
    const end = buffer.indexOf('\r\n\r\n')
    if (end < 0) return
    head = buffer.subarray(0, end).toString()
    waiters.forEach(check => check())
    const rest = buffer.subarray(end + 4)
    if (rest.length) reader.push(rest)
  })
  socket.on('error', () => {})
  const waitFor = (predicate, label) =>
    new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`timed out waiting for ${label}; got ${JSON.stringify(messages)} head ${head}`)), 5000)
      const check = () => {
        const found = predicate()
        if (found) {
          clearTimeout(timer)
          resolve(found)
        }
      }
      waiters.push(check)
      check()
    })
  await waitFor(() => head, 'the handshake answer')
  return {
    head,
    messages,
    waitFor,
    send: text => socket.write(encodeFrame({ opcode: OP.text, payload: Buffer.from(text), isMasked: true })),
    sendRaw: bytes => socket.write(bytes),
    sendFragmented: parts =>
      parts.forEach((part, i) =>
        socket.write(encodeFrame({ opcode: i === 0 ? OP.text : OP.continuation, payload: Buffer.from(part), fin: i === parts.length - 1, isMasked: true })),
      ),
    ping: text => socket.write(encodeFrame({ opcode: OP.ping, payload: Buffer.from(text), isMasked: true })),
    close: () => socket.end(encodeFrame({ opcode: OP.close, payload: closePayload(1000, 'done'), isMasked: true })),
    destroy: () => socket.destroy(),
  }
}

describe('WebSockets', () => {
  let dataDir
  let sidecar
  let ready
  let wsPort
  let wssPort
  let rulesFile
  let runDir
  const seen = []
  const servers = []

  const records = async flow => (await readFile(join(runDir, `${flow.id}.ws.jsonl`), 'utf8')).trim().split('\n').map(line => JSON.parse(line))
  const control = (command, body) =>
    curl(['-X', 'POST', '--data-binary', JSON.stringify(body), `http://127.0.0.1:${ready.port}/__wirepane/${ready.control.token}/${command}`])

  before(async () => {
    dataDir = await mkdtemp(join(tmpdir(), 'proxy-ws-'))
    runDir = join(dataDir, 'proxy', 'flows', 'spec')
    const plain = http.createServer((req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain' })
      res.end(`plain answer to ${req.url}`)
    })
    attachEcho(plain, seen)
    servers.push(plain)
    wsPort = await listen(plain)
    const upstreamCA = await ensureCA(join(dataDir, 'upstream'))
    const context = await createLeafFactory(upstreamCA).get('localhost')
    const secure = https.createServer({ SNICallback: (name, done) => done(null, context) })
    attachEcho(secure, seen)
    servers.push(secure)
    wssPort = await listen(secure)

    rulesFile = join(dataDir, 'rules.json')
    await writeFile(
      rulesFile,
      JSON.stringify({
        rules: [
          {
            id: 'chat-rules',
            match: { path: '/ruled' },
            request: [{ type: 'setHeader', name: 'Authorization', value: 'Bearer from-rule' }],
            messages: [
              { type: 'replaceMessage', direction: 'out', pattern: 'secret', with: '[hidden]' },
              { type: 'reply', direction: 'out', when: '"type":"ping"', json: { type: 'pong' } },
              { type: 'mergeJson', direction: 'in', when: 're:^\\{', json: { patched: true } },
              { type: 'send', on: 'open', to: 'client', text: 'hello from the rule' },
            ],
          },
          {
            id: 'mock-ws',
            match: { path: '/mock' },
            request: [{ type: 'respond', status: 101 }],
            messages: [
              { type: 'send', on: 'open', to: 'client', text: 'welcome to the mock' },
              { type: 'reply', when: 'hi', text: 'hello from the mock' },
            ],
          },
          { id: 'refuse-ws', match: { path: '/refused' }, request: [{ type: 'respond', status: 403, text: 'no sockets here' }] },
        ],
      }),
    )
    sidecar = startSidecar(join(dataDir, 'proxy'), ['--insecure-upstream', '--rules', rulesFile])
    ready = await sidecar.waitFor(() => sidecar.events.find(e => e.t === 'ready'), 'ready')
  })

  after(async () => {
    sidecar?.child.kill()
    for (const server of servers) {
      server.closeAllConnections?.()
      server.close()
    }
    await rm(dataDir, { recursive: true, force: true })
  })

  test('records each message both ways for ws:// through CONNECT, and offers the server no compression', async () => {
    const ws = await wsClient({ proxyPort: ready.port, url: `ws://localhost:${wsPort}/plain?room=1` })
    assert.match(ws.head, /^HTTP\/1\.1 101/)
    ws.send('hello')
    await ws.waitFor(() => ws.messages.find(m => m.text === 'echo: hello'), 'the echo')
    ws.sendFragmented(['frag', 'ment', 'ed'])
    await ws.waitFor(() => ws.messages.find(m => m.text === 'echo: fragmented'), 'the fragmented echo')
    ws.ping('are you there')
    await ws.waitFor(() => ws.messages.find(m => m.opcode === OP.pong), 'the pong')
    ws.close()
    const flow = await sidecar.flow(f => f.path === '/plain?room=1' && f.state === 'done', 'ws flow')
    assert.equal(flow.kind, 'ws')
    assert.equal(flow.status, 101)
    assert.equal(flow.wsOut, 2)
    assert.equal(flow.wsIn, 2)
    assert.equal(seen.find(s => s.path === '/plain?room=1').extensions, null)
    const lines = await records(flow)
    assert.deepEqual(
      lines.filter(l => l.op === 'text').map(l => [l.dir, l.text]),
      [
        ['out', 'hello'],
        ['in', 'echo: hello'],
        ['out', 'fragmented'],
        ['in', 'echo: fragmented'],
      ],
    )
    assert.ok(lines.some(l => l.op === 'ping' && l.dir === 'out'))
    assert.ok(lines.some(l => l.op === 'close' && l.code === 1000))
    const detail = JSON.parse(await readFile(join(runDir, `${flow.id}.json`), 'utf8'))
    assert.equal(detail.ws.file, join(runDir, `${flow.id}.ws.jsonl`))
    assert.deepEqual(detail.ws.close, { code: 1000, reason: 'done', by: 'the client' })
  })

  test('reads wss:// the same way, and an absolute-form ws:// too', async () => {
    const secure = await wsClient({ proxyPort: ready.port, url: `wss://localhost:${wssPort}/secure`, ca: await readFile(ready.ca.path) })
    secure.send('over tls')
    await secure.waitFor(() => secure.messages.find(m => m.text === 'echo: over tls'), 'the tls echo')
    secure.send('close-me')
    await secure.waitFor(() => secure.messages.find(m => m.close?.code === 4000), 'the server closing')
    const flow = await sidecar.flow(f => f.path === '/secure' && f.state === 'done', 'wss flow')
    assert.equal(flow.scheme, 'https')
    const detail = JSON.parse(await readFile(join(runDir, `${flow.id}.json`), 'utf8'))
    assert.deepEqual(detail.ws.close, { code: 4000, reason: 'bye', by: 'the server' })

    const absolute = await wsClient({ proxyPort: ready.port, url: `ws://localhost:${wsPort}/absolute`, how: 'absolute' })
    absolute.send('direct')
    await absolute.waitFor(() => absolute.messages.find(m => m.text === 'echo: direct'), 'the absolute echo')
    absolute.close()
  })

  test('a rule changes the handshake, rewrites messages, answers some itself and greets the client', async () => {
    const ws = await wsClient({ proxyPort: ready.port, url: `ws://localhost:${wsPort}/ruled` })
    await ws.waitFor(() => ws.messages.find(m => m.text === 'hello from the rule'), 'the greeting on open')
    ws.send('my secret')
    await ws.waitFor(() => ws.messages.find(m => m.text === 'echo: my [hidden]'), 'the rewritten echo')
    ws.send('{"type":"ping"}')
    await ws.waitFor(() => ws.messages.find(m => m.text === '{"type":"pong"}'), 'the answer from the rule')
    ws.send('{"type":"data"}')
    const merged = await ws.waitFor(() => ws.messages.find(m => m.text.includes('"from":"server"')), 'the merged JSON')
    assert.deepEqual(JSON.parse(merged.text), { from: 'server', echoed: { type: 'data' }, patched: true })
    ws.close()
    assert.equal(seen.find(s => s.path === '/ruled').auth, 'Bearer from-rule')
    assert.ok(!seen.some(s => s.got === '{"type":"ping"}'), 'the server never saw the ping the rule answered')
    const flow = await sidecar.flow(f => f.path === '/ruled' && f.state === 'done', 'ruled flow')
    assert.deepEqual(flow.rules, ['chat-rules'])
    const lines = await records(flow)
    assert.ok(lines.some(l => l.dir === 'out' && l.text === 'my [hidden]' && l.note === 'changed by a rule' && l.was === 'my secret'))
    assert.ok(lines.some(l => l.dir === 'out' && l.text === '{"type":"ping"}' && l.note === 'answered by a rule'))
  })

  test('a rule plays the WebSocket server itself, and another refuses the handshake', async () => {
    const ws = await wsClient({ proxyPort: ready.port, url: 'ws://localhost:1/mock' })
    assert.match(ws.head, /^HTTP\/1\.1 101/)
    assert.match(ws.head, /Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK\+xOo=/)
    await ws.waitFor(() => ws.messages.find(m => m.text === 'welcome to the mock'), 'the mock greeting')
    ws.send('hi there')
    await ws.waitFor(() => ws.messages.find(m => m.text === 'hello from the mock'), 'the mock answer')
    ws.ping('p')
    await ws.waitFor(() => ws.messages.find(m => m.opcode === OP.pong), 'the mock pong')
    ws.close()
    const flow = await sidecar.flow(f => f.path === '/mock' && f.state === 'done', 'mock flow')
    assert.equal(flow.status, 101)
    assert.equal(flow.error, null)

    const refused = await wsClient({ proxyPort: ready.port, url: `ws://localhost:${wsPort}/refused` })
    assert.match(refused.head, /^HTTP\/1\.1 403/)
    const flow403 = await sidecar.flow(f => f.path === '/refused' && f.state === 'done', 'refused flow')
    assert.equal(flow403.status, 403)
  })

  test('Claude sends a message into a live connection, and closes it', async () => {
    const ws = await wsClient({ proxyPort: ready.port, url: `ws://localhost:${wsPort}/live` })
    ws.send('first')
    await ws.waitFor(() => ws.messages.find(m => m.text === 'echo: first'), 'the first echo')
    const flow = await sidecar.flow(f => f.path === '/live', 'live flow')
    const toClient = JSON.parse((await control('ws/send', { id: flow.id, to: 'client', text: 'from claude' })).stdout)
    assert.deepEqual(toClient, { ok: true })
    await ws.waitFor(() => ws.messages.find(m => m.text === 'from claude'), 'the injected message')
    await control('ws/send', { id: flow.id, to: 'server', json: { injected: true } })
    await ws.waitFor(() => ws.messages.find(m => m.text.includes('"injected":true')), 'the server answering the injected message')
    const wrong = await curl(['-X', 'POST', '--data-binary', '{}', `http://127.0.0.1:${ready.port}/__wirepane/wrong-token/ws/list`])
    assert.match(wrong.stdout, /forbidden/)
    await control('ws/close', { id: flow.id, code: 4001, reason: 'claude says bye' })
    await ws.waitFor(() => ws.messages.find(m => m.close?.code === 4001), 'the close from claude')
    const done = await sidecar.flow(f => f.id === flow.id && f.state === 'done', 'closed live flow')
    const lines = await records(done)
    assert.ok(lines.some(l => l.note === 'sent by Claude' && l.text === 'from claude'))
    const gone = JSON.parse((await control('ws/send', { id: flow.id, to: 'client', text: 'late' })).stdout)
    assert.match(gone.error, /is not open/)
  })

  test('plain HTTP inside a CONNECT tunnel is recorded like any request', async () => {
    const req = http.request({ host: '127.0.0.1', port: ready.port, method: 'CONNECT', path: `localhost:${wsPort}` })
    req.end()
    const [, socket] = await once(req, 'connect')
    socket.write(`GET /tunnelled HTTP/1.1\r\nHost: localhost:${wsPort}\r\nConnection: close\r\n\r\n`)
    const chunks = []
    socket.on('data', chunk => chunks.push(chunk))
    await once(socket, 'end')
    assert.match(Buffer.concat(chunks).toString(), /^HTTP\/1\.1 200[\s\S]*plain answer to \/tunnelled/)
    const flow = await sidecar.flow(f => f.path === '/tunnelled' && f.state === 'done', 'tunnelled flow')
    assert.equal(flow.kind, 'http')
    assert.equal(flow.scheme, 'http')
  })

  test('a message Claude sends while a fragmented one passes waits until it is whole', async () => {
    const ws = await wsClient({ proxyPort: ready.port, url: `ws://localhost:${wsPort}/fragments` })
    const flow = await sidecar.flow(f => f.path === '/fragments', 'the fragments flow')
    // the first piece of a message, then Claude's, then the last piece
    ws.sendRaw(encodeFrame({ opcode: OP.text, payload: Buffer.from('part-1 '), fin: false, isMasked: true }))
    await new Promise(resolve => setTimeout(resolve, 100))
    await control('ws/send', { id: flow.id, to: 'server', text: 'injected' })
    await new Promise(resolve => setTimeout(resolve, 100))
    ws.sendRaw(encodeFrame({ opcode: OP.continuation, payload: Buffer.from('part-2'), fin: true, isMasked: true }))
    await ws.waitFor(() => ws.messages.find(m => m.text === 'echo: injected'), 'the injected echo')
    const texts = ws.messages.filter(m => m.opcode === OP.text).map(m => m.text)
    assert.deepEqual(texts, ['echo: part-1 part-2', 'echo: injected'])
    ws.close()
  })
})
