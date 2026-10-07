#!/usr/bin/env node
// The proxy the `proxy` mod runs beside a Claude Code session: an HTTP proxy
// that decrypts HTTPS with certificates of its own CA, streams every exchange
// through unchanged, records it under <data>/flows/<run>/, and reports each
// one as a JSON line on stdout for the mod to read.
//
// stdout lines: {t:"ready", ...} once listening; {t:"flow", flow} when an
// exchange starts and again as it progresses and ends (same id, latest wins);
// {t:"fatal", code, message} before exiting on a startup failure;
// {t:"log", level, message}.

import dns from 'node:dns'
import http from 'node:http'
import https from 'node:https'
import net from 'node:net'
import os from 'node:os'
import tls from 'node:tls'
import zlib from 'node:zlib'
import { mkdir, readdir, rm, stat, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { parseArgs } from 'node:util'

import { createLeafFactory, ensureCA, mobileConfig } from './certs.mjs'

const MAGIC_HOST = 'claude.proxy'
const HOP_BY_HOP = new Set([
  'connection', 'proxy-connection', 'keep-alive', 'proxy-authenticate',
  'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade',
])

const { values: args } = parseArgs({
  options: {
    port: { type: 'string', default: '8899' },
    host: { type: 'string', default: '127.0.0.1' },
    data: { type: 'string' },
    run: { type: 'string', default: 'default' },
    'first-id': { type: 'string', default: '1' },
    'no-decrypt': { type: 'string', default: '' },
    'max-body': { type: 'string', default: String(3 * 1024 * 1024) },
    'insecure-upstream': { type: 'boolean', default: false },
  },
})

if (!args.data) {
  process.stderr.write('--data <dir> is required\n')
  process.exit(2)
}

const maxBody = Number(args['max-body'])
const insecure = args['insecure-upstream']
const runDir = join(args.data, 'flows', args.run.replace(/[^\w.-]/g, '_'))
const noDecrypt = args['no-decrypt'].split(',').map(s => s.trim().toLowerCase()).filter(Boolean)
let nextId = Number(args['first-id']) || 1
let listenPort = Number(args.port)

function emit(event) {
  process.stdout.write(`${JSON.stringify(event)}\n`)
}

function fatal(code, message) {
  process.stdout.write(`${JSON.stringify({ t: 'fatal', code, message })}\n`, () => process.exit(3))
}

function lanAddresses() {
  return Object.values(os.networkInterfaces())
    .flat()
    .filter(a => a && a.family === 'IPv4' && !a.internal)
    .map(a => a.address)
}

function matchesHost(host, pattern) {
  if (pattern.startsWith('*.')) {
    const base = pattern.slice(2)
    return host === base || host.endsWith(`.${base}`)
  }
  return host === pattern
}

function pairs(raw) {
  const out = []
  for (let i = 0; i + 1 < raw.length; i += 2) out.push([raw[i], raw[i + 1]])
  return out
}

// The raw header list minus hop-by-hop headers and those `Connection` names.
function forwardable(raw, keep = new Set()) {
  const named = new Set()
  for (let i = 0; i + 1 < raw.length; i += 2) {
    if (raw[i].toLowerCase() === 'connection') {
      for (const token of raw[i + 1].split(',')) named.add(token.trim().toLowerCase())
    }
  }
  const out = []
  for (let i = 0; i + 1 < raw.length; i += 2) {
    const name = raw[i].toLowerCase()
    if (keep.has(name) || (!HOP_BY_HOP.has(name) && !named.has(name))) out.push(raw[i], raw[i + 1])
  }
  return out
}

function contentTypeOf(value) {
  return typeof value === 'string' ? value.split(';')[0].trim().toLowerCase() || null : null
}

function parseAuthority(authority) {
  const match = /^\[?([^\]]+?)\]?:(\d+)$/.exec(authority)
  if (match) return { host: match[1].toLowerCase(), port: Number(match[2]) }
  return { host: authority.toLowerCase(), port: 443 }
}

class Capture {
  constructor(cap) {
    this.cap = cap
    this.chunks = []
    this.size = 0
    this.stored = 0
  }
  push(chunk) {
    this.size += chunk.length
    if (this.stored >= this.cap) return
    const part = chunk.length > this.cap - this.stored ? chunk.subarray(0, this.cap - this.stored) : chunk
    this.chunks.push(part)
    this.stored += part.length
  }
  get isTruncated() {
    return this.size > this.stored
  }
  buffer() {
    return Buffer.concat(this.chunks)
  }
}

// Decodes a recorded body for reading, keeping what decodes when the record
// was cut; up to maxBody bytes of output.
function decodeBody(buffer, encoding) {
  const enc = String(encoding ?? '').trim().toLowerCase()
  const makers = {
    gzip: () => zlib.createGunzip({ finishFlush: zlib.constants.Z_SYNC_FLUSH }),
    'x-gzip': () => zlib.createGunzip({ finishFlush: zlib.constants.Z_SYNC_FLUSH }),
    deflate: () => zlib.createInflate({ finishFlush: zlib.constants.Z_SYNC_FLUSH }),
    br: () => zlib.createBrotliDecompress({ finishFlush: zlib.constants.BROTLI_OPERATION_FLUSH }),
    zstd: zlib.createZstdDecompress ? () => zlib.createZstdDecompress() : undefined,
  }
  const make = makers[enc]
  if (!make || buffer.length === 0) return Promise.resolve({ buffer, isDecoded: false })
  return new Promise(resolve => {
    const stream = make()
    const out = []
    let size = 0
    let isDone = false
    const done = isDecoded => {
      if (isDone) return
      isDone = true
      stream.destroy()
      resolve(isDecoded || size > 0 ? { buffer: Buffer.concat(out), isDecoded: true } : { buffer, isDecoded: false })
    }
    stream.on('data', chunk => {
      if (size >= maxBody) return done(true)
      out.push(chunk)
      size += chunk.length
    })
    stream.on('end', () => done(true))
    stream.on('error', () => done(false))
    stream.end(buffer)
  })
}

const flowWrites = new Map()

function writeDetail(flow, detail) {
  const previous = flowWrites.get(flow.id) ?? Promise.resolve()
  const next = previous
    .then(() => writeFile(join(runDir, `${flow.id}.json`), JSON.stringify({ ...flow, ...detail })))
    .catch(error => emit({ t: 'log', level: 'warn', message: `write #${flow.id}: ${error.message}` }))
  flowWrites.set(flow.id, next)
  return next
}

function emitFlow(flow) {
  emit({ t: 'flow', flow: { ...flow } })
}

function newFlow(fields) {
  return {
    id: nextId++,
    ts: Date.now(),
    kind: 'http',
    method: 'GET',
    scheme: 'http',
    host: '',
    port: 80,
    path: '/',
    status: null,
    reqSize: 0,
    resSize: 0,
    durationMs: null,
    contentType: null,
    state: 'pending',
    error: null,
    errorCode: null,
    client: null,
    ...fields,
  }
}

function clientOf(socket) {
  return socket?.remoteAddress?.replace(/^::ffff:/, '') ?? null
}

// --- the network must not reach this machine's loopback through us ----------
//
// With --host 0.0.0.0 anyone on the network can use the proxy; a target on
// 127.0.0.1 would then be a door into this Mac's own services. Clients on
// this machine keep localhost; clients from elsewhere are refused it, by name,
// by literal and by what a name resolves to.

function isLoopback(address) {
  const a = String(address).toLowerCase().replace(/^\[|\]$/g, '')
  return /^127\./.test(a) || a === '::1' || /^::ffff:127\./.test(a) || a === '0.0.0.0' || a === '::' || a === 'localhost' || a.endsWith('.localhost')
}

function isLocalClient(address) {
  return !address || isLoopback(address)
}

function loopbackRefusal(host) {
  return `refused: ${host} is this machine's loopback, which clients from the network may not reach`
}

function guardedLookup(hostname, options, callback) {
  dns.lookup(hostname, options, (error, address, family) => {
    if (error) return callback(error, address, family)
    const all = Array.isArray(address) ? address : [{ address }]
    if (all.some(entry => isLoopback(entry.address))) {
      const refused = new Error(loopbackRefusal(hostname))
      refused.code = 'ELOOPBACK'
      return callback(refused)
    }
    callback(null, address, family)
  })
}

/** Connection options for a client: the guard and its own pool when remote. */
function reachFor(client) {
  return isLocalClient(client) ? {} : { lookup: guardedLookup }
}

function describeUpstreamError(error) {
  const code = error.code ? `${error.code}: ` : ''
  return `${code}${error.message}`.slice(0, 500)
}

// --- the proxy's own pages: setup and the CA in three forms ---------------

let ca
let leafs

function setupPage() {
  const addresses = [...lanAddresses(), '127.0.0.1']
  const links = addresses.map(a => `<code>http://${a}:${listenPort}/</code>`).join(' · ')
  return `<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Claude Code Proxy</title>
<style>body{font:16px/1.5 -apple-system,system-ui,sans-serif;max-width:640px;margin:24px auto;padding:0 16px;color:#222}
a.b{display:block;margin:10px 0;padding:14px;border-radius:10px;background:#d97757;color:#fff;text-decoration:none;text-align:center;font-weight:600}
code{background:#f2f0ec;padding:1px 4px;border-radius:4px;word-break:break-all}small{color:#666}
@media (prefers-color-scheme:dark){body{background:#1f1e1d;color:#eee}code{background:#333}small{color:#aaa}}</style></head><body>
<h1>Claude Code Proxy</h1>
<p>Proxy: ${links}</p>
<a class="b" href="/ca.mobileconfig">iOS: download profile</a>
<a class="b" href="/ca.crt">Android: download certificate (.crt)</a>
<a class="b" href="/ca.pem">PEM (desktop, Firefox, curl)</a>
<h3>iOS</h3><ol><li>Settings → Profile Downloaded → Install.</li>
<li>Settings → General → About → Certificate Trust Settings → turn on <b>${ca.subject.match(/CN=([^,]+)/)?.[1] ?? 'the CA'}</b>.</li></ol>
<h3>Android</h3><ol><li>Settings → Security → Encryption &amp; credentials → Install a certificate → CA certificate → pick the downloaded file.</li>
<li>Apps trust user CAs only with <code>network_security_config</code>; Chrome trusts them.</li></ol>
<p><small>SHA-256: ${ca.fingerprint256}</small></p>
</body></html>`
}

function serveSelf(res, path) {
  const route = path.split('?')[0]
  const send = (status, type, body, extra = {}) => {
    res.writeHead(status, { 'content-type': type, 'cache-control': 'no-store', ...extra })
    res.end(body)
  }
  if (route === '/ca.pem') {
    return send(200, 'application/x-pem-file', ca.caPem, {
      'content-disposition': 'attachment; filename="claude-code-proxy-ca.pem"',
    })
  }
  if (route === '/ca.crt' || route === '/ca.cer' || route === '/ca.der') {
    return send(200, 'application/x-x509-ca-cert', ca.caDer, {
      'content-disposition': 'attachment; filename="claude-code-proxy-ca.crt"',
    })
  }
  if (route === '/ca.mobileconfig') {
    return send(200, 'application/x-apple-aspen-config', mobileConfig(ca), {
      'content-disposition': 'attachment; filename="claude-code-proxy.mobileconfig"',
    })
  }
  if (route === '/' || route === '/index.html') return send(200, 'text/html; charset=utf-8', setupPage())
  return send(404, 'text/plain', 'Not found. Try / for the setup page.\n')
}

function isSelf(host, port) {
  if (host === MAGIC_HOST) return true
  if (port !== listenPort) return false
  return host === 'localhost' || host === '127.0.0.1' || host === '::1' || lanAddresses().includes(host)
}

// --- HTTP exchanges --------------------------------------------------------

const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 64 })
const httpsAgent = new https.Agent({
  keepAlive: true,
  maxSockets: 64,
  rejectUnauthorized: !insecure,
  ALPNProtocols: ['http/1.1'],
})
// Pools of their own, so a socket a local client opened to localhost is
// never handed to a client from the network.
const remoteHttpAgent = new http.Agent({ keepAlive: true, maxSockets: 64 })
const remoteHttpsAgent = new https.Agent({
  keepAlive: true,
  maxSockets: 64,
  rejectUnauthorized: !insecure,
  ALPNProtocols: ['http/1.1'],
})

// `target` is set for requests that arrived inside a CONNECT tunnel; plain
// proxy requests carry their target in the absolute-form URL.
function resolveTarget(req, target) {
  if (target) return { ...target, path: req.url || '/' }
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(req.url ?? '')) return null
  const url = new URL(req.url)
  const scheme = url.protocol === 'https:' || url.protocol === 'wss:' ? 'https' : 'http'
  return {
    scheme,
    host: url.hostname.replace(/^\[|\]$/g, '').toLowerCase(),
    port: Number(url.port) || (scheme === 'https' ? 443 : 80),
    path: `${url.pathname}${url.search}`,
  }
}

function handleRequest(req, res, tunnelTarget) {
  const target = resolveTarget(req, tunnelTarget)
  if (!target) return serveSelf(res, req.url ?? '/')
  if (isSelf(target.host, target.port)) return serveSelf(res, target.path)

  const flow = newFlow({
    method: req.method,
    scheme: target.scheme,
    host: target.host,
    port: target.port,
    path: target.path,
    client: clientOf(req.socket),
  })
  const reqHeaders = pairs(req.rawHeaders)
  const reqBody = new Capture(maxBody)
  let resBody = null
  let resHeaders = []
  let statusMessage = null
  let isFinished = false

  const detail = () => ({
    url: `${flow.scheme}://${flow.host}${(flow.scheme === 'https' && flow.port === 443) || (flow.scheme === 'http' && flow.port === 80) ? '' : `:${flow.port}`}${flow.path}`,
    httpVersion: req.httpVersion,
    statusMessage,
    reqHeaders,
    resHeaders,
  })

  emitFlow(flow)
  writeDetail(flow, { ...detail(), req: null, res: null })


  const finish = async () => {
    if (isFinished) return
    isFinished = true
    flow.durationMs = Date.now() - flow.ts
    flow.reqSize = reqBody.size
    flow.resSize = resBody?.size ?? 0
    flow.state = flow.error ? 'error' : 'done'
    const header = name => resHeaders.find(([k]) => k.toLowerCase() === name)?.[1]
    const reqHeader = name => reqHeaders.find(([k]) => k.toLowerCase() === name)?.[1]
    const bodies = {}
    for (const [side, capture, encoding] of [
      ['req', reqBody, reqHeader('content-encoding')],
      ['res', resBody, header('content-encoding')],
    ]) {
      if (!capture || capture.size === 0) {
        bodies[side] = null
        continue
      }
      const { buffer, isDecoded } = await decodeBody(capture.buffer(), encoding)
      const file = join(runDir, `${flow.id}.${side}`)
      await writeFile(file, buffer).catch(() => {})
      bodies[side] = {
        file,
        size: capture.size,
        stored: buffer.length,
        isTruncated: capture.isTruncated,
        encoding: encoding ?? null,
        isDecoded,
      }
    }
    await writeDetail(flow, { ...detail(), ...bodies })
    emitFlow(flow)
  }

  const isLocal = isLocalClient(flow.client)
  if (!isLocal && isLoopback(target.host)) {
    flow.error = loopbackRefusal(target.host)
    flow.errorCode = 'forbidden'
    res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8' })
    res.end(`Claude Code proxy: ${flow.error}\n`)
    req.resume()
    resBody = new Capture(0)
    return void finish()
  }

  const upstream = (target.scheme === 'https' ? https : http).request({
    host: target.host,
    port: target.port,
    method: req.method,
    path: target.path,
    headers: forwardable(req.rawHeaders),
    agent: target.scheme === 'https' ? (isLocal ? httpsAgent : remoteHttpsAgent) : isLocal ? httpAgent : remoteHttpAgent,
    servername: net.isIP(target.host) ? undefined : target.host,
    ...reachFor(flow.client),
  })

  req.on('data', chunk => reqBody.push(chunk))
  req.pipe(upstream)

  upstream.on('response', upstreamRes => {
    flow.status = upstreamRes.statusCode
    flow.contentType = contentTypeOf(upstreamRes.headers['content-type'])
    flow.state = 'receiving'
    statusMessage = upstreamRes.statusMessage
    resHeaders = pairs(upstreamRes.rawHeaders)
    resBody = new Capture(maxBody)
    emitFlow(flow)
    res.writeHead(upstreamRes.statusCode, upstreamRes.statusMessage, forwardable(upstreamRes.rawHeaders))
    upstreamRes.on('data', chunk => resBody.push(chunk))
    upstreamRes.pipe(res)
    upstreamRes.on('end', finish)
    upstreamRes.on('error', error => {
      flow.error = describeUpstreamError(error)
      flow.errorCode = 'upstream'
      finish()
    })
  })

  upstream.on('error', error => {
    const isRefused = error.code === 'ELOOPBACK'
    flow.error = isRefused ? error.message : describeUpstreamError(error)
    flow.errorCode = isRefused ? 'forbidden' : 'upstream'
    if (!res.headersSent) {
      res.writeHead(isRefused ? 403 : 502, { 'content-type': 'text/plain; charset=utf-8' })
      res.end(`Claude Code proxy could not reach ${target.host}:${target.port}\n${flow.error}\n`)
    } else {
      res.destroy()
    }
    finish()
  })

  res.on('close', () => {
    if (isFinished) return
    if (!res.writableFinished) {
      flow.error ??= 'the client closed the connection before the response ended'
      flow.errorCode ??= 'client-closed'
      upstream.destroy()
      finish()
    }
  })
}

// --- WebSocket and other upgrades: passed through, one row each ------------

function handleUpgrade(req, clientSocket, head, tunnelTarget) {
  const target = resolveTarget(req, tunnelTarget)
  if (!target || isSelf(target.host, target.port)) return clientSocket.destroy()
  const flow = newFlow({
    kind: 'ws',
    method: req.method,
    scheme: target.scheme,
    host: target.host,
    port: target.port,
    path: target.path,
    client: clientOf(req.socket),
  })
  emitFlow(flow)
  const reqHeaders = pairs(req.rawHeaders)
  writeDetail(flow, { url: `${target.scheme === 'https' ? 'wss' : 'ws'}://${target.host}:${target.port}${target.path}`, reqHeaders, resHeaders: [], req: null, res: null })

  let isFinished = false
  const finish = () => {
    if (isFinished) return
    isFinished = true
    flow.durationMs = Date.now() - flow.ts
    flow.state = flow.error ? 'error' : 'done'
    emitFlow(flow)
    writeDetail(flow, { url: `${target.scheme === 'https' ? 'wss' : 'ws'}://${target.host}:${target.port}${target.path}`, reqHeaders, resHeaders: [], req: null, res: null })
  }

  if (!isLocalClient(flow.client) && isLoopback(target.host)) {
    flow.error = loopbackRefusal(target.host)
    flow.errorCode = 'forbidden'
    clientSocket.end('HTTP/1.1 403 Forbidden\r\nconnection: close\r\n\r\n')
    return finish()
  }
  const upstream =
    target.scheme === 'https'
      ? tls.connect({
          host: target.host,
          port: target.port,
          servername: net.isIP(target.host) ? undefined : target.host,
          rejectUnauthorized: !insecure,
          ALPNProtocols: ['http/1.1'],
          ...reachFor(flow.client),
        })
      : net.connect({ port: target.port, host: target.host, ...reachFor(flow.client) })

  // Written and piped at once: the socket holds what is written until it
  // connects, and a listener added before the pipe would drop the client's
  // first bytes.
  const lines = [`${req.method} ${target.path} HTTP/1.1`]
  const headers = forwardable(req.rawHeaders, new Set(['connection', 'upgrade']))
  for (let i = 0; i + 1 < headers.length; i += 2) lines.push(`${headers[i]}: ${headers[i + 1]}`)
  upstream.write(`${lines.join('\r\n')}\r\n\r\n`)
  if (head?.length) upstream.write(head)
  upstream.pipe(clientSocket)
  clientSocket.pipe(upstream)
  let isFirst = true
  upstream.on('data', chunk => {
    flow.resSize += chunk.length
    if (isFirst) {
      isFirst = false
      const status = /^HTTP\/1\.[01] (\d{3})/.exec(chunk.subarray(0, 32).toString('latin1'))
      flow.status = status ? Number(status[1]) : null
      flow.state = 'receiving'
      emitFlow(flow)
    }
  })
  clientSocket.on('data', chunk => {
    flow.reqSize += chunk.length
  })
  upstream.on('error', error => {
    flow.error = error.code === 'ELOOPBACK' ? error.message : describeUpstreamError(error)
    flow.errorCode = error.code === 'ELOOPBACK' ? 'forbidden' : 'upstream'
    clientSocket.destroy()
    finish()
  })
  clientSocket.on('error', () => upstream.destroy())
  upstream.on('close', () => {
    clientSocket.destroy()
    finish()
  })
  clientSocket.on('close', () => {
    upstream.destroy()
    finish()
  })
}

// --- CONNECT: decrypt, or tunnel untouched --------------------------------

const inner = http.createServer()
inner.on('request', (req, res) => handleRequest(req, res, req.socket.proxyTarget))
inner.on('upgrade', (req, socket, head) => handleUpgrade(req, socket, head, socket.proxyTarget))
inner.on('clientError', (error, socket) => socket.destroy())

function tunnel(clientSocket, host, port, reason) {
  const flow = newFlow({
    kind: 'tunnel',
    method: 'CONNECT',
    scheme: 'https',
    host,
    port,
    path: '',
    client: clientOf(clientSocket),
    note: reason,
  })
  emitFlow(flow)
  let isFinished = false
  const finish = () => {
    if (isFinished) return
    isFinished = true
    flow.durationMs = Date.now() - flow.ts
    flow.state = flow.error ? 'error' : 'done'
    emitFlow(flow)
    writeDetail(flow, { url: `${host}:${port}`, reqHeaders: [], resHeaders: [], req: null, res: null })
  }
  if (!isLocalClient(flow.client) && isLoopback(host)) {
    flow.error = loopbackRefusal(host)
    flow.errorCode = 'forbidden'
    clientSocket.destroy()
    return finish()
  }
  const upstream = net.connect({ port, host, ...reachFor(flow.client) }, () => {
    flow.status = 200
    flow.state = 'receiving'
    emitFlow(flow)
  })
  upstream.pipe(clientSocket)
  clientSocket.pipe(upstream)
  upstream.on('data', chunk => (flow.resSize += chunk.length))
  clientSocket.on('data', chunk => (flow.reqSize += chunk.length))
  upstream.on('error', error => {
    flow.error = error.code === 'ELOOPBACK' ? error.message : describeUpstreamError(error)
    flow.errorCode = error.code === 'ELOOPBACK' ? 'forbidden' : 'upstream'
    clientSocket.destroy()
    finish()
  })
  clientSocket.on('error', () => upstream.destroy())
  upstream.on('close', () => {
    clientSocket.destroy()
    finish()
  })
  clientSocket.on('close', () => {
    upstream.destroy()
    finish()
  })
}

function handshakeFailed(host, port, socket, error) {
  const message = error?.message ?? 'closed during the handshake'
  const isAlert = /alert|unknown ca|bad certificate|certificate unknown/i.test(message)
  const flow = newFlow({
    kind: 'tunnel',
    method: 'CONNECT',
    scheme: 'https',
    host,
    port,
    path: '',
    client: clientOf(socket),
    state: 'error',
    durationMs: 0,
    errorCode: isAlert || !error ? 'client-rejected-cert' : 'tls-handshake',
    error: isAlert || !error
      ? `the client refused the proxy's certificate for ${host} (CA not trusted, or the app pins certificates): ${message}`
      : `TLS handshake with the client failed: ${message}`,
  })
  emitFlow(flow)
  writeDetail(flow, { url: `${host}:${port}`, reqHeaders: [], resHeaders: [], req: null, res: null })
}

async function decrypt(rawSocket, host, port) {
  let context
  try {
    context = await leafs.get(host)
  } catch (error) {
    emit({ t: 'log', level: 'warn', message: `certificate for ${host}: ${error.message}` })
    return tunnel(rawSocket, host, port, 'no-certificate')
  }
  const secure = new tls.TLSSocket(rawSocket, {
    isServer: true,
    secureContext: context,
    ALPNProtocols: ['http/1.1'],
    SNICallback: (servername, done) =>
      leafs.get(servername).then(
        sniContext => done(null, sniContext),
        () => done(null, context),
      ),
  })
  secure.proxyTarget = { scheme: 'https', host, port }
  let isSecure = false
  let isReported = false
  secure.once('secure', () => {
    isSecure = true
    inner.emit('connection', secure)
  })
  secure.on('error', error => {
    if (isSecure || isReported) return
    isReported = true
    handshakeFailed(host, port, rawSocket, error)
  })
  secure.on('close', () => {
    if (isSecure || isReported) return
    isReported = true
    handshakeFailed(host, port, rawSocket, null)
  })
}

function handleConnect(req, clientSocket, head) {
  const { host, port } = parseAuthority(req.url ?? '')
  clientSocket.on('error', () => {})
  clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n')
  if (head?.length) clientSocket.unshift(head)
  if (noDecrypt.some(pattern => matchesHost(host, pattern))) {
    return tunnel(clientSocket, host, port, 'no-decrypt')
  }
  clientSocket.once('data', first => {
    clientSocket.pause()
    clientSocket.unshift(first)
    // 0x16: a TLS handshake record. Anything else is passed through as is.
    if (first[0] === 0x16) decrypt(clientSocket, host, port)
    else tunnel(clientSocket, host, port, 'not-tls')
  })
}

// --- start ----------------------------------------------------------------

async function cleanOldRuns() {
  const root = join(args.data, 'flows')
  const entries = await readdir(root).catch(() => [])
  const cutoff = Date.now() - 2 * 24 * 3600 * 1000
  for (const name of entries) {
    const path = join(root, name)
    if (path === runDir) continue
    const info = await stat(path).catch(() => null)
    if (info && info.mtimeMs < cutoff) await rm(path, { recursive: true, force: true }).catch(() => {})
  }
}

async function main() {
  try {
    ca = await ensureCA(args.data)
  } catch (error) {
    return fatal('ca', error.message)
  }
  leafs = createLeafFactory(ca)
  await mkdir(runDir, { recursive: true })
  cleanOldRuns()

  const server = http.createServer()
  server.on('request', (req, res) => handleRequest(req, res, null))
  server.on('connect', handleConnect)
  server.on('upgrade', (req, socket, head) => handleUpgrade(req, socket, head, null))
  server.on('clientError', (error, socket) => socket.destroy())
  server.on('error', error =>
    fatal(error.code === 'EADDRINUSE' ? 'port-busy' : 'listen', `${args.host}:${args.port}: ${error.message}`),
  )
  server.listen(Number(args.port), args.host, () => {
    listenPort = server.address().port
    emit({
      t: 'ready',
      host: args.host,
      port: listenPort,
      addresses: args.host === '127.0.0.1' || args.host === 'localhost' ? ['127.0.0.1'] : lanAddresses(),
      pid: process.pid,
      runDir,
      ca: {
        path: ca.caCertPath,
        subject: ca.subject,
        fingerprint256: ca.fingerprint256,
        validTo: ca.validTo,
        spki: ca.spki,
      },
    })
  })

  const stop = () => process.exit(0)
  process.on('SIGTERM', stop)
  process.on('SIGINT', stop)
  // Claude Code gone without a word: the parent is now launchd.
  setInterval(() => {
    if (process.ppid === 1) process.exit(0)
  }, 2000).unref()
}

process.on('uncaughtException', error => {
  emit({ t: 'log', level: 'error', message: `uncaught: ${error.stack ?? error.message}` })
})

main()
