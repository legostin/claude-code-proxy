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
import { execFileSync } from 'node:child_process'
import { readFileSync, watchFile, writeFileSync } from 'node:fs'
import { mkdir, readdir, rm, stat, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { parseArgs } from 'node:util'

import { createLeafFactory, ensureCA, mobileConfig } from './certs.mjs'
import {
  applyRequestRules,
  applyResponseRules,
  createRuleSet,
  decodeWhole,
  finalizeRequestRules,
  getHeader,
  rulesForRequest,
  rulesForResponse,
  setHeader,
  throttleStream,
  urlOf,
} from './engine.mjs'
import { networkAddresses } from './network.mjs'
import { CLAUDE_HOSTS, createSelfGuard } from './selfguard.mjs'
import { restoreCommands } from '../shared/systemproxy.mjs'
import { isTracked } from '../shared/rules.mjs'

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
    rules: { type: 'string' },
    trust: { type: 'string' },
    tracking: { type: 'string' },
    'system-proxy-backup': { type: 'string' },
    'assume-system-proxy': { type: 'boolean', default: false },
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

// This machine's addresses, best for a phone first (network.mjs); refreshed
// while running so a change of Wi-Fi reaches the mod as a `network` event.
let network = []

function lanAddresses() {
  if (network.length) return network.map(entry => entry.address)
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
const emitFlowRecord = emitFlow

const writeDetailRecord = (flow, detail) => writeDetail(flow, detail)

function flowBase() {
  return {
    id: 0,
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
  }
}

/** A flow record that takes no id: for exchanges nobody records. */
function newFlowShape() {
  return flowBase()
}

function newFlow(fields) {
  return { ...flowBase(), id: nextId++, ...fields }
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
let ruleSet = null

// --- tracked domains: only these are decrypted and recorded -------------------
//
// The session's list (`--tracking`, `{ enabled, patterns }`), read again as it
// changes. Traffic to any other host passes through untouched and unrecorded;
// only how often each host passed is counted, for the mod to suggest.

let tracking = null
const skipped = new Map()
let isSkippedChanged = false

function loadTracking() {
  try {
    const data = JSON.parse(readFileSync(args.tracking, 'utf8'))
    tracking = { enabled: data.enabled === true, patterns: Array.isArray(data.patterns) ? data.patterns.filter(p => typeof p === 'string') : [] }
  } catch {
    tracking = null
  }
  emit({ t: 'tracking', enabled: tracking?.enabled ?? false, patterns: tracking?.patterns ?? [] })
}

function tracks(host) {
  return isTracked(tracking, host)
}

function countSkipped(host) {
  skipped.set(host, (skipped.get(host) ?? 0) + 1)
  isSkippedChanged = true
}

// A tunnel nobody records: for hosts the session does not track.
function quietTunnel(clientSocket, host, port, isCounted = true) {
  if (isCounted) countSkipped(host)
  if (!isLocalClient(clientOf(clientSocket)) && isLoopback(host)) return clientSocket.destroy()
  const upstream = net.connect({ port, host, ...reachFor(clientOf(clientSocket)) })
  upstream.pipe(clientSocket)
  clientSocket.pipe(upstream)
  upstream.on('error', () => clientSocket.destroy())
  clientSocket.on('error', () => upstream.destroy())
  upstream.on('close', () => clientSocket.destroy())
  clientSocket.on('close', () => upstream.destroy())
}

// A plain request nobody records, and no rule touches.
function passThrough(req, res, target, isCounted = true) {
  if (isCounted) countSkipped(target.host)
  const client = clientOf(req.socket)
  const isLocal = isLocalClient(client)
  if (!isLocal && isLoopback(target.host)) {
    res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8' })
    return res.end(`Wirepane: ${loopbackRefusal(target.host)}\n`)
  }
  const isHttps = target.scheme === 'https'
  const upstream = (isHttps ? https : http).request({
    host: target.host,
    port: target.port,
    method: req.method,
    path: target.path,
    headers: forwardable(req.rawHeaders),
    agent: isHttps ? (isLocal ? httpsAgent : remoteHttpsAgent) : isLocal ? httpAgent : remoteHttpAgent,
    servername: net.isIP(target.host) ? undefined : target.host,
    ...reachFor(client),
  })
  upstream.on('response', upstreamRes => {
    res.writeHead(upstreamRes.statusCode, upstreamRes.statusMessage, forwardable(upstreamRes.rawHeaders))
    upstreamRes.pipe(res)
  })
  upstream.on('error', () => {
    if (!res.headersSent) {
      res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' })
      res.end()
    } else {
      res.destroy()
    }
  })
  res.on('close', () => {
    if (!res.writableFinished) upstream.destroy()
  })
  req.pipe(upstream)
}

function setupPage() {
  const primary = network.find(entry => entry.isPrimary)
  const links = primary
    ? `<b>${primary.address}</b> port <b>${listenPort}</b> <small>(${primary.label})</small>`
    : `<code>127.0.0.1:${listenPort}</code>`
  return `<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Wirepane</title>
<style>body{font:16px/1.5 -apple-system,system-ui,sans-serif;max-width:640px;margin:24px auto;padding:0 16px;color:#222}
a.b{display:block;margin:10px 0;padding:14px;border-radius:10px;background:#d97757;color:#fff;text-decoration:none;text-align:center;font-weight:600}
code{background:#f2f0ec;padding:1px 4px;border-radius:4px;word-break:break-all}small{color:#666}
@media (prefers-color-scheme:dark){body{background:#1f1e1d;color:#eee}code{background:#333}small{color:#aaa}}</style></head><body>
<h1>Wirepane</h1>
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
      'content-disposition': 'attachment; filename="wirepane-ca.pem"',
    })
  }
  if (route === '/ca.crt' || route === '/ca.cer' || route === '/ca.der') {
    return send(200, 'application/x-x509-ca-cert', ca.caDer, {
      'content-disposition': 'attachment; filename="wirepane-ca.crt"',
    })
  }
  if (route === '/ca.mobileconfig') {
    return send(200, 'application/x-apple-aspen-config', mobileConfig(ca), {
      'content-disposition': 'attachment; filename="wirepane.mobileconfig"',
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
  if (!tracks(target.host)) return passThrough(req, res, target)
  // Claude's own services are never recorded
  if (isClaudeHost(target.host)) return passThrough(req, res, target, false)
  exchange(req, res, target).catch(error => {
    emit({ t: 'log', level: 'error', message: `exchange: ${error.stack ?? error.message}` })
    if (!res.headersSent) {
      res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' })
      res.end(`Wirepane failed: ${error.message}\n`)
    } else {
      res.destroy()
    }
  })
}

function readWhole(stream) {
  return new Promise((resolveRead, rejectRead) => {
    const chunks = []
    stream.on('data', chunk => chunks.push(chunk))
    stream.on('end', () => resolveRead(Buffer.concat(chunks)))
    stream.on('error', rejectRead)
  })
}

// One request and its response. Without a matching rule the bodies stream
// through untouched; rules may change the request before it is sent, answer
// it themselves, fail it, and change the response before the client gets it.
async function exchange(req, res, target) {
  const flow = newFlow({
    method: req.method,
    scheme: target.scheme,
    host: target.host,
    port: target.port,
    path: target.path,
    client: clientOf(req.socket),
  })
  // the request as the server gets it: the rules work on this
  const sent = {
    method: req.method,
    target: { scheme: target.scheme, host: target.host, port: target.port, path: target.path },
    headers: pairs(req.rawHeaders),
    body: undefined,
    respond: null,
    fail: null,
    throttle: null,
  }
  const reqBody = new Capture(maxBody)
  let resBody = null
  let resHeaders = []
  let statusMessage = null
  let isFinished = false
  let upstream = null
  const ruleLog = []
  const abort = new AbortController()
  const log = (ruleId, text) => {
    ruleLog.push(`${ruleId}: ${text}`)
    flow.rules ??= []
    if (!flow.rules.includes(ruleId)) flow.rules.push(ruleId)
  }
  const detail = () => ({
    url: urlOf(sent.target),
    httpVersion: req.httpVersion,
    statusMessage,
    reqHeaders: sent.headers,
    resHeaders,
    ruleLog,
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
    const bodies = {}
    for (const [side, capture, encoding] of [
      ['req', reqBody, getHeader(sent.headers, 'content-encoding')],
      ['res', resBody, getHeader(resHeaders, 'content-encoding')],
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

  res.on('close', () => {
    if (isFinished) return
    if (!res.writableFinished) {
      abort.abort()
      flow.error ??= 'the client closed the connection before the response ended'
      flow.errorCode ??= 'client-closed'
      upstream?.destroy()
      finish()
    }
  })

  const refuse = (status, text, code) => {
    flow.error = text
    flow.errorCode = code
    res.writeHead(status, { 'content-type': 'text/plain; charset=utf-8' })
    res.end(`Wirepane: ${text}\n`)
    req.resume()
    resBody = new Capture(0)
    return finish()
  }

  const fail = kind => {
    flow.error =
      kind === 'timeout' ? 'a rule held the request unanswered' : kind === 'reset' ? 'a rule reset the connection' : 'a rule closed the connection'
    flow.errorCode = 'rule'
    upstream?.destroy()
    req.resume()
    if (kind === 'timeout') {
      // never answered: the client gives up first, or the proxy after five minutes
      setTimeout(() => res.destroy(), 300_000).unref()
      return
    }
    const socket = req.socket.rawSocket ?? req.socket
    if (kind === 'reset' && typeof socket.resetAndDestroy === 'function') socket.resetAndDestroy()
    else socket.destroy()
  }

  const isLocal = isLocalClient(flow.client)
  if (!isLocal && isLoopback(target.host)) return refuse(403, loopbackRefusal(target.host), 'forbidden')

  // --- the rules, request side
  const view = () => ({
    method: sent.method,
    url: urlOf(sent.target),
    host: sent.target.host,
    path: sent.target.path,
    headers: sent.headers,
    body: sent.body === undefined ? undefined : sent.body.toString('utf8'),
  })
  const context = { projectRoot: ruleSet?.projectRoot ?? process.cwd(), signal: abort.signal, log }
  const { candidates, needsBody } = rulesForRequest(ruleSet?.rules ?? [], view())
  if (needsBody) sent.body = await readWhole(req)
  const matched = candidates.length ? finalizeRequestRules(candidates, view()) : []
  if (matched.length) await applyRequestRules(matched, sent, context)
  if (abort.signal.aborted) return
  if (sent.fail) return fail(sent.fail)
  if (!isLocal && isLoopback(sent.target.host)) return refuse(403, loopbackRefusal(sent.target.host), 'forbidden')

  // --- the response: a rule's own, or the server's
  let response
  if (sent.respond) {
    if (sent.body === undefined) req.on('data', chunk => reqBody.push(chunk)).resume()
    else reqBody.push(sent.body)
    response = { status: sent.respond.status, statusMessage: undefined, headers: sent.respond.headers, body: sent.respond.body }
  } else {
    try {
      response = await new Promise((resolveResponse, rejectResponse) => {
        const headers = forwardable(sent.headers.flat())
        if (sent.body !== undefined) {
          const kept = []
          for (let i = 0; i + 1 < headers.length; i += 2) {
            if (!/^(content-length|transfer-encoding)$/i.test(headers[i])) kept.push(headers[i], headers[i + 1])
          }
          kept.push('content-length', String(sent.body.length))
          headers.splice(0, headers.length, ...kept)
        }
        const isHttps = sent.target.scheme === 'https'
        upstream = (isHttps ? https : http).request({
          host: sent.target.host,
          port: sent.target.port,
          method: sent.method,
          path: sent.target.path,
          headers,
          agent: isHttps ? (isLocal ? httpsAgent : remoteHttpsAgent) : isLocal ? httpAgent : remoteHttpAgent,
          servername: net.isIP(sent.target.host) ? undefined : sent.target.host,
          ...reachFor(flow.client),
        })
        upstream.on('response', upstreamRes =>
          resolveResponse({
            status: upstreamRes.statusCode,
            statusMessage: upstreamRes.statusMessage,
            headers: pairs(upstreamRes.rawHeaders),
            stream: upstreamRes,
          }),
        )
        upstream.on('error', rejectResponse)
        if (sent.body !== undefined) {
          reqBody.push(sent.body)
          upstream.end(sent.body)
        } else {
          req.on('data', chunk => reqBody.push(chunk))
          req.pipe(upstream)
        }
      })
    } catch (error) {
      if (abort.signal.aborted) return
      const isRefused = error.code === 'ELOOPBACK'
      flow.error = isRefused ? error.message : describeUpstreamError(error)
      flow.errorCode = isRefused ? 'forbidden' : 'upstream'
      if (!res.headersSent) {
        res.writeHead(isRefused ? 403 : 502, { 'content-type': 'text/plain; charset=utf-8' })
        res.end(`Wirepane could not reach ${sent.target.host}:${sent.target.port}\n${flow.error}\n`)
      } else {
        res.destroy()
      }
      return finish()
    }
  }

  // --- the rules, response side
  statusMessage = response.statusMessage ?? null
  const state = {
    status: response.status,
    statusMessage: response.statusMessage,
    headers: response.headers,
    body: undefined,
    fail: null,
    throttle: sent.throttle,
    request: {
      method: sent.method,
      url: urlOf(sent.target),
      headers: Object.fromEntries(sent.headers.map(([key, value]) => [key.toLowerCase(), value])),
    },
  }
  const chosen = rulesForResponse(matched, {
    status: response.status,
    contentType: contentTypeOf(getHeader(response.headers, 'content-type')),
  })
  let responseRules = chosen.rules
  const isWhole = chosen.needsBody || response.body !== undefined
  if (isWhole) {
    if (response.body !== undefined) {
      state.body = response.body
    } else {
      const raw = await readWhole(response.stream)
      const decoded = decodeWhole(raw, getHeader(response.headers, 'content-encoding'))
      if (decoded === null) {
        // a body we cannot read is passed on as it came, untouched
        state.body = raw
        responseRules = responseRules.map(rule => ({ ...rule, response: rule.response.filter(action => !['setBody', 'replaceBody', 'mergeJson', 'script'].includes(action.type)) }))
        log(responseRules[0]?.id ?? 'rules', `could not decode the ${getHeader(response.headers, 'content-encoding')} body: body actions skipped`)
      } else {
        state.body = decoded
        setHeader(state.headers, 'content-encoding', undefined)
      }
    }
  }
  if (responseRules.length) await applyResponseRules(responseRules, state, context)
  if (abort.signal.aborted) return response.stream?.destroy()
  if (state.fail) {
    response.stream?.destroy()
    return fail(state.fail)
  }

  flow.status = state.status
  flow.contentType = contentTypeOf(getHeader(state.headers, 'content-type'))
  flow.state = 'receiving'
  statusMessage = state.statusMessage ?? null
  resHeaders = state.headers
  resBody = new Capture(maxBody)
  emitFlow(flow)

  if (isWhole) {
    // the body is whole now, so its length is known
    setHeader(state.headers, 'transfer-encoding', undefined)
    setHeader(state.headers, 'content-length', String(state.body.length))
  }
  res.writeHead(state.status, state.statusMessage ?? undefined, forwardable(state.headers.flat()))
  res.once('finish', finish)
  const out = state.throttle ? throttleStream(state.throttle) : null
  if (out) out.pipe(res)
  const sink = out ?? res
  if (isWhole) {
    resBody.push(state.body)
    sink.end(state.body)
  } else {
    response.stream.on('data', chunk => resBody.push(chunk))
    response.stream.pipe(sink)
    response.stream.on('error', error => {
      flow.error = describeUpstreamError(error)
      flow.errorCode = 'upstream'
      res.destroy()
      finish()
    })
  }
}

// --- WebSocket and other upgrades: passed through, one row each ------------

function handleUpgrade(req, clientSocket, head, tunnelTarget) {
  const target = resolveTarget(req, tunnelTarget)
  if (!target || isSelf(target.host, target.port)) return clientSocket.destroy()
  // a host the session does not track is passed through and not recorded
  const quiet = !tracks(target.host)
  if (quiet) countSkipped(target.host)
  const emitFlow = quiet ? () => {} : record => emitFlowRecord(record)
  const writeDetail = quiet ? () => {} : (record, detail) => writeDetailRecord(record, detail)
  const fields = {
    kind: 'ws',
    method: req.method,
    scheme: target.scheme,
    host: target.host,
    port: target.port,
    path: target.path,
    client: clientOf(req.socket),
  }
  const flow = quiet ? { ...newFlowShape(), ...fields } : newFlow(fields)
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
  // a rule that resets the connection resets the TCP socket beneath the TLS one
  secure.rawSocket = rawSocket
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

function isClaudeHost(host) {
  return CLAUDE_HOSTS.some(pattern => matchesHost(host, pattern))
}

let selfGuard = null

async function handleConnect(req, clientSocket, head) {
  // held until we know what to do with it: the client's first bytes wait in the buffer
  clientSocket.pause()
  const { host, port } = parseAuthority(req.url ?? '')
  clientSocket.on('error', () => {})
  clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n')
  if (head?.length) clientSocket.unshift(head)
  if (!tracks(host)) return quietTunnel(clientSocket, host, port)
  // Claude Code trusts no CA of ours: never decrypt Claude's services, nor
  // anything Claude started while the system proxy sends it here
  if (isClaudeHost(host)) return quietTunnel(clientSocket, host, port, false)
  if (selfGuard && (await selfGuard.isFromClaude(clientSocket).catch(() => false))) {
    return quietTunnel(clientSocket, host, port, false)
  }
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
  clientSocket.resume()
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
  if (args.tracking) {
    loadTracking()
    watchFile(args.tracking, { interval: 400 }, loadTracking)
  }
  setInterval(() => {
    if (!isSkippedChanged) return
    isSkippedChanged = false
    const top = [...skipped.entries()].sort((a, b) => b[1] - a[1]).slice(0, 200)
    emit({ t: 'skipped', hosts: Object.fromEntries(top) })
  }, 2000).unref()
  if (args.rules) {
    ruleSet = createRuleSet({
      rulesFile: args.rules,
      trustFile: args.trust ?? join(args.data, 'trusted-scripts.json'),
      onLoad: loaded => emit({ t: 'rules', ...loaded }),
    })
  }
  await mkdir(runDir, { recursive: true })
  cleanOldRuns()

  const server = http.createServer()
  server.on('request', (req, res) => handleRequest(req, res, null))
  server.on('connect', (req, socket, head) =>
    handleConnect(req, socket, head).catch(error => {
      emit({ t: 'log', level: 'error', message: `connect: ${error.message}` })
      socket.destroy()
    }),
  )
  server.on('upgrade', (req, socket, head) => handleUpgrade(req, socket, head, null))
  server.on('clientError', (error, socket) => socket.destroy())
  server.on('error', error =>
    fatal(error.code === 'EADDRINUSE' ? 'port-busy' : 'listen', `${args.host}:${args.port}: ${error.message}`),
  )
  network = await networkAddresses().catch(() => [])
  setInterval(async () => {
    const now = await networkAddresses().catch(() => network)
    if (JSON.stringify(now) !== JSON.stringify(network)) {
      network = now
      emit({ t: 'network', lan: network })
    }
  }, 10_000).unref()

  server.listen(Number(args.port), args.host, () => {
    listenPort = server.address().port
    selfGuard = createSelfGuard({ port: () => listenPort, addresses: lanAddresses, emit, isAssumed: args['assume-system-proxy'] })
    // the mod writes the backup as it turns the system proxy on or off: look again at once
    if (args['system-proxy-backup']) watchFile(args['system-proxy-backup'], { interval: 300 }, () => selfGuard.recheck())
    emit({
      t: 'ready',
      host: args.host,
      port: listenPort,
      addresses: args.host === '127.0.0.1' || args.host === 'localhost' ? ['127.0.0.1'] : lanAddresses(),
      lan: network,
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
    if (process.ppid !== 1) return
    restoreSystemProxy()
    process.exit(0)
  }, 2000).unref()
}

// The mod turned the system proxy on and Claude Code is gone: put the Mac's
// network settings back, or every app would point at a proxy that is gone.
function restoreSystemProxy() {
  const file = args['system-proxy-backup']
  if (!file) return
  try {
    const text = readFileSync(file, 'utf8')
    if (!text.trim()) return
    for (const argv of restoreCommands(JSON.parse(text))) execFileSync(argv[0], argv.slice(1), { timeout: 5000, stdio: 'ignore' })
    writeFileSync(file, '')
  } catch {}
}

process.on('uncaughtException', error => {
  emit({ t: 'log', level: 'error', message: `uncaught: ${error.stack ?? error.message}` })
})

main()
