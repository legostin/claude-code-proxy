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
import http2 from 'node:http2'
import https from 'node:https'
import net from 'node:net'
import os from 'node:os'
import tls from 'node:tls'
import zlib from 'node:zlib'
import { execFileSync, spawn } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { createWriteStream, readFileSync, unlinkSync, watchFile, writeFileSync } from 'node:fs'
import { mkdir, readdir, rm, stat, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseArgs } from 'node:util'

import { createLeafFactory, ensureCA, mobileConfig } from './certs.mjs'
import { peekServerName } from './clienthello.mjs'
import {
  applyMessageRules,
  applyOpenRules,
  applyRequestRules,
  applyResponseRules,
  createRuleSet,
  decodeWhole,
  finalizeRequestRules,
  getHeader,
  holdsMessages,
  rulesForRequest,
  rulesForResponse,
  setHeader,
  throttleStream,
  urlOf,
} from './engine.mjs'
import { networkAddresses } from './network.mjs'
import { grpcWebTrailers, renderGrpc, renderProtobuf, viewKindOf } from './protobuf.mjs'
import { EventStreamReader } from './sse.mjs'
import { createUpstream } from './upstream.mjs'
import { acceptKey, closePayload, encodeFrame, FrameReader, MessageAssembler, OP, opName, parseClose, withoutDeflate } from './websocket.mjs'
import { CLAUDE_HOSTS, createSelfGuard } from './selfguard.mjs'
import { restoreCommands } from '../shared/systemproxy.mjs'
import { actsOnHttp, isTracked } from '../shared/rules.mjs'

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
    'insecure-hosts': { type: 'string', default: '' },
    'no-auto-passthrough': { type: 'boolean', default: false },
    // an office's or a VPN's proxy that every connection to a server goes through
    'upstream-proxy': { type: 'string', default: '' },
    'upstream-bypass': { type: 'string', default: '' },
    // run detached for every session (attach.mjs starts it so), and go once none is left
    daemon: { type: 'boolean', default: false },
    'linger-ms': { type: 'string', default: '90000' },
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
// upstreams whose certificate is not checked: dev servers with self-signed ones
const insecureHosts = args['insecure-hosts'].split(',').map(s => s.trim().toLowerCase()).filter(Boolean)
const here = dirname(fileURLToPath(import.meta.url))
const upstreamProxy = createUpstream(args['upstream-proxy'], args['upstream-bypass'])
const runDir = join(args.data, 'flows', args.run.replace(/[^\w.-]/g, '_'))
const noDecrypt = args['no-decrypt'].split(',').map(s => s.trim().toLowerCase()).filter(Boolean)
let nextId = Number(args['first-id']) || 1
let listenPort = Number(args.port)

const isDaemon = args.daemon
const startedAt = Date.now()
const VERSION = (() => {
  try {
    return JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', '.claude-plugin', 'plugin.json'), 'utf8')).version ?? ''
  } catch {
    return ''
  }
})()

// --- events: to stdout, and to every session attached ---------------------
//
// A session attached (GET /__wirepane/<token>/events) first gets what is
// already known (the recent flows, the rules, the tracked domains, the hosts
// passed through), then each event as it comes. A daemon writes only its logs
// to stdout, which is its log file.

const eventClients = new Set()
const recentFlows = new Map()
const MAX_RECENT = 2000
const known = { rules: new Map(), tracking: null, skipped: null, network: null, systemProxy: null }

function remember(event) {
  switch (event.t) {
    case 'flow':
      recentFlows.delete(event.flow.id)
      recentFlows.set(event.flow.id, event.flow)
      if (recentFlows.size > MAX_RECENT) {
        const oldest = recentFlows.keys().next().value
        recentFlows.delete(oldest)
        pruneFlowFiles(oldest)
      }
      break
    case 'rules':
      known.rules.set(event.file, event)
      break
    case 'tracking':
      known.tracking = event
      break
    case 'skipped':
      known.skipped = event
      break
    case 'network':
      known.network = event
      break
    case 'system-proxy':
      known.systemProxy = event
      break
    case 'cleared':
      recentFlows.clear()
      break
  }
}

// what a proxy that runs for days keeps on disk: the files of the flows it still lists
function pruneFlowFiles(id) {
  for (const suffix of ['json', 'req', 'res', 'req.view', 'res.view', 'ws.jsonl', 'sse.jsonl']) {
    rm(join(runDir, `${id}.${suffix}`), { force: true }).catch(() => {})
  }
}

function emit(event) {
  const line = `${JSON.stringify(event)}\n`
  if (!isDaemon || event.t === 'log' || event.t === 'fatal') process.stdout.write(line)
  for (const client of eventClients) {
    // a session that stopped reading (suspended with ctrl-z) is let go of, not buffered for without end
    if (client.res.writableLength > 8 * 1024 * 1024) {
      client.res.destroy()
      continue
    }
    client.res.write(line)
  }
  remember(event)
}

function fatal(code, message) {
  for (const client of eventClients) client.res.write(`${JSON.stringify({ t: 'fatal', code, message })}\n`)
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

// --- HTTP/2 beside HTTP/1.1 ---------------------------------------------------
//
// A client that offers h2 gets it; its requests reach the same handler through
// the compatibility API. Headers travel inside as pairs without pseudo-headers,
// and are turned into what each side's protocol allows on the way out.

// what HTTP/2 forbids in a header block (RFC 9113 8.2.2), and host, which is :authority there
const H2_FORBIDDEN = new Set(['connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'upgrade', 'host', 'http2-settings'])

function isH2(req) {
  return req.httpVersionMajor === 2
}

/** The client's headers as pairs: no pseudo-headers; an HTTP/2 :authority becomes host, its cookie crumbs one cookie. */
function requestPairs(req) {
  let out = pairs(req.rawHeaders).filter(([name]) => !name.startsWith(':'))
  if (!isH2(req)) return out
  if (!out.some(([name]) => name.toLowerCase() === 'host') && req.headers[':authority']) out.unshift(['host', req.headers[':authority']])
  const crumbs = out.filter(([name]) => name.toLowerCase() === 'cookie')
  if (crumbs.length > 1) out = [...out.filter(([name]) => name.toLowerCase() !== 'cookie'), ['cookie', crumbs.map(([, value]) => value).join('; ')]]
  return out
}

/** Pairs as an HTTP/2 header object: lower-case names, nothing it forbids, repeats joined. */
function h2Headers(list) {
  const out = {}
  for (const [rawName, value] of list) {
    const name = rawName.toLowerCase()
    if (H2_FORBIDDEN.has(name) || name.startsWith(':')) continue
    if (name === 'set-cookie') (out[name] ??= []).push(value)
    // cookie crumbs join with "; " (RFC 9113 8.2.3), every other repeat with ", "
    else out[name] = name in out ? `${out[name]}${name === 'cookie' ? '; ' : ', '}${value}` : value
  }
  return out
}

/** An HTTP/2 header object as pairs, pseudo-headers left out. */
function pairsOfH2(headers) {
  const out = []
  for (const [name, value] of Object.entries(headers)) {
    if (name.startsWith(':')) continue
    for (const one of Array.isArray(value) ? value : [value]) out.push([name, String(one)])
  }
  return out
}

/** Starts a response to either kind of client. */
function writeHead(res, status, statusMessage, headerPairs) {
  if (res.stream) return res.writeHead(status, h2Headers(headerPairs))
  res.writeHead(status, statusMessage ?? undefined, headerPairs.flat())
}

/**
 * Whether the proxy ended the response. An HTTP/2 response the client cancels
 * (RST_STREAM, GOAWAY, a dropped connection) finishes too, without being ended.
 */
function isResponseEnded(res) {
  return res.stream ? res.writableEnded === true : res.writableFinished === true
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

// Who waits for flows to end (the mod's wait_for_request, a replay): told of each one that does.
const flowWaiters = new Set()

function emitFlow(flow) {
  emit({ t: 'flow', flow: { ...flow } })
  for (const waiter of flowWaiters) waiter(flow)
}

/** The flows after `after` that reach `until` ('end': done or failed; 'start': any) within `ms`. */
function waitForFlows(after, until, ms) {
  return new Promise(resolve => {
    const found = []
    let settle = null
    const done = () => {
      clearTimeout(deadline)
      clearTimeout(settle)
      flowWaiters.delete(waiter)
      resolve(found)
    }
    const waiter = flow => {
      if (flow.id <= after || found.some(f => f.id === flow.id)) return
      if (until === 'end' && flow.state !== 'done' && flow.state !== 'error') return
      found.push({ ...flow })
      // a moment for others that end together, never past the deadline, at most 50
      if (found.length >= 50) return done()
      settle ??= setTimeout(done, 30)
    }
    flowWaiters.add(waiter)
    const deadline = setTimeout(done, ms)
  })
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
// the rules of every attached session's project, each file loaded once
const ruleSets = new Map()

function useRules(file) {
  if (!file) return
  const entry = ruleSets.get(file)
  if (entry) return void (entry.users += 1)
  ruleSets.set(file, {
    users: 1,
    set: createRuleSet({
      rulesFile: file,
      trustFile: args.trust ?? join(args.data, 'trusted-scripts.json'),
      onLoad: loaded => emit({ t: 'rules', ...loaded }),
    }),
  })
}

function dropRules(file) {
  const entry = ruleSets.get(file)
  if (!entry || (entry.users -= 1) > 0) return
  entry.set.close()
  ruleSets.delete(file)
  known.rules.delete(file)
}

function activeRules() {
  return [...ruleSets.values()].flatMap(entry => entry.set.rules)
}

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
  clientSocket.on('error', () => {})
  dial(host, port, clientOf(clientSocket), upstream => {
    upstream.pipe(clientSocket)
    clientSocket.pipe(upstream)
    clientSocket.resume()
    upstream.on('error', () => clientSocket.destroy())
    clientSocket.on('error', () => upstream.destroy())
    upstream.on('close', () => clientSocket.destroy())
    clientSocket.on('close', () => upstream.destroy())
  }, () => clientSocket.destroy())
}

/** A connection to a server for an upgrade (TLS for https), through the upstream proxy when it carries the host. */
function openServerSocket(target, client) {
  const tlsOptions = {
    servername: net.isIP(target.host) ? undefined : target.host,
    rejectUnauthorized: checksCertificate(target.host),
    ALPNProtocols: ['http/1.1'],
  }
  if (upstreamProxy?.carries(target.host)) {
    return target.scheme === 'https'
      ? upstreamProxy.connectTls(target.host, target.port, tlsOptions, reachFor(client))
      : upstreamProxy.connect(target.host, target.port, 'http', reachFor(client))
  }
  // errors of a direct connection come as events, which the caller listens for
  return Promise.resolve(
    target.scheme === 'https'
      ? tls.connect({ host: target.host, port: target.port, ...tlsOptions, ...reachFor(client) })
      : net.connect({ port: target.port, host: target.host, ...reachFor(client) }),
  )
}

/** A TCP connection to host:port, through the upstream proxy when it carries the host. */
function dial(host, port, client, onSocket, onError) {
  if (upstreamProxy?.carries(host)) return void upstreamProxy.connect(host, port, 'https', reachFor(client)).then(onSocket, onError)
  onSocket(net.connect({ port, host, ...reachFor(client) }))
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
  const headers = forwardable(requestPairs(req).flat())
  const direct = { host: target.host, port: target.port, path: target.path, headers, agent: agentFor(target.scheme, target.host, isLocal), ...reachFor(client) }
  if (!isHttps && upstreamProxy?.carries(target.host)) {
    return void upstreamProxy.plainRequest(target, headers).then(
      where => relayPassThrough(req, res, target, where),
      () => {
        res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' })
        res.end()
      },
    )
  }
  relayPassThrough(req, res, target, direct)
}

function relayPassThrough(req, res, target, where) {
  const upstream = (target.scheme === 'https' ? https : http).request({
    ...where,
    method: req.method,
    servername: net.isIP(target.host) ? undefined : target.host,
  })
  upstream.on('response', upstreamRes => {
    writeHead(res, upstreamRes.statusCode, upstreamRes.statusMessage, pairs(forwardable(upstreamRes.rawHeaders)))
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
    if (!isResponseEnded(res)) upstream.destroy()
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
const insecureAgents = {
  local: new https.Agent({ keepAlive: true, maxSockets: 64, rejectUnauthorized: false, ALPNProtocols: ['http/1.1'] }),
  remote: new https.Agent({ keepAlive: true, maxSockets: 64, rejectUnauthorized: false, ALPNProtocols: ['http/1.1'] }),
}

/** Whether the server's certificate is checked: always, but for hosts named insecure. */
function checksCertificate(host) {
  return !insecure && !insecureHosts.some(pattern => matchesHost(host, pattern))
}

let upstreamAgents = null

function agentFor(scheme, host, isLocal) {
  if (scheme === 'https' && upstreamProxy?.carries(host)) {
    upstreamAgents ??= {
      checked: upstreamProxy.agent({ rejectUnauthorized: !insecure, ALPNProtocols: ['http/1.1'] }),
      unchecked: upstreamProxy.agent({ rejectUnauthorized: false, ALPNProtocols: ['http/1.1'] }),
    }
    return checksCertificate(host) ? upstreamAgents.checked : upstreamAgents.unchecked
  }
  if (scheme !== 'https') return isLocal ? httpAgent : remoteHttpAgent
  if (!checksCertificate(host)) return isLocal ? insecureAgents.local : insecureAgents.remote
  return isLocal ? httpsAgent : remoteHttpsAgent
}

// An HTTP/2 client's requests go upstream over HTTP/2 where the server speaks
// it (gRPC needs that); ALPN says so once per origin. One session per origin
// and per kind of client carries the streams, as the agents' pools do.
const h2Refused = new Set()
const h2Sessions = new Map()

function authorityOf(target) {
  const host = net.isIPv6(target.host) ? `[${target.host}]` : target.host
  const isDefault = (target.scheme === 'https' && target.port === 443) || (target.scheme === 'http' && target.port === 80)
  return isDefault ? host : `${host}:${target.port}`
}

/** An open HTTP/2 session to the target's origin, or null when the server does not speak h2. */
async function h2SessionFor(target, client) {
  const origin = `${target.host}:${target.port}`
  const key = `${origin}|${isLocalClient(client) ? 'local' : 'remote'}`
  const cached = await (h2Sessions.get(key) ?? Promise.resolve(null)).catch(() => null)
  if (cached && !cached.closed && !cached.destroyed) return cached
  if (h2Refused.has(origin)) return null
  const tlsOptions = {
    servername: net.isIP(target.host) ? undefined : target.host,
    rejectUnauthorized: checksCertificate(target.host),
    ALPNProtocols: ['h2', 'http/1.1'],
  }
  const secured = upstreamProxy?.carries(target.host)
    ? upstreamProxy.connectTls(target.host, target.port, tlsOptions, reachFor(client))
    : new Promise((resolve, reject) => {
        const socket = tls.connect({ host: target.host, port: target.port, ...tlsOptions, ...reachFor(client) })
        socket.once('error', reject)
        socket.once('secureConnect', () => {
          socket.off('error', reject)
          resolve(socket)
        })
      })
  const opening = new Promise((resolve, reject) => {
    secured.then(socket => {
      if (socket.alpnProtocol !== 'h2') {
        h2Refused.add(origin)
        socket.destroy()
        return resolve(null)
      }
      const session = http2.connect(`https://${authorityOf(target)}`, { createConnection: () => socket })
      const forget = () => {
        if (h2Sessions.get(key) === opening) h2Sessions.delete(key)
      }
      session.on('error', forget)
      session.on('close', forget)
      session.on('goaway', forget)
      // an idle session goes; the next request opens another
      session.setTimeout(60_000, () => session.close())
      resolve(session)
    }, reject)
  })
  h2Sessions.set(key, opening)
  opening.then(
    session => session === null && h2Sessions.get(key) === opening && h2Sessions.delete(key),
    () => h2Sessions.get(key) === opening && h2Sessions.delete(key),
  )
  return opening
}

/** Drops the cached session to an origin, so the next request opens a fresh one (the old one goes when idle). */
function forgetH2Session(target, client) {
  h2Sessions.delete(`${target.host}:${target.port}|${isLocalClient(client) ? 'local' : 'remote'}`)
}

/** Trailers as they come: the list, and listeners told when they arrive. */
function trailerSlot() {
  const list = []
  const listeners = []
  return {
    list,
    on: listener => listeners.push(listener),
    add: more => {
      list.push(...more)
      for (const listener of listeners) listener(list)
    },
  }
}

/** Sends the request over an HTTP/2 session; `feed` writes its body. */
function requestOverH2(session, sent, headerPairs, feed) {
  return new Promise((resolve, reject) => {
    const headers = {
      ...h2Headers(headerPairs),
      ':method': sent.method,
      ':path': sent.target.path,
      ':scheme': 'https',
      ':authority': getHeader(sent.headers, 'host') ?? authorityOf(sent.target),
    }
    // the one TE HTTP/2 allows, which gRPC servers ask for
    if (/\btrailers\b/i.test(getHeader(sent.headers, 'te') ?? '')) headers.te = 'trailers'
    const stream = session.request(headers)
    const trailers = trailerSlot()
    stream.on('trailers', t => trailers.add(pairsOfH2(t)))
    stream.once('response', h =>
      resolve({ status: h[':status'], statusMessage: undefined, headers: pairsOfH2(h), stream, trailers, httpVersion: '2' }),
    )
    stream.once('error', reject)
    feed(stream)
  })
}

/** Sends the request over HTTP/1.1; `feed` writes its body. */
async function requestOverH1(sent, headerPairs, client, feed) {
  const isHttps = sent.target.scheme === 'https'
  const isLocal = isLocalClient(client)
  // plain HTTP through the upstream: an HTTP proxy takes the absolute URL, SOCKS and a PAC's DIRECT a pool of their own
  const where =
    !isHttps && upstreamProxy?.carries(sent.target.host)
      ? await upstreamProxy.plainRequest(sent.target, headerPairs.flat())
      : { host: sent.target.host, port: sent.target.port, path: sent.target.path, headers: headerPairs.flat(), agent: agentFor(sent.target.scheme, sent.target.host, isLocal), ...reachFor(client) }
  return new Promise((resolve, reject) => {
    const upstream = (isHttps ? https : http).request({
      ...where,
      method: sent.method,
      servername: net.isIP(sent.target.host) ? undefined : sent.target.host,
    })
    upstream.on('response', upstreamRes => {
      const trailers = trailerSlot()
      upstreamRes.on('end', () => upstreamRes.rawTrailers.length && trailers.add(pairs(upstreamRes.rawTrailers)))
      resolve({
        status: upstreamRes.statusCode,
        statusMessage: upstreamRes.statusMessage,
        headers: pairs(upstreamRes.rawHeaders),
        stream: upstreamRes,
        trailers,
        httpVersion: upstreamRes.httpVersion,
      })
    })
    upstream.on('error', reject)
    feed(upstream)
  })
}

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

// --- the mod's way in: commands for live connections ------------------------
//
// `POST /__wirepane/<token>/<command>` with a JSON body, from this machine
// only; the token is in the ready event, which only the mod reads.

const controlToken = randomBytes(18).toString('base64url')

function controlAnswer(res, status, value) {
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' })
  res.end(`${JSON.stringify(value)}\n`)
}

function sessionsList() {
  return [...eventClients].map(client => ({ session: client.session, project: client.project, since: client.since }))
}

/** A session attaches: what is known first, then every event. */
function attachSession(req, res, query) {
  res.writeHead(200, { 'content-type': 'application/x-ndjson', 'cache-control': 'no-store' })
  // a session gone mid-write must not take the proxy down with it
  res.on('error', () => {})
  const client = { res, session: query.get('session') ?? '', project: query.get('project') ?? '', rules: query.get('rules') ?? '', since: Date.now() }
  const send = event => res.write(`${JSON.stringify(event)}\n`)
  clearTimeout(lingerTimer)
  eventClients.add(client)
  useRules(client.rules)
  send(readyEvent())
  for (const event of [known.tracking, known.skipped, known.network, known.systemProxy, ...known.rules.values()]) if (event) send(event)
  for (const entry of pinned.values()) send({ t: 'pinned', client: entry.client, host: entry.host })
  for (const flow of recentFlows.values()) send({ t: 'flow', flow })
  emit({ t: 'sessions', sessions: sessionsList() })
  res.on('close', () => {
    eventClients.delete(client)
    dropRules(client.rules)
    emit({ t: 'sessions', sessions: sessionsList() })
    if (eventClients.size === 0 && isDaemon) scheduleLinger()
  })
}

async function dirBytes(dir) {
  let total = 0
  for (const name of await readdir(dir).catch(() => [])) total += (await stat(join(dir, name)).catch(() => ({ size: 0 }))).size
  return total
}

async function handleControl(req, res) {
  const [path, search = ''] = (req.url ?? '').split('?')
  const [, , token, ...rest] = path.split('/')
  if (!isLocalClient(clientOf(req.socket)) || token !== controlToken) return controlAnswer(res, 403, { error: 'forbidden' })
  if (rest.join('/') === 'events') return attachSession(req, res, new URLSearchParams(search))
  let input = {}
  try {
    const text = (await readWhole(req)).toString('utf8')
    input = text.trim() ? JSON.parse(text) : {}
  } catch {
    return controlAnswer(res, 400, { error: 'the body must be JSON' })
  }
  const command = rest.join('/')
  if (command === 'ping') {
    // a session about to attach: the linger starts over, so it has the time to
    if (isDaemon && eventClients.size === 0) scheduleLinger()
    return controlAnswer(res, 200, {
      pid: process.pid,
      version: VERSION,
      sessions: sessionsList(),
      options: { host: args.host, port: args.port, noDecrypt: args['no-decrypt'], insecureHosts: args['insecure-hosts'], upstreamProxy: args['upstream-proxy'], upstreamBypass: args['upstream-bypass'] },
    })
  }
  if (command === 'info') {
    const memory = process.memoryUsage()
    return controlAnswer(res, 200, {
      pid: process.pid,
      version: VERSION,
      isShared: isDaemon,
      startedAt,
      uptimeMs: Date.now() - startedAt,
      host: args.host,
      port: listenPort,
      runDir,
      sessions: sessionsList(),
      memory: { rss: memory.rss, heapUsed: memory.heapUsed },
      flows: recentFlows.size,
      nextId,
      diskBytes: await dirBytes(runDir),
      pinned: pinned.size,
      websockets: liveSockets.size,
      rules: [...ruleSets.keys()],
      // what it was started with: a session that asks for other settings restarts it when nobody else uses it
      options: { host: args.host, port: args.port, noDecrypt: args['no-decrypt'], insecureHosts: args['insecure-hosts'], upstreamProxy: args['upstream-proxy'], upstreamBypass: args['upstream-bypass'] },
    })
  }
  if (command === 'stop') {
    controlAnswer(res, 200, { ok: true, sessions: sessionsList().length })
    for (const client of eventClients) client.res.end('{"t":"stopping"}\n')
    setTimeout(() => process.exit(0), 50)
    return
  }
  if (command === 'flows/clear') {
    emit({ t: 'cleared' })
    return controlAnswer(res, 200, { ok: true })
  }
  if (command === 'tracking/set') {
    if (!args.tracking) return controlAnswer(res, 400, { error: 'this proxy has no tracking file' })
    writeFileSync(args.tracking, `${JSON.stringify({ enabled: input.enabled === true, patterns: Array.isArray(input.patterns) ? input.patterns : [] }, null, 2)}\n`)
    loadTracking()
    return controlAnswer(res, 200, { ok: true })
  }
  if (command === 'ws/list') return controlAnswer(res, 200, { open: [...liveSockets.keys()] })
  if (command === 'pinned/list') return controlAnswer(res, 200, { pinned: [...pinned.values()] })
  if (command === 'pinned/clear') {
    const cleared = [...pinned.values()].filter(entry => !input.host || entry.host === input.host)
    for (const entry of cleared) {
      pinned.delete(pinKey(entry.client, entry.host))
      refusals.delete(pinKey(entry.client, entry.host))
      emit({ t: 'unpinned', client: entry.client, host: entry.host })
    }
    return controlAnswer(res, 200, { cleared: cleared.length })
  }
  if (command === 'flows/wait') {
    const ms = Math.min(25_000, Math.max(0, Number(input.timeoutMs) || 10_000))
    const flows = await waitForFlows(Number(input.after) || 0, input.until === 'start' ? 'start' : 'end', ms)
    return controlAnswer(res, 200, { flows, nextId })
  }
  if (command === 'ws/send' || command === 'ws/close') {
    const live = liveSockets.get(Number(input.id))
    if (!live) return controlAnswer(res, 404, { error: `WebSocket #${input.id} is not open`, open: [...liveSockets.keys()] })
    if (command === 'ws/close') {
      live.close(Number(input.code) || 1000, String(input.reason ?? ''))
      return controlAnswer(res, 200, { ok: true })
    }
    if (input.to !== 'client' && input.to !== 'server') return controlAnswer(res, 400, { error: 'to must be client or server' })
    const isBinary = typeof input.b64 === 'string'
    const data = isBinary ? Buffer.from(input.b64, 'base64') : Buffer.from(input.json !== undefined ? JSON.stringify(input.json) : String(input.text ?? ''))
    return controlAnswer(res, 200, { ok: live.send(input.to, isBinary ? OP.binary : OP.text, data) })
  }
  return controlAnswer(res, 404, { error: `no command ${command}` })
}

function handleRequest(req, res, tunnelTarget) {
  const target = resolveTarget(req, tunnelTarget)
  if (!target && (req.url ?? '').startsWith('/__wirepane/')) {
    return handleControl(req, res).catch(error => controlAnswer(res, 500, { error: error.message }))
  }
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

/** Records a text/event-stream response event by event: `<id>.sse.jsonl`, the count on the flow. */
function eventRecorder(flow) {
  const file = join(runDir, `${flow.id}.sse.jsonl`)
  const started = Date.now()
  const out = createWriteStream(file, { flags: 'a' })
  out.on('error', () => {})
  let timer = null
  let isEnded = false
  const recorder = {
    file,
    count: 0,
    push: chunk => reader.push(chunk),
    end: () => {
      isEnded = true
      clearTimeout(timer)
      out.end()
    },
  }
  flow.sseEvents = 0
  const reader = new EventStreamReader(event => {
    recorder.count += 1
    flow.sseEvents = recorder.count
    const data = event.data.length > maxWsText ? event.data.slice(0, maxWsText) : event.data
    out.write(`${JSON.stringify({ t: Date.now() - started, ...event, data, ...(event.data.length > maxWsText ? { isCut: true } : {}) })}\n`)
    if (!timer && !isEnded) {
      timer = setTimeout(() => {
        timer = null
        if (!isEnded) emitFlow(flow)
      }, 300)
      timer.unref()
    }
  })
  return recorder
}

function safeDecode(text) {
  try {
    return decodeURIComponent(text)
  } catch {
    return text
  }
}

/** A readable rendering beside a body Wirepane can decode (gRPC, protobuf): its file and kind. */
async function writeView(file, buffer, contentType) {
  const kind = viewKindOf(contentType)
  if (!kind) return {}
  const text = kind === 'grpc' ? renderGrpc(buffer, contentType) : renderProtobuf(buffer)
  if (text === null) return {}
  const view = `${file}.view`
  await writeFile(view, text).catch(() => {})
  return { view, viewKind: kind }
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
    httpVersion: isH2(req) ? '2' : req.httpVersion,
  })
  // the request as the server gets it: the rules work on this
  const sent = {
    method: req.method,
    target: { scheme: target.scheme, host: target.host, port: target.port, path: target.path },
    headers: requestPairs(req),
    body: undefined,
    respond: null,
    fail: null,
    throttle: null,
  }
  // a request Claude sent again (replay_request) says what it repeats; the server never sees that
  const replayOf = getHeader(sent.headers, 'x-wirepane-replay')
  if (replayOf !== undefined) {
    flow.replayOf = Number(replayOf) || null
    setHeader(sent.headers, 'x-wirepane-replay', undefined)
  }
  const reqBody = new Capture(maxBody)
  let resBody = null
  let resHeaders = []
  let resTrailers = []
  let upstreamHttpVersion = null
  let events = null
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
    httpVersion: flow.httpVersion,
    upstreamHttpVersion,
    statusMessage,
    reqHeaders: sent.headers,
    resHeaders,
    resTrailers,
    ruleLog,
    ...(events ? { sse: { file: events.file, count: events.count } } : {}),
  })

  emitFlow(flow)
  writeDetail(flow, { ...detail(), req: null, res: null })

  const finish = async () => {
    if (isFinished) return
    isFinished = true
    events?.end()
    flow.durationMs = Date.now() - flow.ts
    flow.reqSize = reqBody.size
    flow.resSize = resBody?.size ?? 0
    flow.state = flow.error ? 'error' : 'done'
    const bodies = {}
    const resType = contentTypeOf(getHeader(resHeaders, 'content-type'))
    let resBuffer = null
    for (const [side, capture, headers] of [
      ['req', reqBody, sent.headers],
      ['res', resBody, resHeaders],
    ]) {
      if (!capture || capture.size === 0) {
        bodies[side] = null
        continue
      }
      const encoding = getHeader(headers, 'content-encoding')
      const { buffer, isDecoded } = await decodeBody(capture.buffer(), encoding)
      if (side === 'res') resBuffer = buffer
      const file = join(runDir, `${flow.id}.${side}`)
      await writeFile(file, buffer).catch(() => {})
      bodies[side] = {
        file,
        size: capture.size,
        stored: buffer.length,
        isTruncated: capture.isTruncated,
        encoding: encoding ?? null,
        isDecoded,
        ...(await writeView(file, buffer, contentTypeOf(getHeader(headers, 'content-type')))),
      }
    }
    if (resType?.startsWith('application/grpc')) {
      const fromBody = resType.startsWith('application/grpc-web') && resBuffer ? grpcWebTrailers(resBuffer, resType) : []
      const all = [...resTrailers, ...fromBody, ...resHeaders]
      const code = getHeader(all, 'grpc-status')
      if (code !== undefined && /^\d+$/.test(code)) flow.grpcStatus = Number(code)
      const message = getHeader(all, 'grpc-message')
      if (message) flow.grpcMessage = safeDecode(message)
    }
    await writeDetail(flow, { ...detail(), ...bodies })
    emitFlow(flow)
  }

  const clientGone = () => {
    if (isFinished) return
    abort.abort()
    flow.error ??= 'the client closed the connection before the response ended'
    flow.errorCode ??= 'client-closed'
    upstream?.destroy()
    finish()
  }
  res.on('close', () => {
    if (!isResponseEnded(res)) clientGone()
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
    if (req.stream) {
      // HTTP/2: a reset ends this stream, a close the whole connection; the
      // response then closes as one already ended, so the record is kept here
      if (kind === 'reset') req.stream.close(http2.constants.NGHTTP2_INTERNAL_ERROR)
      else req.stream.session.destroy()
      return finish()
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
  const context = { projectRoot: process.cwd(), signal: abort.signal, log }
  const { candidates, needsBody } = rulesForRequest(activeRules().filter(actsOnHttp), view())
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
      let headerPairs = pairs(forwardable(sent.headers.flat()))
      if (sent.body !== undefined) {
        headerPairs = headerPairs.filter(([name]) => !/^(content-length|transfer-encoding)$/i.test(name))
        headerPairs.push(['content-length', String(sent.body.length)])
      }
      let isFed = false
      const feed = sink => {
        upstream = sink
        if (sent.body !== undefined) {
          if (!isFed) reqBody.push(sent.body)
          sink.end(sent.body)
        } else if (isFed || req.readableEnded) {
          sink.end()
        } else {
          req.on('data', chunk => reqBody.push(chunk))
          req.pipe(sink)
        }
        isFed = true
      }
      const send = async () => {
        const session = isH2(req) && sent.target.scheme === 'https' ? await h2SessionFor(sent.target, flow.client) : null
        return session ? requestOverH2(session, sent, headerPairs, feed) : requestOverH1(sent, headerPairs, flow.client, feed)
      }
      try {
        response = await send()
      } catch (error) {
        // a session the server was closing (GOAWAY) or a refused stream: once more on a fresh session, when no body bytes went
        const isRetryable = /GOAWAY|INVALID_SESSION|REFUSED_STREAM/.test(`${error.code ?? ''} ${error.message}`)
        const hasNoBody = sent.body !== undefined || req.readableEnded || req.stream?.endAfterHeaders === true
        if (!isRetryable || reqBody.size > 0 || !hasNoBody) throw error
        forgetH2Session(sent.target, flow.client)
        response = await send()
      }
      upstreamHttpVersion = response.httpVersion
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
  // the server may fail while a rule waits (a delay, a script): that ends the exchange
  let streamError = null
  response.stream?.on('error', error => (streamError ??= error))
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
  if (streamError || (!isWhole && response.stream?.destroyed && !response.stream.readableEnded)) {
    flow.error = describeUpstreamError(streamError ?? new Error('the server closed the response while the rules ran'))
    flow.errorCode = 'upstream'
    if (!res.headersSent) {
      res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' })
      res.end(`Wirepane: ${flow.error}\n`)
    } else res.destroy()
    return finish()
  }
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
  writeHead(res, state.status, state.statusMessage, pairs(forwardable(state.headers.flat())))
  // trailers (gRPC's status) go on to an HTTP/2 client, and into the record
  const passTrailers = list => {
    resTrailers = [...list]
    if (res.stream && list.length) res.addTrailers(h2Headers(list))
  }
  if (response.trailers?.list.length) passTrailers(response.trailers.list)
  else response.trailers?.on(passTrailers)
  // an HTTP/2 response the client cancels finishes too: then the server is let go of
  res.once('finish', () => (isResponseEnded(res) ? finish() : clientGone()))
  const out = state.throttle ? throttleStream(state.throttle) : null
  if (out) out.pipe(res)
  const sink = out ?? res
  // server-sent events: each one recorded as it arrives
  if (flow.contentType === 'text/event-stream' && !getHeader(state.headers, 'content-encoding')) events = eventRecorder(flow)
  if (isWhole) {
    resBody.push(state.body)
    events?.push(state.body)
    sink.end(state.body)
  } else {
    response.stream.on('data', chunk => {
      resBody.push(chunk)
      events?.push(chunk)
    })
    response.stream.pipe(sink)
    response.stream.on('error', error => {
      // the client went first, and the server's stream was let go of for it
      if (isFinished || abort.signal.aborted) return
      flow.error = describeUpstreamError(error)
      flow.errorCode = 'upstream'
      res.destroy()
      finish()
    })
  }
}

// --- WebSockets: every message recorded, rules on the messages ------------
//
// A tracked WebSocket is read frame by frame both ways. Without a rule that
// waits for its messages, each frame goes on the moment it is whole, exactly
// as it came; the record is made beside. With one, a message is held until it
// is whole, the rule's steps act on it, and it goes on as it came or written
// anew. permessage-deflate is taken out of the offer, so messages stay
// readable. Bytes the proxy cannot read as frames pass on untouched.

const liveSockets = new Map()
const maxWsText = Math.min(64 * 1024, maxBody)
const MAX_WS_RECORDS = 20_000

function handleUpgrade(req, clientSocket, head, tunnelTarget) {
  const target = resolveTarget(req, tunnelTarget)
  if (!target || isSelf(target.host, target.port)) return clientSocket.destroy()
  const isUntracked = !tracks(target.host)
  const isQuiet = isUntracked || isClaudeHost(target.host)
  if (!isQuiet && /^websocket$/i.test(String(req.headers.upgrade ?? '').trim())) {
    return websocket(req, clientSocket, head, target).catch(error => {
      emit({ t: 'log', level: 'error', message: `websocket: ${error.stack ?? error.message}` })
      clientSocket.destroy()
    })
  }
  if (isUntracked) countSkipped(target.host)
  return rawUpgrade(req, clientSocket, head, target, isQuiet)
}

/** Writes and holds the source back while the other side is full. */
function writeOn(to, bytes, from) {
  if (to.destroyed) return
  if (!to.write(bytes) && from && !from.isPaused()) {
    from.pause()
    to.once('drain', () => from.resume())
  }
}

function httpHead(status, message, headerPairs) {
  return `HTTP/1.1 ${status} ${message}\r\n${headerPairs.map(([k, v]) => `${k}: ${v}\r\n`).join('')}\r\n`
}

function parseHead(text) {
  const [statusLine, ...lines] = text.split('\r\n')
  const status = /^HTTP\/1\.[01] (\d{3}) ?(.*)$/.exec(statusLine)
  const headers = lines
    .filter(line => line.includes(':'))
    .map(line => [line.slice(0, line.indexOf(':')).trim(), line.slice(line.indexOf(':') + 1).trim()])
  return { status: status ? Number(status[1]) : null, statusMessage: status?.[2] ?? null, headers }
}

async function websocket(req, clientSocket, head, target) {
  const client = clientOf(req.socket)
  const flow = newFlow({
    kind: 'ws',
    method: req.method,
    scheme: target.scheme,
    host: target.host,
    port: target.port,
    path: target.path,
    client,
    httpVersion: req.httpVersion,
    wsOut: 0,
    wsIn: 0,
  })
  const sent = {
    method: req.method,
    target: { ...target },
    headers: pairs(req.rawHeaders),
    body: undefined,
    respond: null,
    fail: null,
    throttle: null,
  }
  const ruleLog = []
  const log = (ruleId, text) => {
    ruleLog.push(`${ruleId}: ${text}`)
    flow.rules ??= []
    if (!flow.rules.includes(ruleId)) flow.rules.push(ruleId)
  }
  const abort = new AbortController()
  const file = join(runDir, `${flow.id}.ws.jsonl`)
  const opened = Date.now()
  let resHeaders = []
  let statusMessage = null
  let closed = null
  let records = null
  let recorded = 0
  let isFinished = false
  let isMock = false
  let emitTimer = null

  const wsUrl = () => `${sent.target.scheme === 'https' ? 'wss' : 'ws'}://${authorityOf(sent.target)}${sent.target.path}`
  const detail = () => ({
    url: wsUrl(),
    httpVersion: req.httpVersion,
    statusMessage,
    reqHeaders: sent.headers,
    resHeaders,
    ruleLog,
    req: null,
    res: null,
    ws: { file, count: recorded, close: closed, isMock },
  })
  const progress = () => {
    if (emitTimer || isFinished) return
    emitTimer = setTimeout(() => {
      emitTimer = null
      if (!isFinished) emitFlow(flow)
    }, 500)
    emitTimer.unref()
  }

  // one JSON line per message: t (ms since the upgrade), dir, op, size, text or b64
  const record = (dir, opcode, data, extra = {}) => {
    if (opcode === OP.text || opcode === OP.binary) {
      if (dir === 'out') flow.wsOut += 1
      else flow.wsIn += 1
    }
    if (dir === 'out') flow.reqSize += data.length
    else flow.resSize += data.length
    progress()
    if (recorded >= MAX_WS_RECORDS) return
    recorded += 1
    const line = { t: Date.now() - opened, dir, op: opName(opcode), size: data.length, ...extra }
    if (opcode === OP.text && !extra.isCompressed) {
      const text = data.toString('utf8')
      line.text = text.length > maxWsText ? text.slice(0, maxWsText) : text
      if (text.length > maxWsText) line.isCut = true
    } else if (opcode === OP.close) {
      const { code, reason } = parseClose(data)
      line.code = code
      if (reason) line.reason = reason
    } else if (data.length) {
      line.b64 = data.subarray(0, 4096).toString('base64')
      if (data.length > 4096) line.isCut = true
    }
    if (isFinished) return
    if (!records) {
      records = createWriteStream(file, { flags: 'a' })
      records.on('error', () => {})
    }
    records.write(`${JSON.stringify(line)}\n`)
  }

  const finish = () => {
    if (isFinished) return
    isFinished = true
    liveSockets.delete(flow.id)
    clearTimeout(emitTimer)
    abort.abort()
    flow.durationMs = Date.now() - flow.ts
    flow.state = flow.error ? 'error' : 'done'
    records?.end()
    writeDetail(flow, detail())
    emitFlow(flow)
  }

  emitFlow(flow)
  writeDetail(flow, detail())
  clientSocket.on('error', () => {})

  // --- the handshake, as the rules leave it
  const view = () => ({ method: sent.method, url: urlOf(sent.target), host: sent.target.host, path: sent.target.path, headers: sent.headers, body: undefined })
  const { candidates } = rulesForRequest(activeRules(), view())
  const matched = candidates.length ? finalizeRequestRules(candidates, view()) : []
  const context = { projectRoot: process.cwd(), signal: abort.signal, log }
  if (matched.length) await applyRequestRules(matched, sent, context)
  const messageRules = matched.filter(rule => rule.messages?.length)
  setHeader(sent.headers, 'Sec-WebSocket-Extensions', withoutDeflate(getHeader(sent.headers, 'sec-websocket-extensions')))

  if (!isLocalClient(client) && isLoopback(sent.target.host)) {
    flow.error = loopbackRefusal(sent.target.host)
    flow.errorCode = 'forbidden'
    flow.status = 403
    clientSocket.end(httpHead(403, 'Forbidden', [['connection', 'close']]))
    return finish()
  }
  if (sent.fail) {
    flow.error = sent.fail === 'timeout' ? 'a rule held the upgrade unanswered' : 'a rule closed the connection'
    flow.errorCode = 'rule'
    if (sent.fail === 'timeout') setTimeout(() => clientSocket.destroy(), 300_000).unref()
    else if (sent.fail === 'reset' && typeof clientSocket.resetAndDestroy === 'function') clientSocket.resetAndDestroy()
    else clientSocket.destroy()
    clientSocket.on('close', finish)
    return sent.fail === 'timeout' ? undefined : finish()
  }
  if (sent.respond && sent.respond.status !== 101) {
    // the rule answers the handshake, and no WebSocket opens
    const body = sent.respond.body ?? Buffer.alloc(0)
    flow.status = sent.respond.status
    resHeaders = [...sent.respond.headers, ['content-length', String(body.length)], ['connection', 'close']]
    clientSocket.end(Buffer.concat([Buffer.from(httpHead(sent.respond.status, http.STATUS_CODES[sent.respond.status] ?? '', resHeaders)), body]))
    return finish()
  }

  // --- both sides, frame by frame
  let upstream = null
  // A frame of Wirepane's own may not land between the pieces of a message
  // passing through: it waits until that direction's message is whole.
  const passing = { out: null, in: null }
  const inject = (dir, frame) => {
    const relayed = passing[dir]
    if (relayed?.isMidMessage()) relayed.waiting.push(frame)
    else frame()
  }
  const toClient = (opcode, data) => inject('in', () => writeOn(clientSocket, encodeFrame({ opcode, payload: data })))
  const toServer = (opcode, data) => upstream && inject('out', () => writeOn(upstream, encodeFrame({ opcode, payload: data, isMasked: true })))
  const sendTo = (to, opcode, data, note) => {
    if (isFinished) return false
    if (to === 'server') {
      if (isMock) record('out', opcode, data, { note: `${note}; no server, Wirepane plays it` })
      else {
        toServer(opcode, data)
        record('out', opcode, data, { note })
      }
    } else {
      toClient(opcode, data)
      record('in', opcode, data, { note })
    }
    return true
  }
  const closeBoth = (code, reason, by) => {
    if (isFinished) return
    const payload = closePayload(code, reason)
    closed ??= { code, reason, by }
    toClient(OP.close, payload)
    record('in', OP.close, payload, { note: `closed by ${by}` })
    if (!isMock) toServer(OP.close, payload)
    setTimeout(() => {
      clientSocket.destroy()
      upstream?.destroy()
    }, 1000).unref()
  }
  const ruleContext = {
    ...context,
    send: (to, opcode, data) => sendTo(to, opcode, data, 'sent by a rule'),
    close: (code, reason) => closeBoth(code, reason, 'a rule'),
  }

  const relay = (dir, from, to) => {
    const holds = isMock ? dir === 'out' : holdsMessages(messageRules, dir)
    const pass = raw => (isMock ? undefined : writeOn(to, raw, from))
    let queue = Promise.resolve()
    let isRaw = false
    const assembler = new MessageAssembler(message => {
      if (message.opcode === OP.close) closed ??= { ...parseClose(message.data), by: dir === 'out' ? 'the client' : 'the server' }
      const isCompressed = (message.rsv & 4) !== 0
      if (message.opcode >= 8) {
        if (holds && message.opcode === OP.close) queue = queue.then(() => message.frames.forEach(pass))
        record(dir, message.opcode, message.data)
        // a mock answers the client's pings and close itself
        if (isMock && message.opcode === OP.ping) toClient(OP.pong, message.data)
        if (isMock && message.opcode === OP.close) {
          toClient(OP.close, message.data)
          setTimeout(() => clientSocket.end(), 200).unref()
        }
        return
      }
      if (!holds || isCompressed) {
        if (holds) message.frames.forEach(pass)
        return record(dir, message.opcode, message.data, isCompressed ? { isCompressed: true, note: 'compressed: passed on as it came' } : {})
      }
      queue = queue
        .then(async () => {
          const original = { opcode: message.opcode, data: message.data }
          const result = await applyMessageRules(messageRules, { direction: dir, opcode: message.opcode, data: message.data }, ruleContext)
          if (result.isDropped) return record(dir, original.opcode, original.data, { note: result.fate === 'answered' ? 'answered by a rule' : result.fate === 'closed' ? 'closed by a rule' : 'dropped by a rule' })
          const isChanged = result.opcode !== original.opcode || !result.data.equals(original.data)
          if (isMock) return record(dir, result.opcode, result.data, { note: 'no server, Wirepane plays it' })
          if (isChanged) (dir === 'out' ? toServer : toClient)(result.opcode, result.data)
          else message.frames.forEach(pass)
          record(dir, result.opcode, result.data, isChanged ? { note: 'changed by a rule', was: original.opcode === OP.text ? original.data.toString('utf8').slice(0, 2000) : undefined } : {})
        })
        .catch(error => emit({ t: 'log', level: 'error', message: `websocket rules: ${error.stack ?? error.message}` }))
    })
    const reader = new FrameReader(frame => {
      if (!holds || (frame.opcode >= 8 && frame.opcode !== OP.close)) pass(frame.raw)
      assembler.frame(frame)
      // a message passed whole: what waited behind it goes now
      if (!holds && !assembler.parts) for (const waiting of state.waiting.splice(0)) waiting()
    })
    const state = { isMidMessage: () => !holds && assembler.parts !== null, waiting: [] }
    passing[dir] = state
    return chunk => {
      if (isRaw) return pass(chunk)
      try {
        reader.push(chunk)
      } catch (error) {
        // not frames we can read: the rest goes on as it comes
        isRaw = true
        ruleLog.push(`wirepane: ${dir === 'out' ? 'client' : 'server'} frames unreadable (${error.message}); passed on untouched`)
        pass(Buffer.concat(reader.chunks))
        reader.chunks = []
      }
    }
  }

  liveSockets.set(flow.id, {
    send: (to, opcode, data) => sendTo(to, opcode, data, 'sent by Claude'),
    close: (code, reason) => closeBoth(code, reason, 'Claude'),
  })

  const early = head?.length ? [head] : []
  let fromClient = chunk => early.push(chunk)
  clientSocket.on('data', chunk => fromClient(chunk))
  const startRelaying = () => {
    const out = relay('out', clientSocket, upstream)
    fromClient = out
    for (const chunk of early.splice(0)) out(chunk)
    applyOpenRules(messageRules, ruleContext).catch(() => {})
  }

  if (sent.respond) {
    // status 101: Wirepane is the server; the rule's steps answer the messages
    isMock = true
    const key = getHeader(sent.headers, 'sec-websocket-key') ?? ''
    const offered = getHeader(sent.headers, 'sec-websocket-protocol')?.split(',')[0]?.trim()
    resHeaders = [
      ['Upgrade', 'websocket'],
      ['Connection', 'Upgrade'],
      ['Sec-WebSocket-Accept', acceptKey(key)],
      ...(offered && !getHeader(sent.respond.headers, 'sec-websocket-protocol') ? [['Sec-WebSocket-Protocol', offered]] : []),
      ...sent.respond.headers,
    ]
    flow.status = 101
    statusMessage = 'Switching Protocols'
    clientSocket.write(httpHead(101, statusMessage, resHeaders))
    flow.state = 'receiving'
    emitFlow(flow)
    clientSocket.on('close', finish)
    return startRelaying()
  }

  try {
    upstream = await openServerSocket(sent.target, client)
  } catch (error) {
    flow.error = describeUpstreamError(error)
    flow.errorCode = 'upstream'
    clientSocket.end(httpHead(502, 'Bad Gateway', [['content-type', 'text/plain; charset=utf-8'], ['connection', 'close']]) + `Wirepane could not reach ${sent.target.host}:${sent.target.port}\n${flow.error}\n`)
    return finish()
  }
  const lines = [`${sent.method} ${sent.target.path} HTTP/1.1`]
  const headers = forwardable(sent.headers.flat(), new Set(['connection', 'upgrade']))
  for (let i = 0; i + 1 < headers.length; i += 2) lines.push(`${headers[i]}: ${headers[i + 1]}`)
  upstream.write(`${lines.join('\r\n')}\r\n\r\n`)

  let phase = 'head'
  let headBuffer = Buffer.alloc(0)
  let fromServer = null
  // a tunnel through the upstream proxy was left paused after the proxy's answer
  setImmediate(() => upstream.resume())
  upstream.on('data', chunk => {
    if (phase === 'raw') return writeOn(clientSocket, chunk, upstream)
    if (phase === 'frames') return fromServer(chunk)
    headBuffer = Buffer.concat([headBuffer, chunk])
    const end = headBuffer.indexOf('\r\n\r\n')
    if (end < 0) {
      if (headBuffer.length > 64 * 1024) upstream.destroy(new Error('the server sent a handshake answer over 64 KB'))
      return
    }
    const parsed = parseHead(headBuffer.subarray(0, end).toString('latin1'))
    flow.status = parsed.status
    statusMessage = parsed.statusMessage
    resHeaders = parsed.headers
    flow.state = 'receiving'
    emitFlow(flow)
    writeDetail(flow, detail())
    clientSocket.write(headBuffer.subarray(0, end + 4))
    const rest = headBuffer.subarray(end + 4)
    headBuffer = null
    if (flow.status !== 101) {
      // no WebSocket after all: whatever follows goes on as it is
      phase = 'raw'
      fromClient = chunk => writeOn(upstream, chunk, clientSocket)
      for (const chunk of early.splice(0)) fromClient(chunk)
      if (rest.length) writeOn(clientSocket, rest, upstream)
      return
    }
    phase = 'frames'
    fromServer = relay('in', upstream, clientSocket)
    startRelaying()
    if (rest.length) fromServer(rest)
  })
  upstream.on('error', error => {
    flow.error = error.code === 'ELOOPBACK' ? error.message : describeUpstreamError(error)
    flow.errorCode = error.code === 'ELOOPBACK' ? 'forbidden' : 'upstream'
    if (phase === 'head' && !clientSocket.destroyed) {
      clientSocket.end(httpHead(502, 'Bad Gateway', [['content-type', 'text/plain; charset=utf-8'], ['connection', 'close']]) + `Wirepane could not reach ${sent.target.host}:${sent.target.port}\n${flow.error}\n`)
    } else clientSocket.destroy()
    finish()
  })
  clientSocket.on('error', () => upstream.destroy())
  upstream.on('close', () => {
    clientSocket.end()
    setTimeout(() => clientSocket.destroy(), 1000).unref()
    finish()
  })
  clientSocket.on('close', () => {
    upstream.destroy()
    finish()
  })
}

// Other upgrades (h2c, and upgrades to hosts nobody records): passed through, one row each.
function rawUpgrade(req, clientSocket, head, target, quiet) {
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
  openServerSocket(target, flow.client).then(
    upstream => relayRaw(upstream),
    error => {
      flow.error = describeUpstreamError(error)
      flow.errorCode = 'upstream'
      clientSocket.destroy()
      finish()
    },
  )
  const relayRaw = upstream => {
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
}

// --- CONNECT: decrypt, or tunnel untouched --------------------------------

const inner = http.createServer()
function noteRequest(socket) {
  if (!socket?.proxyTarget || socket.proxyTarget.scheme !== 'https' || socket.hadRequest) return
  socket.hadRequest = true
  noteAccepted(clientOf(socket), socket.proxyTarget.host)
}

inner.on('request', (req, res) => {
  noteRequest(req.socket)
  handleRequest(req, res, req.socket.proxyTarget)
})
inner.on('upgrade', (req, socket, head) => {
  noteRequest(socket)
  handleUpgrade(req, socket, head, socket.proxyTarget)
})
inner.on('clientError', (error, socket) => socket.destroy())

// An HTTP/2 client's connection: a server of its own, so each request knows
// the tunnel it came through. WebSockets stay on HTTP/1.1 (no extended CONNECT
// is offered, so clients open a separate connection for them).
function serveH2(secure) {
  // A server-side TLSSocket made by hand never clears secureConnecting, and an
  // HTTP/2 session would wait for a secureConnect that does not come.
  secure.secureConnecting = false
  const server = http2.createServer({ maxSessionMemory: 64 })
  server.on('request', (req, res) => {
    noteRequest(secure)
    handleRequest(req, res, secure.proxyTarget)
  })
  server.on('sessionError', () => {})
  server.on('session', session => session.on('error', () => {}))
  server.emit('connection', secure)
}

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
  const failed = error => {
    flow.error = error.code === 'ELOOPBACK' ? error.message : describeUpstreamError(error)
    flow.errorCode = error.code === 'ELOOPBACK' ? 'forbidden' : 'upstream'
    clientSocket.destroy()
    finish()
  }
  clientSocket.on('error', () => {})
  clientSocket.on('close', finish)
  dial(host, port, flow.client, upstream => {
    const connected = () => {
      flow.status = 200
      flow.state = 'receiving'
      emitFlow(flow)
    }
    // through an upstream proxy the socket is connected already
    if (upstream.connecting) upstream.once('connect', connected)
    else connected()
    upstream.pipe(clientSocket)
    clientSocket.pipe(upstream)
    upstream.on('data', chunk => (flow.resSize += chunk.length))
    clientSocket.on('data', chunk => (flow.reqSize += chunk.length))
    upstream.on('error', failed)
    clientSocket.on('error', () => upstream.destroy())
    upstream.on('close', () => {
      clientSocket.destroy()
      finish()
    })
    clientSocket.on('close', () => upstream.destroy())
  }, failed)
}

// --- hosts that refuse the certificate: passed through after two refusals --------
//
// Per client and host: a client that refuses one host while it accepts others
// pins that host's certificate; one that refuses everything lacks the CA, and
// its entries go once it accepts a handshake. An app that pins with OkHttp
// completes the handshake and closes at once with nothing sent: half a refusal.

const autoPassthrough = !args['no-auto-passthrough']
const refusals = new Map()
const accepted = new Set()
const acceptingClients = new Set()
const pinned = new Map()
const pinKey = (client, host) => `${client ?? ''}|${host}`

function noteRefusal(client, host, weight) {
  const key = pinKey(client, host)
  if (!autoPassthrough || accepted.has(key) || pinned.has(key)) return
  const total = (refusals.get(key) ?? 0) + weight
  refusals.set(key, total)
  if (total < 2) return
  // while the client accepts nothing at all, it is the CA it lacks, not this host's pin
  pinned.set(key, { client, host, isBlind: !acceptingClients.has(client) })
  emit({ t: 'pinned', client, host })
}

function noteAccepted(client, host) {
  const key = pinKey(client, host)
  if (accepted.has(key)) return
  accepted.add(key)
  refusals.delete(key)
  if (acceptingClients.has(client)) return
  acceptingClients.add(client)
  // the client trusts the CA now: what it refused before was the missing CA
  for (const [other, entry] of pinned) {
    if (entry.client === client && entry.isBlind) {
      pinned.delete(other)
      refusals.delete(other)
      emit({ t: 'unpinned', client, host: entry.host })
    }
  }
}

function handshakeFailed(host, port, socket, error) {
  // a browser dropping a connection it opened ahead and no longer needs: not worth a row
  if (error && /ECONNRESET|EPIPE|socket hang up/i.test(`${error.code ?? ''} ${error.message}`)) return
  const message = error?.message ?? 'closed during the handshake'
  const isAlert = /alert|unknown ca|bad certificate|certificate unknown/i.test(message)
  if (isAlert || !error) noteRefusal(clientOf(socket), host, 1)
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
    ALPNProtocols: ['h2', 'http/1.1'],
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
    const at = Date.now()
    // closed at once with nothing asked: how OkHttp ends a connection whose pin did not match
    secure.once('close', () => {
      if (!secure.hadRequest && Date.now() - at < 1500) noteRefusal(clientOf(rawSocket), host, 0.5)
    })
    if (secure.alpnProtocol === 'h2') serveH2(secure)
    else inner.emit('connection', secure)
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
  const authority = parseAuthority(req.url ?? '')
  const { port } = authority
  clientSocket.on('error', () => {})
  clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n')
  if (head?.length) clientSocket.unshift(head)
  // A client that CONNECTs to an address (the Android emulator does) still
  // names the host in its TLS handshake: that name is what the list tracks,
  // what the rules match and what the flows show.
  const host = net.isIP(authority.host) ? ((await peekServerName(clientSocket, 2000)) ?? authority.host) : authority.host
  if (!tracks(host)) return quietTunnel(clientSocket, host, port)
  // Claude Code trusts no CA of ours: never decrypt Claude's services, nor
  // anything Claude started while the system proxy sends it here
  if (isClaudeHost(host)) return quietTunnel(clientSocket, host, port, false)
  // the mod's own replays carry its token, and are decrypted though curl descends from Claude
  const isMod = req.headers['x-wirepane-control'] === controlToken
  if (!isMod && selfGuard && (await selfGuard.isFromClaude(clientSocket).catch(() => false))) {
    return quietTunnel(clientSocket, host, port, false)
  }
  if (noDecrypt.some(pattern => matchesHost(host, pattern))) {
    return tunnel(clientSocket, host, port, 'no-decrypt')
  }
  if (pinned.has(pinKey(clientOf(clientSocket), host))) return tunnel(clientSocket, host, port, 'pinned')
  clientSocket.once('data', first => {
    clientSocket.pause()
    clientSocket.unshift(first)
    // 0x16: a TLS handshake record. Plain HTTP in a tunnel (a ws:// a browser
    // sends through CONNECT) is read like any other; anything else passes as is.
    if (first[0] === 0x16) decrypt(clientSocket, host, port)
    else if (/^[A-Z]{3,10} \S+ HTTP\/1\.[01]\r?$/m.test(first.subarray(0, 2048).toString('latin1').split('\n')[0])) {
      clientSocket.proxyTarget = { scheme: 'http', host, port }
      inner.emit('connection', clientSocket)
      clientSocket.resume()
    } else tunnel(clientSocket, host, port, 'not-tls')
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
  // a proxy started on its own keeps the rules it was given for as long as it runs
  if (args.rules) useRules(args.rules)
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
    if (args['system-proxy-backup']) {
      watchFile(args['system-proxy-backup'], { interval: 300 }, () => selfGuard.recheck())
      // a kill -9 of this process must not leave the Mac pointing at nothing
      spawn(process.execPath, [join(here, 'watchdog.mjs'), String(process.pid), args['system-proxy-backup'], String(listenPort)], { detached: true, stdio: 'ignore' }).unref()
    }
    // a beat to every attached session, so one whose conversation was cleared notices with no traffic
    setInterval(() => {
      for (const client of eventClients) client.res.write('{"t":"tick"}\n')
    }, 5000).unref()
    if (isDaemon) {
      writeRegistry()
      // started, and nobody came: go after the linger too
      scheduleLinger()
    }
    emit(readyEvent())
  })

  // the sessions attached hear that it stops on purpose (a session's /proxy stop), not that it failed
  const stop = () => {
    for (const client of eventClients) client.res.end('{"t":"stopping"}\n')
    setTimeout(() => process.exit(0), 50).unref()
  }
  process.on('SIGTERM', stop)
  process.on('SIGINT', stop)
  process.on('exit', removeRegistry)
  // Claude Code gone without a word: the parent is now launchd (a daemon's always is).
  if (!isDaemon) {
    setInterval(() => {
      if (process.ppid !== 1) return
      restoreSystemProxy()
      process.exit(0)
    }, 2000).unref()
  }
}

function readyEvent() {
  return {
    t: 'ready',
    host: args.host,
    port: listenPort,
    addresses: args.host === '127.0.0.1' || args.host === 'localhost' ? ['127.0.0.1'] : lanAddresses(),
    lan: network,
    pid: process.pid,
    runDir,
    isShared: isDaemon,
    version: VERSION,
    sessions: sessionsList(),
    control: { token: controlToken },
    ca: {
      path: ca.caCertPath,
      subject: ca.subject,
      fingerprint256: ca.fingerprint256,
      validTo: ca.validTo,
      spki: ca.spki,
    },
  }
}

// --- the one shared proxy: where sessions find it, and when it goes ---------------

const registryFile = join(args.data, 'sidecar.json')
let lingerTimer = null

function writeRegistry() {
  writeFileSync(registryFile, `${JSON.stringify({ pid: process.pid, host: args.host, port: listenPort, token: controlToken, version: VERSION, runDir, startedAt }, null, 2)}\n`)
}

function removeRegistry() {
  try {
    if (JSON.parse(readFileSync(registryFile, 'utf8')).pid === process.pid) unlinkSync(registryFile)
  } catch {}
}

/** Once the last session is gone for the linger, the system proxy and the Android devices go back, and so does the proxy. */
function scheduleLinger() {
  clearTimeout(lingerTimer)
  lingerTimer = setTimeout(() => {
    if (eventClients.size > 0) return
    restoreSystemProxy()
    revertAndroidLeftovers()
    process.exit(0)
  }, Number(args['linger-ms']) || 90_000)
  lingerTimer.unref?.()
}

// The mod writes which Android devices it pointed at the proxy; nobody left to point them back, the proxy does.
function revertAndroidLeftovers() {
  const file = join(args.data, 'android-proxied.json')
  try {
    const { adb, port, serials } = JSON.parse(readFileSync(file, 'utf8'))
    for (const serial of serials ?? []) {
      try {
        execFileSync(adb, ['-s', serial, 'shell', 'settings', 'put', 'global', 'http_proxy', ':0'], { timeout: 5000, stdio: 'ignore' })
        if (!serial.startsWith('emulator-')) execFileSync(adb, ['-s', serial, 'reverse', '--remove', `tcp:${port}`], { timeout: 5000, stdio: 'ignore' })
      } catch {}
    }
    writeFileSync(file, '')
  } catch {}
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
