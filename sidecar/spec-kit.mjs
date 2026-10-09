// What the sidecar specs share: curl, a server on a free port, the sidecar
// itself with its events, and an HTTP/2 session opened through its CONNECT.

import { execFile, spawn } from 'node:child_process'
import { once } from 'node:events'
import http from 'node:http'
import http2 from 'node:http2'
import { dirname, join } from 'node:path'
import tls from 'node:tls'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))

export function curl(args) {
  return new Promise(resolve => {
    execFile('curl', ['-sS', '--noproxy', '', '--max-time', '10', ...args], (error, stdout, stderr) =>
      resolve({ code: error?.code ?? 0, stdout, stderr }),
    )
  })
}

export function listen(server) {
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server.address().port)))
}

export function startSidecar(dataDir, extra = []) {
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
  let stderr = ''
  child.stderr.on('data', chunk => (stderr += chunk))
  const waitFor = (predicate, label, ms = 8000) =>
    new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        waiters.splice(waiters.indexOf(check), 1)
        reject(new Error(`timed out waiting for ${label}${stderr ? `\nsidecar stderr: ${stderr}` : ''}`))
      }, ms)
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
  const flow = (predicate, label) => waitFor(() => [...flows.values()].find(predicate), label)
  return { child, flows, events, waitFor, flow }
}

/** A TLS socket to host:port through the proxy's CONNECT, offering `alpn`. */
export async function connectThrough(proxyPort, host, port, ca, alpn) {
  const req = http.request({ host: '127.0.0.1', port: proxyPort, method: 'CONNECT', path: `${host}:${port}` })
  req.end()
  const [, socket] = await once(req, 'connect')
  const secure = tls.connect({ socket, servername: host, ca, ALPNProtocols: alpn })
  await once(secure, 'secureConnect')
  return secure
}

/** An HTTP/2 session to host:port through the proxy. */
export async function h2Through(proxyPort, host, port, ca) {
  const secure = await connectThrough(proxyPort, host, port, ca, ['h2'])
  if (secure.alpnProtocol !== 'h2') throw new Error(`the proxy chose ${secure.alpnProtocol}, not h2`)
  const session = http2.connect(`https://${host}:${port}`, { createConnection: () => secure })
  session.on('error', () => {})
  return session
}

/** One gRPC message in its 5-byte frame. */
export function grpcFrame(message) {
  const head = Buffer.alloc(5)
  head.writeUInt32BE(message.length, 1)
  return Buffer.concat([head, message])
}

/** A protobuf field `number` holding the UTF-8 `text` (wire type 2). */
export function pbString(number, text) {
  const value = Buffer.from(text)
  return Buffer.concat([Buffer.from([(number << 3) | 2, value.length]), value])
}

/** A unary gRPC call on an HTTP/2 session: the response headers, body and trailers. */
export function grpcCall(session, path, message, extra = {}) {
  return new Promise((resolve, reject) => {
    const stream = session.request({
      ':method': 'POST',
      ':path': path,
      'content-type': 'application/grpc',
      te: 'trailers',
      ...extra,
    })
    let headers = null
    let trailers = null
    const chunks = []
    stream.on('response', h => (headers = h))
    stream.on('trailers', t => (trailers = t))
    stream.on('data', chunk => chunks.push(chunk))
    stream.on('end', () => resolve({ headers, body: Buffer.concat(chunks), trailers }))
    stream.on('error', reject)
    stream.end(grpcFrame(message))
  })
}
