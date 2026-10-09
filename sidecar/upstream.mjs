// An upstream proxy between Wirepane and the servers (an office's, a VPN's):
//   http://[user:pass@]host:port     HTTP CONNECT, plain HTTP in absolute form; Basic or NTLM sign-in
//                                    (DOMAIN\user as DOMAIN%5Cuser), whichever the proxy asks for
//   socks5://[user:pass@]host:port   SOCKS5 (RFC 1928, credentials RFC 1929), names resolved by the proxy
//   pac+http(s)://[user:pass@]host/proxy.pac
//                                    a PAC file's FindProxyForURL chooses, per URL: PROXY, SOCKS, DIRECT;
//                                    the credentials go to the proxies it names, never to the PAC's server
// This Mac's own addresses and the hosts named in the bypass list are reached
// directly: no upstream proxy can reach this Mac's localhost.

import dns from 'node:dns/promises'
import http from 'node:http'
import https from 'node:https'
import net from 'node:net'
import os from 'node:os'
import tls from 'node:tls'
import vm from 'node:vm'

import { authenticateMessage, challengeIn, negotiateMessage, ntlmScheme } from './ntlm.mjs'

const ALWAYS_DIRECT = ['localhost', '*.localhost', '*.local']

function matches(host, pattern) {
  if (pattern.startsWith('*.')) return host === pattern.slice(2) || host.endsWith(pattern.slice(1))
  return host === pattern
}

function authority(host, port) {
  return `${net.isIPv6(host) ? `[${host}]` : host}:${port}`
}

function basic(url) {
  return url.username ? `Basic ${Buffer.from(`${decodeURIComponent(url.username)}:${decodeURIComponent(url.password)}`).toString('base64')}` : null
}

/** A proxy from its URL: { kind: 'http' | 'socks', host, port, auth, user, password }; `credentials` (a URL's) when it has none. */
function proxyOf(text, credentials = null) {
  const url = new URL(/^[a-z0-9+]+:\/\//i.test(text) ? text : `http://${text}`)
  if (credentials?.username && !url.username) {
    url.username = credentials.username
    url.password = credentials.password
  }
  const kind = /^socks/i.test(url.protocol) ? 'socks' : 'http'
  return {
    kind,
    host: url.hostname.replace(/^\[|\]$/g, ''),
    port: Number(url.port) || (kind === 'socks' ? 1080 : 8080),
    auth: basic(url),
    user: decodeURIComponent(url.username),
    password: decodeURIComponent(url.password),
    name: `${url.protocol}//${url.hostname}:${Number(url.port) || (kind === 'socks' ? 1080 : 8080)}`,
  }
}

function upstreamError(text, code = 'EUPSTREAMPROXY') {
  const error = new Error(text)
  error.code = code
  return error
}

/** Reads from a socket until `isWhole(buffer)` says how many bytes make the answer; resolves those, unshifting the rest. */
function readAnswer(socket, isWhole, limit = 16_384) {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0)
    const onData = chunk => {
      buffer = Buffer.concat([buffer, chunk])
      const size = isWhole(buffer)
      if (size === null) {
        if (buffer.length > limit) done(upstreamError('the upstream proxy sent an answer too long'))
        return
      }
      socket.pause()
      const rest = buffer.subarray(size)
      if (rest.length) socket.unshift(rest)
      done(null, buffer.subarray(0, size))
    }
    const onError = error => done(error)
    const onClose = () => done(upstreamError('the upstream proxy closed the connection'))
    const done = (error, answer) => {
      socket.off('data', onData)
      socket.off('error', onError)
      socket.off('close', onClose)
      if (error) reject(error)
      else resolve(answer)
    }
    socket.on('data', onData)
    socket.once('error', onError)
    socket.once('close', onClose)
    socket.resume()
  })
}

function opened(socket) {
  return new Promise((resolve, reject) => {
    socket.once('connect', resolve)
    socket.once('error', reject)
  })
}

/** A proxy's answer head: { status, offers (its Proxy-Authenticate values), length, isChunked, isClosing }. */
async function readHead(socket) {
  const head = await readAnswer(socket, buffer => {
    const end = buffer.indexOf('\r\n\r\n')
    return end < 0 ? null : end + 4
  })
  const [first, ...lines] = head.toString('latin1').split('\r\n')
  const values = name =>
    lines.filter(line => line.toLowerCase().startsWith(`${name}:`)).map(line => line.slice(name.length + 1).trim())
  const status = Number(/^HTTP\/1\.[01] (\d{3})/.exec(first)?.[1] ?? 0)
  return {
    status,
    offers: values('proxy-authenticate'),
    length: Number(values('content-length')[0] ?? 0),
    isChunked: values('transfer-encoding').some(v => /chunked/i.test(v)),
    isClosing: [...values('connection'), ...values('proxy-connection')].some(v => /close/i.test(v)) || /^HTTP\/1\.0/.test(first),
  }
}

/** Reads past the body of an answer whose head was `head`, so the connection can carry the next request. */
async function skipBody(socket, head) {
  if (head.isChunked) await readAnswer(socket, buffer => (buffer.indexOf('0\r\n\r\n') < 0 ? null : buffer.indexOf('0\r\n\r\n') + 5), 1 << 20)
  else if (head.length > 0) await readAnswer(socket, buffer => (buffer.length >= head.length ? head.length : null), 1 << 20)
}

// the proxies that asked for NTLM before ('NTLM' or 'Negotiate'), or that took Basic ('Basic'), by name
const signIns = new Map()

function refusal(proxy, head, what) {
  if (head.status !== 407) return `the upstream proxy ${proxy.name} answered ${head.status || 'what is not HTTP'} to ${what}`
  const scheme = ntlmScheme(head.offers)
  if (!proxy.user) {
    return `the upstream proxy ${proxy.name} answered 407 to ${what}: it wants credentials (http://user:password@host:port${scheme ? ', or http://DOMAIN%5Cuser:password@host:port for its Windows sign-in' : ''})`
  }
  if (scheme === 'Negotiate') return kerberos(proxy)
  return `the upstream proxy ${proxy.name} answered 407 to ${what}: it refused the credentials`
}

function kerberos(proxy) {
  return `the upstream proxy ${proxy.name} wants Kerberos sign-in, which Wirepane cannot do: run a helper on this Mac that signs in for you (such as Px: pip install px-proxy) and set upstreamProxy to it`
}

/**
 * Signs in to an HTTP proxy with NTLM on a fresh connection: `send(socket, authorization)` writes
 * the request with the negotiate message, then with the answer to the proxy's challenge.
 * Resolves { socket, scheme } once the answer is sent, or { socket: null, head } when the proxy
 * did not challenge (it took the request as it was, or it signs in some other way).
 */
async function ntlmSignIn(proxy, scheme, send) {
  const socket = net.connect(proxy.port, proxy.host)
  try {
    await opened(socket)
    send(socket, `${scheme} ${negotiateMessage().toString('base64')}`)
    const head = await readHead(socket)
    const challenge = head.status === 407 ? challengeIn(head.offers, scheme) : null
    if (!challenge) {
      socket.destroy()
      return { socket: null, head }
    }
    await skipBody(socket, head)
    if (head.isClosing) throw upstreamError(`the upstream proxy ${proxy.name} closed the connection in the middle of its NTLM sign-in`)
    send(socket, `${scheme} ${authenticateMessage({ user: proxy.user, password: proxy.password, challenge }).toString('base64')}`)
    return { socket, scheme }
  } catch (error) {
    socket.destroy()
    throw error
  }
}

/** A tunnel to host:port through an HTTP proxy's CONNECT: Basic credentials first, NTLM when the proxy asks for it. */
async function httpConnect(proxy, host, port) {
  const target = authority(host, port)
  const request = authorization =>
    `CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n${authorization ? `Proxy-Authorization: ${authorization}\r\nProxy-Connection: keep-alive\r\n` : ''}\r\n`
  const known = signIns.get(proxy.name)
  if (proxy.user && (known === 'NTLM' || known === 'Negotiate')) return ntlmConnect(proxy, target, known, request)
  const socket = net.connect(proxy.port, proxy.host)
  try {
    await opened(socket)
    socket.write(request(proxy.auth))
    const head = await readHead(socket)
    if (head.status === 200) {
      if (proxy.user) signIns.set(proxy.name, 'Basic')
      return socket
    }
    const scheme = head.status === 407 && proxy.user ? ntlmScheme(head.offers) : null
    if (!scheme) throw upstreamError(refusal(proxy, head, `CONNECT ${target}`))
    socket.destroy()
    return await ntlmConnect(proxy, target, scheme, request)
  } catch (error) {
    socket.destroy()
    throw error
  }
}

/**
 * Learns how an HTTP proxy signs in, with a CONNECT closed as soon as it answers: no request
 * reaches a server. 'NTLM' or 'Negotiate' when its 407 asks for that, 'Basic' otherwise.
 */
async function learnSignIn(proxy, host, port) {
  const socket = net.connect(proxy.port, proxy.host)
  try {
    await opened(socket)
    const target = authority(host, port)
    socket.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\nProxy-Authorization: ${proxy.auth}\r\n\r\n`)
    const head = await readHead(socket)
    signIns.set(proxy.name, (head.status === 407 && ntlmScheme(head.offers)) || 'Basic')
  } catch {
    // unknown still: this request goes with Basic, the next asks again
  } finally {
    socket.destroy()
  }
}

async function ntlmConnect(proxy, target, scheme, request) {
  const signedIn = await ntlmSignIn(proxy, scheme, (socket, authorization) => socket.write(request(authorization)))
  if (!signedIn.socket) {
    if (signedIn.head.status === 200) throw upstreamError(`the upstream proxy ${proxy.name} opened a tunnel before it signed in`)
    throw upstreamError(scheme === 'Negotiate' && signedIn.head.status === 407 ? kerberos(proxy) : refusal(proxy, signedIn.head, `CONNECT ${target}`))
  }
  const { socket } = signedIn
  try {
    const head = await readHead(socket)
    if (head.status !== 200) throw upstreamError(refusal(proxy, head, `CONNECT ${target}`))
    signIns.set(proxy.name, scheme)
    return socket
  } catch (error) {
    socket.destroy()
    throw error
  }
}

const SOCKS_REPLIES = {
  1: 'general failure',
  2: 'not allowed by its rules',
  3: 'network unreachable',
  4: 'host unreachable',
  5: 'connection refused',
  6: 'TTL expired',
  7: 'command not supported',
  8: 'address type not supported',
}

/** A tunnel to host:port through a SOCKS5 proxy; the proxy resolves the name. */
async function socksConnect(proxy, host, port) {
  const socket = net.connect(proxy.port, proxy.host)
  try {
    await opened(socket)
    const hasAuth = Boolean(proxy.user)
    socket.write(Buffer.from(hasAuth ? [5, 2, 0, 2] : [5, 1, 0]))
    const [, method] = await readAnswer(socket, buffer => (buffer.length >= 2 ? 2 : null))
    if (method === 2) {
      const user = Buffer.from(proxy.user)
      const password = Buffer.from(proxy.password)
      socket.write(Buffer.concat([Buffer.from([1, user.length]), user, Buffer.from([password.length]), password]))
      const [, status] = await readAnswer(socket, buffer => (buffer.length >= 2 ? 2 : null))
      if (status !== 0) throw upstreamError(`the SOCKS proxy ${proxy.name} refused the credentials`)
    } else if (method !== 0) {
      throw upstreamError(`the SOCKS proxy ${proxy.name} wants ${method === 255 ? 'a way of signing in Wirepane does not have' : `method ${method}`}${hasAuth ? '' : ' (credentials: socks5://user:password@host:port)'}`)
    }
    const address = net.isIPv4(host)
      ? Buffer.from([1, ...host.split('.').map(Number)])
      : Buffer.concat([Buffer.from([3, Buffer.byteLength(host)]), Buffer.from(host)])
    const portBytes = Buffer.alloc(2)
    portBytes.writeUInt16BE(port)
    socket.write(Buffer.concat([Buffer.from([5, 1, 0]), address, portBytes]))
    const reply = await readAnswer(socket, buffer => {
      if (buffer.length < 5) return null
      const length = buffer[3] === 1 ? 4 : buffer[3] === 4 ? 16 : buffer[3] === 3 ? 1 + buffer[4] : 0
      return buffer.length >= 4 + length + 2 ? 4 + length + 2 : null
    })
    if (reply[1] !== 0) throw upstreamError(`the SOCKS proxy ${proxy.name} could not reach ${authority(host, port)}: ${SOCKS_REPLIES[reply[1]] ?? `reply ${reply[1]}`}`)
    return socket
  } catch (error) {
    socket.destroy()
    throw error
  }
}

// --- PAC files -------------------------------------------------------------------

function shExp(pattern) {
  return new RegExp(`^${pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.')}$`)
}

function ipNumber(ip) {
  return ip.split('.').reduce((n, part) => n * 256 + Number(part), 0)
}

/** FindProxyForURL from a PAC file's text, in a sandbox with the standard helpers; DNS answers come from `names`. */
function pacFunction(text, names) {
  const firstAddress = () =>
    Object.values(os.networkInterfaces())
      .flat()
      .find(a => a && a.family === 'IPv4' && !a.internal)?.address ?? '127.0.0.1'
  const resolve = host => (net.isIPv4(host) ? host : names.get(host) ?? (names.wanted.add(host), null))
  const context = vm.createContext({
    isPlainHostName: host => !String(host).includes('.'),
    dnsDomainIs: (host, domain) => String(host).toLowerCase().endsWith(String(domain).toLowerCase()),
    localHostOrDomainIs: (host, full) => host === full || (!String(host).includes('.') && String(full).startsWith(`${host}.`)),
    isResolvable: host => resolve(host) !== null,
    isInNet: (host, pattern, mask) => {
      const ip = resolve(host)
      if (!ip || !net.isIPv4(ip)) return false
      return (ipNumber(ip) & ipNumber(mask)) >>> 0 === (ipNumber(pattern) & ipNumber(mask)) >>> 0
    },
    dnsResolve: host => resolve(host),
    myIpAddress: firstAddress,
    dnsDomainLevels: host => String(host).split('.').length - 1,
    shExpMatch: (value, pattern) => shExp(String(pattern)).test(String(value)),
    weekdayRange: () => true,
    dateRange: () => true,
    timeRange: () => true,
    alert: () => {},
  })
  vm.runInContext(text, context, { timeout: 1000, filename: 'proxy.pac' })
  if (typeof context.FindProxyForURL !== 'function') throw new Error('the PAC file has no FindProxyForURL')
  return (url, host) => String(vm.runInContext(`FindProxyForURL(${JSON.stringify(url)}, ${JSON.stringify(host)})`, context, { timeout: 1000 }))
}

/** "PROXY a:8080; SOCKS5 b:1080; DIRECT" as routes, in order; `credentials` ({ username, password }) for the proxies. */
export function parsePacResult(text, credentials = null) {
  return String(text)
    .split(';')
    .map(part => part.trim())
    .filter(Boolean)
    .map(part => {
      const [word, where = ''] = part.split(/\s+/)
      const kind = word.toUpperCase()
      if (kind === 'DIRECT') return { kind: 'direct' }
      if (kind === 'PROXY' || kind === 'HTTP' || kind === 'HTTPS') return { kind: 'proxy', proxy: proxyOf(`http://${where}`, credentials) }
      if (kind.startsWith('SOCKS')) return { kind: 'proxy', proxy: proxyOf(`socks5://${where}`, credentials) }
      return null
    })
    .filter(Boolean)
}

function fetchText(url) {
  return new Promise((resolve, reject) => {
    const get = url.startsWith('https:') ? https.get : http.get
    const req = get(url, { timeout: 10_000 }, res => {
      if (res.statusCode !== 200) {
        res.resume()
        return reject(new Error(`the PAC file at ${url} answered ${res.statusCode}`))
      }
      let text = ''
      res.setEncoding('utf8')
      res.on('data', chunk => (text += chunk))
      res.on('end', () => resolve(text))
    })
    req.on('timeout', () => req.destroy(new Error(`the PAC file at ${url} did not come`)))
    req.on('error', reject)
  })
}

// --- the upstream ------------------------------------------------------------------

/** The upstream of `setting` (see the top of this file), or null when none is set. */
export function createUpstream(setting, bypass = '') {
  if (!setting) return null
  const direct = [...ALWAYS_DIRECT, ...String(bypass).split(',').map(s => s.trim().toLowerCase()).filter(Boolean)]
  const isPac = /^pac\+/i.test(setting)
  const fixed = isPac ? null : proxyOf(setting)
  // a PAC URL's credentials are for the proxies it names; its server gets the URL without them
  const pacUrl = isPac ? new URL(setting.replace(/^pac\+/i, '')) : null
  const pacCredentials = pacUrl?.username ? { username: pacUrl.username, password: pacUrl.password } : null
  if (pacUrl) pacUrl.username = pacUrl.password = ''
  const name = isPac ? `pac+${pacUrl}` : fixed.name

  /** Whether `host` may go through the upstream (not this Mac, not bypassed); a PAC file may still say DIRECT. */
  const carries = host => {
    const h = String(host).toLowerCase()
    if (net.isIP(h)) return !(/^127\./.test(h) || h === '::1' || h === '0.0.0.0') && !direct.includes(h)
    return !direct.some(pattern => matches(h, pattern))
  }

  // the PAC file, fetched at first use and again every ten minutes
  let pac = null
  let pacAt = 0
  const names = Object.assign(new Map(), { wanted: new Set() })
  const loadPac = async () => {
    if (pac && Date.now() - pacAt < 600_000) return pac
    const text = await fetchText(String(pacUrl))
    pac = pacFunction(text, names)
    pacAt = Date.now()
    return pac
  }

  /** How to reach a URL: the routes to try, in order. */
  const routes = async (scheme, host, port) => {
    if (!carries(host)) return [{ kind: 'direct' }]
    if (!isPac) return [{ kind: 'proxy', proxy: fixed }]
    const find = await loadPac()
    const url = `${scheme}://${authority(host, port)}/`
    let answer = find(url, host)
    // the file asked for names it could not have: look them up and ask again
    if (names.wanted.size) {
      await Promise.all(
        [...names.wanted].map(name =>
          dns.lookup(name, { family: 4 }).then(
            ({ address }) => names.set(name, address),
            () => names.set(name, null),
          ),
        ),
      )
      names.wanted.clear()
      answer = find(url, host)
    }
    const parsed = parsePacResult(answer, pacCredentials)
    return parsed.length ? parsed : [{ kind: 'direct' }]
  }

  /** A TCP connection to host:port: direct, or through the first route that answers. */
  const connect = async (host, port, scheme = 'https', directOptions = {}) => {
    let failure = null
    for (const route of await routes(scheme, host, port)) {
      try {
        if (route.kind === 'direct') {
          const socket = net.connect({ host, port, ...directOptions })
          await opened(socket)
          return socket
        }
        return route.proxy.kind === 'socks' ? await socksConnect(route.proxy, host, port) : await httpConnect(route.proxy, host, port)
      } catch (error) {
        failure = error
      }
    }
    throw failure ?? upstreamError(`no route to ${authority(host, port)}`)
  }

  /** A TLS connection to host:port through the upstream. */
  const connectTls = async (host, port, options, directOptions = {}) => {
    const socket = await connect(host, port, 'https', directOptions)
    return new Promise((resolve, reject) => {
      const secure = tls.connect({ ...options, socket, servername: options.servername ?? (net.isIP(host) ? undefined : host) })
      secure.once('secureConnect', () => {
        secure.off('error', reject)
        resolve(secure)
      })
      secure.once('error', reject)
    })
  }

  /** An https.Agent whose connections go through the upstream. */
  const agent = options => {
    const pool = new https.Agent({ keepAlive: true, maxSockets: 64, ...options })
    pool.createConnection = (connectOptions, callback) => {
      connect(connectOptions.host, connectOptions.port, 'https').then(
        socket => callback(null, tls.connect({ ...connectOptions, socket, servername: connectOptions.servername ?? (net.isIP(connectOptions.host) ? undefined : connectOptions.host) })),
        error => callback(error),
      )
      return undefined
    }
    return pool
  }

  // plain HTTP through SOCKS (or a PAC's DIRECT): a pool whose connections the upstream makes
  const plainPool = new http.Agent({ keepAlive: true, maxSockets: 64 })
  plainPool.createConnection = (connectOptions, callback) => {
    connect(connectOptions.host, connectOptions.port, 'http').then(
      socket => {
        callback(null, socket)
        // the HTTP client listens now; a tunnel's socket was left paused after the proxy's answer
        socket.resume()
      },
      error => callback(error),
    )
    return undefined
  }

  /**
   * Request options for plain HTTP: an HTTP proxy gets the absolute URL (signed in with NTLM
   * on a connection of its own when it asks for that); SOCKS and DIRECT a pool of their own.
   */
  const plainRequest = async (target, headers, method = 'GET') => {
    const [first] = await routes('http', target.host, target.port)
    if (first?.kind === 'proxy' && first.proxy.kind === 'http') {
      const proxy = first.proxy
      const url = `http://${Number(target.port) === 80 ? authority(target.host, 80).replace(/:80$/, '') : authority(target.host, target.port)}${target.path}`
      if (proxy.user && !signIns.has(proxy.name)) await learnSignIn(proxy, target.host, target.port)
      const known = signIns.get(proxy.name)
      if (proxy.user && (known === 'NTLM' || known === 'Negotiate')) {
        const signedIn = await ntlmPlain(proxy, known, method, url)
        if (signedIn) return { host: proxy.host, port: proxy.port, path: url, headers: [...headers, 'Proxy-Authorization', signedIn.authorization], createConnection: signedIn.connection }
      }
      return { host: proxy.host, port: proxy.port, path: url, headers: proxy.auth ? [...headers, 'Proxy-Authorization', proxy.auth] : headers, agent: false }
    }
    return { host: target.host, port: target.port, path: target.path, headers, agent: plainPool }
  }

  /**
   * NTLM for one plain request to a proxy that asked for it: the negotiate message goes with
   * an empty request the proxy answers itself (407), and the real request carries the answer
   * to its challenge on that connection. Null when the proxy turns out to take Basic.
   */
  const ntlmPlain = async (proxy, scheme, method, url) => {
    let authorization = null
    const host = new URL(url).host
    const signedIn = await ntlmSignIn(proxy, scheme, (socket, value) => {
      // the first message: an empty request; the second goes with the real one
      if (authorization === null) socket.write(`${method} ${url} HTTP/1.1\r\nHost: ${host}\r\nProxy-Authorization: ${value}\r\nProxy-Connection: keep-alive\r\nContent-Length: 0\r\n\r\n`)
      authorization = value
    })
    if (!signedIn.socket) {
      const offered = signedIn.head.status === 407 ? ntlmScheme(signedIn.head.offers) : null
      if (offered && offered !== scheme) return ntlmPlain(proxy, offered, method, url)
      if (offered === 'Negotiate') throw upstreamError(kerberos(proxy))
      signIns.set(proxy.name, 'Basic')
      return null
    }
    signIns.set(proxy.name, signedIn.scheme)
    const { socket } = signedIn
    return {
      authorization,
      connection: () => {
        // the HTTP client listens now; the socket was left paused after the challenge
        process.nextTick(() => socket.resume())
        return socket
      },
    }
  }

  return { name, carries, connect, connectTls, agent, plainRequest }
}
