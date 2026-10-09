// node --test sidecar/ntlm.spec.mjs
// An office proxy that signs in with Windows (NTLM, or NTLM inside Negotiate):
// the crypto against the published test vectors, then a proxy that checks the
// NTLMv2 proof as a real one does, for HTTPS tunnels and plain HTTP.

import assert from 'node:assert/strict'
import { createHmac, randomBytes } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import https from 'node:https'
import net from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, before, describe, test } from 'node:test'

import { createLeafFactory, ensureCA } from './certs.mjs'
import { md4, ntowfv2, responses } from './ntlm.mjs'
import { curl, listen, startSidecar } from './spec-kit.mjs'

const hex = buffer => buffer.toString('hex')

describe('the NTLM crypto', () => {
  test('MD4 matches RFC 1320', () => {
    assert.equal(hex(md4(Buffer.alloc(0))), '31d6cfe0d16ae931b73c59d7e0c089c0')
    assert.equal(hex(md4(Buffer.from('abc'))), 'a448017aaf21d8525fc10ae87aa6729d')
    assert.equal(hex(md4(Buffer.from('1234567890'.repeat(8)))), 'e33b4ddc9c38f2199c3e7b164fcc0536')
  })

  test('NTLMv2 matches MS-NLMP 4.2.4', () => {
    assert.equal(hex(md4(Buffer.from('Password', 'utf16le'))), 'a4f49c406510bdcab6824ee7c30fd852')
    const key = ntowfv2('Password', 'User', 'Domain')
    assert.equal(hex(key), '0c868a403bfd7a93a3001ef22ef02e3f')
    const targetInfo = Buffer.from('02000c0044006f006d00610069006e0001000c0053006500720076006500720000000000', 'hex')
    const out = responses({ key, challenge: Buffer.from('0123456789abcdef', 'hex'), targetInfo, clientChallenge: Buffer.alloc(8, 0xaa), timestamp: Buffer.alloc(8) })
    assert.equal(hex(out.proof), '68cd0ab851e51c96aabc927bebef6a1c')
    assert.equal(hex(out.lm), '86c35097ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa')
  })
})

/** A field of an NTLM message (length, max, offset at `at`). */
function field(message, at) {
  return message.subarray(message.readUInt32LE(at + 4), message.readUInt32LE(at + 4) + message.readUInt16LE(at))
}

/** The challenge message an office proxy sends: its 8 bytes, and target info naming the OFFICE domain. */
function challengeMessage(challenge) {
  const name = Buffer.from('OFFICE', 'utf16le')
  const info = Buffer.concat([Buffer.from([2, 0, name.length, 0]), name, Buffer.alloc(4)])
  const message = Buffer.alloc(48)
  Buffer.from('NTLMSSP\0', 'latin1').copy(message)
  message.writeUInt32LE(2, 8)
  message.writeUInt32LE(48, 16)
  message.writeUInt32LE(0x00898205, 20)
  challenge.copy(message, 24)
  message.writeUInt16LE(info.length, 40)
  message.writeUInt16LE(info.length, 42)
  message.writeUInt32LE(48, 44)
  return Buffer.concat([message, info])
}

/**
 * An office proxy over raw sockets: it signs connections in with `scheme` (NTLM or
 * Negotiate) and checks the NTLMv2 proof against OFFICE\alice's password. CONNECT
 * opens a tunnel (*.test is this machine); a plain request it answers itself.
 * `kerberosOnly` never challenges: it wants a Kerberos ticket.
 */
function officeProxy({ scheme, password, seen, kerberosOnly = false }) {
  return net.createServer(socket => {
    let buffer = Buffer.alloc(0)
    let challenge = null
    socket.on('error', () => {})
    const answer = (status, headers, body = '') =>
      socket.write(`HTTP/1.1 ${status}\r\n${headers.map(h => `${h}\r\n`).join('')}Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`)
    socket.on('data', function onData(chunk) {
      buffer = Buffer.concat([buffer, chunk])
      for (;;) {
        const end = buffer.indexOf('\r\n\r\n')
        if (end < 0) return
        const [line, ...lines] = buffer.subarray(0, end).toString('latin1').split('\r\n')
        const headers = Object.fromEntries(lines.map(l => [l.slice(0, l.indexOf(':')).toLowerCase(), l.slice(l.indexOf(':') + 1).trim()]))
        const length = Number(headers['content-length'] ?? 0)
        if (buffer.length < end + 4 + length) return
        const body = buffer.subarray(end + 4, end + 4 + length).toString()
        buffer = buffer.subarray(end + 4 + length)
        const [method, target] = line.split(' ')
        const [word, token] = (headers['proxy-authorization'] ?? '').split(' ')
        const message = token ? Buffer.from(token, 'base64') : Buffer.alloc(0)
        const type = message.length >= 12 && message.subarray(0, 7).toString('latin1') === 'NTLMSSP' ? message.readUInt32LE(8) : 0
        seen.push({ method, target, auth: word ? `${word} ${type || token}` : null, length })
        if (word !== scheme || type === 0) {
          answer('407 Proxy Authentication Required', [`Proxy-Authenticate: ${scheme}`, 'Proxy-Authenticate: Basic realm="office"'], 'sign in')
          continue
        }
        if (type === 1) {
          if (kerberosOnly) {
            answer('407 Proxy Authentication Required', ['Proxy-Authenticate: Negotiate'], 'a ticket, please')
            continue
          }
          challenge = randomBytes(8)
          answer('407 Proxy Authentication Required', [`Proxy-Authenticate: ${scheme} ${challengeMessage(challenge).toString('base64')}`], 'go on')
          continue
        }
        // type 3: check the proof as the domain controller would
        const nt = field(message, 20)
        const domain = field(message, 28).toString('utf16le')
        const user = field(message, 36).toString('utf16le')
        const proof = createHmac('md5', ntowfv2(password, user, domain)).update(Buffer.concat([challenge ?? Buffer.alloc(8), nt.subarray(16)])).digest()
        const isSigned = challenge !== null && proof.equals(nt.subarray(0, 16)) && domain === 'OFFICE' && user === 'alice'
        seen.at(-1).user = `${domain}\\${user}`
        if (!isSigned) {
          answer('407 Proxy Authentication Required', [`Proxy-Authenticate: ${scheme}`], 'no')
          socket.end()
          return
        }
        if (method === 'CONNECT') {
          socket.off('data', onData)
          const [host, port] = target.split(':')
          const out = net.connect(Number(port), host.endsWith('.test') ? '127.0.0.1' : host, () => {
            socket.write('HTTP/1.1 200 Connection Established\r\n\r\n')
            if (buffer.length) out.write(buffer)
            out.pipe(socket)
            socket.pipe(out)
          })
          out.on('error', () => socket.destroy())
          return
        }
        answer('200 OK', ['Content-Type: text/plain'], `office answered ${method} ${target} "${body}"`)
      }
    })
  })
}

describe('an upstream proxy that signs in with Windows', () => {
  let dataDir
  let securePort
  const servers = []

  before(async () => {
    dataDir = await mkdtemp(join(tmpdir(), 'proxy-ntlm-'))
    const upstreamCA = await ensureCA(join(dataDir, 'upstream-ca'))
    const context = await createLeafFactory(upstreamCA).get('localhost')
    const secure = https.createServer({ SNICallback: (name, done) => done(null, context) }, (req, res) => res.end(`secure ${req.url}`))
    servers.push(secure)
    securePort = await listen(secure)
  })

  after(async () => {
    for (const server of servers) server.close()
    await rm(dataDir, { recursive: true, force: true })
  })

  /** A sidecar behind an office proxy; `run` gets the curl arguments to use it, and what the office saw. */
  async function behind(options, run) {
    const seen = []
    const office = officeProxy({ password: 's3cret', seen, ...options })
    const officePort = await listen(office)
    const credentials = options.credentials ?? 'OFFICE%5Calice:s3cret'
    const sidecar = startSidecar(join(dataDir, `proxy-${officePort}`), ['--insecure-upstream', '--upstream-proxy', `http://${credentials}@127.0.0.1:${officePort}`])
    try {
      const ready = await sidecar.waitFor(() => sidecar.events.find(e => e.t === 'ready'), 'ready')
      await run({ via: ['-x', `http://127.0.0.1:${ready.port}`, '--cacert', ready.ca.path], seen, sidecar })
    } finally {
      sidecar.child.kill()
      office.close()
    }
  }

  test('HTTPS: it signs in with NTLM on the tunnel, and then goes straight to NTLM', async () => {
    await behind({ scheme: 'NTLM' }, async ({ via, seen, sidecar }) => {
      const out = await curl([...via, `https://secure.test:${securePort}/first`])
      assert.equal(out.stdout, 'secure /first', out.stderr)
      const connects = seen.filter(s => s.method === 'CONNECT')
      // Basic first (it may be enough), then the Windows sign-in on a connection of its own; one
      // tunnel, though curl offered HTTP/2 and the server chose HTTP/1.1
      assert.deepEqual(connects.map(s => (s.auth.startsWith('Basic') ? 'Basic' : s.auth)), ['Basic', 'NTLM 1', 'NTLM 3'])
      assert.equal(connects.at(-1).user, 'OFFICE\\alice')
      const flow = await sidecar.flow(f => f.path === '/first' && f.state === 'done', 'the recorded flow')
      assert.equal(flow.status, 200)

      const before = seen.length
      // another host, so a new tunnel: no Basic this time
      assert.equal((await curl([...via, `https://other.test:${securePort}/second`])).stdout, 'secure /second')
      assert.deepEqual(seen.slice(before).map(s => s.auth), ['NTLM 1', 'NTLM 3'])
    })
  })

  test('plain HTTP: the negotiate message goes with an empty request, the real one carries the answer', async () => {
    await behind({ scheme: 'NTLM' }, async ({ via, seen }) => {
      const out = await curl([...via, '--data-binary', 'hello', 'http://plain.test/form'])
      assert.equal(out.stdout, 'office answered POST http://plain.test/form "hello"', out.stderr)
      assert.deepEqual(
        seen.map(s => [s.method, s.auth.split(' ')[0] === 'Basic' ? 'Basic' : s.auth, s.length]),
        [
          // how it signs in, learned with a CONNECT closed at once: nothing reaches a server
          ['CONNECT', 'Basic', 0],
          ['POST', 'NTLM 1', 0],
          ['POST', 'NTLM 3', 5],
        ],
      )
    })
  })

  test('a proxy that offers Negotiate takes the same NTLM messages', async () => {
    await behind({ scheme: 'Negotiate' }, async ({ via, seen }) => {
      assert.equal((await curl([...via, `https://secure.test:${securePort}/negotiate`])).stdout, 'secure /negotiate')
      assert.deepEqual(seen.filter(s => s.method === 'CONNECT').map(s => s.auth.split(' ')[0]).slice(-2), ['Negotiate', 'Negotiate'])
    })
  })

  test('a wrong password, a proxy that wants Kerberos, and no credentials say so in the flow', async () => {
    await behind({ scheme: 'NTLM', credentials: 'OFFICE%5Calice:wrong' }, async ({ via, sidecar }) => {
      await curl([...via, `https://secure.test:${securePort}/wrong`])
      const flow = await sidecar.flow(f => f.path === '/wrong' && f.state === 'error', 'the refused flow')
      assert.match(flow.error, /refused the credentials/)
    })
    await behind({ scheme: 'Negotiate', kerberosOnly: true }, async ({ via, sidecar }) => {
      await curl([...via, `https://secure.test:${securePort}/kerberos`])
      const flow = await sidecar.flow(f => f.path === '/kerberos' && f.state === 'error', 'the Kerberos flow')
      assert.match(flow.error, /Kerberos .*Px/)
    })
    await behind({ scheme: 'NTLM', credentials: '' }, async ({ via, sidecar }) => {
      await curl([...via, `https://secure.test:${securePort}/anonymous`])
      const flow = await sidecar.flow(f => f.path === '/anonymous' && f.state === 'error', 'the anonymous flow')
      assert.match(flow.error, /DOMAIN%5Cuser/)
    })
  })
})
