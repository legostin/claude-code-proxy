// NTLM sign-in to an upstream proxy (MS-NLMP): the negotiate message, the
// server's challenge, and the authenticate message with an NTLMv2 response.
// Proxies that offer Negotiate take the same raw NTLM messages; Kerberos needs
// the system's GSSAPI, which Wirepane does not have.

import { createHmac, randomBytes } from 'node:crypto'
import os from 'node:os'

const SIGNATURE = Buffer.from('NTLMSSP\0', 'latin1')

const FLAGS = {
  unicode: 0x00000001,
  oem: 0x00000002,
  requestTarget: 0x00000004,
  ntlm: 0x00000200,
  alwaysSign: 0x00008000,
  extendedSessionSecurity: 0x00080000,
  targetInfo: 0x00800000,
  bits128: 0x20000000,
  bits56: 0x80000000,
}

// --- MD4 (RFC 1320): OpenSSL 3 has it only in its legacy provider, which Node leaves off ---

/** MD4 of `data`, 16 bytes. */
export function md4(data) {
  const length = data.length
  const padded = Buffer.alloc(((length + 8) >> 6) * 64 + 64)
  data.copy(padded)
  padded[length] = 0x80
  padded.writeUInt32LE((length * 8) >>> 0, padded.length - 8)
  padded.writeUInt32LE(Math.floor((length * 8) / 0x100000000), padded.length - 4)
  let [a, b, c, d] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
  const rotate = (x, n) => (x << n) | (x >>> (32 - n))
  const f = (x, y, z) => (x & y) | (~x & z)
  const g = (x, y, z) => (x & y) | (x & z) | (y & z)
  const k = (x, y, z) => x ^ y ^ z
  for (let offset = 0; offset < padded.length; offset += 64) {
    const x = Array.from({ length: 16 }, (_, i) => padded.readUInt32LE(offset + i * 4))
    const [aa, bb, cc, dd] = [a, b, c, d]
    for (const i of [0, 4, 8, 12]) {
      a = rotate((a + f(b, c, d) + x[i]) | 0, 3)
      d = rotate((d + f(a, b, c) + x[i + 1]) | 0, 7)
      c = rotate((c + f(d, a, b) + x[i + 2]) | 0, 11)
      b = rotate((b + f(c, d, a) + x[i + 3]) | 0, 19)
    }
    for (const i of [0, 1, 2, 3]) {
      a = rotate((a + g(b, c, d) + x[i] + 0x5a827999) | 0, 3)
      d = rotate((d + g(a, b, c) + x[i + 4] + 0x5a827999) | 0, 5)
      c = rotate((c + g(d, a, b) + x[i + 8] + 0x5a827999) | 0, 9)
      b = rotate((b + g(c, d, a) + x[i + 12] + 0x5a827999) | 0, 13)
    }
    for (const i of [0, 2, 1, 3]) {
      a = rotate((a + k(b, c, d) + x[i] + 0x6ed9eba1) | 0, 3)
      d = rotate((d + k(a, b, c) + x[i + 8] + 0x6ed9eba1) | 0, 9)
      c = rotate((c + k(d, a, b) + x[i + 4] + 0x6ed9eba1) | 0, 11)
      b = rotate((b + k(c, d, a) + x[i + 12] + 0x6ed9eba1) | 0, 15)
    }
    a = (a + aa) | 0
    b = (b + bb) | 0
    c = (c + cc) | 0
    d = (d + dd) | 0
  }
  const out = Buffer.alloc(16)
  ;[a, b, c, d].forEach((word, i) => out.writeInt32LE(word, i * 4))
  return out
}

// --- the keys and responses (MS-NLMP 3.3.2) ---

const utf16 = text => Buffer.from(text, 'utf16le')
const hmac = (key, ...parts) => createHmac('md5', key).update(Buffer.concat(parts)).digest()

/** NTOWFv2: the NTLMv2 key from the password, the user and the domain. */
export function ntowfv2(password, user, domain) {
  return hmac(md4(utf16(password)), utf16(user.toUpperCase() + domain))
}

/** "DOMAIN\user" (or "user", or "user@domain.com", which Windows takes with no domain) as its parts. */
export function splitUser(name) {
  const slash = name.indexOf('\\')
  return slash < 0 ? { domain: '', user: name } : { domain: name.slice(0, slash), user: name.slice(slash + 1) }
}

/** The negotiate message (type 1). */
export function negotiateMessage() {
  const message = Buffer.alloc(32)
  SIGNATURE.copy(message)
  message.writeUInt32LE(1, 8)
  const flags = FLAGS.unicode | FLAGS.oem | FLAGS.requestTarget | FLAGS.ntlm | FLAGS.alwaysSign | FLAGS.extendedSessionSecurity | FLAGS.bits128 | FLAGS.bits56
  message.writeUInt32LE(flags >>> 0, 12)
  // empty domain and workstation fields, pointing at the end of the message
  message.writeUInt32LE(32, 20)
  message.writeUInt32LE(32, 28)
  return message
}

/** The challenge message (type 2): { flags, challenge, targetInfo }, or null when it is not one. */
export function parseChallenge(message) {
  if (message.length < 32 || !message.subarray(0, 8).equals(SIGNATURE) || message.readUInt32LE(8) !== 2) return null
  const flags = message.readUInt32LE(20)
  const challenge = message.subarray(24, 32)
  let targetInfo = Buffer.alloc(0)
  if (message.length >= 48) {
    const size = message.readUInt16LE(40)
    const offset = message.readUInt32LE(44)
    if (offset + size <= message.length) targetInfo = message.subarray(offset, offset + size)
  }
  return { flags, challenge, targetInfo }
}

/** Milliseconds since 1970 as a Windows FILETIME: 100-nanosecond steps since 1601, 8 bytes. */
function filetime(ms) {
  const out = Buffer.alloc(8)
  out.writeBigUInt64LE((BigInt(ms) + 11_644_473_600_000n) * 10_000n)
  return out
}

/** The NTLMv2 and LMv2 responses to a challenge. */
export function responses({ key, challenge, targetInfo, clientChallenge, timestamp }) {
  const blob = Buffer.concat([Buffer.from([1, 1, 0, 0, 0, 0, 0, 0]), timestamp, clientChallenge, Buffer.alloc(4), targetInfo, Buffer.alloc(4)])
  const proof = hmac(key, challenge, blob)
  return {
    nt: Buffer.concat([proof, blob]),
    lm: Buffer.concat([hmac(key, challenge, clientChallenge), clientChallenge]),
    proof,
  }
}

/** The authenticate message (type 3) answering `challenge` (from parseChallenge). */
export function authenticateMessage({ user: name, password, challenge, workstation = os.hostname().split('.')[0].toUpperCase(), clientChallenge = randomBytes(8), now = Date.now() }) {
  const { user, domain } = splitUser(name)
  const { nt, lm } = responses({
    key: ntowfv2(password, user, domain),
    challenge: challenge.challenge,
    targetInfo: challenge.targetInfo,
    clientChallenge,
    timestamp: filetime(now),
  })
  const fields = [lm, nt, utf16(domain), utf16(user), utf16(workstation), Buffer.alloc(0)]
  const header = Buffer.alloc(64)
  SIGNATURE.copy(header)
  header.writeUInt32LE(3, 8)
  let offset = header.length
  fields.forEach((field, i) => {
    header.writeUInt16LE(field.length, 12 + i * 8)
    header.writeUInt16LE(field.length, 14 + i * 8)
    header.writeUInt32LE(offset, 16 + i * 8)
    offset += field.length
  })
  const offered = challenge.flags
  const flags = FLAGS.unicode | FLAGS.ntlm | FLAGS.alwaysSign | (offered & (FLAGS.extendedSessionSecurity | FLAGS.targetInfo | FLAGS.bits128 | FLAGS.bits56))
  header.writeUInt32LE(flags >>> 0, 60)
  return Buffer.concat([header, ...fields])
}

/** The scheme to sign in with from a 407's Proxy-Authenticate values: 'NTLM', 'Negotiate' or null; NTLM first. */
export function ntlmScheme(offers) {
  const words = offers.map(offer => offer.trim().split(/\s+/)[0].toLowerCase())
  return words.includes('ntlm') ? 'NTLM' : words.includes('negotiate') ? 'Negotiate' : null
}

/** The challenge in a 407's Proxy-Authenticate values for `scheme`, or null. */
export function challengeIn(offers, scheme) {
  for (const offer of offers) {
    const [word, token] = offer.trim().split(/\s+/)
    if (word?.toLowerCase() === scheme.toLowerCase() && token) return parseChallenge(Buffer.from(token, 'base64'))
  }
  return null
}
