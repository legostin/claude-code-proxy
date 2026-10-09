// WebSocket frames (RFC 6455): read from a byte stream, put together into
// messages, and written back, masked toward the server as the protocol asks.

import { createHash, randomBytes } from 'node:crypto'

export const OP = { continuation: 0, text: 1, binary: 2, close: 8, ping: 9, pong: 10 }
const OP_NAMES = { 0: 'continuation', 1: 'text', 2: 'binary', 8: 'close', 9: 'ping', 10: 'pong' }

export function opName(opcode) {
  return OP_NAMES[opcode] ?? `op${opcode}`
}

/** The Sec-WebSocket-Accept a server answers a Sec-WebSocket-Key with. */
export function acceptKey(key) {
  return createHash('sha1').update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest('base64')
}

function unmask(payload, mask) {
  const out = Buffer.allocUnsafe(payload.length)
  for (let i = 0; i < payload.length; i++) out[i] = payload[i] ^ mask[i & 3]
  return out
}

/**
 * Reads frames out of chunks as they come. Each frame reaches `onFrame` with
 * its bytes exactly as they arrived (`raw`, to pass on untouched) and its
 * payload unmasked. A frame larger than `maxFrame` is an error.
 */
export class FrameReader {
  constructor(onFrame, { maxFrame = 64 * 1024 * 1024 } = {}) {
    this.onFrame = onFrame
    this.maxFrame = maxFrame
    this.chunks = []
    this.size = 0
  }

  push(chunk) {
    this.chunks.push(chunk)
    this.size += chunk.length
    for (;;) {
      const frame = this.next()
      if (!frame) return
      this.onFrame(frame)
    }
  }

  /** What is left over after the last whole frame. */
  get pending() {
    return this.size
  }

  next() {
    if (this.size < 2) return null
    const head = this.peek(Math.min(this.size, 14))
    const fin = (head[0] & 0x80) !== 0
    const rsv = (head[0] & 0x70) >> 4
    const opcode = head[0] & 0x0f
    const isMasked = (head[1] & 0x80) !== 0
    let length = head[1] & 0x7f
    let offset = 2
    if (length === 126) {
      if (head.length < 4) return null
      length = head.readUInt16BE(2)
      offset = 4
    } else if (length === 127) {
      if (head.length < 10) return null
      const big = head.readBigUInt64BE(2)
      if (big > BigInt(this.maxFrame)) throw new Error(`a frame of ${big} bytes is larger than allowed`)
      length = Number(big)
      offset = 10
    }
    if (length > this.maxFrame) throw new Error(`a frame of ${length} bytes is larger than allowed`)
    const maskAt = offset
    if (isMasked) offset += 4
    const total = offset + length
    if (this.size < total) return null
    const raw = this.take(total)
    const payload = raw.subarray(offset)
    return {
      fin,
      rsv,
      opcode,
      isMasked,
      payload: isMasked ? unmask(payload, raw.subarray(maskAt, maskAt + 4)) : Buffer.from(payload),
      raw,
    }
  }

  peek(n) {
    if (this.chunks[0].length >= n) return this.chunks[0].subarray(0, n)
    return Buffer.concat(this.chunks).subarray(0, n)
  }

  take(n) {
    const all = this.chunks.length === 1 ? this.chunks[0] : Buffer.concat(this.chunks)
    const taken = all.subarray(0, n)
    const rest = all.subarray(n)
    this.chunks = rest.length ? [rest] : []
    this.size = rest.length
    return taken
  }
}

/** One frame's bytes; masked with a fresh key when it goes to a server. */
export function encodeFrame({ opcode, payload = Buffer.alloc(0), fin = true, isMasked = false }) {
  const length = payload.length
  const extra = length < 126 ? 0 : length < 65536 ? 2 : 8
  const head = Buffer.alloc(2 + extra + (isMasked ? 4 : 0))
  head[0] = (fin ? 0x80 : 0) | opcode
  head[1] = (isMasked ? 0x80 : 0) | (length < 126 ? length : length < 65536 ? 126 : 127)
  if (extra === 2) head.writeUInt16BE(length, 2)
  if (extra === 8) head.writeBigUInt64BE(BigInt(length), 2)
  if (!isMasked) return Buffer.concat([head, payload])
  const mask = randomBytes(4)
  mask.copy(head, 2 + extra)
  return Buffer.concat([head, unmask(payload, mask)])
}

/** A close frame's payload: the code (two bytes) and the reason. */
export function closePayload(code = 1000, reason = '') {
  const text = Buffer.from(reason).subarray(0, 123)
  const out = Buffer.alloc(2 + text.length)
  out.writeUInt16BE(code, 0)
  text.copy(out, 2)
  return out
}

export function parseClose(payload) {
  if (payload.length < 2) return { code: null, reason: '' }
  return { code: payload.readUInt16BE(0), reason: payload.subarray(2).toString('utf8') }
}

/**
 * Puts data frames together into messages; control frames pass at once, as
 * they may come between the pieces of a message. `onMessage` gets
 * `{ opcode, data, frames }`, `frames` the raw bytes of every frame it took.
 */
export class MessageAssembler {
  constructor(onMessage) {
    this.onMessage = onMessage
    this.parts = null
  }

  frame(frame) {
    if (frame.opcode >= 8) return this.onMessage({ opcode: frame.opcode, data: frame.payload, frames: [frame.raw], rsv: frame.rsv })
    if (frame.opcode !== OP.continuation) this.parts = { opcode: frame.opcode, rsv: frame.rsv, data: [], frames: [] }
    if (!this.parts) return // a continuation of nothing: dropped, as the peer would
    this.parts.data.push(frame.payload)
    this.parts.frames.push(frame.raw)
    if (!frame.fin) return
    const { opcode, data, frames, rsv } = this.parts
    this.parts = null
    this.onMessage({ opcode, data: Buffer.concat(data), frames, rsv })
  }
}

/** Takes permessage-deflate out of a client's extension offer, so frames stay readable. */
export function withoutDeflate(value) {
  if (value === undefined) return undefined
  const kept = String(value)
    .split(',')
    .map(part => part.trim())
    .filter(part => part && !/^permessage-deflate\b/i.test(part) && !/^x-webkit-deflate-frame\b/i.test(part))
  return kept.length ? kept.join(', ') : undefined
}
