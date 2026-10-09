// node --test sidecar/websocket.spec.mjs

import assert from 'node:assert/strict'
import { describe, test } from 'node:test'

import { acceptKey, closePayload, encodeFrame, FrameReader, MessageAssembler, OP, parseClose, withoutDeflate } from './websocket.mjs'

const read = bytes => {
  const frames = []
  new FrameReader(frame => frames.push(frame)).push(Buffer.from(bytes))
  return frames
}

describe('WebSocket frames', () => {
  test('reads the examples of RFC 6455 5.7', () => {
    const [plain] = read([0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f])
    assert.equal(plain.opcode, OP.text)
    assert.equal(plain.fin, true)
    assert.equal(plain.payload.toString(), 'Hello')
    const [masked] = read([0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58])
    assert.equal(masked.isMasked, true)
    assert.equal(masked.payload.toString(), 'Hello')
    const [ping] = read([0x89, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f])
    assert.equal(ping.opcode, OP.ping)
  })

  test('keeps the bytes of each frame as they came, and waits for the rest of one split anywhere', () => {
    const bytes = Buffer.concat([encodeFrame({ opcode: OP.text, payload: Buffer.from('one') }), encodeFrame({ opcode: OP.binary, payload: Buffer.alloc(300, 7), isMasked: true })])
    const frames = []
    const reader = new FrameReader(frame => frames.push(frame))
    for (const byte of bytes) reader.push(Buffer.from([byte]))
    assert.equal(frames.length, 2)
    assert.equal(frames[0].payload.toString(), 'one')
    assert.deepEqual(frames[1].payload, Buffer.alloc(300, 7))
    assert.deepEqual(Buffer.concat(frames.map(f => f.raw)), bytes)
    assert.equal(reader.pending, 0)
  })

  test('writes 16- and 64-bit lengths, masked toward a server', () => {
    for (const size of [125, 126, 65535, 65536, 70000]) {
      const payload = Buffer.alloc(size, size % 251)
      const [frame] = read(encodeFrame({ opcode: OP.binary, payload, isMasked: size % 2 === 0 }))
      assert.equal(frame.payload.length, size)
      assert.deepEqual(frame.payload, payload)
      assert.equal(frame.isMasked, size % 2 === 0)
    }
  })

  test('refuses a frame larger than allowed', () => {
    const reader = new FrameReader(() => {}, { maxFrame: 10 })
    assert.throws(() => reader.push(encodeFrame({ opcode: OP.text, payload: Buffer.alloc(11) })), /larger than allowed/)
  })

  test('puts fragments together, with control frames passing between them', () => {
    const messages = []
    const assembler = new MessageAssembler(message => messages.push(message))
    const frames = [
      encodeFrame({ opcode: OP.text, payload: Buffer.from('Hel'), fin: false }),
      encodeFrame({ opcode: OP.ping, payload: Buffer.from('p') }),
      encodeFrame({ opcode: OP.continuation, payload: Buffer.from('lo') }),
    ]
    new FrameReader(frame => assembler.frame(frame)).push(Buffer.concat(frames))
    assert.deepEqual(
      messages.map(m => [m.opcode, m.data.toString(), m.frames.length]),
      [
        [OP.ping, 'p', 1],
        [OP.text, 'Hello', 2],
      ],
    )
  })

  test('a close carries its code and reason', () => {
    assert.deepEqual(parseClose(closePayload(4001, 'bye')), { code: 4001, reason: 'bye' })
    assert.deepEqual(parseClose(Buffer.alloc(0)), { code: null, reason: '' })
  })

  test('answers a key as RFC 6455 1.3 does, and offers no compression', () => {
    assert.equal(acceptKey('dGhlIHNhbXBsZSBub25jZQ=='), 's3pPLMBiTxaQ9kYGzzhZRbK+xOo=')
    assert.equal(withoutDeflate('permessage-deflate; client_max_window_bits'), undefined)
    assert.equal(withoutDeflate('permessage-deflate, x-custom'), 'x-custom')
    assert.equal(withoutDeflate(undefined), undefined)
  })
})
