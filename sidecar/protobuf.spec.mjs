// node --test sidecar/protobuf.spec.mjs

import assert from 'node:assert/strict'
import { describe, test } from 'node:test'
import { gzipSync } from 'node:zlib'

import { grpcFrames, renderGrpc, renderProtobuf } from './protobuf.mjs'

const varint = n => {
  const out = []
  let v = BigInt(n)
  if (v < 0n) v += 1n << 64n
  do {
    let byte = Number(v & 0x7fn)
    v >>= 7n
    if (v > 0n) byte |= 0x80
    out.push(byte)
  } while (v > 0n)
  return Buffer.from(out)
}
const key = (field, wire) => varint((field << 3) | wire)
const len = (field, bytes) => Buffer.concat([key(field, 2), varint(bytes.length), bytes])
const frame = (message, flag = 0) => {
  const head = Buffer.alloc(5)
  head[0] = flag
  head.writeUInt32BE(message.length, 1)
  return Buffer.concat([head, message])
}

describe('raw protobuf', () => {
  test('shows varints, strings and nested messages by field number', () => {
    const inner = Buffer.concat([key(1, 0), varint(42), len(2, Buffer.from('nested'))])
    const message = Buffer.concat([key(1, 0), varint(150), len(2, Buffer.from('hello')), len(3, inner), key(4, 0), varint(-1)])
    assert.equal(
      renderProtobuf(message),
      ['1: 150', '2: "hello"', '3 {', '  1: 42', '  2: "nested"', '}', '4: 18446744073709551615 (-1)'].join('\n'),
    )
  })

  test('shows fixed-width numbers and bytes that are not text', () => {
    const fixed32 = Buffer.alloc(4)
    fixed32.writeFloatLE(1.5)
    const fixed64 = Buffer.alloc(8)
    fixed64.writeDoubleLE(2.25)
    const message = Buffer.concat([key(1, 5), fixed32, key(2, 1), fixed64, len(3, Buffer.from([0xff, 0x00, 0x10]))])
    assert.equal(renderProtobuf(message), ['1: 1069547520 (float 1.5)', '2: 4612248968380809216 (double 2.25)', '3: 0xff0010'].join('\n'))
  })

  test('answers null for what is not protobuf', () => {
    assert.equal(renderProtobuf(Buffer.from('{"json": true}')), null)
    assert.equal(renderProtobuf(Buffer.from([0x0a, 0x05, 0x61])), null)
  })
})

describe('gRPC bodies', () => {
  test('splits the length-prefixed messages, gunzipping the compressed ones', () => {
    const one = len(1, Buffer.from('first'))
    const two = len(1, Buffer.from('second'))
    const body = Buffer.concat([frame(one), frame(gzipSync(two), 1)])
    assert.deepEqual(
      grpcFrames(body).map(f => f.data.toString('latin1')),
      [one.toString('latin1'), two.toString('latin1')],
    )
    assert.equal(renderGrpc(body, 'application/grpc'), ['message 1 (7 bytes)', '1: "first"', '', 'message 2 (8 bytes, compressed)', '1: "second"'].join('\n'))
  })

  test('reads gRPC-Web, its trailer frame and its base64 text form', () => {
    const body = Buffer.concat([frame(len(1, Buffer.from('web'))), frame(Buffer.from('grpc-status:0\r\ngrpc-message:ok\r\n'), 0x80)])
    const rendered = ['message 1 (5 bytes)', '1: "web"', '', 'trailers', 'grpc-status: 0', 'grpc-message: ok'].join('\n')
    assert.equal(renderGrpc(body, 'application/grpc-web+proto'), rendered)
    assert.equal(renderGrpc(Buffer.from(body.toString('base64')), 'application/grpc-web-text'), rendered)
  })
})
