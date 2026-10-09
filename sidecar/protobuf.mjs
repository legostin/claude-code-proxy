// Protobuf without its schema, and the gRPC bodies that carry it: what a
// person reading a capture can still learn from the wire format alone (field
// numbers, varints, strings, nested messages), the way `protoc --decode_raw`
// shows it.

import { gunzipSync, inflateSync } from 'node:zlib'

const MAX_DEPTH = 16
const MAX_TEXT = 4000
const MAX_HEX = 64
const MAX_FIELD = 536870911

function readVarint(buf, pos) {
  let value = 0n
  let shift = 0n
  while (pos < buf.length) {
    const byte = buf[pos++]
    value |= BigInt(byte & 0x7f) << shift
    if ((byte & 0x80) === 0) return { value, pos }
    shift += 7n
    if (shift > 63n) return null
  }
  return null
}

/** The fields of one message in wire order, or null when the bytes are not one. */
export function decodeFields(buf) {
  const fields = []
  let pos = 0
  while (pos < buf.length) {
    const tag = readVarint(buf, pos)
    if (!tag) return null
    pos = tag.pos
    const field = Number(tag.value >> 3n)
    const wire = Number(tag.value & 7n)
    if (field < 1 || field > MAX_FIELD) return null
    if (wire === 0) {
      const v = readVarint(buf, pos)
      if (!v) return null
      pos = v.pos
      fields.push({ field, wire, value: v.value })
    } else if (wire === 1 || wire === 5) {
      const size = wire === 1 ? 8 : 4
      if (pos + size > buf.length) return null
      fields.push({ field, wire, bytes: buf.subarray(pos, pos + size) })
      pos += size
    } else if (wire === 2) {
      const n = readVarint(buf, pos)
      if (!n || n.value > BigInt(buf.length)) return null
      pos = n.pos
      const size = Number(n.value)
      if (pos + size > buf.length) return null
      fields.push({ field, wire, bytes: buf.subarray(pos, pos + size) })
      pos += size
    } else {
      // groups (3, 4) are long deprecated, and 6, 7 do not exist
      return null
    }
  }
  return fields
}

/** UTF-8 text a person can read, or null. */
function readableText(bytes) {
  let text
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    return null
  }
  // eslint-disable-next-line no-control-regex
  return /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(text) ? null : text
}

function hex(bytes) {
  const shown = bytes.subarray(0, MAX_HEX).toString('hex')
  return bytes.length > MAX_HEX ? `0x${shown}… (${bytes.length} bytes)` : `0x${shown}`
}

function quoted(text) {
  return text.length > MAX_TEXT ? `${JSON.stringify(text.slice(0, MAX_TEXT))}… (${text.length} characters)` : JSON.stringify(text)
}

function niceFloat(value, digits) {
  if (!Number.isFinite(value)) return null
  const abs = Math.abs(value)
  if (value !== 0 && (abs < 1e-4 || abs >= 1e12)) return null
  return String(Number(value.toPrecision(digits)))
}

function renderFields(fields, indent, depth) {
  const lines = []
  for (const f of fields) {
    const at = `${indent}${f.field}`
    if (f.wire === 0) {
      const signed = f.value >= 1n << 63n ? ` (${f.value - (1n << 64n)})` : ''
      lines.push(`${at}: ${f.value}${signed}`)
    } else if (f.wire === 5) {
      const float = niceFloat(f.bytes.readFloatLE(0), 7)
      lines.push(`${at}: ${f.bytes.readUInt32LE(0)}${float === null ? '' : ` (float ${float})`}`)
    } else if (f.wire === 1) {
      const double = niceFloat(f.bytes.readDoubleLE(0), 15)
      lines.push(`${at}: ${f.bytes.readBigUInt64LE(0)}${double === null ? '' : ` (double ${double})`}`)
    } else {
      const text = readableText(f.bytes)
      const nested = text === null && depth < MAX_DEPTH && f.bytes.length > 0 ? decodeFields(f.bytes) : null
      if (text !== null) lines.push(`${at}: ${quoted(text)}`)
      else if (nested) lines.push(`${at} {`, ...renderFields(nested, `${indent}  `, depth + 1), `${indent}}`)
      else lines.push(`${at}: ${hex(f.bytes)}`)
    }
  }
  return lines
}

/** A message as `field: value` lines, nested messages indented; null when not protobuf. */
export function renderProtobuf(buf) {
  const fields = decodeFields(buf)
  return fields ? renderFields(fields, '', 0).join('\n') : null
}

// --- gRPC: messages in 5-byte frames (flag, length) ----------------------------

/** gRPC-Web text is base64, possibly several pieces each padded. */
function fromBase64Pieces(buf) {
  const pieces = buf.toString('latin1').match(/[A-Za-z0-9+/]+={0,2}/g) ?? []
  return Buffer.concat(pieces.map(piece => Buffer.from(piece, 'base64')))
}

/** The frames of a gRPC (or gRPC-Web) body: compressed ones gunzipped, the trailer frame marked. */
export function grpcFrames(buf) {
  const frames = []
  let pos = 0
  while (pos + 5 <= buf.length) {
    const flag = buf[pos]
    const size = buf.readUInt32BE(pos + 1)
    const end = pos + 5 + size
    const isCut = end > buf.length
    let data = buf.subarray(pos + 5, Math.min(end, buf.length))
    const isCompressed = (flag & 1) === 1
    let isUnreadable = false
    if (isCompressed && !isCut) {
      try {
        data = gunzipSync(data)
      } catch {
        isUnreadable = true
      }
    }
    frames.push({ isTrailers: (flag & 0x80) !== 0, isCompressed, isCut, isUnreadable, data })
    if (isCut) break
    pos = end
  }
  return frames
}

function trailerPairs(data) {
  return data
    .toString('utf8')
    .split(/\r?\n/)
    .filter(line => line.includes(':'))
    .map(line => {
      const at = line.indexOf(':')
      return [line.slice(0, at).trim().toLowerCase(), line.slice(at + 1).trim()]
    })
}

/** The trailers a gRPC-Web body carries in its trailer frame, as pairs. */
export function grpcWebTrailers(buf, contentType) {
  const body = String(contentType).includes('grpc-web-text') ? fromBase64Pieces(buf) : buf
  const frame = grpcFrames(body).find(f => f.isTrailers)
  return frame ? trailerPairs(frame.data) : []
}

/** A gRPC body for reading: each message decoded as raw protobuf; null when it holds no frame. */
export function renderGrpc(buf, contentType) {
  const body = String(contentType).includes('grpc-web-text') ? fromBase64Pieces(buf) : buf
  const frames = grpcFrames(body)
  if (frames.length === 0) return null
  const blocks = []
  let n = 0
  for (const frame of frames) {
    if (frame.isTrailers) {
      blocks.push(['trailers', ...trailerPairs(frame.data).map(([k, v]) => `${k}: ${v}`)].join('\n'))
      continue
    }
    n += 1
    const notes = [`${frame.data.length} bytes`]
    if (frame.isCompressed) notes.push(frame.isUnreadable ? 'compressed, could not gunzip' : 'compressed')
    if (frame.isCut) notes.push('cut short in the record')
    const decoded = frame.isUnreadable ? null : renderProtobuf(frame.data)
    const text = decoded === null ? readableText(frame.data) : null
    blocks.push([`message ${n} (${notes.join(', ')})`, decoded ?? (text !== null ? quoted(text) : hex(frame.data))].filter(line => line !== '').join('\n'))
  }
  return blocks.join('\n\n')
}

/** Whether a content type carries gRPC or bare protobuf, and so has a view. */
export function viewKindOf(contentType) {
  const type = String(contentType ?? '').toLowerCase()
  if (type.startsWith('application/grpc')) return 'grpc'
  if (/^application\/(x-)?protobuf|^application\/x-google-protobuf|^application\/vnd\.google\.protobuf/.test(type)) return 'protobuf'
  return null
}

// --- binary messages (a WebSocket's): what they hold, without a schema ---------------

const MAX_VIEW = 4000

/** Messages each after its varint length, as protobuf's writeDelimitedTo writes them, filling `buf` exactly; null otherwise. */
function delimitedMessages(buf) {
  const messages = []
  let pos = 0
  while (pos < buf.length) {
    const size = readVarint(buf, pos)
    // an empty message in a run is a weak sign (a gRPC frame's zero bytes look like that)
    if (!size || size.value > BigInt(buf.length - size.pos) || (size.value === 0n && buf.length > 1)) return null
    const end = size.pos + Number(size.value)
    const fields = decodeFields(buf.subarray(size.pos, end))
    if (!fields) return null
    messages.push(fields)
    pos = end
  }
  return messages.length ? messages : null
}

/** gzip or zlib around the bytes: { kind, data } unpacked, or null. */
function unpacked(buf) {
  try {
    if (buf[0] === 0x1f && buf[1] === 0x8b) return { kind: 'gzip', data: gunzipSync(buf) }
    // a zlib header: deflate, a window size, and a check that makes the first two bytes a multiple of 31
    if ((buf[0] & 0x0f) === 8 && buf.length > 2 && buf.readUInt16BE(0) % 31 === 0) return { kind: 'zlib', data: inflateSync(buf) }
  } catch {}
  return null
}

function clipped(text) {
  return text.length > MAX_VIEW ? `${text.slice(0, MAX_VIEW)}… (${text.length} characters)` : text
}

/**
 * What a binary message holds, read without its schema: UTF-8 text; protobuf, bare,
 * after a varint length (writeDelimitedTo), or in a gRPC frame; gzip or zlib around
 * any of them. { kind, view } with `view` as protoc --decode_raw shows it, or null.
 */
export function binaryView(buf, depth = 0) {
  if (!buf.length || buf.length > 1 << 20) return null
  const text = readableText(buf)
  if (text !== null) return { kind: 'text', view: clipped(text) }
  const inner = depth === 0 ? unpacked(buf) : null
  if (inner) {
    const view = binaryView(inner.data, 1)
    return view ? { kind: `${inner.kind}, ${view.kind}`, view: view.view } : null
  }
  // a length that names exactly the bytes after it is the surest sign; bare protobuf decodes from almost anything
  if (buf.length >= 5 && (buf[0] === 0 || buf[0] === 1) && buf.readUInt32BE(1) === buf.length - 5) {
    const [frame] = grpcFrames(buf)
    const view = frame && !frame.isUnreadable ? renderProtobuf(frame.data) : null
    if (view !== null) return { kind: `protobuf in a gRPC frame${frame.isCompressed ? ', gzipped' : ''}`, view: clipped(view || '(empty)') }
  }
  const delimited = delimitedMessages(buf)
  if (delimited) {
    const views = delimited.map(fields => renderFields(fields, '', 0).join('\n') || '(empty)')
    return { kind: delimited.length > 1 ? `${delimited.length} protobuf messages, each after its length` : 'protobuf after its length', view: clipped(views.join('\n---\n')) }
  }
  const bare = renderProtobuf(buf)
  return bare ? { kind: 'protobuf', view: clipped(bare) } : null
}
