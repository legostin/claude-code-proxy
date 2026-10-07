// A QR code encoder for short text, so a phone can scan the proxy's setup
// address: byte mode, error correction level M, versions 1 to 10, the mask
// chosen by the standard's penalty rules (ISO/IEC 18004). A mod ships no
// dependencies, hence this file; it follows the structure of Project Nayuki's
// reference encoder.

export type QrCode = {
  /** Modules per side, the quiet zone not included. */
  size: number
  /** `modules[y][x]`: true for a dark module. */
  modules: boolean[][]
}

const MAX_VERSION = 10
// per version 1..10, error correction level M
const ECC_PER_BLOCK = [10, 16, 26, 18, 24, 16, 18, 22, 22, 26]
const BLOCKS = [1, 1, 1, 2, 2, 4, 4, 4, 5, 5]
const FORMAT_BITS_M = 0

function rawDataModules(version: number): number {
  let result = (16 * version + 128) * version + 64
  if (version >= 2) {
    const aligns = Math.floor(version / 7) + 2
    result -= (25 * aligns - 10) * aligns - 55
    if (version >= 7) result -= 36
  }
  return result
}

function dataCodewords(version: number): number {
  return Math.floor(rawDataModules(version) / 8) - ECC_PER_BLOCK[version - 1]! * BLOCKS[version - 1]!
}

function gfMultiply(x: number, y: number): number {
  let z = 0
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d)
    z ^= ((y >>> i) & 1) * x
  }
  return z
}

function rsDivisor(degree: number): number[] {
  const result = new Array<number>(degree).fill(0)
  result[degree - 1] = 1
  let root = 1
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < result.length; j++) {
      result[j] = gfMultiply(result[j]!, root)
      if (j + 1 < result.length) result[j]! ^= result[j + 1]!
    }
    root = gfMultiply(root, 0x02)
  }
  return result
}

function rsRemainder(data: readonly number[], divisor: readonly number[]): number[] {
  const result = divisor.map(() => 0)
  for (const byte of data) {
    const factor = byte ^ result.shift()!
    result.push(0)
    divisor.forEach((coefficient, i) => {
      result[i]! ^= gfMultiply(coefficient, factor)
    })
  }
  return result
}

/** Splits the data into blocks, adds each block's error correction, interleaves. */
function withErrorCorrection(data: readonly number[], version: number): number[] {
  const blockCount = BLOCKS[version - 1]!
  const eccLength = ECC_PER_BLOCK[version - 1]!
  const raw = Math.floor(rawDataModules(version) / 8)
  const shortBlocks = blockCount - (raw % blockCount)
  const shortLength = Math.floor(raw / blockCount)
  const divisor = rsDivisor(eccLength)
  const blocks: number[][] = []
  for (let i = 0, k = 0; i < blockCount; i++) {
    const block = data.slice(k, k + shortLength - eccLength + (i < shortBlocks ? 0 : 1))
    k += block.length
    const ecc = rsRemainder(block, divisor)
    if (i < shortBlocks) block.push(0)
    blocks.push([...block, ...ecc])
  }
  const result: number[] = []
  for (let i = 0; i < blocks[0]!.length; i++) {
    blocks.forEach((block, j) => {
      // the padding byte of a short block is not sent
      if (i !== shortLength - eccLength || j >= shortBlocks) result.push(block[i]!)
    })
  }
  return result
}

function alignmentPositions(version: number, size: number): number[] {
  if (version === 1) return []
  const count = Math.floor(version / 7) + 2
  const step = Math.ceil((version * 4 + 4) / (count * 2 - 2)) * 2
  const result = [6]
  for (let position = size - 7; result.length < count; position -= step) result.splice(1, 0, position)
  return result
}

function masked(mask: number, x: number, y: number): boolean {
  switch (mask) {
    case 0: return (x + y) % 2 === 0
    case 1: return y % 2 === 0
    case 2: return x % 3 === 0
    case 3: return (x + y) % 3 === 0
    case 4: return (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0
    case 5: return ((x * y) % 2) + ((x * y) % 3) === 0
    case 6: return (((x * y) % 2) + ((x * y) % 3)) % 2 === 0
    default: return (((x + y) % 2) + ((x * y) % 3)) % 2 === 0
  }
}

function penalty(modules: boolean[][]): number {
  const size = modules.length
  let score = 0
  const lines: string[] = []
  for (let y = 0; y < size; y++) lines.push(modules[y]!.map(dark => (dark ? '1' : '0')).join(''))
  for (let x = 0; x < size; x++) lines.push(modules.map(row => (row[x] ? '1' : '0')).join(''))
  for (const line of lines) {
    // runs of five or more of one color
    for (const run of line.match(/0{5,}|1{5,}/g) ?? []) score += 3 + run.length - 5
    // a pattern that looks like a finder, with light on either side
    const padded = `0000${line}0000`
    for (let i = 0; i + 11 <= padded.length; i++) {
      const window = padded.slice(i, i + 11)
      if (window === '10111010000' || window === '00001011101') score += 40
    }
  }
  // 2x2 blocks of one color
  for (let y = 0; y + 1 < size; y++) {
    for (let x = 0; x + 1 < size; x++) {
      const color = modules[y]![x]
      if (color === modules[y]![x + 1] && color === modules[y + 1]![x] && color === modules[y + 1]![x + 1]) score += 3
    }
  }
  // balance of dark and light
  const dark = modules.reduce((sum, row) => sum + row.filter(Boolean).length, 0)
  const total = size * size
  score += (Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1) * 10
  return score
}

export function encodeQr(text: string): QrCode {
  const bytes = [...new TextEncoder().encode(text)]
  let version = 1
  while (version <= MAX_VERSION && 4 + (version <= 9 ? 8 : 16) + bytes.length * 8 > dataCodewords(version) * 8) version++
  if (version > MAX_VERSION) throw new Error(`${bytes.length} bytes do not fit a version ${MAX_VERSION} QR code`)

  const bits: number[] = []
  const push = (value: number, length: number) => {
    for (let i = length - 1; i >= 0; i--) bits.push((value >>> i) & 1)
  }
  const capacity = dataCodewords(version) * 8
  push(0b0100, 4) // byte mode
  push(bytes.length, version <= 9 ? 8 : 16)
  for (const byte of bytes) push(byte, 8)
  push(0, Math.min(4, capacity - bits.length))
  push(0, (8 - (bits.length % 8)) % 8)
  for (let pad = 0xec; bits.length < capacity; pad ^= 0xec ^ 0x11) push(pad, 8)
  const data: number[] = []
  for (let i = 0; i < bits.length; i += 8) data.push(bits.slice(i, i + 8).reduce((byte, bit) => (byte << 1) | bit, 0))
  const codewords = withErrorCorrection(data, version)

  const size = version * 4 + 17
  const modules = Array.from({ length: size }, () => new Array<boolean>(size).fill(false))
  const isFunction = Array.from({ length: size }, () => new Array<boolean>(size).fill(false))
  const set = (x: number, y: number, dark: boolean) => {
    modules[y]![x] = dark
    isFunction[y]![x] = true
  }

  for (let i = 0; i < size; i++) {
    set(6, i, i % 2 === 0)
    set(i, 6, i % 2 === 0)
  }
  for (const [cx, cy] of [[3, 3], [size - 4, 3], [3, size - 4]] as const) {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) {
        const x = cx + dx
        const y = cy + dy
        const distance = Math.max(Math.abs(dx), Math.abs(dy))
        if (x >= 0 && x < size && y >= 0 && y < size) set(x, y, distance !== 2 && distance !== 4)
      }
    }
  }
  const aligns = alignmentPositions(version, size)
  for (let i = 0; i < aligns.length; i++) {
    for (let j = 0; j < aligns.length; j++) {
      const isFinderCorner = (i === 0 && j === 0) || (i === 0 && j === aligns.length - 1) || (i === aligns.length - 1 && j === 0)
      if (isFinderCorner) continue
      for (let dy = -2; dy <= 2; dy++) {
        for (let dx = -2; dx <= 2; dx++) set(aligns[i]! + dx, aligns[j]! + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1)
      }
    }
  }

  const drawFormat = (mask: number) => {
    const value = (FORMAT_BITS_M << 3) | mask
    let rem = value
    for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537)
    const formatBits = ((value << 10) | rem) ^ 0x5412
    const bit = (i: number) => ((formatBits >>> i) & 1) !== 0
    for (let i = 0; i <= 5; i++) set(8, i, bit(i))
    set(8, 7, bit(6))
    set(8, 8, bit(7))
    set(7, 8, bit(8))
    for (let i = 9; i < 15; i++) set(14 - i, 8, bit(i))
    for (let i = 0; i < 8; i++) set(size - 1 - i, 8, bit(i))
    for (let i = 8; i < 15; i++) set(8, size - 15 + i, bit(i))
    set(8, size - 8, true)
  }
  drawFormat(0)

  if (version >= 7) {
    let rem = version
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25)
    const versionBits = (version << 12) | rem
    for (let i = 0; i < 18; i++) {
      const dark = ((versionBits >>> i) & 1) !== 0
      const a = size - 11 + (i % 3)
      const b = Math.floor(i / 3)
      set(a, b, dark)
      set(b, a, dark)
    }
  }

  // the data, two columns at a time, zigzagging up and down from the right
  let index = 0
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5
    for (let vertical = 0; vertical < size; vertical++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j
        const isUpward = ((right + 1) & 2) === 0
        const y = isUpward ? size - 1 - vertical : vertical
        if (!isFunction[y]![x] && index < codewords.length * 8) {
          modules[y]![x] = ((codewords[index >>> 3]! >>> (7 - (index & 7))) & 1) === 1
          index++
        }
      }
    }
  }

  const applyMask = (mask: number) => {
    for (let y = 0; y < size; y++) {
      for (let x = 0; x < size; x++) {
        if (!isFunction[y]![x] && masked(mask, x, y)) modules[y]![x] = !modules[y]![x]
      }
    }
  }
  let best = 0
  let bestScore = Infinity
  for (let mask = 0; mask < 8; mask++) {
    applyMask(mask)
    drawFormat(mask)
    const score = penalty(modules)
    if (score < bestScore) {
      best = mask
      bestScore = score
    }
    applyMask(mask)
  }
  applyMask(best)
  drawFormat(best)
  return { size, modules }
}

const DARK = 0x000000
const LIGHT = 0xffffff
const UPPER_HALF = 0x2580

/** The module at (x, y), with `quiet` light modules around the code. */
function moduleAt(qr: QrCode, quiet: number, x: number, y: number): boolean {
  const mx = x - quiet
  const my = y - quiet
  return mx >= 0 && my >= 0 && mx < qr.size && my < qr.size && qr.modules[my]![mx]!
}

const BASE64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

export function toBase64(bytes: Uint8Array): string {
  let out = ''
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i]!
    const b = bytes[i + 1]
    const c = bytes[i + 2]
    const n = (a << 16) | ((b ?? 0) << 8) | (c ?? 0)
    out += BASE64[(n >>> 18) & 63]! + BASE64[(n >>> 12) & 63]!
    out += b === undefined ? '=' : BASE64[(n >>> 6) & 63]!
    out += c === undefined ? '=' : BASE64[n & 63]!
  }
  return out
}

/**
 * The code as a terminal Raster: one cell holds two modules, the upper half
 * block painted with the top one and its background with the bottom one, in
 * black and white whatever the terminal's theme, so the modules come out
 * square and the right way round.
 */
export function qrRaster(qr: QrCode, quiet = 2): { columns: number; rows: number; cells: string } {
  const columns = qr.size + quiet * 2
  const rows = Math.ceil(columns / 2)
  const words = new Uint32Array(columns * rows * 3)
  for (let row = 0; row < rows; row++) {
    for (let x = 0; x < columns; x++) {
      const at = (row * columns + x) * 3
      words[at] = UPPER_HALF
      words[at + 1] = moduleAt(qr, quiet, x, row * 2) ? DARK : LIGHT
      words[at + 2] = moduleAt(qr, quiet, x, row * 2 + 1) ? DARK : LIGHT
    }
  }
  // Uint32Array stores in the platform's order; every engine this runs on is little-endian
  return { columns, rows, cells: toBase64(new Uint8Array(words.buffer)) }
}

/** The code as SVG markup, dark modules on a white square. */
export function qrSvg(qr: QrCode, quiet = 4): string {
  const side = qr.size + quiet * 2
  const path: string[] = []
  for (let y = 0; y < qr.size; y++) {
    for (let x = 0; x < qr.size; x++) {
      if (qr.modules[y]![x]) path.push(`M${x + quiet} ${y + quiet}h1v1h-1z`)
    }
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${side} ${side}" shape-rendering="crispEdges"><rect width="${side}" height="${side}" fill="#fff"/><path d="${path.join('')}" fill="#000"/></svg>`
}
