import { describe, expect, test } from 'claude-code/testing'

import { encodeQr, qrRaster, qrSvg, toBase64 } from '../hooks/qr'

const URL = 'http://10.7.9.5:8899/'

// Decoded with jsQR for versions 1 to 10 while this encoder was written; these
// tests hold the structure every reader relies on.
describe('the QR encoder', () => {
  test('picks the smallest version that holds the text at level M', () => {
    expect(encodeQr('A').size).toBe(21)
    expect(encodeQr(URL).size).toBe(25)
    expect(encodeQr('x'.repeat(213)).size).toBe(57)
    expect(() => encodeQr('x'.repeat(214))).toThrow()
  })

  test('draws the finder patterns, timing lines and the dark module', () => {
    const { size, modules } = encodeQr(URL)
    const at = (x: number, y: number) => modules[y]![x]!
    for (const [ox, oy] of [[0, 0], [size - 7, 0], [0, size - 7]] as const) {
      for (let i = 0; i < 7; i++) {
        expect(at(ox + i, oy)).toBe(true)
        expect(at(ox + i, oy + 6)).toBe(true)
        expect(at(ox, oy + i)).toBe(true)
      }
      for (let i = 1; i < 6; i++) expect(at(ox + i, oy + 1)).toBe(false)
      expect(at(ox + 3, oy + 3)).toBe(true)
    }
    for (let i = 8; i < size - 8; i++) {
      expect(at(i, 6)).toBe(i % 2 === 0)
      expect(at(6, i)).toBe(i % 2 === 0)
    }
    expect(at(8, size - 8)).toBe(true)
  })

  test('writes both copies of the format information alike', () => {
    const { size, modules } = encodeQr(URL)
    const at = (x: number, y: number) => modules[y]![x]!
    const first = [0, 1, 2, 3, 4, 5, 7, 8].map(y => at(8, y)).concat([7, 5, 4, 3, 2, 1, 0].map(x => at(x, 8)))
    const second = Array.from({ length: 8 }, (_, i) => at(size - 1 - i, 8)).concat(
      Array.from({ length: 7 }, (_, i) => at(8, size - 7 + i)),
    )
    expect(first).toEqual(second)
  })

  test('packs two modules per terminal cell, black on white', () => {
    const raster = qrRaster(encodeQr(URL))
    expect([raster.columns, raster.rows]).toEqual([29, 15])
    // three 32-bit words per cell, padded base64
    expect(raster.cells.length).toBe((Math.ceil((29 * 15 * 12) / 3) * 4))
    expect(toBase64(Uint8Array.of(1, 2, 3, 4))).toBe('AQIDBA==')
    expect(toBase64(Uint8Array.of(0x25, 0x80, 0, 0))).toBe('JYAAAA==')
  })

  test('draws SVG on a white square with a quiet zone', () => {
    const svg = qrSvg(encodeQr(URL))
    expect(svg).toStartWith('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 33 33"')
    expect(svg).toContain('<rect width="33" height="33" fill="#fff"/>')
    expect(svg).toContain('M4 4h1v1h-1z')
  })
})
