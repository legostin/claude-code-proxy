import { describe, expect, test } from 'claude-code/testing'

import {
  clip,
  filterFlows,
  type FlowDetail,
  flowTable,
  flowUrl,
  grpcLabel,
  isFailure,
  mergeFlows,
  parseEvent,
  parseFilter,
  splitLines,
  statusLabel,
  toCurl,
  typeOf,
} from '../hooks/flows'
import type { ProxyFlow } from '../types'

function flow(id: number, extra: Partial<ProxyFlow> = {}): ProxyFlow {
  return {
    id,
    ts: 0,
    kind: 'http',
    method: 'GET',
    scheme: 'https',
    host: 'api.example.com',
    port: 443,
    path: `/v1/items/${id}`,
    status: 200,
    reqSize: 0,
    resSize: 100,
    durationMs: 12,
    contentType: 'application/json',
    state: 'done',
    error: null,
    errorCode: null,
    client: '127.0.0.1',
    ...extra,
  }
}

const FLOWS: ProxyFlow[] = [
  flow(1),
  flow(2, { method: 'POST', path: '/v1/login', status: 401 }),
  flow(3, { host: 'cdn.example.com', path: '/logo.png', contentType: 'image/png' }),
  flow(4, { host: 'example.com', path: '/', contentType: 'text/html; charset=utf-8'.split(';')[0]! }),
  flow(5, { status: 503, host: 'other.dev', path: '/health' }),
  flow(6, { kind: 'tunnel', method: 'CONNECT', host: 'gateway.icloud.com', path: '', status: null, state: 'error', errorCode: 'client-rejected-cert', error: 'refused' }),
  flow(7, { status: null, state: 'receiving', path: '/stream', contentType: 'text/event-stream' }),
  flow(8, { kind: 'ws', path: '/socket', status: 101, contentType: null }),
]

const ids = (query: string) => filterFlows(FLOWS, query).map(f => f.id)

describe('the line protocol', () => {
  test('reassembles lines split across chunks', () => {
    let rest = ''
    const lines: string[] = []
    for (const chunk of ['{"t":"lo', 'g","level":"info","message":"a"}\n{"t":', '"log","level":"info","message":"b"}\n\n{"t"']) {
      const split = splitLines(rest, chunk)
      rest = split.rest
      lines.push(...split.lines)
    }
    expect(lines.map(line => parseEvent(line))).toEqual([
      { t: 'log', level: 'info', message: 'a' },
      { t: 'log', level: 'info', message: 'b' },
    ])
    expect(rest).toBe('{"t"')
  })

  test('ignores lines that are not events', () => {
    expect(parseEvent('not json')).toBeNull()
    expect(parseEvent('{"no":"type"}')).toBeNull()
  })

  test('merges updates by id, oldest first, keeping the newest max', () => {
    const merged = mergeFlows([flow(1), flow(2)], [flow(2, { status: 500 }), flow(3)], 2)
    expect(merged.map(f => f.id)).toEqual([2, 3])
    expect(merged[0]!.status).toBe(500)
  })
})

describe('the filter language', () => {
  test('free text matches the URL', () => {
    expect(ids('login')).toEqual([2])
    expect(ids('LOGIN')).toEqual([2])
  })

  test('keys narrow by method, status, host, type and path', () => {
    expect(ids('method:POST')).toEqual([2])
    expect(ids('method:get,post status:2xx')).toEqual([1, 3, 4])
    expect(ids('status:4xx')).toEqual([2])
    expect(ids('status:>=400')).toEqual([2, 5])
    expect(ids('status:500-599')).toEqual([5])
    expect(ids('status:401')).toEqual([2])
    expect(ids('host:*.example.com')).toEqual([1, 2, 3, 4, 7, 8])
    expect(ids('host:cdn')).toEqual([3])
    expect(ids('type:img')).toEqual([3])
    expect(ids('type:image,html')).toEqual([3, 4])
    expect(ids('path:/v1')).toEqual([1, 2])
  })

  test('is: names states, and - negates any term', () => {
    expect(ids('is:error')).toEqual([2, 5, 6])
    expect(ids('is:rejected')).toEqual([6])
    expect(ids('is:pending')).toEqual([7])
    expect(ids('is:tunnel')).toEqual([6])
    expect(ids('is:ws')).toEqual([8])
    expect(ids('-host:*.example.com')).toEqual([5, 6])
    expect(ids('host:*.example.com -is:error -type:ws')).toEqual([1, 3, 4, 7])
  })

  test('quoted text keeps its spaces; unknown terms are reported, not fatal', () => {
    expect(filterFlows([flow(1, { path: '/a b' })], '"a b"')).toHaveLength(1)
    const parsed = parseFilter('status:abc is:nonsense login')
    expect(parsed.errors).toEqual(['status:abc', 'is:nonsense'])
    expect(parsed.terms).toHaveLength(1)
  })

  test('an empty query keeps everything', () => {
    expect(ids('   ')).toHaveLength(FLOWS.length)
  })
})

describe('formats', () => {
  test('URLs drop default ports and name tunnels and sockets', () => {
    expect(flowUrl(flow(1))).toBe('https://api.example.com/v1/items/1')
    expect(flowUrl(flow(1, { scheme: 'http', port: 8080 }))).toBe('http://api.example.com:8080/v1/items/1')
    expect(flowUrl(FLOWS[5]!)).toBe('gateway.icloud.com:443')
    expect(flowUrl(FLOWS[7]!)).toBe('wss://api.example.com/socket')
  })

  test('status labels say CERT, ERR and pending', () => {
    expect(statusLabel(FLOWS[5]!)).toBe('CERT')
    expect(statusLabel(flow(9, { status: null, state: 'error', errorCode: 'upstream' }))).toBe('ERR')
    expect(statusLabel(FLOWS[6]!)).toBe('…')
    expect(typeOf(FLOWS[7]!)).toBe('ws')
  })

  test('the model table has one line per flow with ids and errors', () => {
    const table = flowTable([FLOWS[1]!, FLOWS[5]!])
    expect(table).toMatch(/^#2 {2}POST {4}401 {2}https:\/\/api\.example\.com\/v1\/login/)
    expect(table).toContain('#6  CONNECT CERT gateway.icloud.com:443')
    expect(table).toContain('! refused')
  })

  test('curl keeps headers and inlines a short text body', () => {
    const detail: FlowDetail = {
      ...flow(2, { method: 'POST' }),
      url: 'https://api.example.com/v1/login',
      reqHeaders: [
        ['Host', 'api.example.com'],
        ['Content-Type', 'application/json'],
        ['Accept-Encoding', 'gzip'],
        ['Content-Length', '13'],
        ['X-Note', "it's"],
      ],
      resHeaders: [],
      req: { file: '/tmp/2.req', size: 13, stored: 13, isTruncated: false, encoding: null, isDecoded: false },
      res: null,
    }
    const curl = toCurl(detail, '{"user":"me"}')
    expect(curl).toContain("-X POST")
    expect(curl).toContain("'https://api.example.com/v1/login'")
    expect(curl).toContain("-H 'Content-Type: application/json'")
    expect(curl).toContain(`-H 'X-Note: it'\\''s'`)
    expect(curl).toContain('--compressed')
    expect(curl).toContain(`--data-raw '{"user":"me"}'`)
    expect(curl).not.toContain('Host:')
    expect(curl).not.toContain('Content-Length')
    expect(toCurl(detail, null)).toContain("--data-binary @'/tmp/2.req'")
  })

  test('clip cuts by lines and characters and says so', () => {
    expect(clip('a\nb\nc', 2, 100)).toEqual({ text: 'a\nb', isClipped: true })
    expect(clip('abcdef', 10, 3)).toEqual({ text: 'abc', isClipped: true })
    expect(clip('ok', 10, 10)).toEqual({ text: 'ok', isClipped: false })
  })
})

describe('gRPC and HTTP/2', () => {
  const ok = flow(1, { contentType: 'application/grpc', httpVersion: '2', grpcStatus: 0 })
  const missing = flow(2, { contentType: 'application/grpc+proto', httpVersion: '2', grpcStatus: 5, grpcMessage: 'no such greeter' })
  const plain = flow(3, { httpVersion: '1.1' })

  test('a gRPC call is its own type, and a non-zero status is a failure', () => {
    expect(typeOf(ok)).toBe('grpc')
    expect(isFailure(ok)).toBe(false)
    expect(isFailure(missing)).toBe(true)
    expect(grpcLabel(missing)).toBe('gRPC NOT_FOUND: no such greeter')
    expect(grpcLabel(plain)).toBeNull()
  })

  test('the filter finds HTTP/2, gRPC and failed calls', () => {
    const all = [ok, missing, plain]
    expect(filterFlows(all, 'is:h2').map(f => f.id)).toEqual([1, 2])
    expect(filterFlows(all, 'type:grpc is:error').map(f => f.id)).toEqual([2])
    expect(parseFilter('is:grpc').errors).toEqual([])
  })

  test('the model table says why a gRPC call failed', () => {
    expect(flowTable([missing])).toContain('! gRPC NOT_FOUND: no such greeter')
    expect(flowTable([ok])).not.toContain('!')
  })
})
