import { describe, expect, test } from 'claude-code/testing'

import { diffRequests } from '../hooks/diff'
import { toHar } from '../hooks/har'
import { bodyForModel, busiestHosts, clipValue, jsonPath, modelUrl, splitBudget } from '../hooks/model'
import type { FlowDetail } from '../hooks/flows'
import type { ProxyFlow } from '../types'

function flow(id: number, extra: Partial<ProxyFlow> = {}): ProxyFlow {
  return {
    id,
    ts: 1_700_000_000_000,
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

function detail(id: number, extra: Partial<FlowDetail> = {}): FlowDetail {
  return {
    ...flow(id),
    url: `https://api.example.com/v1/items/${id}`,
    reqHeaders: [['Accept', 'application/json']],
    resHeaders: [['Content-Type', 'application/json']],
    req: null,
    res: null,
    ...extra,
  }
}

describe('what the model is shown', () => {
  test('a long URL keeps its host and path and cuts the query first', () => {
    const long = flow(1, { path: `/v4/threatListUpdates:fetch?$req=${'A'.repeat(400)}&key=abc` })
    const shown = modelUrl(long, 120)
    expect(shown.length).toBeLessThanOrEqual(120)
    expect(shown.startsWith('https://api.example.com/v4/threatListUpdates:fetch?$req=AAA')).toBe(true)
    expect(shown).toMatch(/…\(\+\d+\)$/)
    expect(modelUrl(flow(2), 120)).toBe('https://api.example.com/v1/items/2')
    const longPath = flow(3, { path: `/${'segment/'.repeat(40)}end` })
    expect(modelUrl(longPath, 80).length).toBeLessThanOrEqual(80)
  })

  test('a long value is cut and says how long it was', () => {
    expect(clipValue('short', 10)).toBe('short')
    expect(clipValue('x'.repeat(50), 10)).toBe('xxxxxxxxxx…(50 chars)')
  })

  test('one budget is shared by the bodies: a small one keeps all it needs', () => {
    expect(splitBudget([100, 50_000], 12_000)).toEqual([100, 11_900])
    expect(splitBudget([20_000, 50_000], 12_000)).toEqual([6000, 6000])
    expect(splitBudget([0, 0], 12_000)).toEqual([0, 0])
  })

  test('JSON is pretty when it fits and compact when it does not', () => {
    const text = JSON.stringify({ items: [{ id: 1, name: 'one' }, { id: 2, name: 'two' }] })
    expect(bodyForModel(text, 'application/json', 1000).text).toContain('\n  "items": [')
    const compact = bodyForModel(text, 'application/json', 40)
    expect(compact.text.startsWith('{"items":[{"id":1')).toBe(true)
    expect(compact.isCut).toBe(true)
    expect(bodyForModel('plain words', 'text/plain', 5)).toEqual({ text: 'plain', isCut: true })
  })

  test('a JSON path picks one part of a body', () => {
    const value = { data: { items: [{ id: 1, tags: ['a'] }, { id: 2, tags: ['b', 'c'] }] } }
    expect(jsonPath(value, 'data.items[1].tags')).toEqual({ value: ['b', 'c'] })
    expect(jsonPath(value, '$.data.items.0.id')).toEqual({ value: 1 })
    expect(jsonPath(value, 'data.missing.x')).toEqual({ error: 'data.missing has no x' })
  })

  test('the busiest hosts, most requests first', () => {
    const flows = [flow(1), flow(2), flow(3, { host: 'cdn.example.com' }), flow(4, { host: 'ads.example.net' }), flow(5, { host: 'cdn.example.com' }), flow(6)]
    expect(busiestHosts(flows, 2)).toEqual([
      ['api.example.com', 3],
      ['cdn.example.com', 2],
    ])
  })
})

describe('comparing two requests', () => {
  test('names what differs: method, query, headers, status and JSON fields', () => {
    const a = {
      detail: detail(1, { method: 'POST', url: 'https://api.example.com/v1/login?client=ios&v=1', reqHeaders: [['Authorization', 'Bearer old'], ['Accept', 'application/json']], status: 200 }),
      reqText: JSON.stringify({ user: 'tester', remember: true }),
      resText: JSON.stringify({ token: 'abc', user: { id: 7 } }),
    }
    const b = {
      detail: detail(2, { method: 'POST', url: 'https://api.example.com/v1/login?client=android&v=1', reqHeaders: [['Accept', 'application/json'], ['X-Debug', '1']], status: 401 }),
      reqText: JSON.stringify({ user: 'tester' }),
      resText: JSON.stringify({ error: 'invalid_credentials' }),
    }
    const lines = diffRequests(a, b).join('\n')
    expect(lines).toContain('status: 200 → 401')
    expect(lines).toContain('query client: "ios" → "android"')
    expect(lines).toContain('request header Authorization: only in #1')
    expect(lines).toContain('request header X-Debug: only in #2 ("1")')
    expect(lines).toContain('request body .remember: true → (absent)')
    expect(lines).toContain('response body .token: "abc" → (absent)')
    expect(lines).toContain('response body .error: (absent) → "invalid_credentials"')
    expect(lines).not.toContain('Accept')
  })

  test('says so when two requests are alike', () => {
    const one = { detail: detail(1), reqText: null, resText: '{"a":1}' }
    expect(diffRequests(one, { ...one, detail: detail(2, { url: one.detail.url, path: one.detail.path }) })).toEqual(['no difference in method, URL, headers, status or bodies'])
  })
})

describe('HAR', () => {
  test('writes HAR 1.2 entries with headers, query, bodies and timing', () => {
    const har = toHar(
      [
        {
          detail: detail(1, {
            method: 'POST',
            url: 'https://api.example.com/v1/login?client=ios',
            httpVersion: '2',
            statusMessage: 'Unauthorized',
            status: 401,
            durationMs: 87,
            reqHeaders: [['Content-Type', 'application/json']],
            resHeaders: [['Content-Type', 'application/json']],
          }),
          reqText: '{"user":"tester"}',
          resText: '{"error":"invalid"}',
        },
      ],
      '1.0.0',
    )
    const entry = har.log.entries[0]!
    expect(har.log.version).toBe('1.2')
    expect(har.log.creator).toEqual({ name: 'Wirepane', version: '1.0.0' })
    expect(entry.request.method).toBe('POST')
    expect(entry.request.httpVersion).toBe('HTTP/2')
    expect(entry.request.queryString).toEqual([{ name: 'client', value: 'ios' }])
    expect(entry.request.postData).toEqual({ mimeType: 'application/json', text: '{"user":"tester"}' })
    expect(entry.response.status).toBe(401)
    expect(entry.response.content).toEqual({ size: 100, mimeType: 'application/json', text: '{"error":"invalid"}' })
    expect(entry.time).toBe(87)
    expect(entry.startedDateTime).toBe(new Date(1_700_000_000_000).toISOString())
  })
})
