import { describe, expect, test } from 'claude-code/testing'

import { describeRule, matchesRequest, matchesResponse, parseRules, ruleErrors, statusMatcher } from '../shared/rules.mjs'

const request = (path: string, extra: Record<string, unknown> = {}) => ({
  method: 'GET',
  url: `https://api.example.com${path}`,
  host: 'api.example.com',
  path,
  headers: [['Accept', 'application/json']] as [string, string][],
  ...extra,
})

describe('rules', () => {
  test('a valid file reads with no errors; a broken rule keeps its errors', () => {
    const parsed = parseRules(
      JSON.stringify({
        rules: [
          { id: 'ok', match: { path: '/v1/*' }, request: [{ type: 'delay', ms: 10 }] },
          { id: 'ok', request: [{ type: 'delay', ms: 10 }] },
          { id: 'bad id!', response: [{ type: 'respond', status: 200 }] },
        ],
      }),
    )
    expect(parsed.errors).toEqual([])
    expect(parsed.rules[0]!.errors).toEqual([])
    expect(parsed.rules[1]!.errors).toEqual(['rule ok: another rule has this id'])
    expect(parsed.rules[2]!.errors.join('\n')).toContain('id must be')
    expect(parsed.rules[2]!.errors.join('\n')).toContain('type must be one of')
    expect(parseRules('{').errors[0]).toContain('not valid JSON')
    expect(parseRules('').rules).toEqual([])
  })

  test('action fields are checked per type', () => {
    expect(ruleErrors({ id: 'a', request: [{ type: 'mapRemote' }] })[0]).toContain('give at least one of scheme, host, port, path')
    expect(ruleErrors({ id: 'a', request: [{ type: 'setBody', text: 'x', json: {} }] })[0]).toContain('exactly one of text, json, file')
    expect(ruleErrors({ id: 'a', response: [{ type: 'fail', kind: 'explode' }] })[0]).toContain('kind must be reset, close or timeout')
    expect(ruleErrors({ id: 'a', match: { status: '5xx' }, request: [{ type: 'delay', ms: 1 }] }).join()).toContain('response actions only')
    expect(ruleErrors({ id: 'a' })[0]).toContain('at least one action')
    expect(ruleErrors({ id: 'a', match: { path: '/files (1)/*' }, response: [{ type: 'setStatus', status: 200 }] })).toEqual([])
    expect(ruleErrors({ id: 'a', match: { path: 're:(' }, response: [{ type: 'setStatus', status: 200 }] })[0]).toContain('match.path')
    // a path is a glob, never mistaken for an expression
    expect(ruleErrors({ id: 'a', match: { path: '/v1/login' }, response: [{ type: 'setStatus', status: 200 }] })).toEqual([])
  })

  test('matching: globs, regexes, methods, headers, query, body, response', () => {
    const rule = (match: object) => ({ id: 'r', match, response: [{ type: 'setStatus', status: 200 }] })
    expect(matchesRequest(rule({ path: '/v1/*' }), request('/v1/items?x=1'))).toBe(true)
    expect(matchesRequest(rule({ path: '/v1/*' }), request('/v2/items'))).toBe(false)
    expect(matchesRequest(rule({ path: 're:^/v\\d+/' }), request('/v9/x'))).toBe(true)
    expect(matchesRequest(rule({ path: '/v1/login' }), request('/v1/login'))).toBe(true)
    expect(matchesRequest(rule({ host: '*.example.com' }), request('/'))).toBe(true)
    expect(matchesRequest(rule({ host: '*.example.com' }), { ...request('/'), host: 'example.com' })).toBe(true)
    expect(matchesRequest(rule({ methods: ['post'] }), request('/'))).toBe(false)
    expect(matchesRequest(rule({ headers: { accept: '*json*' } }), request('/'))).toBe(true)
    expect(matchesRequest(rule({ query: { page: '2' } }), request('/list?page=2'))).toBe(true)
    expect(matchesRequest(rule({ query: { page: '2' } }), request('/list?page=3'))).toBe(false)
    expect(matchesRequest(rule({ bodyContains: 'ann' }), request('/', { body: '{"user":"ann"}' }))).toBe(true)
    expect(matchesResponse(rule({ status: '5xx' }), { status: 503, contentType: null })).toBe(true)
    expect(matchesResponse(rule({ contentType: 'json' }), { status: 200, contentType: 'text/html' })).toBe(false)
    expect(statusMatcher('>=400')!(404)).toBe(true)
  })

  test('a rule reads as one line', () => {
    expect(
      describeRule({
        id: 'r',
        match: { methods: ['get'], host: 'api.example.com', path: '/v1/feed*' },
        request: [{ type: 'delay', ms: 1500, msMax: 3000 }, { type: 'setHeader', name: 'X-Debug', value: '1' }],
        response: [{ type: 'setStatus', status: 503 }, { type: 'fail', kind: 'reset' }],
        stop: true,
      }),
    ).toBe(
      'GET · host api.example.com · path /v1/feed* → before sending: wait 1.5 s to 3 s, set header X-Debug: 1; on the response: set status 503, reset the connection; then stop',
    )
    expect(describeRule({ id: 'r', request: [{ type: 'mapRemote', host: 'localhost', port: 3000 }] })).toBe('every request → before sending: send to localhost:3000')
  })
})
