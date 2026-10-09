// Two captured requests side by side: what differs, one line each, in the
// order a person checks (method and URL, query, headers, status, bodies).

import type { FlowDetail } from './flows'

export type Exchange = { detail: FlowDetail; reqText: string | null; resText: string | null }

// headers that differ between any two requests and say nothing
const NOISE = new Set(['date', 'age', 'x-wirepane-replay'])
const MAX_LINES = 60

function show(value: unknown): string {
  if (value === undefined) return '(absent)'
  const text = JSON.stringify(value)
  return text.length > 80 ? `${text.slice(0, 79)}…` : text
}

function headerMap(headers: readonly [string, string][]): Map<string, { name: string; value: string }> {
  const out = new Map<string, { name: string; value: string }>()
  for (const [name, value] of headers) {
    const key = name.toLowerCase()
    const had = out.get(key)
    out.set(key, { name: had?.name ?? name, value: had ? `${had.value}, ${value}` : value })
  }
  return out
}

function diffHeaders(where: string, a: readonly [string, string][], b: readonly [string, string][], ids: [string, string], out: string[]) {
  const left = headerMap(a)
  const right = headerMap(b)
  for (const key of new Set([...left.keys(), ...right.keys()])) {
    if (NOISE.has(key)) continue
    const x = left.get(key)
    const y = right.get(key)
    if (x && !y) out.push(`${where} ${x.name}: only in ${ids[0]} (${show(x.value)})`)
    else if (!x && y) out.push(`${where} ${y.name}: only in ${ids[1]} (${show(y.value)})`)
    else if (x && y && x.value !== y.value) out.push(`${where} ${x.name}: ${show(x.value)} → ${show(y.value)}`)
  }
}

function diffJson(where: string, path: string, a: unknown, b: unknown, out: string[]) {
  if (out.length > MAX_LINES) return
  const isObject = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object'
  if (isObject(a) && isObject(b) && Array.isArray(a) === Array.isArray(b)) {
    for (const key of new Set([...Object.keys(a), ...Object.keys(b)])) {
      diffJson(where, Array.isArray(a) ? `${path}[${key}]` : `${path}.${key}`, a[key], b[key], out)
    }
    return
  }
  if (JSON.stringify(a) !== JSON.stringify(b)) out.push(`${where} ${path || '(the whole)'}: ${show(a)} → ${show(b)}`)
}

function parse(text: string | null): { value: unknown } | null {
  if (text === null) return null
  try {
    return { value: JSON.parse(text) }
  } catch {
    return null
  }
}

function diffBodies(where: string, a: string | null, b: string | null, ids: [string, string], out: string[]) {
  if (a === b) return
  if (a === null || a === '') return void out.push(`${where}: only in ${ids[1]} (${b?.length ?? 0} chars)`)
  if (b === null || b === '') return void out.push(`${where}: only in ${ids[0]} (${a.length} chars)`)
  const x = parse(a)
  const y = parse(b)
  if (x && y) return diffJson(where, '', x.value, y.value, out)
  let at = 0
  while (at < a.length && at < b.length && a[at] === b[at]) at += 1
  const around = (text: string) => JSON.stringify(text.slice(Math.max(0, at - 20), at + 40))
  out.push(`${where}: differs from character ${at + 1}: ${around(a)} vs ${around(b)}`)
}

/** What differs between two exchanges, a line each; one line saying so when nothing does. */
export function diffRequests(a: Exchange, b: Exchange): string[] {
  const ids: [string, string] = [`#${a.detail.id}`, `#${b.detail.id}`]
  const out: string[] = []
  if (a.detail.method !== b.detail.method) out.push(`method: ${a.detail.method} → ${b.detail.method}`)
  const ua = new URL(a.detail.url)
  const ub = new URL(b.detail.url)
  if (ua.origin !== ub.origin) out.push(`origin: ${ua.origin} → ${ub.origin}`)
  if (ua.pathname !== ub.pathname) out.push(`path: ${ua.pathname} → ${ub.pathname}`)
  const keys = new Set<string>()
  ua.searchParams.forEach((_, key) => keys.add(key))
  ub.searchParams.forEach((_, key) => keys.add(key))
  for (const key of keys) {
    const x = ua.searchParams.getAll(key)
    const y = ub.searchParams.getAll(key)
    if (x.join('\u0000') === y.join('\u0000')) continue
    if (y.length === 0) out.push(`query ${key}: only in ${ids[0]} (${show(x.join(','))})`)
    else if (x.length === 0) out.push(`query ${key}: only in ${ids[1]} (${show(y.join(','))})`)
    else out.push(`query ${key}: ${show(x.join(','))} → ${show(y.join(','))}`)
  }
  diffHeaders('request header', a.detail.reqHeaders, b.detail.reqHeaders, ids, out)
  diffBodies('request body', a.reqText, b.reqText, ids, out)
  if (a.detail.status !== b.detail.status) out.push(`status: ${a.detail.status ?? 'none'} → ${b.detail.status ?? 'none'}`)
  if ((a.detail.grpcStatus ?? null) !== (b.detail.grpcStatus ?? null)) out.push(`gRPC status: ${a.detail.grpcStatus ?? 'none'} → ${b.detail.grpcStatus ?? 'none'}`)
  diffHeaders('response header', a.detail.resHeaders, b.detail.resHeaders, ids, out)
  diffBodies('response body', a.resText, b.resText, ids, out)
  if (out.length === 0) return ['no difference in method, URL, headers, status or bodies']
  return out.length > MAX_LINES ? [...out.slice(0, MAX_LINES), `…and ${out.length - MAX_LINES} more`] : out
}
