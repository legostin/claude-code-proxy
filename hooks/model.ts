// Pure logic for what the tools show Claude: as much as helps, in as few
// tokens as it takes. URLs cut at the query, long header values cut, one
// budget shared by the bodies, JSON compact when pretty would not fit.

import type { ProxyFlow } from '../types'

export { modelUrl } from './flows'

/** A value cut at `max` characters, saying how long it was. */
export function clipValue(value: string, max: number): string {
  return value.length <= max ? value : `${value.slice(0, max)}…(${value.length} chars)`
}

/** Shares `total` characters among parts of these lengths: a short part keeps all it needs, the rest is split evenly. */
export function splitBudget(lengths: readonly number[], total: number): number[] {
  const out = lengths.map(() => 0)
  const order = lengths.map((length, i) => ({ length, i })).sort((a, b) => a.length - b.length)
  let left = total
  order.forEach(({ length, i }, k) => {
    const share = Math.floor(left / (order.length - k))
    out[i] = Math.min(length, share)
    left -= out[i]!
  })
  return out
}

function isJsonType(contentType: string | null, text: string): boolean {
  return (contentType ?? '').includes('json') || /^\s*[[{]/.test(text)
}

/** A body in at most `budget` characters: JSON pretty when it fits, compact when not, then cut. */
export function bodyForModel(text: string, contentType: string | null, budget: number): { text: string; isCut: boolean } {
  if (isJsonType(contentType, text)) {
    try {
      const value: unknown = JSON.parse(text)
      const pretty = JSON.stringify(value, null, 2)
      if (pretty.length <= budget) return { text: pretty, isCut: false }
      const compact = JSON.stringify(value)
      return compact.length <= budget ? { text: compact, isCut: false } : { text: compact.slice(0, budget), isCut: true }
    } catch {}
  }
  return text.length <= budget ? { text, isCut: false } : { text: text.slice(0, budget), isCut: true }
}

/** One part of a JSON value by a path like `data.items[0].name` (a leading `$.` is fine). */
export function jsonPath(value: unknown, path: string): { value: unknown } | { error: string } {
  const tokens = path
    .trim()
    .replace(/^\$\.?/, '')
    .replace(/\[(\d+)\]/g, '.$1')
    .split('.')
    .filter(Boolean)
  let current: unknown = value
  const walked: string[] = []
  for (const token of tokens) {
    if (current === null || typeof current !== 'object') {
      return { error: `${walked.join('.') || 'the body'} has no ${token}` }
    }
    current = (current as Record<string, unknown>)[token]
    walked.push(token)
  }
  return current === undefined ? { error: `${walked.join('.')} is not in the body` } : { value: current }
}

/** The hosts with the most requests, most first. */
export function busiestHosts(flows: readonly ProxyFlow[], n: number): [string, number][] {
  const counts = new Map<string, number>()
  for (const flow of flows) counts.set(flow.host, (counts.get(flow.host) ?? 0) + 1)
  return [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, n)
}
