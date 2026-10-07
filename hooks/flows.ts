// Pure logic shared by the pane and the tools: the sidecar's line protocol,
// the flow list, the filter language and the formats.

import type { ProxyCa, ProxyFlow } from '../types'

export type SidecarEvent =
  | {
      t: 'ready'
      host: string
      port: number
      addresses: string[]
      pid: number
      runDir: string
      ca: ProxyCa
    }
  | { t: 'flow'; flow: ProxyFlow }
  | { t: 'fatal'; code: string; message: string }
  | { t: 'log'; level: string; message: string }

export type FlowBody = {
  file: string
  size: number
  stored: number
  isTruncated: boolean
  encoding: string | null
  isDecoded: boolean
}

export type FlowDetail = ProxyFlow & {
  url: string
  httpVersion?: string
  statusMessage?: string | null
  reqHeaders: [string, string][]
  resHeaders: [string, string][]
  req: FlowBody | null
  res: FlowBody | null
}

// --- the line protocol ------------------------------------------------------

/** Splits what arrived after `rest` into whole lines and what is left over. */
export function splitLines(rest: string, text: string): { lines: string[]; rest: string } {
  const joined = rest + text
  const parts = joined.split('\n')
  const tail = parts.pop() ?? ''
  return { lines: parts.filter(line => line.trim() !== ''), rest: tail }
}

export function parseEvent(line: string): SidecarEvent | null {
  try {
    const value = JSON.parse(line) as { t?: unknown }
    return typeof value?.t === 'string' ? (value as SidecarEvent) : null
  } catch {
    return null
  }
}

/** The list with `updates` laid over it by id, oldest first, the newest `max` kept. */
export function mergeFlows(list: readonly ProxyFlow[], updates: readonly ProxyFlow[], max: number): ProxyFlow[] {
  if (updates.length === 0) return [...list]
  const byId = new Map<number, ProxyFlow>()
  for (const flow of list) byId.set(flow.id, flow)
  for (const flow of updates) byId.set(flow.id, flow)
  const merged = [...byId.values()].sort((a, b) => a.id - b.id)
  return merged.length > max ? merged.slice(merged.length - max) : merged
}

// --- what a flow is ------------------------------------------------------------

export function flowUrl(flow: Pick<ProxyFlow, 'scheme' | 'host' | 'port' | 'path' | 'kind'>): string {
  if (flow.kind === 'tunnel') return `${flow.host}:${flow.port}`
  const isDefaultPort = (flow.scheme === 'https' && flow.port === 443) || (flow.scheme === 'http' && flow.port === 80)
  const scheme = flow.kind === 'ws' ? (flow.scheme === 'https' ? 'wss' : 'ws') : flow.scheme
  return `${scheme}://${flow.host}${isDefaultPort ? '' : `:${flow.port}`}${flow.path}`
}

export type FlowType = 'json' | 'html' | 'xml' | 'js' | 'css' | 'img' | 'font' | 'media' | 'text' | 'form' | 'ws' | 'tunnel' | 'other'

export function typeOf(flow: Pick<ProxyFlow, 'kind' | 'contentType'>): FlowType {
  if (flow.kind === 'ws') return 'ws'
  if (flow.kind === 'tunnel') return 'tunnel'
  const type = flow.contentType ?? ''
  if (type.includes('json')) return 'json'
  if (type.includes('html')) return 'html'
  if (type.includes('xml')) return 'xml'
  if (type.includes('javascript') || type.includes('ecmascript')) return 'js'
  if (type.includes('css')) return 'css'
  if (type.startsWith('image/')) return 'img'
  if (type.startsWith('font/') || type.includes('woff')) return 'font'
  if (type.startsWith('video/') || type.startsWith('audio/')) return 'media'
  if (type.includes('form')) return 'form'
  if (type.startsWith('text/')) return 'text'
  return 'other'
}

export function isFailure(flow: ProxyFlow): boolean {
  return flow.state === 'error' || (flow.status !== null && flow.status >= 400)
}

export function isTextual(contentType: string | null): boolean {
  const type = contentType ?? ''
  return (
    type === '' ||
    type.startsWith('text/') ||
    /json|xml|javascript|ecmascript|x-www-form-urlencoded|graphql|yaml|csv/.test(type)
  )
}

// --- the filter language --------------------------------------------------------
//
// Terms separated by spaces all hold (AND); a leading `-` negates a term.
// Free text: a substring of the URL. Keys: method:, status:, host:, path:,
// type:, is:, client:. "Quoted text" keeps its spaces.

type Term = { isNegated: boolean; test: (flow: ProxyFlow) => boolean }

export type ParsedFilter = { terms: Term[]; errors: string[] }

function tokenize(query: string): string[] {
  const tokens: string[] = []
  const pattern = /(-?)(?:(\w+):)?"([^"]*)"|(\S+)/g
  for (const match of query.matchAll(pattern)) {
    if (match[4] !== undefined) tokens.push(match[4])
    else tokens.push(`${match[1]}${match[2] ? `${match[2]}:` : ''}${match[3]}`)
  }
  return tokens
}

function globToRegExp(glob: string): RegExp {
  const escaped = glob.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')
  return new RegExp(`^${escaped}$`, 'i')
}

function statusTest(value: string): ((flow: ProxyFlow) => boolean) | null {
  const v = value.toLowerCase()
  const has = (flow: ProxyFlow) => flow.status !== null
  if (/^[1-5]xx$/.test(v)) {
    const base = Number(v[0]) * 100
    return flow => has(flow) && flow.status! >= base && flow.status! < base + 100
  }
  if (/^\d{3}$/.test(v)) return flow => flow.status === Number(v)
  const range = /^(\d{3})-(\d{3})$/.exec(v)
  if (range) return flow => has(flow) && flow.status! >= Number(range[1]) && flow.status! <= Number(range[2])
  const compare = /^(>=|<=|>|<)(\d{3})$/.exec(v)
  if (compare) {
    const n = Number(compare[2])
    const op = compare[1]
    return flow =>
      has(flow) &&
      (op === '>=' ? flow.status! >= n : op === '<=' ? flow.status! <= n : op === '>' ? flow.status! > n : flow.status! < n)
  }
  if (v === 'none' || v === 'pending') return flow => flow.status === null
  return null
}

const IS_TESTS: Record<string, (flow: ProxyFlow) => boolean> = {
  error: isFailure,
  err: isFailure,
  ok: flow => !isFailure(flow) && flow.state === 'done',
  pending: flow => flow.state === 'pending' || flow.state === 'receiving',
  tunnel: flow => flow.kind === 'tunnel',
  ws: flow => flow.kind === 'ws',
  https: flow => flow.scheme === 'https',
  http: flow => flow.scheme === 'http',
  rejected: flow => flow.errorCode === 'client-rejected-cert',
}

export function parseFilter(query: string): ParsedFilter {
  const terms: Term[] = []
  const errors: string[] = []
  for (const raw of tokenize(query.trim())) {
    const isNegated = raw.startsWith('-') && raw.length > 1
    const token = isNegated ? raw.slice(1) : raw
    const keyed = /^(\w+):(.*)$/.exec(token)
    const key = keyed?.[1]?.toLowerCase()
    const value = keyed?.[2] ?? ''
    let test: ((flow: ProxyFlow) => boolean) | null = null
    switch (key) {
      case 'method': {
        const methods = value.toUpperCase().split(',').filter(Boolean)
        test = flow => methods.includes(flow.method.toUpperCase())
        break
      }
      case 'status':
        test = statusTest(value)
        if (!test) errors.push(`status:${value}`)
        break
      case 'host': {
        const v = value.toLowerCase()
        if (v.includes('*')) {
          const re = globToRegExp(v)
          // *.example.com also covers example.com itself
          const apex = v.startsWith('*.') ? v.slice(2) : null
          test = flow => re.test(flow.host) || flow.host === apex
        } else {
          test = flow => flow.host.includes(v)
        }
        break
      }
      case 'path': {
        const v = value.toLowerCase()
        test = flow => flow.path.toLowerCase().includes(v)
        break
      }
      case 'type': {
        const types = value.toLowerCase().split(',').map(t => (t === 'image' ? 'img' : t))
        test = flow => types.includes(typeOf(flow))
        break
      }
      case 'is':
        test = IS_TESTS[value.toLowerCase()] ?? null
        if (!test) errors.push(`is:${value}`)
        break
      case 'client':
        test = flow => (flow.client ?? '').includes(value)
        break
      default: {
        const v = token.toLowerCase()
        test = flow => flowUrl(flow).toLowerCase().includes(v)
      }
    }
    if (test) terms.push({ isNegated, test })
  }
  return { terms, errors }
}

export function matchesFilter(flow: ProxyFlow, filter: ParsedFilter): boolean {
  return filter.terms.every(term => term.test(flow) !== term.isNegated)
}

export function filterFlows(flows: readonly ProxyFlow[], query: string): ProxyFlow[] {
  const filter = parseFilter(query)
  return filter.terms.length === 0 ? [...flows] : flows.filter(flow => matchesFilter(flow, filter))
}

// --- formats -----------------------------------------------------------------

export function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes}B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(bytes < 10 * 1024 ? 1 : 0)}KB`
  return `${(bytes / 1024 / 1024).toFixed(1)}MB`
}

export function formatDuration(ms: number | null): string {
  if (ms === null) return '…'
  if (ms < 1000) return `${ms}ms`
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`
  return `${Math.floor(ms / 60_000)}m${Math.round((ms % 60_000) / 1000)}s`
}

export function statusLabel(flow: ProxyFlow): string {
  if (flow.errorCode === 'client-rejected-cert') return 'CERT'
  if (flow.state === 'error' && flow.status === null) return 'ERR'
  if (flow.status === null) return '…'
  return String(flow.status)
}

export function truncate(text: string, width: number): string {
  if (width <= 0) return ''
  return text.length <= width ? text : `${text.slice(0, Math.max(0, width - 1))}…`
}

/** One line per flow for the model: aligned, newest last. */
export function flowTable(flows: readonly ProxyFlow[]): string {
  return flows
    .map(flow => {
      const error = flow.error ? `  ! ${truncate(flow.error, 160)}` : ''
      return `#${flow.id}  ${flow.method.padEnd(7)} ${statusLabel(flow).padEnd(4)} ${flowUrl(flow)}  ${formatSize(flow.resSize)}  ${formatDuration(flow.durationMs)}  ${typeOf(flow)}${error}`
    })
    .join('\n')
}

const CURL_SKIPPED = new Set(['host', 'content-length', 'connection', 'proxy-connection', 'keep-alive', 'transfer-encoding'])

function shellQuote(text: string): string {
  return `'${text.replace(/'/g, `'\\''`)}'`
}

/** The request as a curl command; a body too long or not text is referenced by its file. */
export function toCurl(detail: FlowDetail, body: string | null): string {
  // One line per flag and its value, continued with backslashes.
  const lines = [`curl${detail.method !== 'GET' ? ` -X ${detail.method}` : ''} ${shellQuote(detail.url)}`]
  let isCompressed = false
  for (const [name, value] of detail.reqHeaders) {
    const lower = name.toLowerCase()
    if (CURL_SKIPPED.has(lower)) continue
    if (lower === 'accept-encoding') {
      isCompressed = true
      continue
    }
    lines.push(`-H ${shellQuote(`${name}: ${value}`)}`)
  }
  if (isCompressed) lines.push('--compressed')
  if (detail.req) {
    if (body !== null && body.length <= 8000 && !detail.req.isTruncated) lines.push(`--data-raw ${shellQuote(body)}`)
    else lines.push(`--data-binary @${shellQuote(detail.req.file)}`)
  }
  return lines.join(' \\\n  ')
}

/** JSON pretty-printed when it parses; the text as it came otherwise. */
export function prettyBody(text: string, contentType: string | null): string {
  if ((contentType ?? '').includes('json') || /^\s*[[{]/.test(text)) {
    try {
      return JSON.stringify(JSON.parse(text), null, 2)
    } catch {
      return text
    }
  }
  return text
}

export function languageOf(contentType: string | null): string | undefined {
  const type = contentType ?? ''
  if (type.includes('json')) return 'json'
  if (type.includes('html')) return 'html'
  if (type.includes('xml')) return 'xml'
  if (type.includes('javascript')) return 'javascript'
  if (type.includes('css')) return 'css'
  if (type.includes('graphql')) return 'graphql'
  if (type.includes('yaml')) return 'yaml'
  return undefined
}

/** At most `maxLines` lines and `maxChars` characters, saying what was cut. */
export function clip(text: string, maxLines: number, maxChars: number): { text: string; isClipped: boolean } {
  let out = text.length > maxChars ? text.slice(0, maxChars) : text
  const lines = out.split('\n')
  if (lines.length > maxLines) out = lines.slice(0, maxLines).join('\n')
  return { text: out, isClipped: out.length < text.length }
}
