// The rules engine's shared half: what a rules file holds, whether a rule
// matches a request or a response, and how a rule reads as text. Plain
// JavaScript with no Node API, so the sidecar (which applies rules) and the
// mod (which lists and edits them) read a file the same way.
//
// A rules file is `{ "rules": [Rule, ...] }`; its order is the priority, the
// first rule applying first. A rule:
//   { id, name?, description?, enabled?, match?, request?: Action[],
//     response?: Action[], stop? }

export const REQUEST_ACTIONS = [
  'delay', 'throttle', 'setHeader', 'removeHeader', 'setQuery', 'removeQuery',
  'mapRemote', 'replaceUrl', 'setBody', 'replaceBody', 'mergeJson', 'respond', 'fail', 'script',
]
export const RESPONSE_ACTIONS = [
  'delay', 'throttle', 'setStatus', 'setHeader', 'removeHeader',
  'setBody', 'replaceBody', 'mergeJson', 'fail', 'script',
]
const BODY_ACTIONS = new Set(['setBody', 'replaceBody', 'mergeJson', 'script'])
const MATCH_KEYS = ['url', 'host', 'path', 'methods', 'headers', 'query', 'bodyContains', 'status', 'contentType']
const ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/

// --- patterns ---------------------------------------------------------------
//
// A pattern is a glob (`*` any run of characters, `?` one) matched whole and
// without regard to case, or a regular expression written `re:<source>`. (Not
// `/source/flags`: every path starts with a slash, and `/v1/login` would read
// as the expression `v1` with the flags `login`.)

export function isRegexPattern(pattern) {
  return typeof pattern === 'string' && pattern.startsWith('re:') && pattern.length > 3
}

const compiled = new Map()

export function toRegExp(pattern) {
  let regex = compiled.get(pattern)
  if (!regex) {
    regex = compile(pattern)
    if (compiled.size > 500) compiled.clear()
    compiled.set(pattern, regex)
  }
  return regex
}

function compile(pattern) {
  if (isRegexPattern(pattern)) return new RegExp(pattern.slice(3))
  const source = String(pattern)
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.')
  return new RegExp(`^${source}$`, 'i')
}

function patternError(pattern, where) {
  if (typeof pattern !== 'string' || pattern === '') return `${where} must be a non-empty string`
  try {
    toRegExp(pattern)
    return null
  } catch (error) {
    return `${where}: ${error.message}`
  }
}

function matchesPattern(pattern, value) {
  return toRegExp(pattern).test(value)
}

function matchesHost(pattern, host) {
  // *.example.com covers example.com itself too
  if (!isRegexPattern(pattern) && pattern.startsWith('*.') && host.toLowerCase() === pattern.slice(2).toLowerCase()) return true
  return matchesPattern(pattern, host)
}

/** `404`, `4xx`, `>=400`, `<300`, `500-599`. */
export function statusMatcher(text) {
  const value = String(text).trim().toLowerCase()
  if (/^[1-5]xx$/.test(value)) {
    const base = Number(value[0]) * 100
    return status => status >= base && status < base + 100
  }
  if (/^\d{3}$/.test(value)) return status => status === Number(value)
  const range = /^(\d{3})-(\d{3})$/.exec(value)
  if (range) return status => status >= Number(range[1]) && status <= Number(range[2])
  const compare = /^(>=|<=|>|<)(\d{3})$/.exec(value)
  if (compare) {
    const n = Number(compare[2])
    const op = compare[1]
    return status => (op === '>=' ? status >= n : op === '<=' ? status <= n : op === '>' ? status > n : status < n)
  }
  return null
}

// --- validation ---------------------------------------------------------------

const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value)
const isString = value => typeof value === 'string'
const isNumber = (value, min, max) => typeof value === 'number' && Number.isFinite(value) && value >= min && value <= max

function bodySourceError(action, where) {
  const given = ['text', 'json', 'file'].filter(key => action[key] !== undefined)
  if (given.length !== 1) return `${where}: give exactly one of text, json, file`
  if (action.text !== undefined && !isString(action.text)) return `${where}: text must be a string`
  if (action.file !== undefined && (!isString(action.file) || action.file === '')) return `${where}: file must be a path`
  return null
}

function actionErrors(action, phase, where) {
  if (!isObject(action)) return [`${where} must be an object`]
  const allowed = phase === 'request' ? REQUEST_ACTIONS : RESPONSE_ACTIONS
  if (!allowed.includes(action.type)) {
    return [`${where}: type must be one of ${allowed.join(', ')} in ${phase} (got ${JSON.stringify(action.type)})`]
  }
  const errors = []
  const need = (ok, text) => {
    if (!ok) errors.push(`${where} (${action.type}): ${text}`)
  }
  switch (action.type) {
    case 'delay':
      need(isNumber(action.ms, 0, 600_000), 'ms must be a number from 0 to 600000')
      if (action.msMax !== undefined) need(isNumber(action.msMax, action.ms ?? 0, 600_000), 'msMax must be at least ms and at most 600000')
      break
    case 'throttle':
      need(isNumber(action.bytesPerSecond, 1, 1e10), 'bytesPerSecond must be a positive number')
      break
    case 'setHeader':
    case 'setQuery':
      need(isString(action.name) && action.name !== '', 'name must be a non-empty string')
      need(isString(action.value), 'value must be a string')
      break
    case 'removeHeader':
    case 'removeQuery':
      need(isString(action.name) && action.name !== '', 'name must be a non-empty string')
      break
    case 'mapRemote':
      need(['scheme', 'host', 'port', 'path'].some(key => action[key] !== undefined), 'give at least one of scheme, host, port, path')
      if (action.scheme !== undefined) need(action.scheme === 'http' || action.scheme === 'https', 'scheme must be http or https')
      if (action.host !== undefined) need(isString(action.host) && action.host !== '', 'host must be a non-empty string')
      if (action.port !== undefined) need(isNumber(action.port, 1, 65535) && Number.isInteger(action.port), 'port must be 1 to 65535')
      if (action.path !== undefined) need(isString(action.path) && action.path.startsWith('/'), 'path must start with /')
      break
    case 'replaceUrl':
    case 'replaceBody': {
      const error = patternError(action.pattern, `${where} (${action.type}) pattern`)
      if (error) errors.push(error)
      need(isString(action.with), 'with must be a string')
      break
    }
    case 'setBody': {
      const error = bodySourceError(action, `${where} (setBody)`)
      if (error) errors.push(error)
      break
    }
    case 'mergeJson':
      need(isObject(action.json) || Array.isArray(action.json), 'json must be an object or an array')
      break
    case 'respond': {
      need(isNumber(action.status, 100, 599) && Number.isInteger(action.status), 'status must be 100 to 599')
      if (action.headers !== undefined) need(isObject(action.headers) && Object.values(action.headers).every(isString), 'headers must map names to strings')
      const given = ['text', 'json', 'file'].filter(key => action[key] !== undefined)
      need(given.length <= 1, 'give at most one of text, json, file')
      break
    }
    case 'setStatus':
      need(isNumber(action.status, 100, 599) && Number.isInteger(action.status), 'status must be 100 to 599')
      break
    case 'fail':
      need(['reset', 'close', 'timeout'].includes(action.kind), 'kind must be reset, close or timeout')
      break
    case 'script':
      need(isString(action.code) && action.code.trim() !== '', 'code must be a non-empty string')
      break
  }
  return errors
}

function matchErrors(match, where) {
  if (match === undefined) return []
  if (!isObject(match)) return [`${where} must be an object`]
  const errors = []
  for (const key of Object.keys(match)) {
    if (!MATCH_KEYS.includes(key)) errors.push(`${where}: unknown key ${JSON.stringify(key)} (known: ${MATCH_KEYS.join(', ')})`)
  }
  for (const key of ['url', 'host', 'path', 'contentType']) {
    if (match[key] !== undefined) {
      const error = patternError(match[key], `${where}.${key}`)
      if (error) errors.push(error)
    }
  }
  if (match.methods !== undefined && !(Array.isArray(match.methods) && match.methods.length > 0 && match.methods.every(isString))) {
    errors.push(`${where}.methods must be a non-empty list of strings`)
  }
  for (const key of ['headers', 'query']) {
    if (match[key] === undefined) continue
    if (!isObject(match[key])) errors.push(`${where}.${key} must map names to patterns`)
    else {
      for (const [name, pattern] of Object.entries(match[key])) {
        const error = patternError(pattern, `${where}.${key}.${name}`)
        if (error) errors.push(error)
      }
    }
  }
  if (match.bodyContains !== undefined && (!isString(match.bodyContains) || match.bodyContains === '')) {
    errors.push(`${where}.bodyContains must be a non-empty string`)
  }
  if (match.status !== undefined && !statusMatcher(match.status)) {
    errors.push(`${where}.status must look like 404, 4xx, >=400 or 500-599`)
  }
  return errors
}

/** What is wrong with one rule, as sentences; empty when nothing is. */
export function ruleErrors(rule, where = 'rule') {
  if (!isObject(rule)) return [`${where} must be an object`]
  const label = isString(rule.id) ? `rule ${rule.id}` : where
  const errors = []
  if (!isString(rule.id) || !ID.test(rule.id)) errors.push(`${label}: id must be 1-64 of letters, digits, ., _ and - (got ${JSON.stringify(rule.id)})`)
  for (const key of ['name', 'description']) {
    if (rule[key] !== undefined && !isString(rule[key])) errors.push(`${label}: ${key} must be a string`)
  }
  for (const key of ['enabled', 'stop']) {
    if (rule[key] !== undefined && typeof rule[key] !== 'boolean') errors.push(`${label}: ${key} must be true or false`)
  }
  errors.push(...matchErrors(rule.match, `${label}: match`))
  for (const phase of ['request', 'response']) {
    if (rule[phase] === undefined) continue
    if (!Array.isArray(rule[phase])) {
      errors.push(`${label}: ${phase} must be a list of actions`)
      continue
    }
    rule[phase].forEach((action, i) => errors.push(...actionErrors(action, phase, `${label}: ${phase}[${i}]`)))
  }
  if (!(rule.request?.length || rule.response?.length)) errors.push(`${label}: give at least one action in request or response`)
  const responseOnly = rule.match && (rule.match.status !== undefined || rule.match.contentType !== undefined)
  if (responseOnly && rule.request?.length) errors.push(`${label}: match.status and match.contentType are known only after the response, so such a rule takes response actions only`)
  return errors
}

/**
 * Reads a rules file's text. A rule with errors is kept, with its errors,
 * and never applied; `errors` holds the file's own problems.
 *
 * @returns `{ rules: [{ rule, errors }], errors }`
 */
export function parseRules(text) {
  if (text === null || text === undefined || String(text).trim() === '') return { rules: [], errors: [] }
  let data
  try {
    data = JSON.parse(text)
  } catch (error) {
    return { rules: [], errors: [`not valid JSON: ${error.message}`] }
  }
  if (!isObject(data) || !Array.isArray(data.rules)) return { rules: [], errors: ['the file must be {"rules": [...]}'] }
  const seen = new Set()
  const rules = data.rules.map((rule, index) => {
    const errors = ruleErrors(rule, `rules[${index}]`)
    if (isObject(rule) && isString(rule.id)) {
      if (seen.has(rule.id)) errors.push(`rule ${rule.id}: another rule has this id`)
      seen.add(rule.id)
    }
    return { rule, errors }
  })
  return { rules, errors: [] }
}

export function isEnabled(rule) {
  return rule.enabled !== false
}

// --- matching -----------------------------------------------------------------
//
// A request is `{ method, url, host, path, headers, body }`: `path` with its
// query, `headers` as [name, value] pairs, `body` the text when it was read.
// A response is `{ status, contentType }`.

function headerValue(headers, name) {
  const lower = name.toLowerCase()
  return headers.find(([key]) => key.toLowerCase() === lower)?.[1]
}

/** Whether the request-side conditions hold (status and contentType wait for the response). */
export function matchesRequest(rule, request) {
  const match = rule.match ?? {}
  if (match.methods && !match.methods.some(method => method.toUpperCase() === request.method.toUpperCase())) return false
  if (match.url && !matchesPattern(match.url, request.url)) return false
  if (match.host && !matchesHost(match.host, request.host)) return false
  if (match.path && !matchesPattern(match.path, request.path.split('?')[0])) return false
  if (match.headers) {
    for (const [name, pattern] of Object.entries(match.headers)) {
      const value = headerValue(request.headers, name)
      if (value === undefined || !matchesPattern(pattern, value)) return false
    }
  }
  if (match.query) {
    const params = new URLSearchParams(request.path.split('?').slice(1).join('?'))
    for (const [name, pattern] of Object.entries(match.query)) {
      const values = params.getAll(name)
      if (values.length === 0 || !values.some(value => matchesPattern(pattern, value))) return false
    }
  }
  if (match.bodyContains !== undefined && !(request.body ?? '').includes(match.bodyContains)) return false
  return true
}

export function matchesResponse(rule, response) {
  const match = rule.match ?? {}
  if (match.status !== undefined && !statusMatcher(match.status)(response.status)) return false
  if (match.contentType !== undefined) {
    const type = response.contentType ?? ''
    const pattern = match.contentType
    const holds = isRegexPattern(pattern) || pattern.includes('*') ? matchesPattern(pattern, type) : type.toLowerCase().includes(pattern.toLowerCase())
    if (!holds) return false
  }
  return true
}

/** The request's body must be read before the rule can match or act. */
export function needsRequestBody(rule) {
  return rule.match?.bodyContains !== undefined || (rule.request ?? []).some(action => BODY_ACTIONS.has(action.type))
}

/** The response's body must be held back so the rule can change it. */
export function needsResponseBody(rule) {
  return (rule.response ?? []).some(action => BODY_ACTIONS.has(action.type))
}

export function scriptsOf(rule) {
  return [...(rule.request ?? []), ...(rule.response ?? [])].filter(action => action?.type === 'script').map(action => action.code)
}

// --- text -------------------------------------------------------------------

function short(value, length = 40) {
  const text = typeof value === 'string' ? value : JSON.stringify(value)
  return text.length > length ? `${text.slice(0, length - 1)}…` : text
}

function duration(ms) {
  return ms >= 1000 && ms % 100 === 0 ? `${ms / 1000} s` : `${ms} ms`
}

function bytes(n) {
  return n >= 1024 * 1024 ? `${(n / 1024 / 1024).toFixed(1)} MB/s` : n >= 1024 ? `${Math.round(n / 1024)} KB/s` : `${n} B/s`
}

function bodySource(action) {
  if (action.file !== undefined) return `file ${action.file}`
  if (action.json !== undefined) return `JSON ${short(action.json)}`
  if (action.text !== undefined) return `"${short(action.text)}"`
  return 'an empty body'
}

export function describeAction(action) {
  switch (action?.type) {
    case 'delay':
      return action.msMax !== undefined && action.msMax > action.ms ? `wait ${duration(action.ms)} to ${duration(action.msMax)}` : `wait ${duration(action.ms)}`
    case 'throttle':
      return `throttle to ${bytes(action.bytesPerSecond)}`
    case 'setHeader':
      return `set header ${action.name}: ${short(action.value, 30)}`
    case 'removeHeader':
      return `remove header ${action.name}`
    case 'setQuery':
      return `set query ${action.name}=${short(action.value, 30)}`
    case 'removeQuery':
      return `remove query ${action.name}`
    case 'mapRemote': {
      const parts = [action.scheme && `${action.scheme}://`, action.host, action.port && `:${action.port}`, action.path].filter(Boolean)
      return `send to ${parts.join('')}`
    }
    case 'replaceUrl':
      return `rewrite URL ${action.pattern} → ${short(action.with, 30)}`
    case 'setBody':
      return `set body to ${bodySource(action)}`
    case 'replaceBody':
      return `replace ${action.pattern} with "${short(action.with, 30)}" in the body`
    case 'mergeJson':
      return `merge JSON ${short(action.json)}`
    case 'respond':
      return `answer ${action.status} with ${bodySource(action)} without asking the server`
    case 'setStatus':
      return `set status ${action.status}`
    case 'fail':
      return action.kind === 'timeout' ? 'never answer (time out)' : action.kind === 'reset' ? 'reset the connection' : 'close the connection'
    case 'script':
      return `run a script (${action.code.split('\n').length} lines)`
    default:
      return `unknown action ${JSON.stringify(action?.type)}`
  }
}

export function describeMatch(match = {}) {
  const parts = []
  if (match.methods) parts.push(match.methods.map(method => method.toUpperCase()).join(', '))
  if (match.url) parts.push(`URL ${match.url}`)
  if (match.host) parts.push(`host ${match.host}`)
  if (match.path) parts.push(`path ${match.path}`)
  for (const [name, pattern] of Object.entries(match.query ?? {})) parts.push(`query ${name}=${pattern}`)
  for (const [name, pattern] of Object.entries(match.headers ?? {})) parts.push(`header ${name}: ${pattern}`)
  if (match.bodyContains !== undefined) parts.push(`body has "${short(match.bodyContains, 30)}"`)
  if (match.status !== undefined) parts.push(`status ${match.status}`)
  if (match.contentType !== undefined) parts.push(`type ${match.contentType}`)
  return parts.length ? parts.join(' · ') : 'every request'
}

/** One line a person reads: what the rule catches and what it does there. */
export function describeRule(rule) {
  const phases = []
  if (rule.request?.length) phases.push(`before sending: ${rule.request.map(describeAction).join(', ')}`)
  if (rule.response?.length) phases.push(`on the response: ${rule.response.map(describeAction).join(', ')}`)
  return `${describeMatch(rule.match)} → ${phases.join('; ')}${rule.stop ? '; then stop' : ''}`
}
