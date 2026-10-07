// The rules engine's applying half: it keeps the project's rules file loaded
// as it changes on disk, and carries out a rule's actions on a request before
// it is sent and on a response before the client gets it. shared/rules.mjs
// says what a rule is and whether it matches.

import { createHash } from 'node:crypto'
import { readFileSync, unwatchFile, watchFile } from 'node:fs'
import { readFile } from 'node:fs/promises'
import { dirname, isAbsolute, resolve } from 'node:path'
import { Transform } from 'node:stream'
import vm from 'node:vm'
import zlib from 'node:zlib'

import {
  describeAction,
  isEnabled,
  isRegexPattern,
  matchesRequest,
  matchesResponse,
  needsRequestBody,
  needsResponseBody,
  parseRules,
  scriptsOf,
  toRegExp,
} from '../shared/rules.mjs'

export function hashScript(code) {
  return createHash('sha256').update(code).digest('hex')
}

function readText(path) {
  try {
    return readFileSync(path, 'utf8')
  } catch {
    return null
  }
}

/**
 * The rules in force: the file's valid, enabled rules whose scripts were
 * approved, in the file's order. `onLoad` hears every (re)load.
 */
export function createRuleSet({ rulesFile, trustFile, onLoad }) {
  let active = []
  const load = () => {
    const parsed = parseRules(rulesFile ? readText(rulesFile) : null)
    let trusted = new Set()
    try {
      trusted = new Set(JSON.parse(readText(trustFile) ?? '{}').sha256 ?? [])
    } catch {}
    const untrusted = []
    const errors = [...parsed.errors]
    active = []
    for (const { rule, errors: ruleErrors } of parsed.rules) {
      if (ruleErrors.length) {
        errors.push(...ruleErrors)
        continue
      }
      if (!isEnabled(rule)) continue
      if (scriptsOf(rule).some(code => !trusted.has(hashScript(code)))) {
        untrusted.push(rule.id)
        continue
      }
      active.push(rule)
    }
    onLoad?.({ file: rulesFile, total: parsed.rules.length, active: active.length, errors, untrusted })
  }
  load()
  const watched = [rulesFile, trustFile].filter(Boolean)
  for (const file of watched) watchFile(file, { interval: 400 }, load)
  return {
    get rules() {
      return active
    },
    projectRoot: rulesFile ? dirname(dirname(rulesFile)) : process.cwd(),
    close: () => watched.forEach(file => unwatchFile(file)),
  }
}

// --- what a request is while the rules act on it ----------------------------------

export function urlOf(target) {
  const isDefault = (target.scheme === 'https' && target.port === 443) || (target.scheme === 'http' && target.port === 80)
  return `${target.scheme}://${target.host}${isDefault ? '' : `:${target.port}`}${target.path}`
}

function setUrl(target, url) {
  const parsed = new URL(url)
  target.scheme = parsed.protocol === 'https:' ? 'https' : 'http'
  target.host = parsed.hostname.replace(/^\[|\]$/g, '')
  target.port = Number(parsed.port) || (target.scheme === 'https' ? 443 : 80)
  target.path = `${parsed.pathname}${parsed.search}`
}

export function getHeader(headers, name) {
  const lower = name.toLowerCase()
  return headers.find(([key]) => key.toLowerCase() === lower)?.[1]
}

export function setHeader(headers, name, value) {
  const lower = name.toLowerCase()
  const kept = headers.filter(([key]) => key.toLowerCase() !== lower)
  if (value !== undefined) kept.push([name, value])
  headers.splice(0, headers.length, ...kept)
}

function hostHeader(target) {
  const isDefault = (target.scheme === 'https' && target.port === 443) || (target.scheme === 'http' && target.port === 80)
  return isDefault ? target.host : `${target.host}:${target.port}`
}

function replaceText(text, pattern, replacement) {
  if (isRegexPattern(pattern)) return text.replace(new RegExp(toRegExp(pattern).source, 'g'), replacement)
  return text.split(pattern).join(replacement)
}

export function deepMerge(base, patch) {
  if (Array.isArray(patch) || patch === null || typeof patch !== 'object') return patch
  const out = base !== null && typeof base === 'object' && !Array.isArray(base) ? { ...base } : {}
  for (const [key, value] of Object.entries(patch)) out[key] = deepMerge(out[key], value)
  return out
}

/** The whole body, decoded from its content-encoding; null when it cannot be. */
export function decodeWhole(buffer, encoding) {
  const enc = String(encoding ?? '').trim().toLowerCase()
  try {
    if (enc === '' || enc === 'identity') return buffer
    if (enc === 'gzip' || enc === 'x-gzip') return zlib.gunzipSync(buffer)
    if (enc === 'br') return zlib.brotliDecompressSync(buffer)
    if (enc === 'deflate') {
      try {
        return zlib.inflateSync(buffer)
      } catch {
        return zlib.inflateRawSync(buffer)
      }
    }
    if (enc === 'zstd' && zlib.zstdDecompressSync) return zlib.zstdDecompressSync(buffer)
  } catch {}
  return null
}

async function bodyFrom(action, projectRoot) {
  if (action.file !== undefined) {
    const path = isAbsolute(action.file) ? action.file : resolve(projectRoot, action.file)
    return { body: await readFile(path), type: null }
  }
  if (action.json !== undefined) return { body: Buffer.from(JSON.stringify(action.json)), type: 'application/json' }
  if (action.text !== undefined) return { body: Buffer.from(action.text), type: null }
  return { body: Buffer.alloc(0), type: null }
}

function sleep(ms, signal) {
  return new Promise(resolveSleep => {
    const timer = setTimeout(resolveSleep, ms)
    signal?.addEventListener('abort', () => {
      clearTimeout(timer)
      resolveSleep()
    })
  })
}

// --- scripts ---------------------------------------------------------------------

const scripts = new Map()

/**
 * Runs a rule's script: the body of `async (req, res, ctx) => {}`. Its
 * synchronous part is cut off after a second, the whole of it after five.
 */
async function runScript(code, req, res, ctx, log) {
  let entry = scripts.get(code)
  if (!entry) {
    const context = vm.createContext({
      console: { log: (...parts) => log(parts.map(part => (typeof part === 'string' ? part : JSON.stringify(part))).join(' ')) },
      URL,
      URLSearchParams,
      TextEncoder,
      TextDecoder,
      setTimeout,
      clearTimeout,
    })
    vm.runInContext(`globalThis.__rule = async function (req, res, ctx) {\n${code}\n}`, context, {
      timeout: 1000,
      filename: 'proxy-rule-script.js',
    })
    entry = { context }
    if (scripts.size > 100) scripts.clear()
    scripts.set(code, entry)
  }
  entry.context.__args = [req, res, ctx]
  const running = vm.runInContext('__rule(...__args)', entry.context, { timeout: 1000 })
  let timer
  const limit = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('the script ran past 5 s')), 5000)
  })
  try {
    await Promise.race([running, limit])
  } finally {
    clearTimeout(timer)
  }
}

function headersObject(pairs) {
  const out = {}
  for (const [key, value] of pairs) out[key.toLowerCase()] = value
  return out
}

function pairsFrom(object) {
  return Object.entries(object ?? {})
    .filter(([, value]) => value !== undefined && value !== null)
    .map(([key, value]) => [key, String(value)])
}

function bodyText(value) {
  if (value === null || value === undefined) return null
  return Buffer.from(typeof value === 'string' ? value : JSON.stringify(value))
}

// --- the request side ------------------------------------------------------------

/**
 * Applies the request actions of `rules` (already matched) to `state`:
 * `{ target, headers, body, respond, fail, throttle }`, `target` the URL's
 * parts, `body` a Buffer when it was read whole. Returns the rules that
 * applied, in order; `log(ruleId, text)` records each step.
 */
export async function applyRequestRules(rules, state, { projectRoot, signal, log }) {
  for (const rule of rules) {
    for (const action of rule.request ?? []) {
      if (state.fail || signal?.aborted) return
      const note = text => log(rule.id, text ?? describeAction(action))
      switch (action.type) {
        case 'delay': {
          const ms = action.msMax !== undefined ? action.ms + Math.random() * (action.msMax - action.ms) : action.ms
          note(`wait ${Math.round(ms)} ms`)
          await sleep(ms, signal)
          break
        }
        case 'throttle':
          state.throttle = action.bytesPerSecond
          note()
          break
        case 'setHeader':
          setHeader(state.headers, action.name, action.value)
          note()
          break
        case 'removeHeader':
          setHeader(state.headers, action.name, undefined)
          note()
          break
        case 'setQuery':
        case 'removeQuery': {
          const [path, ...rest] = state.target.path.split('?')
          const params = new URLSearchParams(rest.join('?'))
          if (action.type === 'setQuery') params.set(action.name, action.value)
          else params.delete(action.name)
          const query = params.toString()
          state.target.path = query ? `${path}?${query}` : path
          note()
          break
        }
        case 'mapRemote': {
          const wasDefault = (state.target.scheme === 'https' && state.target.port === 443) || (state.target.scheme === 'http' && state.target.port === 80)
          if (action.scheme) state.target.scheme = action.scheme
          if (action.host) state.target.host = action.host
          if (action.port) state.target.port = action.port
          else if (action.scheme && wasDefault) state.target.port = action.scheme === 'https' ? 443 : 80
          if (action.path) {
            const query = state.target.path.includes('?') ? `?${state.target.path.split('?').slice(1).join('?')}` : ''
            state.target.path = action.path.includes('?') ? action.path : `${action.path}${query}`
          }
          setHeader(state.headers, 'host', hostHeader(state.target))
          note()
          break
        }
        case 'replaceUrl':
          setUrl(state.target, replaceText(urlOf(state.target), action.pattern, action.with))
          setHeader(state.headers, 'host', hostHeader(state.target))
          note(`URL is now ${urlOf(state.target)}`)
          break
        case 'setBody': {
          const { body, type } = await bodyFrom(action, projectRoot)
          state.body = body
          if (type && !getHeader(state.headers, 'content-type')) setHeader(state.headers, 'content-type', type)
          note()
          break
        }
        case 'replaceBody':
          state.body = Buffer.from(replaceText((state.body ?? Buffer.alloc(0)).toString('utf8'), action.pattern, action.with))
          note()
          break
        case 'mergeJson': {
          let parsed
          try {
            parsed = JSON.parse((state.body ?? Buffer.alloc(0)).toString('utf8') || '{}')
          } catch {
            note('the body is not JSON: merge skipped')
            break
          }
          state.body = Buffer.from(JSON.stringify(deepMerge(parsed, action.json)))
          note()
          break
        }
        case 'respond': {
          const { body, type } = await bodyFrom(action, projectRoot)
          const headers = pairsFrom(action.headers)
          if (type && !getHeader(headers, 'content-type')) headers.push(['content-type', type])
          state.respond = { status: action.status, headers, body }
          note()
          break
        }
        case 'fail':
          state.fail = action.kind
          note()
          return
        case 'script': {
          const req = {
            method: state.method,
            url: urlOf(state.target),
            headers: headersObject(state.headers),
            body: state.body ? state.body.toString('utf8') : null,
            respond: undefined,
          }
          req.json = () => {
            try {
              return JSON.parse(req.body)
            } catch {
              return undefined
            }
          }
          try {
            await runScript(action.code, req, null, { phase: 'request', ruleId: rule.id }, text => log(rule.id, `script: ${text}`))
          } catch (error) {
            note(`script failed: ${error.message}`)
            break
          }
          state.method = String(req.method || state.method).toUpperCase()
          if (req.url !== urlOf(state.target)) {
            setUrl(state.target, req.url)
            setHeader(state.headers, 'host', hostHeader(state.target))
          }
          state.headers.splice(0, state.headers.length, ...pairsFrom(req.headers))
          state.body = bodyText(req.body)
          if (req.respond) {
            state.respond = {
              status: Number(req.respond.status) || 200,
              headers: pairsFrom(req.respond.headers),
              body: bodyText(req.respond.body) ?? Buffer.alloc(0),
            }
          }
          note('ran the script')
          break
        }
      }
    }
  }
}

// --- the response side -------------------------------------------------------------

/**
 * Applies the response actions of `rules` (already matched) to `state`:
 * `{ status, headers, body, fail, throttle }`, `body` a Buffer when the
 * response was read whole (body actions need it) and undefined while it
 * streams.
 */
export async function applyResponseRules(rules, state, { projectRoot, signal, log }) {
  for (const rule of rules) {
    for (const action of rule.response ?? []) {
      if (state.fail || signal?.aborted) return
      const note = text => log(rule.id, text ?? describeAction(action))
      switch (action.type) {
        case 'delay': {
          const ms = action.msMax !== undefined ? action.ms + Math.random() * (action.msMax - action.ms) : action.ms
          note(`wait ${Math.round(ms)} ms`)
          await sleep(ms, signal)
          break
        }
        case 'throttle':
          state.throttle = action.bytesPerSecond
          note()
          break
        case 'setStatus':
          state.status = action.status
          state.statusMessage = undefined
          note()
          break
        case 'setHeader':
          setHeader(state.headers, action.name, action.value)
          note()
          break
        case 'removeHeader':
          setHeader(state.headers, action.name, undefined)
          note()
          break
        case 'setBody': {
          const { body, type } = await bodyFrom(action, projectRoot)
          state.body = body
          if (type) setHeader(state.headers, 'content-type', type)
          note()
          break
        }
        case 'replaceBody':
          state.body = Buffer.from(replaceText((state.body ?? Buffer.alloc(0)).toString('utf8'), action.pattern, action.with))
          note()
          break
        case 'mergeJson': {
          let parsed
          try {
            parsed = JSON.parse((state.body ?? Buffer.alloc(0)).toString('utf8') || '{}')
          } catch {
            note('the body is not JSON: merge skipped')
            break
          }
          state.body = Buffer.from(JSON.stringify(deepMerge(parsed, action.json)))
          note()
          break
        }
        case 'fail':
          state.fail = action.kind
          note()
          return
        case 'script': {
          const res = {
            status: state.status,
            headers: headersObject(state.headers),
            body: state.body ? state.body.toString('utf8') : null,
          }
          res.json = () => {
            try {
              return JSON.parse(res.body)
            } catch {
              return undefined
            }
          }
          try {
            await runScript(action.code, state.request, res, { phase: 'response', ruleId: rule.id }, text => log(rule.id, `script: ${text}`))
          } catch (error) {
            note(`script failed: ${error.message}`)
            break
          }
          state.status = Number(res.status) || state.status
          state.headers.splice(0, state.headers.length, ...pairsFrom(res.headers))
          state.body = bodyText(res.body) ?? Buffer.alloc(0)
          note('ran the script')
          break
        }
      }
    }
  }
}

// --- choosing rules ----------------------------------------------------------------

/**
 * The rules whose request-side conditions hold, cut after the first that
 * stops the chain; and whether the request body must be read first.
 */
export function rulesForRequest(rules, request) {
  const noBody = { ...request, body: undefined }
  const pre = rules.filter(rule => matchesRequest({ ...rule, match: { ...rule.match, bodyContains: undefined } }, noBody))
  return { candidates: pre, needsBody: pre.some(needsRequestBody) }
}

export function finalizeRequestRules(candidates, request) {
  const out = []
  for (const rule of candidates) {
    if (!matchesRequest(rule, request)) continue
    out.push(rule)
    const waitsForResponse = rule.match?.status !== undefined || rule.match?.contentType !== undefined
    if (rule.stop && !waitsForResponse) break
  }
  return out
}

export function rulesForResponse(rules, response) {
  const out = []
  for (const rule of rules) {
    if (!(rule.response ?? []).length) continue
    if (!matchesResponse(rule, response)) continue
    out.push(rule)
    if (rule.stop) break
  }
  return { rules: out, needsBody: out.some(needsResponseBody) }
}

/** Slows a stream to `bytesPerSecond`, in tenth-of-a-second slices. */
export function throttleStream(bytesPerSecond) {
  const slice = Math.max(1, Math.floor(bytesPerSecond / 10))
  return new Transform({
    async transform(chunk, encoding, done) {
      for (let i = 0; i < chunk.length; i += slice) {
        this.push(chunk.subarray(i, i + slice))
        await sleep(100)
      }
      done()
    },
  })
}
