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
  describeStep,
  isEnabled,
  isRegexPattern,
  matchesRequest,
  matchesResponse,
  needsRequestBody,
  needsResponseBody,
  parseRules,
  scriptsOf,
  stepTakes,
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
  const projectRoot = rulesFile ? dirname(dirname(rulesFile)) : process.cwd()
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
      // a rule's files are its own project's, whichever project another rule came from
      Object.defineProperty(rule, '__root', { value: projectRoot })
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
    projectRoot,
    close: () => watched.forEach(file => unwatchFile(file)),
  }
}

// --- what a request is while the rules act on it ----------------------------------

export function urlOf(target) {
  const isDefault = (target.scheme === 'https' && target.port === 443) || (target.scheme === 'http' && target.port === 80)
  return `${target.scheme}://${target.host}${isDefault ? '' : `:${target.port}`}${target.path}`
}

export function setUrl(target, url) {
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

export function hostHeader(target) {
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
function runScript(code, req, res, ctx, log) {
  return runFunction(code, 'req, res, ctx', [req, res, ctx], log)
}

/** A script's body as an async function of `params`, run on `args` in its own context. */
async function runFunction(code, params, args, log) {
  const cacheKey = `${params}\n${code}`
  let entry = scripts.get(cacheKey)
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
    vm.runInContext(`globalThis.__rule = async function (${params}) {\n${code}\n}`, context, {
      timeout: 1000,
      filename: 'proxy-rule-script.js',
    })
    entry = { context }
    if (scripts.size > 100) scripts.clear()
    scripts.set(cacheKey, entry)
  }
  entry.context.__args = args
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
export async function applyRequestRules(rules, state, { projectRoot, signal, log, hold }) {
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
          const { body, type } = await bodyFrom(action, rule.__root ?? projectRoot)
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
          const { body, type } = await bodyFrom(action, rule.__root ?? projectRoot)
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
        case 'breakpoint':
          // held until the person or Claude lets it go (hold says how), or its time runs out
          if (hold) note(await hold(rule.id, action, state))
          break
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
export async function applyResponseRules(rules, state, { projectRoot, signal, log, hold }) {
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
          const { body, type } = await bodyFrom(action, rule.__root ?? projectRoot)
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
        case 'breakpoint':
          // held until the person or Claude lets it go (hold says how), or its time runs out
          if (hold) note(await hold(rule.id, action, state))
          break
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

// --- WebSocket messages -------------------------------------------------------------
//
// A message is `{ direction: 'out' | 'in', opcode, data }`: out from the client
// to the server, in the other way; `data` a Buffer, text messages in UTF-8.
// `ctx.send(to, opcode, data)` sends another message to 'client' or 'server',
// `ctx.close(code, reason)` closes both sides. A step marks the message
// `isDropped` to pass nothing on.

const TEXT = 1
const BINARY = 2

function textOf(message) {
  return message.opcode === TEXT ? message.data.toString('utf8') : null
}

async function payloadFrom(step, projectRoot) {
  const { body } = await bodyFrom(step, projectRoot)
  // text and JSON go as text; a file as text when it reads as UTF-8
  if (step.file === undefined) return { opcode: TEXT, data: body }
  try {
    new TextDecoder('utf-8', { fatal: true }).decode(body)
    return { opcode: TEXT, data: body }
  } catch {
    return { opcode: BINARY, data: body }
  }
}

/** A message as a script sees it: text to read and change, JSON, and drop. */
function scriptMessage(message) {
  const view = {
    direction: message.direction,
    isBinary: message.opcode !== TEXT,
    text: textOf(message),
    bytes: new Uint8Array(message.data),
    drop: false,
    json: () => JSON.parse(view.text ?? ''),
  }
  return view
}

function scriptContext(ctx, log) {
  return {
    send: (to, value) => {
      if (to !== 'client' && to !== 'server') throw new Error('send to client or server')
      ctx.send(to, TEXT, bodyText(value) ?? Buffer.alloc(0))
    },
    close: (code = 1000, reason = '') => ctx.close(code, reason),
    log,
  }
}

/** Applies the steps of `rules` (matched on the upgrade request) to one message. */
export async function applyMessageRules(rules, message, ctx) {
  const { projectRoot, signal, log } = ctx
  for (const rule of rules) {
    for (const step of rule.messages ?? []) {
      if (message.isDropped || signal?.aborted) return message
      if (!stepTakes(step, { direction: message.direction, text: textOf(message) })) continue
      const note = text => log(rule.id, text ?? describeStep(step))
      switch (step.type) {
        case 'replaceMessage': {
          const text = textOf(message)
          if (text === null) break
          const next = replaceText(text, step.pattern, step.with)
          if (next !== text) {
            message.data = Buffer.from(next)
            note()
          }
          break
        }
        case 'setMessage': {
          const payload = await payloadFrom(step, rule.__root ?? projectRoot)
          message.opcode = payload.opcode
          message.data = payload.data
          note()
          break
        }
        case 'mergeJson': {
          const text = textOf(message)
          try {
            message.data = Buffer.from(JSON.stringify(deepMerge(JSON.parse(text ?? ''), step.json)))
            note()
          } catch {
            note('not JSON: merge skipped')
          }
          break
        }
        case 'drop':
          message.isDropped = true
          message.fate = 'dropped'
          note()
          break
        case 'delay': {
          const ms = step.msMax !== undefined ? step.ms + Math.random() * (step.msMax - step.ms) : step.ms
          note(`wait ${Math.round(ms)} ms`)
          await sleep(ms, signal)
          break
        }
        case 'reply': {
          const payload = await payloadFrom(step, rule.__root ?? projectRoot)
          ctx.send(message.direction === 'out' ? 'client' : 'server', payload.opcode, payload.data)
          message.isDropped = true
          message.fate = 'answered'
          note()
          break
        }
        case 'send': {
          const payload = await payloadFrom(step, rule.__root ?? projectRoot)
          ctx.send(step.to, payload.opcode, payload.data)
          note()
          break
        }
        case 'close':
          ctx.close(step.code ?? 1000, step.reason ?? '')
          message.isDropped = true
          message.fate = 'closed'
          note()
          break
        case 'script': {
          const view = scriptMessage(message)
          const before = view.text
          try {
            await runFunction(step.code, 'msg, ctx', [view, scriptContext(ctx, text => log(rule.id, text))], text => log(rule.id, text))
            if (view.drop) {
              message.isDropped = true
              message.fate = 'dropped'
              note('script: dropped')
            } else if (view.text !== before && typeof view.text === 'string') {
              message.opcode = TEXT
              message.data = Buffer.from(view.text)
              note('script: changed the message')
            }
          } catch (error) {
            note(`script failed: ${error.message}`)
          }
          break
        }
      }
    }
  }
  return message
}

/** Carries out the steps `on: 'open'` of `rules` as the WebSocket opens. */
export async function applyOpenRules(rules, ctx) {
  const { projectRoot, signal, log } = ctx
  for (const rule of rules) {
    for (const step of rule.messages ?? []) {
      if (step.on !== 'open' || signal?.aborted) continue
      const note = text => log(rule.id, text ?? describeStep(step))
      switch (step.type) {
        case 'send': {
          const payload = await payloadFrom(step, rule.__root ?? projectRoot)
          ctx.send(step.to, payload.opcode, payload.data)
          note()
          break
        }
        case 'close':
          ctx.close(step.code ?? 1000, step.reason ?? '')
          note()
          return
        case 'delay':
          note(`wait ${step.ms} ms`)
          await sleep(step.ms, signal)
          break
        case 'script':
          try {
            await runFunction(step.code, 'msg, ctx', [null, scriptContext(ctx, text => log(rule.id, text))], text => log(rule.id, text))
            note('script ran on open')
          } catch (error) {
            note(`script failed: ${error.message}`)
          }
          break
      }
    }
  }
}

/** Whether `rules` hold back the messages going `direction`, to act on them before passing them on. */
export function holdsMessages(rules, direction) {
  return rules.some(rule => (rule.messages ?? []).some(step => (step.on ?? 'message') === 'message' && [direction, 'both', undefined].includes(step.direction)))
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
