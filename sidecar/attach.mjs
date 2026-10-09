#!/usr/bin/env node
// What the mod runs: one Wirepane proxy serves every Claude Code session on
// this Mac. This finds it (the registry in <data>/sidecar.json, checked by
// asking it), or starts it detached so it outlives this session, and passes
// its events on as JSON lines on stdout: what it holds already (the recent
// requests, the rules, the tracked domains), then everything as it happens.
//
// Its own arguments: --session <id>, --project <dir>, --rules <file> (this
// session's project rules, applied while it is attached). Every other one is
// the proxy's (proxy.mjs), given to it when this starts it.
//
// stdout: {t:"attached", pid, isStarted}, then the proxy's events; {t:"fatal"}
// when it cannot be had or goes away.

import { spawn } from 'node:child_process'
import { closeSync, mkdirSync, openSync, readFileSync, statSync, unlinkSync, writeSync } from 'node:fs'
import http from 'node:http'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const OWN = new Set(['--session', '--project', '--rules'])

const argv = process.argv.slice(2)
const own = {}
const forwarded = []
for (let i = 0; i < argv.length; i++) {
  if (OWN.has(argv[i])) own[argv[i].slice(2)] = argv[++i]
  else forwarded.push(argv[i])
}
const valueOf = name => {
  const at = forwarded.indexOf(`--${name}`)
  return at >= 0 ? forwarded[at + 1] : undefined
}
const data = valueOf('data')
if (!data) {
  process.stderr.write('--data <dir> is required\n')
  process.exit(2)
}
// the first start on a Mac: the folder for the registry, the lock and the log is not there yet
mkdirSync(data, { recursive: true })
const registryFile = join(data, 'sidecar.json')
const lockFile = join(data, 'sidecar.lock')
const logFile = join(data, 'sidecar.log')

function emit(event) {
  process.stdout.write(`${JSON.stringify(event)}\n`)
}

function fatal(code, message) {
  process.stdout.write(`${JSON.stringify({ t: 'fatal', code, message })}\n`, () => process.exit(3))
}

function version() {
  try {
    return JSON.parse(readFileSync(join(here, '..', '.claude-plugin', 'plugin.json'), 'utf8')).version ?? ''
  } catch {
    return ''
  }
}

function isAlive(pid) {
  try {
    process.kill(Number(pid), 0)
    return true
  } catch (error) {
    return error.code === 'EPERM'
  }
}

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))

/** A command to the proxy on its port; the JSON answer, or null. */
function control(entry, command, body = {}, ms = 2000) {
  return new Promise(resolve => {
    const text = JSON.stringify(body)
    const req = http.request(
      { host: '127.0.0.1', port: entry.port, method: 'POST', path: `/__wirepane/${entry.token}/${command}`, headers: { 'content-length': Buffer.byteLength(text) } },
      res => {
        let answer = ''
        res.on('data', chunk => (answer += chunk))
        res.on('end', () => {
          try {
            resolve(res.statusCode === 200 ? JSON.parse(answer) : null)
          } catch {
            resolve(null)
          }
        })
      },
    )
    req.setTimeout(ms, () => req.destroy())
    req.on('error', () => resolve(null))
    req.end(text)
  })
}

/** The proxy the registry names, when it runs and answers; null otherwise. */
async function liveProxy() {
  let entry
  try {
    entry = JSON.parse(readFileSync(registryFile, 'utf8'))
  } catch {
    return null
  }
  if (!isAlive(entry.pid)) return null
  // ping: cheap, and it holds a proxy with no session yet from going while this one attaches
  const info = await control(entry, 'ping')
  return info ? { ...entry, info } : null
}

/** The last fatal line the proxy wrote to its log, when it gave up starting. */
function lastFatal() {
  try {
    const lines = readFileSync(logFile, 'utf8').trim().split('\n').slice(-20).reverse()
    for (const line of lines) {
      try {
        const event = JSON.parse(line)
        if (event.t === 'fatal') return event
      } catch {}
    }
  } catch {}
  return null
}

/** Starts the proxy detached, one session at a time (a lock file), and waits until it answers. */
async function startProxy() {
  for (let attempt = 0; attempt < 150; attempt++) {
    let lock
    try {
      lock = openSync(lockFile, 'wx')
    } catch (error) {
      if (error.code !== 'EEXIST') throw error
      // another session starts it: wait for that one, or take a stale lock over
      let holder = null
      try {
        holder = Number(readFileSync(lockFile, 'utf8'))
      } catch {}
      // empty: the session that made it has not written its pid yet
      let isFresh = false
      try {
        isFresh = !holder && Date.now() - statSync(lockFile).mtimeMs < 2000
      } catch {}
      if ((holder && isAlive(holder)) || isFresh) {
        await sleep(100)
        const ready = await liveProxy()
        if (ready) return { entry: ready, isStarted: false }
        continue
      }
      try {
        unlinkSync(lockFile)
      } catch {}
      continue
    }
    try {
      writeSync(lock, String(process.pid))
      const already = await liveProxy()
      if (already) return { entry: already, isStarted: false }
      const log = openSync(logFile, 'a')
      const child = spawn(process.execPath, [join(here, 'proxy.mjs'), '--daemon', ...forwarded], { detached: true, stdio: ['ignore', log, log] })
      closeSync(log)
      let exited = false
      child.once('exit', () => (exited = true))
      child.unref()
      for (let i = 0; i < 150; i++) {
        await sleep(100)
        const ready = await liveProxy()
        if (ready && ready.pid === child.pid) return { entry: ready, isStarted: true }
        if (exited) break
      }
      const failure = lastFatal()
      return { failure: failure ?? { code: 'start', message: `the proxy did not start (see ${logFile})` } }
    } finally {
      closeSync(lock)
      try {
        unlinkSync(lockFile)
      } catch {}
    }
  }
  return { failure: { code: 'start', message: 'another session holds the start lock' } }
}

async function main(isRetry = false) {
  let found = await liveProxy()
  let isStarted = false
  const ours = version()
  const wanted = {
    host: valueOf('host') ?? '127.0.0.1',
    port: valueOf('port') ?? '8899',
    noDecrypt: valueOf('no-decrypt') ?? '',
    insecureHosts: valueOf('insecure-hosts') ?? '',
    upstreamProxy: valueOf('upstream-proxy') ?? '',
    upstreamBypass: valueOf('upstream-bypass') ?? '',
  }
  const differs = found?.info.options && Object.entries(wanted).some(([key, value]) => String(found.info.options[key] ?? '') !== String(value))
  const isOtherVersion = found && ours && found.info.version && found.info.version !== ours
  // a proxy nobody uses any more, of another version or other settings, makes way for this one
  if (found && (isOtherVersion || differs) && found.info.sessions.length === 0) {
    await control(found, 'stop')
    for (let i = 0; i < 50 && isAlive(found.pid); i++) await sleep(100)
    found = null
  } else if (found && differs) {
    emit({ t: 'log', level: 'warn', source: 'attach', message: 'the running proxy has other settings; they apply once the other sessions let go of it, or after /proxy restart' })
  }
  if (!found) {
    const started = await startProxy()
    if (started.failure) return fatal(started.failure.code, started.failure.message)
    found = started.entry
    isStarted = started.isStarted
  }
  emit({ t: 'attached', pid: process.pid, proxyPid: found.pid, isStarted, version: found.info.version })
  if (ours && found.info.version && found.info.version !== ours) {
    emit({ t: 'log', level: 'warn', source: 'attach', message: `the running proxy is Wirepane ${found.info.version}, this session's is ${ours}; /proxy restart moves to ${ours}` })
  }
  const query = new URLSearchParams({ session: own.session ?? '', project: own.project ?? '', rules: own.rules ?? '' })
  const req = http.get({ host: '127.0.0.1', port: found.port, path: `/__wirepane/${found.token}/events?${query}` }, res => {
    if (res.statusCode !== 200) return fatal('attach', `the proxy refused this session (${res.statusCode})`)
    res.on('data', chunk => process.stdout.write(chunk))
    res.on('end', () => fatal('proxy-gone', 'the proxy stopped'))
    res.on('error', () => fatal('proxy-gone', 'the proxy went away'))
  })
  // the proxy went in the moment between the ping and the attach: start one, once
  req.on('error', error => (isRetry ? fatal('attach', error.message) : main(true).catch(e => fatal('attach', e.message))))
  // Claude Code gone without a word: the parent is now launchd; let go of the proxy
  setInterval(() => process.ppid === 1 && process.exit(0), 2000).unref()
  for (const signal of ['SIGTERM', 'SIGINT', 'SIGHUP']) process.on(signal, () => process.exit(0))
}

main().catch(error => fatal('attach', error.stack ?? error.message))
