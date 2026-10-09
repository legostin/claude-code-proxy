// node --test sidecar/shared.spec.mjs
// One proxy for every session: the first starts it detached, the others
// attach and get what it already holds; each project's rules apply while its
// session is attached; once no session is left the proxy goes.

import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { once } from 'node:events'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import http from 'node:http'
import net from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { after, before, describe, test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { curl, listen } from './spec-kit.mjs'

const here = dirname(fileURLToPath(import.meta.url))

function attach(dataDir, session, extra = []) {
  const child = spawn(process.execPath, [join(here, 'attach.mjs'), '--data', dataDir, '--port', '0', '--run', 'shared', '--linger-ms', '700', '--session', session, ...extra], {
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  const events = []
  const waiters = []
  let buffer = ''
  child.stdout.on('data', chunk => {
    buffer += chunk
    let newline
    while ((newline = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, newline)
      buffer = buffer.slice(newline + 1)
      if (line.trim()) events.push(JSON.parse(line))
      for (const waiter of [...waiters]) waiter()
    }
  })
  const waitFor = (predicate, label, ms = 10_000) =>
    new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`${session}: timed out waiting for ${label}; got ${JSON.stringify(events.map(e => e.t))}`)), ms)
      const check = () => {
        const found = predicate(events)
        if (found) {
          clearTimeout(timer)
          waiters.splice(waiters.indexOf(check), 1)
          resolve(found)
        }
      }
      waiters.push(check)
      check()
    })
  return { child, events, waitFor }
}

const isAlive = pid => {
  try {
    process.kill(pid, 0)
    return true
  } catch {
    return false
  }
}

describe('one proxy shared by sessions', () => {
  let dataDir
  let upstreamPort
  const rules = {}
  const servers = []

  before(async () => {
    dataDir = await mkdtemp(join(tmpdir(), 'proxy-shared-'))
    const upstream = http.createServer((req, res) => res.end(`upstream ${req.url}`))
    servers.push(upstream)
    upstreamPort = await listen(upstream)
    for (const [name, path] of [
      ['a', '/a'],
      ['b', '/b'],
    ]) {
      await mkdir(join(dataDir, name, '.claude'), { recursive: true })
      rules[name] = join(dataDir, name, '.claude', 'proxy-rules.json')
      await writeFile(rules[name], JSON.stringify({ rules: [{ id: `mock-${name}`, match: { path }, request: [{ type: 'respond', status: 200, text: `mocked by ${name}` }] }] }))
    }
  })

  after(async () => {
    try {
      const { pid } = JSON.parse(await readFile(join(dataDir, 'sidecar.json'), 'utf8'))
      process.kill(pid)
    } catch {}
    for (const server of servers) server.close()
    await rm(dataDir, { recursive: true, force: true })
  })

  test('sessions share the proxy, its requests, its tracked domains and their own rules; it goes when they do', { timeout: 40_000 }, async () => {
    const tracking = join(dataDir, 'tracking.json')
    const a = attach(dataDir, 'A', ['--project', join(dataDir, 'a'), '--rules', rules.a, '--tracking', tracking])
    const attachedA = await a.waitFor(events => events.find(e => e.t === 'attached'), 'attached')
    assert.equal(attachedA.isStarted, true)
    const ready = await a.waitFor(events => events.find(e => e.t === 'ready'), 'ready')
    assert.equal(ready.isShared, true)
    const proxy = `http://127.0.0.1:${ready.port}`
    assert.equal((await curl(['-x', proxy, `http://localhost:${upstreamPort}/before`])).stdout, 'upstream /before')
    await a.waitFor(events => events.find(e => e.t === 'flow' && e.flow.path === '/before' && e.flow.state === 'done'), 'the first flow')

    const b = attach(dataDir, 'B', ['--project', join(dataDir, 'b'), '--rules', rules.b, '--tracking', tracking])
    const attachedB = await b.waitFor(events => events.find(e => e.t === 'attached'), 'B attached')
    assert.equal(attachedB.isStarted, false)
    assert.equal(attachedB.proxyPid, attachedA.proxyPid)
    // what the proxy recorded before B came
    await b.waitFor(events => events.find(e => e.t === 'flow' && e.flow.path === '/before'), 'the earlier flow, for B')
    await a.waitFor(events => events.find(e => e.t === 'sessions' && e.sessions.length === 2), 'two sessions')

    // both projects' rules apply while both sessions are attached
    assert.equal((await curl(['-x', proxy, `http://localhost:${upstreamPort}/a`])).stdout, 'mocked by a')
    assert.equal((await curl(['-x', proxy, `http://localhost:${upstreamPort}/b`])).stdout, 'mocked by b')

    // the tracked domains are the proxy's: one session sets them, both hear it
    const token = ready.control.token
    await curl(['-X', 'POST', '--data-binary', '{"enabled":true,"patterns":["localhost"]}', `${proxy}/__wirepane/${token}/tracking/set`])
    await b.waitFor(events => events.find(e => e.t === 'tracking' && e.patterns?.includes('localhost')), 'tracking for B')
    await a.waitFor(events => events.find(e => e.t === 'tracking' && e.patterns?.includes('localhost')), 'tracking for A')

    // B leaves: its rules go with it, the proxy stays for A
    b.child.kill()
    await a.waitFor(events => events.filter(e => e.t === 'sessions').at(-1)?.sessions.length === 1, 'one session again')
    assert.equal((await curl(['-x', proxy, `http://localhost:${upstreamPort}/b`])).stdout, 'upstream /b')
    assert.equal((await curl(['-x', proxy, `http://localhost:${upstreamPort}/a`])).stdout, 'mocked by a')
    const info = JSON.parse((await curl(['-X', 'POST', '--data-binary', '{}', `${proxy}/__wirepane/${token}/info`])).stdout)
    assert.deepEqual(info.sessions.map(s => s.session), ['A'])
    assert.equal(info.isShared, true)
    assert.ok(info.flows >= 4)

    // A leaves too: after the linger the proxy is gone, and so is its registry entry
    a.child.kill()
    await once(a.child, 'exit')
    for (let i = 0; i < 50 && isAlive(attachedA.proxyPid); i++) await new Promise(resolve => setTimeout(resolve, 100))
    assert.equal(isAlive(attachedA.proxyPid), false)
    await assert.rejects(readFile(join(dataDir, 'sidecar.json'), 'utf8'))
  })

  test('the first start on a Mac makes the data folder', { timeout: 20_000 }, async () => {
    const fresh = join(dataDir, 'never-made', 'proxy-mod')
    const session = attach(fresh, 'first')
    try {
      const ready = await session.waitFor(events => events.find(e => e.t === 'ready' || e.t === 'fatal'), 'ready')
      assert.equal(ready.t, 'ready', JSON.stringify(ready))
      assert.ok(JSON.parse(await readFile(join(fresh, 'sidecar.json'), 'utf8')).pid)
    } finally {
      session.child.kill()
      try {
        process.kill(JSON.parse(await readFile(join(fresh, 'sidecar.json'), 'utf8')).pid)
      } catch {}
    }
  })

  test('a port another program holds is said so', { timeout: 20_000 }, async () => {
    const holder = net.createServer()
    await new Promise(resolve => holder.listen(0, '127.0.0.1', resolve))
    try {
      const c = attach(dataDir, 'C', ['--port', String(holder.address().port)])
      const failed = await c.waitFor(events => events.find(e => e.t === 'fatal'), 'the failure')
      assert.equal(failed.code, 'port-busy')
    } finally {
      holder.close()
    }
  })
})
