// node --test sidecar/control.spec.mjs
// The mod's commands: waiting for requests to end, and replays marked.

import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import http from 'node:http'
import https from 'node:https'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, before, describe, test } from 'node:test'

import { createLeafFactory, ensureCA } from './certs.mjs'
import { curl, listen, startSidecar } from './spec-kit.mjs'

describe('control', () => {
  let dataDir
  let sidecar
  let ready
  let port
  let securePort
  const seen = []
  const servers = []
  const control = (command, body) =>
    curl(['-X', 'POST', '--data-binary', JSON.stringify(body), `http://127.0.0.1:${ready.port}/__wirepane/${ready.control.token}/${command}`]).then(out =>
      JSON.parse(out.stdout),
    )

  before(async () => {
    dataDir = await mkdtemp(join(tmpdir(), 'proxy-control-'))
    const server = http.createServer((req, res) => {
      seen.push({ path: req.url, replay: req.headers['x-wirepane-replay'] ?? null })
      setTimeout(() => res.end(`ok ${req.url}`), 100)
    })
    servers.push(server)
    port = await listen(server)
    const upstreamCA = await ensureCA(join(dataDir, 'upstream'))
    const context = await createLeafFactory(upstreamCA).get('localhost')
    const secure = https.createServer({ SNICallback: (name, done) => done(null, context) }, (req, res) => res.end(`secure ${req.url}`))
    servers.push(secure)
    securePort = await listen(secure)
    sidecar = startSidecar(join(dataDir, 'proxy'))
    ready = await sidecar.waitFor(() => sidecar.events.find(e => e.t === 'ready'), 'ready')
  })

  after(async () => {
    sidecar?.child.kill()
    for (const server of servers) server.close()
    await rm(dataDir, { recursive: true, force: true })
  })

  test('waits for the next request to end, and answers it', async () => {
    const waiting = control('flows/wait', { after: 0, timeoutMs: 5000 })
    await new Promise(resolve => setTimeout(resolve, 100))
    await curl(['-x', `http://127.0.0.1:${ready.port}`, `http://localhost:${port}/later`])
    const answer = await waiting
    assert.equal(answer.flows.length, 1)
    assert.equal(answer.flows[0].path, '/later')
    assert.equal(answer.flows[0].state, 'done')
    const nothing = await control('flows/wait', { after: answer.flows[0].id, timeoutMs: 200 })
    assert.deepEqual(nothing.flows, [])
  })

  test('a replay is marked with what it repeats, and the server never sees the mark', async () => {
    await curl(['-x', `http://127.0.0.1:${ready.port}`, '-H', 'x-wirepane-replay: 7', `http://localhost:${port}/again`])
    const flow = await sidecar.flow(f => f.path === '/again' && f.state === 'done', 'the replay')
    assert.equal(flow.replayOf, 7)
    assert.equal(seen.find(s => s.path === '/again').replay, null)
  })

  test('a wait answers within its deadline while requests keep ending', async () => {
    const started = Date.now()
    const waiting = control('flows/wait', { after: 0, timeoutMs: 1500 })
    let isWaiting = true
    waiting.then(() => (isWaiting = false))
    for (let i = 0; i < 30 && isWaiting; i++) curl(['-x', `http://127.0.0.1:${ready.port}`, `http://localhost:${port}/busy-${i}`])
    const answer = await waiting
    assert.ok(answer.flows.length >= 1)
    assert.ok(Date.now() - started < 4000, 'it answered')
  })

  test("the mod's own CONNECT (its token in a proxy header) is decrypted while the system proxy is on", async () => {
    const dataDir2 = await mkdtemp(join(tmpdir(), 'proxy-control-guard-'))
    const guarded = startSidecar(join(dataDir2, 'proxy'), ['--assume-system-proxy', '--insecure-upstream'])
    try {
      const r = await guarded.waitFor(() => guarded.events.find(e => e.t === 'ready'), 'ready')
      const out = await curl([
        '-x', `http://127.0.0.1:${r.port}`, '--proxy-header', `x-wirepane-control: ${r.control.token}`, '--cacert', r.ca.path,
        `https://localhost:${securePort}/replayed`,
      ])
      assert.equal(out.stdout, 'secure /replayed', out.stderr)
      const flow = await guarded.flow(f => f.path === '/replayed' && f.state === 'done', 'the decrypted replay')
      assert.equal(flow.kind, 'http')
    } finally {
      guarded.child.kill()
      await rm(dataDir2, { recursive: true, force: true })
    }
  })
})
