// node --test sidecar/breakpoints.spec.mjs
// Breakpoints: an exchange held at a rule's breakpoint until it is let go,
// as it was, changed, answered by hand, or cut.

import assert from 'node:assert/strict'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import http from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, before, describe, test } from 'node:test'

import { curl, listen, startSidecar } from './spec-kit.mjs'

describe('breakpoints', () => {
  let dataDir
  let sidecar
  let ready
  let proxy
  let port
  const seen = []
  const servers = []
  const control = (command, body) =>
    curl(['-X', 'POST', '--data-binary', JSON.stringify(body), `http://127.0.0.1:${ready.port}/__wirepane/${ready.control.token}/${command}`]).then(out => JSON.parse(out.stdout))
  const heldFor = path => sidecar.waitFor(() => sidecar.events.find(e => e.t === 'held' && e.view.url.endsWith(path)), `held ${path}`)

  before(async () => {
    dataDir = await mkdtemp(join(tmpdir(), 'proxy-breakpoints-'))
    const server = http.createServer((req, res) => {
      let body = ''
      req.on('data', chunk => (body += chunk))
      req.on('end', () => {
        seen.push({ path: req.url, method: req.method, body, edited: req.headers['x-edited'] ?? null })
        res.writeHead(200, { 'content-type': 'text/plain' })
        res.end(`server saw ${req.method} ${req.url} "${body}"`)
      })
    })
    servers.push(server)
    port = await listen(server)
    const rules = join(dataDir, 'rules.json')
    await writeFile(
      rules,
      JSON.stringify({
        rules: [
          { id: 'pause-request', match: { path: '/req*' }, request: [{ type: 'breakpoint' }] },
          { id: 'pause-response', match: { path: '/res*' }, response: [{ type: 'breakpoint' }] },
          { id: 'pause-briefly', match: { path: '/brief' }, request: [{ type: 'breakpoint', timeoutMs: 300 }] },
        ],
      }),
    )
    sidecar = startSidecar(join(dataDir, 'proxy'), ['--rules', rules])
    ready = await sidecar.waitFor(() => sidecar.events.find(e => e.t === 'ready'), 'ready')
    proxy = `http://127.0.0.1:${ready.port}`
  })

  after(async () => {
    sidecar?.child.kill()
    for (const server of servers) server.close()
    await rm(dataDir, { recursive: true, force: true })
  })

  test('a request held at its breakpoint goes on changed: method, URL, headers and body', async () => {
    const out = curl(['-x', proxy, '-X', 'POST', '--data-binary', 'original', `http://localhost:${port}/req-change`])
    const held = await heldFor('/req-change')
    assert.equal(held.phase, 'request')
    assert.equal(held.view.method, 'POST')
    assert.equal(held.view.body, 'original')
    const flow = await sidecar.flow(f => f.id === held.id && f.held === 'request', 'the held flow')
    assert.equal(flow.held, 'request')
    assert.deepEqual((await control('held/list', {})).held.map(h => h.id), [held.id])
    const answer = await control('held/resume', { id: held.id, changes: { method: 'PUT', url: `http://localhost:${port}/req-changed?x=1`, headers: { 'x-edited': 'yes' }, body: 'changed' } })
    assert.equal(answer.ok, true)
    assert.equal((await out).stdout, 'server saw PUT /req-changed?x=1 "changed"')
    assert.deepEqual(seen.at(-1), { path: '/req-changed?x=1', method: 'PUT', body: 'changed', edited: 'yes' })
    const done = await sidecar.flow(f => f.id === held.id && f.state === 'done', 'the released flow')
    assert.equal(done.held, undefined)
    assert.ok(sidecar.events.some(e => e.t === 'released' && e.id === held.id))
  })

  test('a response held at its breakpoint reaches the client with a new status and body', async () => {
    const out = curl(['-x', proxy, '-w', ' %{http_code}', `http://localhost:${port}/res-edit`])
    const held = await heldFor('/res-edit')
    assert.equal(held.phase, 'response')
    assert.equal(held.view.status, 200)
    assert.equal(held.view.body, 'server saw GET /res-edit ""')
    await control('held/resume', { id: held.id, changes: { status: 418, json: { edited: true } } })
    assert.equal((await out).stdout, '{"edited":true} 418')
  })

  test('a held request can be answered by hand, never reaching the server, or cut', async () => {
    const before = seen.length
    const answered = curl(['-x', proxy, '-w', ' %{http_code}', `http://localhost:${port}/req-answer`])
    const held = await heldFor('/req-answer')
    await control('held/resume', { id: held.id, action: 'respond', respond: { status: 503, text: 'down for maintenance' } })
    assert.equal((await answered).stdout, 'down for maintenance 503')
    assert.equal(seen.length, before)

    const cut = curl(['-x', proxy, `http://localhost:${port}/req-cut`])
    const heldCut = await heldFor('/req-cut')
    await control('held/resume', { id: heldCut.id, action: 'abort' })
    assert.notEqual((await cut).code, 0)
    const flow = await sidecar.flow(f => f.id === heldCut.id && f.state === 'error', 'the cut flow')
    assert.equal(flow.errorCode, 'rule')
  })

  test('a breakpoint nobody answers lets the request go after its time', async () => {
    const out = await curl(['-x', proxy, `http://localhost:${port}/brief`])
    assert.equal(out.stdout, 'server saw GET /brief ""')
    const gone = await control('held/resume', { id: 999, action: 'continue' })
    assert.match(gone.error, /not held/)
  })
})
