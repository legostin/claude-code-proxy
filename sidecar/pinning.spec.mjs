// node --test sidecar/pinning.spec.mjs
// Hosts that refuse the certificate pass through after two refusals, and
// the upstreams named insecure have their certificates accepted.

import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import https from 'node:https'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, before, describe, test } from 'node:test'

import { createLeafFactory, ensureCA } from './certs.mjs'
import { curl, listen, startSidecar } from './spec-kit.mjs'

describe('pinned hosts and insecure upstreams', () => {
  let dataDir
  let sidecar
  let ready
  let proxy
  let port
  const servers = []

  before(async () => {
    dataDir = await mkdtemp(join(tmpdir(), 'proxy-pinning-'))
    const upstreamCA = await ensureCA(join(dataDir, 'upstream'))
    const context = await createLeafFactory(upstreamCA).get('localhost')
    const server = https.createServer({ SNICallback: (name, done) => done(null, context) }, (req, res) => res.end(`upstream ${req.url}`))
    servers.push(server)
    port = await listen(server)
    // no --insecure-upstream: only localhost's certificate is accepted
    sidecar = startSidecar(join(dataDir, 'proxy'), ['--insecure-hosts', 'localhost'])
    ready = await sidecar.waitFor(() => sidecar.events.find(e => e.t === 'ready'), 'ready')
    proxy = `http://127.0.0.1:${ready.port}`
  })

  after(async () => {
    sidecar?.child.kill()
    for (const server of servers) server.close()
    await rm(dataDir, { recursive: true, force: true })
  })

  test('a host refused twice passes through untouched, and is decrypted again once the client trusts the CA', async () => {
    for (let i = 0; i < 2; i++) assert.notEqual((await curl(['-x', proxy, `https://localhost:${port}/refused`])).code, 0)
    await sidecar.waitFor(() => sidecar.events.find(e => e.t === 'pinned' && e.host === 'localhost'), 'the pinned event')
    // passed through: the client meets the server's own certificate
    const through = await curl(['-k', '-x', proxy, `https://localhost:${port}/through`])
    assert.equal(through.stdout, 'upstream /through', through.stderr)
    const tunnel = await sidecar.flow(f => f.kind === 'tunnel' && f.note === 'pinned', 'the pinned tunnel')
    assert.equal(tunnel.host, 'localhost')

    // the client trusts the CA after all (it accepts another host): the blind pin goes
    const other = await curl(['-x', proxy, '--cacert', ready.ca.path, '--resolve', `other.localhost:${port}:127.0.0.1`, `https://other.localhost:${port}/x`])
    assert.notEqual(other.code, 6, other.stderr)
    await sidecar.waitFor(() => sidecar.events.find(e => e.t === 'unpinned' && e.host === 'localhost'), 'the unpinned event')
    const decrypted = await curl(['-x', proxy, '--cacert', ready.ca.path, `https://localhost:${port}/again`])
    assert.equal(decrypted.stdout, 'upstream /again', decrypted.stderr)
    const flow = await sidecar.flow(f => f.path === '/again' && f.state === 'done', 'the decrypted request')
    assert.equal(flow.kind, 'http')
  })

  test('only the hosts named insecure have their certificates accepted', async () => {
    const named = await curl(['-x', proxy, '--cacert', ready.ca.path, `https://localhost:${port}/named`])
    assert.equal(named.stdout, 'upstream /named')
    const unnamed = await curl(['-x', proxy, '--cacert', ready.ca.path, '-w', '%{http_code}', '-o', '/dev/null', `https://other.localhost:${port}/unnamed`])
    assert.equal(unnamed.stdout, '502')
    const flow = await sidecar.flow(f => f.path === '/unnamed' && f.state === 'error', 'the refused upstream')
    assert.match(flow.error, /certificate|self.signed|altnames/i)
  })
})
