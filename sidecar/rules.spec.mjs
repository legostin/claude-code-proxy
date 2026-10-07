// node --test sidecar/rules.spec.mjs
// The rules engine end to end: a rules file, the sidecar, an echo upstream, curl.

import assert from 'node:assert/strict'
import { execFile, spawn } from 'node:child_process'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import http from 'node:http'
import https from 'node:https'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { after, before, describe, test } from 'node:test'
import { gzipSync } from 'node:zlib'

import { createLeafFactory, ensureCA } from './certs.mjs'
import { hashScript } from './engine.mjs'

const here = dirname(fileURLToPath(import.meta.url))

function curl(args) {
  return new Promise(resolve => {
    execFile('curl', ['-sS', '--noproxy', '', '--max-time', '10', ...args], (error, stdout, stderr) =>
      resolve({ code: error?.code ?? 0, stdout, stderr }),
    )
  })
}

describe('rules', () => {
  let dir
  let rulesFile
  let trustFile
  let child
  let proxy
  let echoPort
  let otherPort
  let securePort
  let caPath
  let echoHits = 0
  const servers = []
  const events = []
  const flows = new Map()
  const waiters = []

  const waitFor = (predicate, label) =>
    new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`timed out waiting for ${label}`)), 8000)
      const check = () => {
        const found = predicate()
        if (found) {
          clearTimeout(timer)
          waiters.splice(waiters.indexOf(check), 1)
          resolve(found)
        }
      }
      waiters.push(check)
      check()
    })

  let loads = 0
  /** Writes the rules and waits until the sidecar has loaded them. */
  async function useRules(rules) {
    const before = events.filter(e => e.t === 'rules').length
    await writeFile(rulesFile, JSON.stringify({ rules }, null, 2))
    loads++
    return waitFor(() => events.filter(e => e.t === 'rules').length > before && events.filter(e => e.t === 'rules').at(-1), `rules load ${loads}`)
  }

  const flowOf = path => waitFor(() => [...flows.values()].find(f => f.path.startsWith(path) && (f.state === 'done' || f.state === 'error')), path)

  before(async () => {
    dir = await mkdtemp(join(tmpdir(), 'proxy-rules-'))
    await mkdir(join(dir, 'project', '.claude'), { recursive: true })
    rulesFile = join(dir, 'project', '.claude', 'proxy-rules.json')
    trustFile = join(dir, 'trusted-scripts.json')
    await writeFile(rulesFile, JSON.stringify({ rules: [] }))
    await writeFile(join(dir, 'project', 'mock.json'), '{"from":"file"}')

    const echo = http.createServer((req, res) => {
      echoHits++
      let body = ''
      req.on('data', c => (body += c))
      req.on('end', () => {
        if (req.url.startsWith('/gzip')) {
          res.writeHead(200, { 'content-type': 'application/json', 'content-encoding': 'gzip' })
          return res.end(gzipSync(JSON.stringify({ user: { name: 'ann', role: 'user' }, items: [1, 2] })))
        }
        if (req.url.startsWith('/missing')) {
          res.writeHead(404, { 'content-type': 'text/plain' })
          return res.end('not here')
        }
        res.writeHead(200, { 'content-type': 'application/json', 'x-upstream': 'echo' })
        res.end(JSON.stringify({ method: req.method, url: req.url, headers: req.headers, body }))
      })
    })
    servers.push(echo)
    echoPort = await new Promise(r => echo.listen(0, () => r(echo.address().port)))
    const other = http.createServer((req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain' })
      res.end(`other:${req.url}`)
    })
    servers.push(other)
    otherPort = await new Promise(r => other.listen(0, () => r(other.address().port)))
    const upstreamCA = await ensureCA(join(dir, 'upstream'))
    const context = await createLeafFactory(upstreamCA).get('localhost')
    const secure = https.createServer({ SNICallback: (name, done) => done(null, context) }, (req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain' })
      res.end('secure upstream')
    })
    servers.push(secure)
    securePort = await new Promise(r => secure.listen(0, () => r(secure.address().port)))

    child = spawn(process.execPath, [join(here, 'proxy.mjs'), '--port', '0', '--data', join(dir, 'data'), '--rules', rulesFile, '--trust', trustFile, '--insecure-upstream'], {
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let buffer = ''
    child.stdout.on('data', chunk => {
      buffer += chunk
      let newline
      while ((newline = buffer.indexOf('\n')) >= 0) {
        const event = JSON.parse(buffer.slice(0, newline))
        buffer = buffer.slice(newline + 1)
        events.push(event)
        if (event.t === 'flow') flows.set(event.flow.id, event.flow)
        for (const waiter of [...waiters]) waiter()
      }
    })
    const ready = await waitFor(() => events.find(e => e.t === 'ready'), 'ready')
    proxy = `http://127.0.0.1:${ready.port}`
    caPath = ready.ca.path
  })

  after(async () => {
    child?.kill()
    for (const server of servers) server.close()
    await rm(dir, { recursive: true, force: true })
  })

  const echoUrl = path => `http://127.0.0.1:${echoPort}${path}`

  test('reports the rules it loaded, and the broken ones', async () => {
    const loaded = await useRules([
      { id: 'ok', request: [{ type: 'delay', ms: 1 }] },
      { id: 'broken', request: [{ type: 'setStatus', status: 500 }] },
      { id: 'off', enabled: false, request: [{ type: 'delay', ms: 1 }] },
    ])
    assert.equal(loaded.total, 3)
    assert.equal(loaded.active, 1)
    assert.match(loaded.errors.join('\n'), /rule broken: request\[0\]: type must be one of/)
  })

  test('delays, sets headers and query before sending', async () => {
    await useRules([
      {
        id: 'shape',
        match: { path: '/shape*' },
        request: [
          { type: 'delay', ms: 300 },
          { type: 'setHeader', name: 'X-Debug', value: 'on' },
          { type: 'removeHeader', name: 'User-Agent' },
          { type: 'setQuery', name: 'page', value: '2' },
        ],
      },
    ])
    const out = await curl(['-x', proxy, '-w', '\n%{time_total}', echoUrl('/shape?page=1&q=a')])
    const [body, time] = out.stdout.split('\n')
    const echoed = JSON.parse(body)
    assert.ok(Number(time) >= 0.3, `took ${time}s`)
    assert.equal(echoed.headers['x-debug'], 'on')
    assert.equal(echoed.headers['user-agent'], undefined)
    assert.equal(echoed.url, '/shape?page=2&q=a')
    const flow = await flowOf('/shape')
    assert.deepEqual(flow.rules, ['shape'])
    const detail = JSON.parse(await readFile(join(dir, 'data', 'flows', 'default', `${flow.id}.json`), 'utf8'))
    assert.ok(detail.ruleLog.some(line => line.startsWith('shape: wait')))
  })

  test('answers from a rule without asking the server', async () => {
    await useRules([
      { id: 'mock', match: { path: '/mocked' }, request: [{ type: 'respond', status: 418, json: { teapot: true }, headers: { 'x-mock': '1' } }] },
      { id: 'from-file', match: { path: '/file' }, request: [{ type: 'respond', status: 200, file: 'mock.json' }] },
    ])
    const hits = echoHits
    const out = await curl(['-x', proxy, '-i', echoUrl('/mocked')])
    assert.match(out.stdout, /^HTTP\/1\.1 418/)
    assert.match(out.stdout, /x-mock: 1/i)
    assert.match(out.stdout, /\{"teapot":true\}$/)
    const fromFile = await curl(['-x', proxy, echoUrl('/file')])
    assert.equal(fromFile.stdout, '{"from":"file"}')
    assert.equal(echoHits, hits, 'the server was not asked')
  })

  test('changes a gzip response: status, merged JSON, decoded for the client', async () => {
    await useRules([
      {
        id: 'admin',
        match: { path: '/gzip' },
        response: [
          { type: 'setStatus', status: 201 },
          { type: 'mergeJson', json: { user: { role: 'admin' }, extra: true } },
          { type: 'setHeader', name: 'X-Rule', value: 'admin' },
        ],
      },
    ])
    const out = await curl(['-x', proxy, '-i', '-H', 'accept-encoding: gzip', echoUrl('/gzip')])
    assert.match(out.stdout, /^HTTP\/1\.1 201/)
    assert.doesNotMatch(out.stdout, /content-encoding/i)
    assert.match(out.stdout, /x-rule: admin/i)
    const json = JSON.parse(out.stdout.split('\r\n\r\n')[1])
    assert.deepEqual(json, { user: { name: 'ann', role: 'admin' }, items: [1, 2], extra: true })
  })

  test('response-only conditions: a 404 gets a new body, a 200 does not', async () => {
    await useRules([
      { id: 'soft-404', match: { status: '4xx' }, response: [{ type: 'setStatus', status: 200 }, { type: 'setBody', text: 'replaced' }] },
    ])
    assert.equal((await curl(['-x', proxy, echoUrl('/missing')])).stdout, 'replaced')
    assert.match((await curl(['-x', proxy, echoUrl('/fine')])).stdout, /"url":"\/fine"/)
  })

  test('rewrites the body with a pattern and sends elsewhere', async () => {
    await useRules([
      { id: 'mask', match: { path: '/mask' }, response: [{ type: 'replaceBody', pattern: 're:"method":"(\\w+)"', with: '"method":"<$1>"' }] },
      { id: 'elsewhere', match: { path: '/moved/*' }, request: [{ type: 'mapRemote', port: otherPort, path: '/new' }] },
    ])
    assert.match((await curl(['-x', proxy, echoUrl('/mask')])).stdout, /"method":"<GET>"/)
    assert.equal((await curl(['-x', proxy, echoUrl('/moved/x?keep=1')])).stdout, 'other:/new?keep=1')
  })

  test('matches on the request body, and changes it', async () => {
    await useRules([
      { id: 'login', match: { methods: ['POST'], bodyContains: '"user":"ann"' }, request: [{ type: 'mergeJson', json: { password: '***' } }] },
    ])
    const hit = JSON.parse((await curl(['-x', proxy, '-H', 'content-type: application/json', '-d', '{"user":"ann","password":"x"}', echoUrl('/login')])).stdout)
    assert.equal(hit.body, '{"user":"ann","password":"***"}')
    assert.equal(hit.headers['content-length'], String(hit.body.length))
    const miss = JSON.parse((await curl(['-x', proxy, '-d', '{"user":"bob"}', echoUrl('/login')])).stdout)
    assert.equal(miss.body, '{"user":"bob"}')
  })

  test('applies rules in order, and stop ends the chain', async () => {
    const twoRules = stop => [
      { id: 'first', stop, request: [{ type: 'setHeader', name: 'X-Order', value: 'first' }] },
      { id: 'second', request: [{ type: 'setHeader', name: 'X-Order', value: 'second' }] },
    ]
    await useRules(twoRules(false))
    assert.equal(JSON.parse((await curl(['-x', proxy, echoUrl('/order')])).stdout).headers['x-order'], 'second')
    await useRules(twoRules(true))
    assert.equal(JSON.parse((await curl(['-x', proxy, echoUrl('/order')])).stdout).headers['x-order'], 'first')
    const flow = await waitFor(() => [...flows.values()].filter(f => f.path === '/order' && f.state === 'done').at(-1)?.rules?.length === 1 && [...flows.values()].filter(f => f.path === '/order').at(-1), 'order flow')
    assert.deepEqual(flow.rules, ['first'])
  })

  test('fails the connection when a rule says so', async () => {
    await useRules([{ id: 'down', match: { path: '/down' }, request: [{ type: 'fail', kind: 'reset' }] }])
    const out = await curl(['-x', proxy, echoUrl('/down')])
    assert.notEqual(out.code, 0)
    const flow = await flowOf('/down')
    assert.equal(flow.errorCode, 'rule')
  })

  test('throttles a response to the given rate', async () => {
    await useRules([{ id: 'slow-net', match: { path: '/throttled' }, response: [{ type: 'setBody', text: 'x'.repeat(1200) }, { type: 'throttle', bytesPerSecond: 2000 }] }])
    const out = await curl(['-x', proxy, '-w', '\n%{time_total}', echoUrl('/throttled')])
    const [body, time] = out.stdout.split('\n')
    assert.equal(body.length, 1200)
    // 200-byte slices every 100 ms: about half a second for 1200 bytes
    assert.ok(Number(time) >= 0.45, `took ${time}s`)
  })

  test('applies rules inside decrypted HTTPS too', async () => {
    await useRules([
      { id: 'secure-mock', match: { host: 'localhost', path: '/mocked' }, request: [{ type: 'respond', status: 200, text: 'mocked over TLS' }] },
      { id: 'secure-reset', match: { path: '/reset' }, request: [{ type: 'fail', kind: 'reset' }] },
    ])
    const base = `https://localhost:${securePort}`
    assert.equal((await curl(['-x', proxy, '--cacert', caPath, `${base}/mocked`])).stdout, 'mocked over TLS')
    assert.equal((await curl(['-x', proxy, '--cacert', caPath, `${base}/plain`])).stdout, 'secure upstream')
    const reset = await curl(['-x', proxy, '--cacert', caPath, `${base}/reset`])
    assert.notEqual(reset.code, 0)
    assert.equal((await flowOf('/reset')).errorCode, 'rule')
  })

  test('runs a script only once it is approved, and picks up approval live', async () => {
    const script = {
      id: 'scripted',
      match: { path: '/script' },
      request: [{ type: 'script', code: "req.headers['x-script'] = 'request'" }],
      response: [{ type: 'script', code: "const data = res.json(); data.patched = req.method; res.body = data; res.status = 202" }],
    }
    const loaded = await useRules([script])
    assert.deepEqual(loaded.untrusted, ['scripted'])
    assert.equal(loaded.active, 0)
    assert.equal(JSON.parse((await curl(['-x', proxy, echoUrl('/script')])).stdout).headers['x-script'], undefined)

    const before = events.filter(e => e.t === 'rules').length
    await writeFile(trustFile, JSON.stringify({ sha256: [script.request[0].code, script.response[0].code].map(hashScript) }))
    await waitFor(() => events.filter(e => e.t === 'rules').length > before, 'trust reload')
    const out = await curl(['-x', proxy, '-i', echoUrl('/script')])
    assert.match(out.stdout, /^HTTP\/1\.1 202/)
    const json = JSON.parse(out.stdout.split('\r\n\r\n')[1])
    assert.equal(json.headers['x-script'], 'request')
    assert.equal(json.patched, 'GET')
  })

  test('a script that throws is logged and the request goes on', async () => {
    const code = "throw new Error('boom')"
    await writeFile(trustFile, JSON.stringify({ sha256: [hashScript(code)] }))
    await useRules([{ id: 'broken-script', match: { path: '/throws' }, request: [{ type: 'script', code }] }])
    const out = await curl(['-x', proxy, echoUrl('/throws')])
    assert.match(out.stdout, /"url":"\/throws"/)
    const flow = await flowOf('/throws')
    const detail = JSON.parse(await readFile(join(dir, 'data', 'flows', 'default', `${flow.id}.json`), 'utf8'))
    assert.ok(detail.ruleLog.some(line => /script failed: boom/.test(line)), detail.ruleLog.join('\n'))
  })
})
