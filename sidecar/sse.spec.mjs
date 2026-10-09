// node --test sidecar/sse.spec.mjs
// Server-sent events: each event recorded as it arrives, while the stream is open.

import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import http from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, before, describe, test } from 'node:test'

import { curl, listen, startSidecar } from './spec-kit.mjs'
import { EventStreamReader } from './sse.mjs'

describe('server-sent events', () => {
  let dataDir
  let sidecar
  let proxy
  let port
  let release
  const servers = []

  before(async () => {
    dataDir = await mkdtemp(join(tmpdir(), 'proxy-sse-'))
    const server = http.createServer((req, res) => {
      res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' })
      res.write('event: start\nid: 1\ndata: {"step":1}\n\n')
      // one event split across two writes, and a comment line
      res.write('data: first line\n')
      setTimeout(() => res.write('data: second line\n: a comment\n\n'), 50)
      // the last one only once the test has seen the stream open
      release = () => {
        res.write('event: done\ndata: [DONE]\n\n')
        res.end()
      }
    })
    servers.push(server)
    port = await listen(server)
    sidecar = startSidecar(join(dataDir, 'proxy'))
    const ready = await sidecar.waitFor(() => sidecar.events.find(e => e.t === 'ready'), 'ready')
    proxy = `http://127.0.0.1:${ready.port}`
  })

  after(async () => {
    sidecar?.child.kill()
    for (const server of servers) server.close()
    await rm(dataDir, { recursive: true, force: true })
  })

  test('records each event as it arrives, while the stream is still open', async () => {
    const out = curl(['-N', '-x', proxy, `http://localhost:${port}/stream`])
    // two events counted before the response ends
    const open = await sidecar.flow(f => f.path === '/stream' && f.sseEvents === 2 && f.state === 'receiving', 'two events, still open')
    assert.equal(open.state, 'receiving')
    release()
    assert.match((await out).stdout, /\[DONE\]/)
    const flow = await sidecar.flow(f => f.path === '/stream' && f.state === 'done', 'the finished stream')
    assert.equal(flow.sseEvents, 3)
    const events = (await readFile(join(dataDir, 'proxy', 'flows', 'spec', `${flow.id}.sse.jsonl`), 'utf8'))
      .trim()
      .split('\n')
      .map(line => JSON.parse(line))
    assert.deepEqual(
      events.map(({ event, id, data }) => ({ event, id, data })),
      [
        { event: 'start', id: '1', data: '{"step":1}' },
        { event: undefined, id: undefined, data: 'first line\nsecond line' },
        { event: 'done', id: undefined, data: '[DONE]' },
      ],
    )
    assert.ok(events.every(e => typeof e.t === 'number'))
    const detail = JSON.parse(await readFile(join(dataDir, 'proxy', 'flows', 'spec', `${flow.id}.json`), 'utf8'))
    assert.deepEqual(detail.sse, { file: join(dataDir, 'proxy', 'flows', 'spec', `${flow.id}.sse.jsonl`), count: 3 })
  })
})

describe('the event-stream reader', () => {
  test('a CRLF split across two pieces ends one line, not two', () => {
    const events = []
    const reader = new EventStreamReader(event => events.push(event))
    reader.push(Buffer.from('data: a\r'))
    reader.push(Buffer.from('\ndata: b\r\n\r\n'))
    assert.deepEqual(events.map(e => e.data), ['a\nb'])
  })
})
