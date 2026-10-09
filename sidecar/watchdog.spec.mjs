// node --test sidecar/watchdog.spec.mjs

import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { once } from 'node:events'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import net from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { after, before, describe, test } from 'node:test'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const BACKUP = {
  service: 'Wi-Fi',
  port: 8899,
  previous: { web: { enabled: false, server: '', port: 0 }, secure: { enabled: false, server: '', port: 0 }, bypass: ['*.local'] },
}

describe('the watchdog', () => {
  let dir
  before(async () => {
    dir = await mkdtemp(join(tmpdir(), 'proxy-watchdog-'))
  })
  after(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const run = async (port, name) => {
    const backup = join(dir, `${name}.json`)
    const dry = join(dir, `${name}.commands`)
    await writeFile(backup, JSON.stringify(BACKUP))
    // stands for the proxy: a process that dies when told
    const proxy = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'])
    const watchdog = spawn(process.execPath, [join(here, 'watchdog.mjs'), String(proxy.pid), backup, String(port)], {
      env: { ...process.env, WIREPANE_WATCHDOG_DRY: dry },
    })
    await new Promise(resolve => setTimeout(resolve, 300))
    proxy.kill('SIGKILL')
    await once(watchdog, 'exit')
    return { backup: await readFile(backup, 'utf8'), commands: await readFile(dry, 'utf8').catch(() => '') }
  }

  test('puts the system proxy back once the proxy is killed', { timeout: 15_000 }, async () => {
    const { backup, commands } = await run(1, 'killed')
    assert.match(commands, /networksetup -setwebproxystate Wi-Fi off/)
    assert.match(commands, /networksetup -setsecurewebproxystate Wi-Fi off/)
    assert.match(commands, /networksetup -setproxybypassdomains Wi-Fi \*\.local/)
    assert.equal(backup, '')
  })

  test('leaves it be when a proxy answers on the port again', { timeout: 15_000 }, async () => {
    const server = net.createServer(socket => socket.destroy())
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
    try {
      const { backup, commands } = await run(server.address().port, 'restarted')
      assert.equal(commands, '')
      assert.notEqual(backup, '')
    } finally {
      server.close()
    }
  })
})
