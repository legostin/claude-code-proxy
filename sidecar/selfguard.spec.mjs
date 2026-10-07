// node --test sidecar/selfguard.spec.mjs
// What keeps the proxy from breaking Claude, and the system proxy's round trip.

import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { existsSync } from 'node:fs'
import { mkdtemp, readFile, rm, symlink } from 'node:fs/promises'
import https from 'node:https'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { after, before, describe, test } from 'node:test'

import { createLeafFactory, ensureCA } from './certs.mjs'

import { clientPidFromLsof, descendsFromClaude, parseProcessTable, systemProxyPointsAt } from './selfguard.mjs'
import {
  asAdminScript,
  BYPASS,
  enableCommands,
  parseBypass,
  parseProxyState,
  parseServiceOrder,
  restoreCommands,
} from '../shared/systemproxy.mjs'

const SCUTIL_OFF = `<dictionary> {
  ExceptionsList : <array> {
    0 : *.local
    1 : 169.254/16
  }
  FTPPassive : 1
  HTTPEnable : 0
  HTTPSEnable : 0
}`

const SCUTIL_ON = `<dictionary> {
  HTTPEnable : 1
  HTTPPort : 8899
  HTTPProxy : 127.0.0.1
  HTTPSEnable : 1
  HTTPSPort : 8899
  HTTPSProxy : 127.0.0.1
}`

describe('the self guard', () => {
  test('knows when the system proxy points at this proxy', () => {
    assert.equal(systemProxyPointsAt(SCUTIL_OFF, 8899, []), false)
    assert.equal(systemProxyPointsAt(SCUTIL_ON, 8899, []), true)
    assert.equal(systemProxyPointsAt(SCUTIL_ON, 9000, []), false)
    assert.equal(systemProxyPointsAt(SCUTIL_ON.replace(/127\.0\.0\.1/g, '10.7.9.5'), 8899, ['10.7.9.5']), true)
    assert.equal(systemProxyPointsAt(SCUTIL_ON.replace(/127\.0\.0\.1/g, '10.7.9.5'), 8899, []), false)
  })

  test('finds the process at the client end of a connection', () => {
    const lsof = 'p16290\nf13\nn127.0.0.1:8899->127.0.0.1:51409\np777\nf20\nn127.0.0.1:51409->127.0.0.1:8899\n'
    assert.equal(clientPidFromLsof(lsof, 51409), 777)
    assert.equal(clientPidFromLsof(lsof, 51410), 0)
  })

  test('recognises Claude and whatever it started', () => {
    const table = parseProcessTable(
      [
        '    1     0 /sbin/launchd',
        '  636     1 /Applications/cmux.app/Contents/MacOS/cmux',
        '62386 62120 /Users/me/.local/bin/claude',
        '62120   636 -/bin/zsh',
        '18472 62386 /bin/zsh',
        '18500 18472 /usr/bin/curl',
        '18600 62386 node /Users/me/.npm/_npx/server.js',
        '19000   636 node /Users/me/claude-code-video-toolkit/server.js',
        '20000   636 /Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
        '21000     1 /Applications/Claude.app/Contents/MacOS/Claude',
        '22000 30000 node /opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/cli.js --resume',
        '22100 22000 /bin/zsh -c npm test',
      ].join('\n'),
    )
    assert.equal(descendsFromClaude(table, 18500), true, 'a command Claude Code ran')
    assert.equal(descendsFromClaude(table, 18600), true, 'an MCP server')
    assert.equal(descendsFromClaude(table, 62386), true, 'Claude Code itself')
    assert.equal(descendsFromClaude(table, 21000), true, 'the Claude app')
    assert.equal(descendsFromClaude(table, 22000), true, 'Claude Code from npm')
    assert.equal(descendsFromClaude(table, 22100), true, 'a command the npm Claude Code ran')
    assert.equal(descendsFromClaude(table, 19000), false, 'a project that is only named claude-code-something')
    assert.equal(descendsFromClaude(table, 20000), false, 'a browser')
    assert.equal(descendsFromClaude(table, 99999), false, 'a process that is gone')
  })
})

describe('the system proxy', () => {
  const ORDER = `An asterisk (*) denotes that a network service is disabled.
(1) Thunderbolt Bridge
(Hardware Port: Thunderbolt Bridge, Device: bridge0)

(2) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)

(*) Old VPN
(Hardware Port: L2TP, Device: )
`

  test('reads networksetup', () => {
    assert.deepEqual(parseServiceOrder(ORDER), [
      { name: 'Thunderbolt Bridge', device: 'bridge0', isDisabled: false },
      { name: 'Wi-Fi', device: 'en0', isDisabled: false },
      { name: 'Old VPN', device: '', isDisabled: true },
    ])
    assert.deepEqual(parseProxyState('Enabled: No\nServer: 127.0.0.1\nPort: 8729\nAuthenticated Proxy Enabled: 0\n'), {
      enabled: false,
      server: '127.0.0.1',
      port: 8729,
    })
    assert.deepEqual(parseBypass('*.local\n169.254/16\n'), ['*.local', '169.254/16'])
    assert.deepEqual(parseBypass("There aren't any bypass domains set on Wi-Fi.\n"), [])
  })

  test('turns on with Claude bypassed, and goes back exactly as it was', () => {
    const on = enableCommands('Wi-Fi', 8899, ['*.local', 'corp.example.com'])
    assert.deepEqual(on[0], ['networksetup', '-setwebproxy', 'Wi-Fi', '127.0.0.1', '8899'])
    assert.deepEqual(on[1], ['networksetup', '-setsecurewebproxy', 'Wi-Fi', '127.0.0.1', '8899'])
    assert.ok(on[2].includes('*.anthropic.com') && on[2].includes('claude.ai') && on[2].includes('corp.example.com'))
    assert.equal(on[2].filter(host => host === '*.local').length, 1)
    assert.ok(BYPASS.includes('*.claude.com'))

    const back = restoreCommands({
      service: 'Wi-Fi',
      previous: {
        web: { enabled: false, server: '127.0.0.1', port: 8729 },
        secure: { enabled: true, server: 'corp-proxy', port: 3128 },
        bypass: [],
      },
    })
    assert.deepEqual(back, [
      ['networksetup', '-setwebproxy', 'Wi-Fi', '127.0.0.1', '8729'],
      ['networksetup', '-setwebproxystate', 'Wi-Fi', 'off'],
      ['networksetup', '-setsecurewebproxy', 'Wi-Fi', 'corp-proxy', '3128'],
      ['networksetup', '-setproxybypassdomains', 'Wi-Fi', 'Empty'],
    ])
  })

  test('asks for an administrator in one dialog when it must', () => {
    const script = asAdminScript([['networksetup', '-setwebproxy', "Bob's Wi-Fi", '127.0.0.1', '8899']])
    assert.equal(script, `do shell script "'networksetup' '-setwebproxy' 'Bob'\\\\''s Wi-Fi' '127.0.0.1' '8899'" with administrator privileges`)
  })
})

describe('while the system proxy points here', () => {
  const here = dirname(fileURLToPath(import.meta.url))
  let dir
  let child
  let ready
  let securePort
  let server
  const flows = []

  before(async () => {
    dir = await mkdtemp(join(tmpdir(), 'proxy-guard-'))
    const upstreamCA = await ensureCA(join(dir, 'upstream'))
    const context = await createLeafFactory(upstreamCA).get('localhost')
    server = https.createServer({ SNICallback: (name, done) => done(null, context) }, (req, res) => res.end('upstream'))
    securePort = await new Promise(r => server.listen(0, () => r(server.address().port)))
    // a shell named claude: whatever it runs descends from "Claude"
    await symlink('/bin/sh', join(dir, 'claude'))
    child = spawn(process.execPath, [join(here, 'proxy.mjs'), '--port', '0', '--data', join(dir, 'data'), '--assume-system-proxy', '--insecure-upstream'], {
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let buffer = ''
    ready = await new Promise(resolve => {
      child.stdout.on('data', chunk => {
        buffer += chunk
        let newline
        while ((newline = buffer.indexOf('\n')) >= 0) {
          const event = JSON.parse(buffer.slice(0, newline))
          buffer = buffer.slice(newline + 1)
          if (event.t === 'ready') resolve(event)
          if (event.t === 'flow') flows.push(event.flow)
        }
      })
    })
  })

  after(async () => {
    child?.kill()
    server?.close()
    await rm(dir, { recursive: true, force: true })
  })

  /** Runs curl through the proxy from `shell`, detached when asked; answers its output. */
  async function curlFrom(shell, path, isDetached) {
    const out = join(dir, `${path.replace(/\W/g, '')}.out`)
    const curl = `curl -sS --noproxy '' --max-time 10 -x http://127.0.0.1:${ready.port} --cacert ${ready.ca.path} https://localhost:${securePort}/${path} > ${out} 2>&1; echo "exit:$?" >> ${out}`
    // detached: the shell exits at once, and curl's parent becomes launchd
    const script = isDetached ? `(${curl}) &` : curl
    await new Promise(resolve => spawn(shell, ['-c', script], { stdio: 'ignore' }).on('close', resolve))
    for (let i = 0; i < 100 && !(existsSync(out) && (await readFile(out, 'utf8')).includes('exit:')); i++) await new Promise(r => setTimeout(r, 100))
    return readFile(out, 'utf8')
  }

  test('Claude and what it runs are tunnelled, never decrypted', async () => {
    const out = await curlFrom(join(dir, 'claude'), 'from-claude', false)
    // not decrypted: curl met the server's own certificate, which the proxy CA did not sign
    assert.match(out, /exit:60/)
    assert.equal(flows.some(flow => flow.path === '/from-claude'), false)
  })

  test('any other client is decrypted and recorded', async () => {
    const out = await curlFrom('/bin/sh', 'from-elsewhere', true)
    assert.match(out, /^upstream/)
    assert.match(out, /exit:0/)
    await new Promise(r => setTimeout(r, 200))
    assert.equal(flows.some(flow => flow.path === '/from-elsewhere'), true)
  })
})
