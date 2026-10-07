// Keeps the proxy from breaking Claude itself. Claude Code does not trust the
// proxy's CA, so a TLS connection of its own that the proxy decrypted would
// fail. Two guards:
//
// - Anthropic's and Claude's hosts are never decrypted, whoever asks.
// - While the macOS system proxy points at this proxy, every app's traffic
//   arrives here, Claude Code's included (its web fetches, MCP servers,
//   updates, the commands it runs). A local connection whose process
//   descends from Claude (any Claude Code session, the Claude app) is
//   tunnelled untouched. Finding the process costs an lsof, so it is done
//   only while the system proxy points here.

import { execFile } from 'node:child_process'

export const CLAUDE_HOSTS = ['*.anthropic.com', '*.claude.ai', '*.claude.com']

function run(argv, timeout = 2000) {
  return new Promise(resolve => {
    execFile(argv[0], argv.slice(1), { timeout, maxBuffer: 8 * 1024 * 1024 }, (error, stdout) => resolve(error ? '' : String(stdout)))
  })
}

/** Whether `scutil --proxy` output sends HTTP or HTTPS to `port` on one of `addresses`. */
export function systemProxyPointsAt(text, port, addresses) {
  const value = key => new RegExp(`\\b${key}\\s*:\\s*(\\S+)`).exec(text)?.[1]
  const hosts = new Set(['127.0.0.1', 'localhost', '::1', ...addresses])
  const points = (enable, proxy, portKey) => value(enable) === '1' && Number(value(portKey)) === port && hosts.has(value(proxy) ?? '')
  return points('HTTPSEnable', 'HTTPSProxy', 'HTTPSPort') || points('HTTPEnable', 'HTTPProxy', 'HTTPPort')
}

/** The pid that owns the client end `127.0.0.1:<port>->…` in `lsof -Fpn` output. */
export function clientPidFromLsof(text, port) {
  let pid = 0
  for (const line of text.split('\n')) {
    if (line.startsWith('p')) pid = Number(line.slice(1))
    else if (line.startsWith('n') && new RegExp(`^n(127\\.0\\.0\\.1|\\[::1\\]|localhost):${port}->`).test(line)) return pid
  }
  return 0
}

/** `ps -A -o pid=,ppid=,args=` as pid → { ppid, comm }, comm the whole command line. */
export function parseProcessTable(text) {
  const table = new Map()
  for (const line of text.split('\n')) {
    const match = /^\s*(\d+)\s+(\d+)\s+(.*)$/.exec(line)
    if (match) table.set(Number(match[1]), { ppid: Number(match[2]), comm: match[3].trim() })
  }
  return table
}

// The executable `claude` (Claude Code's native build, the Claude app), or
// node running the npm package. A path that merely contains "claude-code" (a
// project of that name) is no sign.
function isClaudeCommand(command) {
  const executable = command.split(/\s+/)[0] ?? ''
  const name = executable.replace(/^-/, '').split('/').pop() ?? ''
  return /^claude$/i.test(name) || /[/\\]@anthropic-ai[/\\]claude-code[/\\]/.test(command)
}

/** Whether the process or one of its ancestors is Claude (Claude Code, the Claude app). */
export function descendsFromClaude(table, pid) {
  for (let i = 0; i < 64 && pid > 1; i++) {
    const entry = table.get(pid)
    if (!entry) return false
    if (isClaudeCommand(entry.comm)) return true
    pid = entry.ppid
  }
  return false
}

export function createSelfGuard({ port, addresses, emit, isAssumed = false }) {
  // isAssumed: tests act as if the system proxy pointed here
  let isSystemProxied = isAssumed
  let table = null
  let tableAt = 0

  const check = async () => {
    if (isAssumed || process.platform !== 'darwin') return
    const was = isSystemProxied
    isSystemProxied = systemProxyPointsAt(await run(['scutil', '--proxy']), port(), addresses())
    if (was !== isSystemProxied) emit({ t: 'system-proxy', isOn: isSystemProxied })
  }
  check()
  setInterval(check, 3000).unref()

  const processTable = async () => {
    if (!table || Date.now() - tableAt > 2000) {
      table = parseProcessTable(await run(['ps', '-A', '-o', 'pid=,ppid=,args=']))
      tableAt = Date.now()
    }
    return table
  }

  return {
    get isSystemProxied() {
      return isSystemProxied
    },
    /** Looks again now: the mod just changed the system proxy. */
    recheck: check,
    /** Whether a local connection comes from Claude or something it started. */
    async isFromClaude(socket) {
      if (!isSystemProxied) return false
      const remote = socket.remoteAddress?.replace(/^::ffff:/, '')
      if (remote !== '127.0.0.1' && remote !== '::1') return false
      const pid = clientPidFromLsof(await run(['lsof', '-nP', `-iTCP:${socket.remotePort}`, '-Fpn'], 1500), socket.remotePort)
      if (!pid || pid === process.pid) return false
      return descendsFromClaude(await processTable(), pid)
    },
  }
}
