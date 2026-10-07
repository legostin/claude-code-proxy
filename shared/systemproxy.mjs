// The macOS system proxy: what networksetup says, the commands that point a
// network service at the proxy, and the ones that put it back exactly as it
// was. Plain JavaScript: the mod runs the commands through $.process.run, the
// sidecar through child_process when Claude Code is gone without a word.

/** Hosts the system proxy never sends to the proxy: Claude's own, and the usual local ones. */
export const BYPASS = ['*.local', '169.254/16', 'localhost', '127.0.0.1', '*.anthropic.com', 'anthropic.com', '*.claude.ai', 'claude.ai', '*.claude.com', 'claude.com']

/** `networksetup -listnetworkserviceorder` as [{ name, device, isDisabled }]. */
export function parseServiceOrder(text) {
  const services = []
  const lines = String(text).split('\n')
  for (let i = 0; i < lines.length; i++) {
    const head = /^\((\d+|\*)\)\s+(.+)$/.exec(lines[i].trim())
    if (!head) continue
    const port = /Device:\s*([^)]*)\)/.exec(lines[i + 1] ?? '')
    services.push({ name: head[2].replace(/^\*\s*/, ''), device: port?.[1]?.trim() ?? '', isDisabled: head[1] === '*' || head[2].startsWith('*') })
  }
  return services
}

/** `networksetup -getwebproxy <service>` (or -getsecurewebproxy) as { enabled, server, port }. */
export function parseProxyState(text) {
  const value = key => new RegExp(`^${key}:\\s*(.*)$`, 'm').exec(String(text))?.[1]?.trim() ?? ''
  return { enabled: value('Enabled') === 'Yes', server: value('Server'), port: Number(value('Port')) || 0 }
}

/** `networksetup -getproxybypassdomains <service>` as a list; empty when none is set. */
export function parseBypass(text) {
  const lines = String(text).split('\n').map(line => line.trim()).filter(Boolean)
  return lines.length === 1 && /aren't any|There are no/i.test(lines[0]) ? [] : lines
}

/** Points `service` at the proxy for HTTP and HTTPS, keeping its bypass list and adding Claude's hosts. */
export function enableCommands(service, port, previousBypass = []) {
  const bypass = [...new Set([...previousBypass, ...BYPASS])]
  return [
    ['networksetup', '-setwebproxy', service, '127.0.0.1', String(port)],
    ['networksetup', '-setsecurewebproxy', service, '127.0.0.1', String(port)],
    ['networksetup', '-setproxybypassdomains', service, ...bypass],
  ]
}

/**
 * Puts the service back as the backup recorded it:
 * `{ service, previous: { web, secure, bypass } }`.
 */
export function restoreCommands(backup) {
  const { service, previous } = backup
  const commands = []
  for (const [kind, state] of [['web', previous.web], ['secure', previous.secure]]) {
    const set = kind === 'web' ? '-setwebproxy' : '-setsecurewebproxy'
    const toggle = kind === 'web' ? '-setwebproxystate' : '-setsecurewebproxystate'
    if (state.enabled && state.server && state.port) commands.push(['networksetup', set, service, state.server, String(state.port)])
    else {
      if (state.server && state.port) commands.push(['networksetup', set, service, state.server, String(state.port)])
      commands.push(['networksetup', toggle, service, 'off'])
    }
  }
  commands.push(['networksetup', '-setproxybypassdomains', service, ...(previous.bypass.length ? previous.bypass : ['Empty'])])
  return commands
}

function shellQuote(text) {
  return `'${String(text).replace(/'/g, `'\\''`)}'`
}

/** The commands as one line for `do shell script ... with administrator privileges`. */
export function asAdminScript(commands) {
  const line = commands.map(argv => argv.map(shellQuote).join(' ')).join(' && ')
  return `do shell script "${line.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}" with administrator privileges`
}

export function needsAdmin(output) {
  return /requires admin|administrator|not authorized|permission/i.test(String(output))
}
