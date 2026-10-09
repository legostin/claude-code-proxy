// The doctor: what stands between the person and their traffic, read from
// what the proxy saw and what this Mac says, each finding with its fix. Pure:
// the hooks module gathers the facts (networksetup, route, adb, the flows).

import type { ProxyFlow, ProxyStatus, ProxyTracking } from '../types'

export type FindingLevel = 'ok' | 'info' | 'warn' | 'fail'

/** What the pane can do about a finding in one press. */
export type DoctorAction =
  | { kind: 'start' }
  | { kind: 'restore-system-proxy' }
  | { kind: 'trust-mac' }
  | { kind: 'track'; patterns: string[] }
  | { kind: 'insecure-host'; host: string }
  | { kind: 'no-decrypt'; host: string }
  | { kind: 'android-system-ca'; serial: string }
  | { kind: 'setup'; tab: 'ios' | 'android' | 'cli' }
  | { kind: 'upstream'; proxy: string }
  | { kind: 'stop-old'; pid: number }

export type Finding = { level: FindingLevel; title: string; detail?: string; fix?: string; action?: DoctorAction; label?: string }

export type ProxyState = { enabled: boolean; server: string; port: number }

export type AndroidFacts = { serial: string; sdk: number | null; proxy: string | null; isRootable: boolean; hasSystemCa: boolean }

export type DoctorFacts = {
  status: ProxyStatus
  flows: readonly ProxyFlow[]
  tracking: ProxyTracking
  skipped: Record<string, number>
  macTrust: 'trusted' | 'untrusted' | 'unknown'
  /** The default network service's web and secure proxies; null when it could not be read. */
  systemProxy: { service: string; web: ProxyState; secure: ProxyState } | null
  /** A backup of the settings before Wirepane turned the system proxy on. */
  hasBackup: boolean
  /** The upstream proxy Wirepane is set to use, empty for none. */
  upstreamProxy?: string
  /** The proxy the network service had before Wirepane took its place (an office's): host:port, socks5://host:port or pac+URL. */
  previousProxy?: string | null
  /** The network service's automatic proxy configuration (a PAC file), when it is on. */
  autoProxyUrl?: string | null
  /** The interface of the default route when it is a VPN's (utun, ppp, ipsec). */
  vpn: string | null
  /** Other proxy apps that run (Charles, Proxyman, mitmproxy, HTTP Toolkit). */
  otherProxies: string[]
  /** Who holds the port when the proxy could not take it. */
  portHolder: string | null
  /** The pid of a Wirepane proxy from before the shared one (0.7), when that is what holds the port. */
  oldProxyPid?: number | null
  android: AndroidFacts[]
  /** Hosts passed through untouched after refusing the certificate (per client). */
  pinned: { client: string; host: string }[]
}

const isLocal = (client: string | null) => !client || client === '127.0.0.1' || client === '::1'

function clientName(client: string | null): string {
  return isLocal(client) ? 'this Mac (a browser, a simulator, the Android emulator or a Mac app)' : `the device at ${client}`
}

function list(items: readonly string[], max = 5): string {
  return items.length > max ? `${items.slice(0, max).join(', ')} and ${items.length - max} more` : items.join(', ')
}

const KNOWN_PROXY_PORTS: Record<number, string> = { 8888: 'Charles', 9090: 'Proxyman', 8080: 'mitmproxy or HTTP Toolkit', 8000: 'HTTP Toolkit' }

function proxyFindings(facts: DoctorFacts, out: Finding[]) {
  const { status } = facts
  if (status.phase === 'running') out.push({ level: 'ok', title: `The proxy runs on port ${status.port}` })
  else if (status.phase === 'failed') {
    const busy = /EADDRINUSE|port-busy|address already in use/i.test(status.error ?? '')
    const old = busy ? facts.oldProxyPid : null
    out.push({
      level: 'fail',
      title: old
        ? `Port ${status.port} is held by a Wirepane proxy from before 0.8 (pid ${old}), which another session may still use`
        : busy
          ? `Port ${status.port} is taken${facts.portHolder ? ` by ${facts.portHolder}` : ''}`
          : 'The proxy failed to start',
      detail: status.error ?? undefined,
      fix: old
        ? 'Stop it and start the shared proxy in its place; a session still on the old one gets the new one with /proxy.'
        : busy
          ? 'Quit what holds the port, or set another port in the plugin settings (/plugin → Wirepane → Port).'
          : 'Start it again; the error above says why it stopped.',
      action: old ? { kind: 'stop-old', pid: old } : { kind: 'start' },
      label: old ? 'Stop it and start' : 'Start again',
    })
  } else out.push({ level: 'info', title: 'The proxy is stopped', fix: 'Start it with /proxy start or the Start button.', action: { kind: 'start' }, label: 'Start' })
}

function systemProxyFindings(facts: DoctorFacts, out: Finding[]) {
  const sp = facts.systemProxy
  if (!sp) return
  const running = facts.status.phase === 'running'
  const ours = (state: ProxyState) => state.enabled && (state.server === '127.0.0.1' || state.server === 'localhost') && state.port === facts.status.port
  const states = [sp.web, sp.secure]
  if (states.some(ours) && !running) {
    out.push({
      level: 'fail',
      title: `${sp.service} points at Wirepane, but no proxy runs: Mac apps and the iOS Simulator have no internet`,
      fix: facts.hasBackup ? 'Put the settings back as they were.' : 'System Settings → Network → Details → Proxies: turn the web proxies off.',
      ...(facts.hasBackup ? { action: { kind: 'restore-system-proxy' } as DoctorAction, label: 'Put back' } : {}),
    })
    return
  }
  const elsewhere = states.find(state => state.enabled && !ours(state))
  if (elsewhere) {
    const who = KNOWN_PROXY_PORTS[elsewhere.port]
    out.push({
      level: 'warn',
      title: `${sp.service} sends web traffic to ${elsewhere.server}:${elsewhere.port}${who ? ` (${who}'s port)` : ''}, not to Wirepane`,
      detail: 'Mac apps and the iOS Simulator follow the system proxy, so they skip Wirepane.',
      fix: 'Quit the other proxy, or turn the system proxy to Wirepane in Setup → macOS.',
      action: { kind: 'setup', tab: 'cli' },
      label: 'Setup',
    })
    return
  }
  if (states.some(ours)) out.push({ level: 'ok', title: `Mac apps and the iOS Simulator go through Wirepane (${sp.service})` })
  else
    out.push({
      level: 'info',
      title: 'The system proxy is off',
      detail: 'Only clients pointed at Wirepane themselves are recorded: the browser it opens, the Android emulator it starts, phones set up by hand.',
      fix: 'For Mac apps and the iOS Simulator, turn the system proxy on in Setup.',
      action: { kind: 'setup', tab: 'ios' },
      label: 'Setup',
    })
}

function trustFindings(facts: DoctorFacts, out: Finding[]) {
  if (facts.status.phase !== 'running') return
  if (facts.macTrust === 'untrusted') {
    out.push({
      level: 'warn',
      title: 'This Mac does not trust the Wirepane CA',
      detail: 'Safari and Mac apps behind the system proxy refuse HTTPS; the browser Wirepane opens and the simulators do not need it.',
      action: { kind: 'trust-mac' },
      label: 'Trust on this Mac',
    })
  }
  // refusals, by client: every host refused means no trust; one host among working ones means pinning
  const byClient = new Map<string, { refused: Set<string>; decrypted: Set<string> }>()
  for (const flow of facts.flows) {
    const client = flow.client ?? '127.0.0.1'
    const entry = byClient.get(client) ?? { refused: new Set(), decrypted: new Set() }
    if (flow.errorCode === 'client-rejected-cert') entry.refused.add(flow.host)
    else if (flow.kind !== 'tunnel' && flow.scheme === 'https' && flow.status !== null) entry.decrypted.add(flow.host)
    byClient.set(client, entry)
  }
  for (const [client, { refused, decrypted }] of byClient) {
    const pinnedHosts = [...refused].filter(host => !decrypted.has(host))
    if (pinnedHosts.length === 0) continue
    if (decrypted.size === 0 && refused.size >= 2) {
      out.push({
        level: 'fail',
        title: `${clientName(client)} refuses the Wirepane CA for every host (${list([...refused])})`,
        fix: isLocal(client)
          ? 'iOS Simulator: Setup → iOS installs the CA in one press. Android emulator: Setup → Android. A Mac app: Trust on this Mac.'
          : 'iPhone: install the profile, then Settings → General → About → Certificate Trust Settings → turn on Wirepane CA. ' +
            "Android: install the CA as a user certificate; apps trust it only with a network_security_config (Chrome does).",
        action: isLocal(client) ? { kind: 'setup', tab: 'ios' } : { kind: 'setup', tab: 'ios' },
        label: 'Setup',
      })
    } else {
      for (const host of pinnedHosts.slice(0, 5)) {
        out.push({
          level: 'warn',
          title: `${host} refuses the Wirepane CA while other hosts work: the app pins its certificate`,
          detail: `Seen from ${clientName(client)}. After two refusals Wirepane passes it through untouched, so the app keeps working, unrecorded.`,
          fix: "Your own app: trust user CAs and switch pinning off in debug builds (the wirepane-troubleshooting skill shows how). Someone else's: it stays encrypted.",
          action: { kind: 'no-decrypt', host },
          label: 'Never decrypt it',
        })
      }
    }
  }
}

const UPSTREAM_HINTS: [RegExp, (host: string, bare: string) => Finding][] = [
  [
    /ENOTFOUND|EAI_AGAIN/,
    host => ({
      level: 'warn',
      title: `${host} does not resolve from this Mac`,
      detail: 'The proxy looks names up on this Mac: a name only a VPN, a phone or a container knows fails here.',
      fix: 'Check the name, connect this Mac to the VPN it needs, or map it with a rule (mapRemote).',
    }),
  ],
  [
    /DEPTH_ZERO_SELF_SIGNED_CERT|SELF_SIGNED_CERT_IN_CHAIN|UNABLE_TO_VERIFY_LEAF_SIGNATURE|UNABLE_TO_GET_ISSUER_CERT|ERR_TLS_CERT_ALTNAME_INVALID|CERT_HAS_EXPIRED/,
    (host, bare) => ({
      level: 'warn',
      title: `${host} shows a certificate this Mac does not trust (a dev server?)`,
      fix: 'Let Wirepane accept its certificate (for this host only).',
      action: { kind: 'insecure-host', host: bare },
      label: 'Accept its certificate',
    }),
  ],
  [
    /ECONNREFUSED/,
    host => ({
      level: 'warn',
      title: `Nothing answers at ${host}`,
      detail: /^(localhost|127\.|::1|10\.0\.2\.2)/.test(host)
        ? "The proxy reaches this Mac's own ports: is the dev server running, on that port?"
        : 'The server is down, or a firewall closes the port.',
    }),
  ],
  [/ETIMEDOUT|ENETUNREACH|EHOSTUNREACH/, host => ({ level: 'warn', title: `${host} cannot be reached from this Mac`, detail: 'A network or a VPN in the way.' })],
]

function upstreamFindings(facts: DoctorFacts, out: Finding[]) {
  const seen = new Set<string>()
  for (const flow of [...facts.flows].reverse()) {
    if (flow.errorCode !== 'upstream' || !flow.error) continue
    for (const [pattern, make] of UPSTREAM_HINTS) {
      if (!pattern.test(flow.error)) continue
      const key = `${pattern.source}|${flow.host}`
      if (seen.has(key)) break
      seen.add(key)
      const finding = make(flow.port === 443 || flow.port === 80 ? flow.host : `${flow.host}:${flow.port}`, flow.host)
      out.push({ ...finding, detail: [finding.detail, `#${flow.id}: ${flow.error}`].filter(Boolean).join(' ') })
      break
    }
  }
}

function trackingFindings(facts: DoctorFacts, out: Finding[]) {
  const { tracking, skipped } = facts
  if (!tracking.enabled || tracking.patterns.length === 0) {
    const hosts = new Set(facts.flows.map(flow => flow.host))
    if (hosts.size > 15) {
      out.push({
        level: 'info',
        title: `${hosts.size} hosts recorded: most of it is noise`,
        fix: "Track only your app's domains; the rest passes through unrecorded.",
      })
    }
    return
  }
  const recorded = facts.flows.filter(flow => flow.kind !== 'tunnel').length
  const passing = Object.entries(skipped).sort((a, b) => b[1] - a[1])
  if (recorded === 0 && passing.length > 0) {
    out.push({
      level: 'warn',
      title: `The tracked domains (${list(tracking.patterns)}) match nothing that came`,
      detail: `What passed through, busiest first: ${list(passing.map(([host, n]) => `${host} ×${n}`), 6)}.`,
      fix: 'Add the app’s real hosts to the list.',
    })
  } else out.push({ level: 'ok', title: `Only ${list(tracking.patterns)} recorded; ${passing.length} other hosts passed through` })
}

function androidFindings(facts: DoctorFacts, out: Finding[]) {
  const port = facts.status.port
  for (const device of facts.android) {
    const name = device.serial
    const proxied = device.proxy && /:(\d+)$/.exec(device.proxy)?.[1] === String(port)
    if (!proxied && device.serial.startsWith('emulator-')) {
      out.push({
        level: 'info',
        title: `${name} does not go through Wirepane${device.proxy ? ` (its proxy is ${device.proxy})` : ''}`,
        fix: 'Setup → Android points it at the proxy (or start the emulator from there).',
        action: { kind: 'setup', tab: 'android' },
        label: 'Setup',
      })
    }
    const sdk = device.sdk ?? 0
    if (device.hasSystemCa) out.push({ level: 'ok', title: `${name} trusts the CA in every app (system CA)` })
    else if (device.isRootable && sdk >= 24) {
      out.push({
        level: 'info',
        title: `${name}: apps trust user CAs only with a network_security_config`,
        detail:
          `This image allows root (API ${sdk}): Wirepane can put its CA among the system CAs until the next reboot, so every app trusts it.` +
          (sdk >= 37 ? ' Android 17 also asks system CAs for Certificate Transparency, which Wirepane’s certificates do not carry: some apps may still refuse.' : ''),
        action: { kind: 'android-system-ca', serial: device.serial },
        label: 'Trust in all apps',
      })
    } else if (sdk >= 24 && device.serial.startsWith('emulator-')) {
      out.push({
        level: 'info',
        title: `${name} runs a Google Play image: apps trust user CAs only with a network_security_config`,
        detail: 'Chrome trusts the user CA; an app does only when its network_security_config says so, and this image refuses root, so the CA cannot be a system CA.',
        fix: 'Your own app: add debug-overrides with <certificates src="user" /> (the wirepane-troubleshooting skill shows it). Every app: an emulator with a Google APIs image, then Trust in all apps.',
      })
    }
  }
}

/** Every finding, the worst first. */
export function diagnose(facts: DoctorFacts): Finding[] {
  const out: Finding[] = []
  proxyFindings(facts, out)
  systemProxyFindings(facts, out)
  if (facts.vpn) {
    out.push({
      level: 'warn',
      title: `A VPN carries this Mac's traffic (${facts.vpn})`,
      detail: 'A phone on Wi-Fi may not reach this Mac, some VPNs put back or skip the system proxy, and names may resolve only inside it.',
      fix: 'If a phone cannot connect, try with the VPN off, or connect the phone over USB (Android: adb reverse).',
    })
  }
  if (facts.previousProxy && !facts.upstreamProxy) {
    const failing = facts.flows.filter(flow => flow.errorCode === 'upstream').length
    out.push({
      level: failing ? 'warn' : 'info',
      title: `This network had its own proxy (${facts.previousProxy}), which Wirepane does not go through`,
      detail: `An office or a VPN may let servers be reached only through it${failing ? `; ${failing} requests failed upstream` : ''}.`,
      fix: 'Set it as the upstream proxy (add user:password@ if it asks for credentials).',
      action: { kind: 'upstream', proxy: facts.previousProxy },
      label: 'Use it upstream',
    })
  }
  if (facts.autoProxyUrl && facts.systemProxy && [facts.systemProxy.web, facts.systemProxy.secure].some(state => state.enabled && state.port === facts.status.port)) {
    out.push({
      level: 'warn',
      title: `${facts.systemProxy.service} also has automatic proxy configuration on (${facts.autoProxyUrl}), which apps may follow instead of Wirepane`,
      fix: 'Turn "Automatic proxy configuration" off in System Settings → Network → Details → Proxies while you debug; Wirepane can use that PAC file upstream.',
    })
  }
  if (facts.upstreamProxy) out.push({ level: 'info', title: `Servers are reached through the upstream proxy ${facts.upstreamProxy.replace(/\/\/[^@/]*@/, '//…@')}` })
  if (facts.otherProxies.length) out.push({ level: 'info', title: `Other proxy apps run: ${list(facts.otherProxies)}`, detail: 'They may hold the system proxy or the same ports.' })
  trustFindings(facts, out)
  for (const { client, host } of facts.pinned.slice(0, 8)) {
    out.push({ level: 'info', title: `${host} passes through untouched for ${clientName(client)}`, detail: 'It refused the certificate twice; its traffic flows, unrecorded.' })
  }
  upstreamFindings(facts, out)
  trackingFindings(facts, out)
  androidFindings(facts, out)
  if (facts.status.phase === 'running' && facts.flows.length === 0) {
    out.push({
      level: 'info',
      title: 'Nothing recorded yet',
      fix: 'Point a client at the proxy (Setup), then use the app. An app that ignores the system proxy (Flutter, some games, Go and Node tools) needs its own setting.',
    })
  }
  const rank: Record<FindingLevel, number> = { fail: 0, warn: 1, info: 2, ok: 3 }
  return out.map((finding, i) => ({ finding, i })).sort((a, b) => rank[a.finding.level] - rank[b.finding.level] || a.i - b.i).map(({ finding }) => finding)
}

const MARKS: Record<FindingLevel, string> = { fail: '✗', warn: '!', info: '•', ok: '✓' }

/** The findings as text for Claude or a command's answer. */
export function findingsText(findings: readonly (Omit<Finding, 'action'> & { action?: unknown })[]): string {
  return findings
    .map(f => [`${MARKS[f.level]} ${f.title}`, f.detail ? `    ${f.detail}` : '', f.fix ? `    fix: ${f.fix}` : '', f.action ? `    (the Health view has a button: ${f.label})` : ''].filter(Boolean).join('\n'))
    .join('\n')
}
