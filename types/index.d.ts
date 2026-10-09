export type ProxyFlow = {
  id: number
  ts: number
  kind: 'http' | 'ws' | 'tunnel'
  method: string
  scheme: 'http' | 'https'
  host: string
  port: number
  path: string
  status: number | null
  reqSize: number
  resSize: number
  durationMs: number | null
  contentType: string | null
  state: 'pending' | 'receiving' | 'done' | 'error'
  error: string | null
  errorCode: string | null
  client: string | null
  note?: string
  /** The ids of the rules that changed this exchange, in the order they acted. */
  rules?: string[]
  /** The client's protocol: '2' for HTTP/2, else '1.1' or '1.0'. */
  httpVersion?: string
  /** A gRPC call's status from its trailers (0 is OK), and its message. */
  grpcStatus?: number
  grpcMessage?: string
  /** A WebSocket's text and binary messages so far: client to server, server to client. */
  wsOut?: number
  wsIn?: number
  /** A text/event-stream response's events so far. */
  sseEvents?: number
  /** The request this one sent again (replay_request). */
  replayOf?: number | null
  /** Held at a rule's breakpoint, before it is sent (request) or before the client gets the answer (response). */
  held?: 'request' | 'response'
}

/** An exchange held at a breakpoint, as the proxy shows it. */
export type ProxyHeld = {
  id: number
  phase: 'request' | 'response'
  since: number
  view: { method: string; url: string; status?: number; headers: [string, string][]; body: string | null }
}

export type ProxyCa = {
  path: string
  subject: string
  fingerprint256: string
  validTo: string
  spki: string[]
}

/** One of this machine's addresses, as the sidecar ranks them for a phone. */
export type ProxyAddress = {
  address: string
  iface: string
  label: string
  kind: 'lan' | 'vpn' | 'virtual'
  isPrimary: boolean
}

export type ProxyPhase = 'stopped' | 'starting' | 'running' | 'failed'

export type ProxyStatus = {
  phase: ProxyPhase
  host: string
  port: number
  addresses: string[]
  lan: ProxyAddress[]
  runDir: string | null
  pid: number | null
  ca: ProxyCa | null
  /** The sidecar's token for its control commands (live WebSockets). */
  control?: { token: string } | null
  /** One proxy for every session on this Mac (it outlives the session that started it). */
  isShared?: boolean
  /** The running proxy's Wirepane version (another session may have started an older one). */
  proxyVersion?: string
  error: string | null
  /** No Node 18 or newer was found to run the proxy: the pane offers to install it. */
  isNodeMissing?: boolean
}

/** One rule as the rules view shows it: the file's entry, checked. */
export type ProxyRuleEntry = {
  id: string
  name: string | null
  description: string | null
  enabled: boolean
  /** What it does, in words (shared/rules.mjs describeRule). */
  summary: string
  errors: string[]
  /** It holds a script whose code is not approved yet. */
  isUntrusted: boolean
}

export type ProxyRules = {
  file: string | null
  entries: ProxyRuleEntry[]
  /** Problems of the file itself (not JSON, wrong shape). */
  fileErrors: string[]
}

/** The session's tracked domains: while on and not empty, only these are decrypted and recorded. */
export type ProxyTracking = {
  enabled: boolean
  patterns: string[]
}

export type ProxySimulator = { udid: string; name: string; runtime: string; state: string }

export type ProxyAndroidDevice = { serial: string; avd: string | null; isEmulator: boolean }

/** What the setup tabs found on this Mac, when they last looked. */
export type ProxyDevices = {
  simulators: ProxySimulator[]
  simulatorError: string | null
  avds: string[]
  android: ProxyAndroidDevice[]
  androidError: string | null
}

/** The macOS system proxy: whether it points here (scutil), on which service, and whether we set it. */
export type ProxySystemProxy = { isOn: boolean; service: string | null; isOurs: boolean }

export type ProxySetupTab = 'browser' | 'ios' | 'android' | 'cli'

export type ProxySession = { session: string; project: string; since: number }

/** What the doctor found, and the proxy process as it answered. */
export type ProxyHealth = {
  checkedAt: number | null
  findings: { level: 'ok' | 'info' | 'warn' | 'fail'; title: string; detail?: string; fix?: string; label?: string; action?: unknown }[]
  process: {
    pid: number
    version: string
    uptimeMs: number
    rss: number
    flows: number
    diskBytes: number
    sessions: ProxySession[]
    websockets: number
    pinned: number
    isShared: boolean
  } | null
}

export type ProxyView = {
  mode: 'list' | 'detail' | 'setup' | 'rules' | 'domains' | 'health' | 'held'
  selectedId: number | null
  setupTab: ProxySetupTab
  layout?: 'list' | 'tree'
  /** On the iOS and Android tabs: the simulator/emulator, or a real phone. */
  device?: 'virtual' | 'real'
  /** In the rules view: the rule whose ✕ was pressed, waiting for Remove or Keep. */
  removing?: string | null
}

declare module 'claude-code' {
  interface PluginState {
    wirepane: {
      flows: ProxyFlow[]
      status: ProxyStatus
      view: ProxyView
      filter: string
      wanted: boolean
      nextId: number
      notice: string
      emulators: string[]
      expanded: string[]
      rules: ProxyRules
      tracking: ProxyTracking
      /** Hosts that passed through untracked, and how often, since the proxy started. */
      skipped: Record<string, number>
      devices: ProxyDevices
      systemProxy: ProxySystemProxy
      /** Simulators this session put the CA into. */
      caSimulators: string[]
      /** A long action under way (booting a simulator), shown until it ends. */
      busy: string
      /** Whether this Mac's keychain trusts the proxy CA, as last checked. */
      macTrust: 'unknown' | 'trusted' | 'untrusted'
      /** This mod's version, from its plugin.json. */
      version: string
      /** The Claude Code sessions attached to the one shared proxy, this one among them. */
      sessions: ProxySession[]
      /** Hosts passed through untouched after refusing the certificate, per client. */
      pinned: { client: string | null; host: string }[]
      /** The doctor's last findings, for the Health view. */
      health: ProxyHealth
      /** Exchanges held at a breakpoint now. */
      held: ProxyHeld[]
    }
  }
}
