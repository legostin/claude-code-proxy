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
  error: string | null
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

export type ProxyView = {
  mode: 'list' | 'detail' | 'setup' | 'rules' | 'domains'
  selectedId: number | null
  setupTab: ProxySetupTab
  layout?: 'list' | 'tree'
  /** On the iOS and Android tabs: the simulator/emulator, or a real phone. */
  device?: 'virtual' | 'real'
}

declare module 'claude-code' {
  interface PluginState {
    proxy: {
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
    }
  }
}
