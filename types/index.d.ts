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

export type ProxySetupTab = 'browser' | 'ios' | 'android' | 'cli'

export type ProxyView = {
  mode: 'list' | 'detail' | 'setup'
  selectedId: number | null
  setupTab: ProxySetupTab
  layout?: 'list' | 'tree'
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
    }
  }
}
