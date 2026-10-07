// Types of shared/systemproxy.mjs, for the hooks module.

export type ProxyState = { enabled: boolean; server: string; port: number }
export type SystemProxyBackup = {
  service: string
  port?: number
  previous: { web: ProxyState; secure: ProxyState; bypass: string[] }
}

export const BYPASS: readonly string[]
export function parseServiceOrder(text: string): { name: string; device: string; isDisabled: boolean }[]
export function parseProxyState(text: string): ProxyState
export function parseBypass(text: string): string[]
export function enableCommands(service: string, port: number, previousBypass?: readonly string[]): string[][]
export function restoreCommands(backup: SystemProxyBackup): string[][]
export function asAdminScript(commands: readonly (readonly string[])[]): string
export function needsAdmin(output: string): boolean
