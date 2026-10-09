// Types of shared/rules.mjs, for the hooks module.

export type RulePhase = 'request' | 'response' | 'messages'

export type RuleMatch = {
  url?: string
  host?: string
  path?: string
  methods?: string[]
  headers?: Record<string, string>
  query?: Record<string, string>
  bodyContains?: string
  status?: string
  contentType?: string
}

export type RuleAction = { type: string; [field: string]: unknown }

export type Rule = {
  id: string
  name?: string
  description?: string
  enabled?: boolean
  match?: RuleMatch
  request?: RuleAction[]
  response?: RuleAction[]
  /** Steps on a WebSocket's messages; `match` then matches the upgrade request. */
  messages?: RuleAction[]
  stop?: boolean
}

export type ParsedRule = { rule: Rule; errors: string[] }

export const REQUEST_ACTIONS: readonly string[]
export const RESPONSE_ACTIONS: readonly string[]
export const MESSAGE_ACTIONS: readonly string[]
export function isRegexPattern(pattern: string): boolean
export function toRegExp(pattern: string): RegExp
export function statusMatcher(text: string): ((status: number) => boolean) | null
export function ruleErrors(rule: unknown, where?: string): string[]
export function parseRules(text: string | null | undefined): { rules: ParsedRule[]; errors: string[] }
export function isEnabled(rule: Rule): boolean
export function matchesRequest(
  rule: Rule,
  request: { method: string; url: string; host: string; path: string; headers: [string, string][]; body?: string | null },
): boolean
export function matchesResponse(rule: Rule, response: { status: number; contentType: string | null }): boolean
export function needsRequestBody(rule: Rule): boolean
export function needsResponseBody(rule: Rule): boolean
export function scriptsOf(rule: Rule): string[]
export function actsOnHttp(rule: Rule): boolean
export function stepTakes(step: RuleAction, message: { direction: 'out' | 'in'; text: string | null }): boolean
export function describeAction(action: RuleAction): string
export function describeStep(step: RuleAction): string
export function describeMatch(match?: RuleMatch): string
export function describeRule(rule: Rule): string

export type Tracking = { enabled: boolean; patterns: string[] }
export function normalizeHostPattern(text: string): string | null
export function matchesHostPattern(pattern: string, host: string): boolean
export function isTracked(tracking: Tracking | null | undefined, host: string): boolean
export function wildcardFor(host: string): string | null
