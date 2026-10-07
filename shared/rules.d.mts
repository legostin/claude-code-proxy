// Types of shared/rules.mjs, for the hooks module.

export type RulePhase = 'request' | 'response'

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
  stop?: boolean
}

export type ParsedRule = { rule: Rule; errors: string[] }

export const REQUEST_ACTIONS: readonly string[]
export const RESPONSE_ACTIONS: readonly string[]
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
export function describeAction(action: RuleAction): string
export function describeMatch(match?: RuleMatch): string
export function describeRule(rule: Rule): string
