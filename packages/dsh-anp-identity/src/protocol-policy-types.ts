/** Browser-safe protocol permission settings. Service directories never grant permission. */
import { z } from 'zod'

export const protocolNames = ['anp', 'pap', 'mcp'] as const
export type ManagedProtocol = typeof protocolNames[number]
export type ProtocolEffect = 'read' | 'write' | 'unknown' | 'payment'
export type ProtocolDecision = 'allow' | 'ask' | 'deny'
export interface ProtocolClassification { effect: ProtocolEffect; extraPermissions: boolean }
export interface HttpEffectEvidence {
  method: string
  hasRequestBody: boolean
  security?: unknown
  declaredEffect?: unknown
  annotations?: unknown
}
function hints(raw: unknown): Record<string, unknown> | undefined {
  if (raw === undefined) return {}
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return undefined
  const value = raw as Record<string, unknown>
  return ['readOnlyHint', 'destructiveHint', 'paymentHint'].some(key => value[key] !== undefined && typeof value[key] !== 'boolean') ? undefined : value
}
/** HTTP safety alone is insufficient: body, explicit semantics and authorization declarations all participate. */
export function classifyHttpEffect(input: HttpEffectEvidence): ProtocolClassification {
  const security = input.security
  const extraPermissions = security !== undefined && (!Array.isArray(security) || security.some(requirement => !requirement || typeof requirement !== 'object' || Array.isArray(requirement)
    || Object.values(requirement).some(scopes => !Array.isArray(scopes) || scopes.length > 0)))
  const annotations = hints(input.annotations)
  let effect: ProtocolEffect = 'unknown'
  if (annotations && typeof input.method === 'string' && typeof input.hasRequestBody === 'boolean') {
    if (annotations.paymentHint === true || input.declaredEffect === 'payment') effect = 'payment'
    else if (input.declaredEffect !== undefined) {
      if (input.declaredEffect === 'read' && annotations.readOnlyHint !== false && annotations.destructiveHint !== true) effect = 'read'
      else if (input.declaredEffect === 'write' && annotations.readOnlyHint !== true) effect = 'write'
    } else if (annotations.readOnlyHint === true) effect = annotations.destructiveHint === true ? 'unknown' : 'read'
    else if (annotations.readOnlyHint === false || annotations.destructiveHint === true) effect = 'write'
    else if (['GET', 'HEAD'].includes(input.method) && !input.hasRequestBody) effect = 'read'
    else if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(input.method)) effect = 'write'
    if (effect === 'read' && ['GET', 'HEAD'].includes(input.method) && input.hasRequestBody) effect = 'unknown'
  }
  return { effect, extraPermissions }
}
/** MCP uses semantic tool hints, not its POST transport or the tool's name. */
export function classifyMcpEffect(raw: unknown): ProtocolClassification {
  const annotations = hints(raw)
  const effect: ProtocolEffect = !annotations ? 'unknown' : annotations.paymentHint === true ? 'payment'
    : annotations.readOnlyHint === true ? annotations.destructiveHint === false ? 'read' : 'unknown'
    : annotations.readOnlyHint === false || annotations.destructiveHint === true ? 'write' : 'unknown'
  return { effect, extraPermissions: false }
}
/** Scope suffixes select credential privilege, never the semantic effect of a business tool. Unknown scopes always ask. */
export function classifyMcpScopes(scopes: readonly string[]): ProtocolClassification {
  if(!scopes.length||scopes.length>64||scopes.some(scope=>typeof scope!=='string'||!/^[\x21\x23-\x5b\x5d-\x7e]{1,128}$/u.test(scope)))return {effect:'unknown',extraPermissions:true}
  const read=(scope:string)=>/(?:^|[.:/_-])read$/iu.test(scope)
  const write=(scope:string)=>/(?:^|[.:/_-])write$/iu.test(scope)
  if(scopes.some(scope=>!read(scope)&&!write(scope)))return {effect:'unknown',extraPermissions:true}
  return {effect:scopes.some(write)?'write':'read',extraPermissions:false}
}
export class ProtocolPolicyError extends Error {
  constructor(readonly code: string) { super(code) }
}

/** Exact IDNA hostname, not a URL, suffix pattern, port, or implicit subdomain rule. */
export function protocolDomain(input: string): string {
  if (typeof input !== 'string' || !input || input.length > 253 || /[\s/:?#@\\*%]/u.test(input)) throw new ProtocolPolicyError('protocol_policy_invalid_domain')
  let domain: string
  try { domain = new URL(`https://${input}`).hostname } catch { throw new ProtocolPolicyError('protocol_policy_invalid_domain') }
  if (!domain.includes('.') || domain.endsWith('.') || domain.length > 253 || /^[\d.]+$/u.test(domain)
    || !domain.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label))) throw new ProtocolPolicyError('protocol_policy_invalid_domain')
  return domain
}

const domainSchema = z.string().max(253).transform((input, ctx) => {
  try { return protocolDomain(input) } catch { ctx.addIssue({ code: 'custom', message: 'protocol_policy_invalid_domain' }); return z.NEVER }
})
const entry = z.object({ domain: domainSchema, protocols: z.array(z.enum(protocolNames)).min(1).max(3) }).strict()
const rule = z.object({
  mode: z.enum(['allow_all', 'whitelist', 'ask', 'deny']),
  outside: z.enum(['ask', 'deny']),
  domains: z.array(entry).max(256),
}).strict()
export const protocolPolicyInputSchema = z.object({ read: rule, write: rule }).strict()
export type ProtocolPolicyInput = z.infer<typeof protocolPolicyInputSchema>
export const protocolPolicySchema = protocolPolicyInputSchema.extend({ schema: z.literal(1), version: z.number().int().nonnegative() }).strict()
export type ProtocolPolicy = z.infer<typeof protocolPolicySchema>
export const updateProtocolPolicySchema = z.object({ expectedVersion: z.number().int().nonnegative(), policy: protocolPolicyInputSchema }).strict()
export type UpdateProtocolPolicy = z.infer<typeof updateProtocolPolicySchema>
export interface ProtocolManagementState {
  policy: ProtocolPolicy
  domainAccessEnabled: boolean
  protocols: { protocol: ManagedProtocol; installed: boolean; enabled: boolean; ready: boolean; managedAdapters: number; unmanagedAdapters: number }[]
}

export function initialProtocolPolicy(): ProtocolPolicy {
  return { schema: 1, version: 0, read: { mode: 'allow_all', outside: 'ask', domains: [] }, write: { mode: 'ask', outside: 'ask', domains: [] } }
}

/** Effects are classified by installed adapters, never by model-provided labels. */
export function protocolDecision(policy: ProtocolPolicy, protocol: ManagedProtocol, domain: string, effect: ProtocolEffect, extraPermissions = false): ProtocolDecision {
  const canonical = protocolDomain(domain)
  if (!protocolNames.includes(protocol) || !['read', 'write', 'unknown', 'payment'].includes(effect) || typeof extraPermissions !== 'boolean') throw new ProtocolPolicyError('protocol_policy_invalid_operation')
  const selected = policy[effect === 'read' ? 'read' : 'write']
  const listed = selected.domains.some(entry => entry.domain === canonical && entry.protocols.includes(protocol))
  const decision = selected.mode === 'allow_all' ? 'allow' : selected.mode === 'whitelist' ? listed ? 'allow' : selected.outside : selected.mode
  if (decision === 'deny') return 'deny'
  // Write permission is not payment, unknown-effect, or additional-privilege permission.
  return extraPermissions || effect === 'unknown' || effect === 'payment' ? 'ask' : decision
}
