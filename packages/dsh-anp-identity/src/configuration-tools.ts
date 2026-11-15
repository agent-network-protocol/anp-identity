/** Purpose-specific Agent settings tools; no manager, signing or lifecycle capability escapes. */
import type { Context } from '@deepseek-ai/cordis'
import type { IdentityReference } from '@agent-network-protocol/anp-identity'
import { z } from 'zod'
import { updateProtocolPolicySchema, type ProtocolManagementState, type UpdateProtocolPolicy, type ProtocolPolicy } from './protocol-policy-types.js'
import type { DefaultIdentitySettings, UpdateDefaultIdentity } from './default-identity-types.js'
import { registrationOrigin } from './registration-service-settings.js'
import type { RegistrationServiceSettings, UpdateRegistrationServiceSettings } from './registration-service-types.js'

interface AgentCaller { id: string; session: { header: { origin?: string; delegationDepth?: number } } }
interface Execution { agent?: AgentCaller; signal?: AbortSignal; callId?: string }
interface Approval {
  request(input: object): Promise<string>
  overrideOf?(session: AgentCaller['session']): 'ask' | 'never' | undefined
  config?: { policy?: 'ask' | 'never' }
}
export interface ConfigurationHandlers {
  assertOwner(): void
  protocols(): Promise<ProtocolManagementState>
  setProtocols(input: UpdateProtocolPolicy, check: () => void): Promise<ProtocolPolicy>
  identity(): Promise<{ defaultIdentity: DefaultIdentitySettings; registrationService: RegistrationServiceSettings; identities: { reference: IdentityReference; state: string }[] }>
  setDefault(input: UpdateDefaultIdentity, check: () => void): Promise<DefaultIdentitySettings>
  setRegistration(input: UpdateRegistrationServiceSettings, check: () => void): Promise<RegistrationServiceSettings>
}
const registrationInput = z.object({ expectedVersion: z.number().int().nonnegative(), origin: z.string().max(2048) }).strict()
const protocolArguments = z.discriminatedUnion('action', [
  z.object({ action: z.literal('get') }).strict(),
  updateProtocolPolicySchema.extend({ action: z.literal('set') }).strict(),
])
const identityArguments = z.union([
  z.object({ action: z.literal('get') }).strict(),
  z.object({ action: z.literal('set_default'), expectedVersion: z.number().int().nonnegative(), identityId: z.string().min(1).max(256) }).strict(),
  z.object({ action: z.literal('set_default'), expectedVersion: z.number().int().nonnegative(), identity: z.null() }).strict(),
  registrationInput.extend({ action: z.literal('set_registration_service') }).strict(),
])
const domainEntry = { type: 'object', additionalProperties: false, required: ['domain', 'protocols'], properties: {
  domain: { type: 'string', maxLength: 253 }, protocols: { type: 'array', minItems: 1, maxItems: 3, items: { type: 'string', enum: ['anp', 'pap', 'mcp'] } },
} }
const rule = { type: 'object', additionalProperties: false, required: ['mode', 'outside', 'domains'], properties: {
  mode: { type: 'string', enum: ['allow_all', 'whitelist', 'ask', 'deny'] }, outside: { type: 'string', enum: ['ask', 'deny'] },
  domains: { type: 'array', maxItems: 256, items: domainEntry },
} }
const knownErrors = new Set(['consumer_forbidden', 'configuration_caller_forbidden', 'configuration_approval_required', 'configuration_approval_disabled', 'configuration_rejected',
  'configuration_cancelled', 'protocol_policy_conflict', 'protocol_policy_unavailable', 'default_identity_conflict', 'default_identity_settings_unavailable',
  'published_identity_required', 'not_published', 'identity_not_found', 'identity_deleting', 'provider_unavailable', 'provider_disposed',
  'registration_service_conflict', 'registration_service_invalid_origin', 'registration_service_settings_unavailable'])

/** Only the actual installed owner manager registers these definitions. Mutations always ask the owner in-session. */
export function registerConfigurationTools(ctx: Context, handlers: ConfigurationHandlers): void {
  handlers.assertOwner()
  ctx.inject(['tools', 'agents'], inner => {
    const tools = inner.get('tools') as { register(value: object): unknown }
    const agents = inner.get('agents') as { get(id: string): unknown }
    const approvalPolicy = (exec: Execution) => {
      const approval = inner.get('approval') as Approval | undefined
      return approval?.overrideOf?.(exec.agent!.session) ?? approval?.config?.policy ?? null
    }
    let active = true
    inner.effect(() => () => { active = false })
    const check = (exec: Execution, mutation: boolean) => {
      handlers.assertOwner()
      if (!active || !exec.agent || agents.get(exec.agent.id) !== exec.agent
        || mutation && (exec.agent.session.header.origin === 'subagent' || (exec.agent.session.header.delegationDepth ?? 0) > 0)) throw new Error('configuration_caller_forbidden')
      if (!exec.signal || exec.signal.aborted) throw new Error('configuration_cancelled')
    }
    const approve = async (exec: Execution, name: string, before: unknown, after: unknown) => {
      check(exec, true)
      const approval = inner.get('approval') as Approval | undefined
      if (!approval) throw new Error('configuration_approval_required')
      if (approvalPolicy(exec) === 'never') throw new Error('configuration_approval_disabled')
      const outcome = await approval.request({ agent: exec.agent, toolName: name, callId: exec.callId, signal: exec.signal,
        reason: `Persistent profile settings change, affecting all sessions. Before: ${JSON.stringify(before)}. After: ${JSON.stringify(after)}. This changes protocol/identity preferences only; it does not grant signing, payment or key export permissions.`,
        displayReason: { en: `Apply this persistent settings change to all sessions?\nBefore: ${JSON.stringify(before)}\nAfter: ${JSON.stringify(after)}`,
          zh: `是否保存本次配置修改？对所有会话持续生效，不包含通用签名、支付或密钥导出权限。\n修改前：${JSON.stringify(before)}\n修改后：${JSON.stringify(after)}` } })
      check(exec, true)
      if (outcome === 'rejected' && approvalPolicy(exec) === 'never') throw new Error('configuration_approval_disabled')
      if (outcome !== 'allowed-once') throw new Error(outcome === 'cancelled' ? 'configuration_cancelled' : outcome === 'rejected' ? 'configuration_rejected' : 'configuration_approval_required')
    }
    const register = (name: string, description: string, parameters: object, run: (raw: unknown, exec: Execution) => Promise<unknown>) => {
      tools.register({ name, description, parameters, timeoutMs: 180000, isConcurrencySafe: () => false,
        output: { schema: { type: 'object', additionalProperties: true }, render: (_args: unknown, value: unknown) => [{ type: 'text', text: JSON.stringify(value) }] },
        presentCall: (args: unknown) => ({ card: 'generic', title: name === 'protocol_permissions' ? 'Protocol permissions' : 'Identity settings', kind: 'other', rawInput: args }),
        execute: async (raw: unknown, exec: Execution) => {
          try { check(exec, false); const value = await run(raw, exec); return { ok: true, value } }
          catch (error) {
            const code = error instanceof z.ZodError ? 'invalid_parameters' : error instanceof Error && knownErrors.has((error as Error & { code?: string }).code ?? error.message)
              ? (error as Error & { code?: string }).code ?? error.message : 'configuration_unavailable'
            return { ok: false, error: { code }, next: code === 'configuration_approval_disabled'
              ? 'This session uses the never approval policy, which automatically rejects required confirmations. Ask the owner to change the session approval policy to ask, or save the preference directly in Identity Management. No settings changed. Do not change write permissions or retry until the owner changes the approval policy.'
              : code === 'configuration_rejected'
              ? 'The approval service rejected this configuration change. Stop; do not retry or substitute another identity or policy. This result alone does not prove that the owner clicked Reject.'
              : 'Query current settings before retrying. Never edit profile files, approve for the owner, or retry an unconfirmed change blindly.' }
          }
        } })
    }
    register('protocol_permissions', 'Query or change shared ANP/PAP/MCP read/write rules and exact-domain whitelists. Get first; set requires the returned version and complete read/write rules. Changes are persistent for all sessions, use the same settings backend as Protocol Management, and open one in-session owner confirmation (no Settings navigation). Existing business denials remain enforced; unknown effects, payments and extra privileges are not automatically granted. Do not call set unless the user explicitly requests the exact change.', {
      type: 'object', additionalProperties: false, required: ['action'], properties: {
        action: { type: 'string', enum: ['get', 'set'] }, expectedVersion: { type: 'integer', minimum: 0 },
        policy: { type: 'object', additionalProperties: false, required: ['read', 'write'], properties: { read: rule, write: rule } },
      },
    }, async (raw, exec) => {
      const args = protocolArguments.parse(raw)
      const before = await handlers.protocols(); check(exec, args.action === 'set')
      if (args.action === 'get') return { ...before, approvalPolicy: approvalPolicy(exec) }
      const { action: _action, ...input } = args
      if (before.policy.version !== input.expectedVersion) throw new Error('protocol_policy_conflict')
      await approve(exec, 'protocol_permissions', before.policy, input.policy)
      const after = await handlers.setProtocols(input, () => check(exec, true))
      return { applied: true, confirmation: { status: 'approved', scope: 'configuration_change', presentation: 'in_session' }, before: before.policy, after }
    })
    register('identity_settings', 'Query public identity settings, select the default published identity used by ANP/PAP/MCP, or change the HTTPS registration service for future registrations only. Get first; mutation requires that setting version and opens one in-session owner confirmation. For set_default supply the exact short identityId from a returned published identity; the Host resolves its full reference and DID. Never copy or reconstruct a DID/reference. Alternatively identity:null restores automatic selection, which fails if multiple identities are eligible. Supply exactly one selector. Switching defaults requires fresh protocol discovery/connection; requests already in flight keep their original identity fences, and writes must not be replayed automatically. This tool cannot create/publish/delete identities, approve business requests, handle OTPs, export keys or sign.', {
      type: 'object', additionalProperties: false, required: ['action'], properties: {
        action: { type: 'string', enum: ['get', 'set_default', 'set_registration_service'] }, expectedVersion: { type: 'integer', minimum: 0 },
        identityId: { type: 'string', minLength: 1, maxLength: 256 }, identity: { type: 'null' }, origin: { type: 'string', maxLength: 2048 },
      },
    }, async (raw, exec) => {
      const args = identityArguments.parse(raw)
      const before = await handlers.identity(); check(exec, args.action !== 'get')
      if (args.action === 'get') return { ...before, approvalPolicy: approvalPolicy(exec), capabilities: ['default_identity', 'registration_service', 'protocol_permissions'],
        unavailable: ['private_keys', 'tokens', 'otp', 'general_signing', 'lifecycle_approval'], notes: 'Display-row selection is not the default. Existing identities and in-progress registrations keep their pinned service origin.' }
      if (args.action === 'set_default') {
        let identity: IdentityReference | null = null
        if ('identityId' in args) {
          const candidates = before.identities.filter(item => item.state === 'published' && item.reference.identityId === args.identityId)
          if (candidates.length !== 1) throw new Error('published_identity_required')
          identity = structuredClone(candidates[0]!.reference)
        }
        const input = { expectedVersion: args.expectedVersion, identity }
        if (before.defaultIdentity.version !== input.expectedVersion) throw new Error('default_identity_conflict')
        await approve(exec, 'identity_settings', before.defaultIdentity, input)
        const after = await handlers.setDefault(input, () => check(exec, true))
        return { applied: true, confirmation: { status: 'approved', scope: 'configuration_change', presentation: 'in_session' }, before: before.defaultIdentity, after, next: 'Reconnect and rediscover with each protocol. In-flight requests keep their original identity fences; do not automatically replay writes.' }
      }
      const normalized = { expectedVersion: args.expectedVersion, origin: registrationOrigin(args.origin) }
      if (before.registrationService.version !== normalized.expectedVersion) throw new Error('registration_service_conflict')
      await approve(exec, 'identity_settings', before.registrationService, normalized)
      const after = await handlers.setRegistration(normalized, () => check(exec, true))
      return { applied: true, confirmation: { status: 'approved', scope: 'configuration_change', presentation: 'in_session' }, before: before.registrationService, after, next: 'Only future registrations use this origin; no existing identity or in-progress flow was migrated.' }
    })
  })
}
