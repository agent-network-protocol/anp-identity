/** Host-only protocol identity leases. These objects never cross Remote or tool APIs. */
import type { Context } from '@deepseek-ai/cordis'
import type { IdentityReference } from '@agent-network-protocol/anp-identity'
import type { PapCallbackManagementOperations } from './pap-callback.js'

/** Installed PAP Host capability. Callback operations additionally require a current opaque C target. */
export interface PapHostConsumer {
  resolveBinding(identityRef: IdentityReference, policyRef: string, profile: 'pap_session' | 'pap_account'): Promise<{
    binding: { identityRef: IdentityReference; ownerRef: string; clientId: string }
    redirectUri?: string
  }>
  callbackManagementFor(input: { identityRef: IdentityReference; policyRef: string; targetRef: object }): Promise<PapCallbackManagementOperations & { dispose(): void }>
  assertActive(): Promise<void>
  dispose(): void
}

export interface ValidatedTargetEvidence {
  profile: 'mcp_machine' | 'pap_session' | 'pap_account'
  issuer: string
  resource: string
  tokenEndpoint?: string
  companyId?: string
  allowedEndpoints?: string[]
  revocationEndpoint?: string
  metadataDigest: string
  expiresAt: number
  sources: { resource: string; authorizationServer: string }
}
/** Explicit Host configuration is the management approval; updates reload and revoke old leases. */
export interface ProtocolUsePolicy {
  id: string
  version: number
  consumer: string
  identity: IdentityReference
  owner: string
  profiles: ValidatedTargetEvidence['profile'][]
  issuers: string[]
  resources: string[]
  publicTargets: boolean
  scopes: string[]
  expiresAt: number
}
export interface ProtocolKeyReference {
  readonly handle: string
  readonly keyRef: object
  readonly purpose: 'pap_session' | 'pap_dpop'
  readonly generation: number
  readonly publicJwk: { kty: 'EC'; crv: 'P-256'; x: string; y: string }
  readonly thumbprint: string
}
export interface PapSessionSigningInput {
  keyRef: object; delegation: string; clientId: string; sid: string; sub: string; agentId?: string
  httpMethod: string; httpUri: string; accessToken?: string
}
export interface DpopSigningInput { keyRef: object; httpMethod: string; httpUri: string; accessToken?: string; nonce?: string }
export interface ProtocolSignerLease {
  readonly targetRef: object
  readonly policyGeneration: number
  getOAuthClientIdentity(): Promise<{ clientId: string; keyId: string; algorithm: 'ES256'; version: number; signerMode: 'local'; publicJwk: { kty: 'EC'; crv: 'P-256'; x: string; y: string }; redirectUris: string[] }>
  assertActive(): Promise<void>
  signOAuthClientAssertion(targetRef: object): Promise<string>
  bindPapScope(input: { userId: string; accountSlot?: string }): object
  restorePapKey(scopeRef: object, input: { handle: string; generation: number; purpose: 'pap_session' | 'pap_dpop' }): Promise<ProtocolKeyReference>
  createDelegatedKey(scopeRef: object, operationId: string): Promise<ProtocolKeyReference>
  createDpopKey(scopeRef: object, operationId: string): Promise<ProtocolKeyReference>
  issuePapDelegation(scopeRef: object, input: { keyRef: object; ttlSeconds: number }): Promise<string>
  signPapSessionRequest(scopeRef: object, input: PapSessionSigningInput): Promise<string>
  signDpopProof(scopeRef: object, input: DpopSigningInput): Promise<string>
  retireTemporaryKey(scopeRef: object, keyRef: object): Promise<void>
  dispose(): void
}
export interface ProtocolIdentityClient {
  registerValidatedTarget(input: { identityRef: IdentityReference; policyRef: string; discovery: ValidatedTargetEvidence; requestedScopes: string[] }): Promise<ProtocolSignerLease>
}
/** Bind only from the installed discovery adapter's Context. No consumer name is accepted.
 * @param context - Installed trusted Host adapter context.
 * @returns Caller-bound protocol client.
 */
export function bindProtocolIdentityClient(context: Context): ProtocolIdentityClient {
  const service = context.get('anpIdentity') as unknown as { bindProtocolConsumer(context: Context): ProtocolIdentityClient } | undefined
  if (!service || typeof service.bindProtocolConsumer !== 'function') throw new Error('provider_incompatible')
  return service.bindProtocolConsumer(context)
}
