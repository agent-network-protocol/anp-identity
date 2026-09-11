import type { IdentityReference } from '@agent-network-protocol/anp-identity'

/** Only the Host may construct this from the installed plugin context. */
export interface VerifiedCaller { readonly consumer: string; readonly displayName: string }
export type OrdinaryCapability = 'identity:read' | 'identity:sign' | 'identity:http-auth'
export interface CapabilitySnapshot {
  readonly version: string
  readonly capabilities: readonly OrdinaryCapability[]
  readonly signingPurposes: readonly string[]
  readonly httpOrigins: readonly string[]
}
export type AuthorizationMode = 'once' | 'permanent'
export type RequestStatus = 'pending' | 'approved' | 'denied' | 'cancelled' | 'expired'
export interface ControlledOperation {
  readonly capability: OrdinaryCapability
  readonly fingerprint: string
  /** Host-produced safe summary, never a signature payload or HTTP body. */
  readonly summary: string
  readonly signingPurpose?: string
  readonly httpOrigin?: string
}
export interface CreateParameters { readonly label: string; readonly domain: string; readonly path: string }
export interface CreateResult { readonly reference: IdentityReference; readonly label: string }
interface RequestBase {
  readonly id: string
  readonly caller: VerifiedCaller
  readonly purpose: string
  readonly version: number
  readonly status: RequestStatus
  readonly createdAt: number
  readonly expiresAt: number
  readonly fingerprint: string
  readonly prompted: boolean
  readonly decidedAt?: number
  readonly retryOf?: string
}
export interface CreateAuthorizationRequest extends RequestBase {
  readonly kind: 'create'
  readonly parameters: CreateParameters
  readonly operationId?: string
  readonly executionStatus?: 'running' | 'succeeded' | 'unknown' | 'deleted'
  readonly result?: CreateResult
}
export interface AccessAuthorizationRequest extends RequestBase {
  readonly kind: 'access'
  readonly identity?: IdentityReference
  readonly operation?: ControlledOperation
  readonly mode?: AuthorizationMode
  readonly grantId?: string
}
export type AuthorizationRequest = CreateAuthorizationRequest | AccessAuthorizationRequest
export interface AuthorizationGrant {
  readonly id: string
  readonly requestId: string
  readonly caller: VerifiedCaller
  readonly identity: IdentityReference
  readonly snapshot: CapabilitySnapshot
  readonly mode: AuthorizationMode
  readonly version: number
  readonly approvedAt: number
  readonly status: 'active' | 'consumed' | 'revoked' | 'expired'
  readonly expiresAt?: number
  readonly operation?: ControlledOperation
  readonly executionId?: string
  readonly revokedAt?: number
}
export interface AuthorizedLease {
  readonly grantId: string
  readonly consumer: string
  readonly identity: IdentityReference
  readonly grantVersion: number
  readonly expiresAt: number
}
export interface AuthorizationExecution {
  readonly id: string
  readonly grantId: string
  readonly consumer: string
  readonly fingerprint: string
  readonly admittedAt: number
  readonly grantVersion: number
  readonly operation: ControlledOperation
  readonly status: 'admitted' | 'succeeded' | 'failed' | 'unknown'
  readonly finishedAt?: number
}
export interface AuthorizationState {
  readonly schema: 'anp-identity-authorization/1'
  generation: number
  requests: AuthorizationRequest[]
  grants: AuthorizationGrant[]
  executions: AuthorizationExecution[]
  deletedIdentities: IdentityReference[]
  deletingIdentities: IdentityReference[]
  suppressions: { consumer: string; kind: 'create' | 'access'; identity?: IdentityReference; requestId: string }[]
}
export interface RequestCreateInput { readonly requestId: string; readonly purpose: string; readonly parameters: CreateParameters }
export interface RequestAccessInput { readonly requestId: string; readonly purpose: string; readonly identity?: IdentityReference; readonly operation?: ControlledOperation }
export interface AuthorizationDecision {
  readonly requestId: string
  readonly expectedVersion: number
  readonly decision: 'approve' | 'deny'
  readonly identity?: IdentityReference
  readonly mode?: AuthorizationMode
  /** Exact scope shown for the selected identity; access approvals must echo it. */
  readonly reviewedSnapshot?: CapabilitySnapshot
}
export interface DeletionReconciliation {
  /** Host-sourced durable catalog deletion fences, never arbitrary missing identities. */
  readonly catalogFences: readonly IdentityReference[]
  /** Must positively verify this exact reference is absent from both native storage and catalog. */
  readonly isAbsent: (reference: IdentityReference) => Promise<boolean>
}
export interface AuthorizationOptions {
  readonly validateCaller: (caller: VerifiedCaller) => Promise<void>
  readonly resolveSnapshot: (caller: VerifiedCaller, identity: IdentityReference) => Promise<CapabilitySnapshot>
  /** Must use the native durable create journal and never implicitly grant use. */
  readonly createIdentity: (operationId: string, caller: VerifiedCaller, parameters: CreateParameters) => Promise<CreateResult>
  /** Only recover an existing operation; undefined must not trigger creation. */
  readonly reconcileCreation?: (operationId: string, caller: VerifiedCaller, parameters: CreateParameters) => Promise<CreateResult | undefined>
  readonly now?: () => number
  readonly requestTtlMs?: number
  readonly onceTtlMs?: number
  readonly leaseTtlMs?: number
  readonly fault?: (point: 'before_rename' | 'after_rename') => void
}
