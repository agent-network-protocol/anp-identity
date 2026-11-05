/** Host-only, exact-device PAP callback commands. Claim results must never enter Remote or model output. */
import { z } from 'zod'

export interface PapCallbackRegistration {
  transaction_id: string
  client_id: string
  issuer: string
  redirect_uri: string
  state_sha256: string
  claim_sha256: string
  expires_at: string
}
export interface PapCallbackClaim { transaction_id: string; claim_secret: string }
export interface PapCallbackRegistrationResult { transaction_id: string; callback_uri: string; expires_at: string }
export type PapCallbackOAuthError = 'invalid_request' | 'unauthorized_client' | 'access_denied' | 'unsupported_response_type'
  | 'invalid_scope' | 'server_error' | 'temporarily_unavailable'
/** A one-shot private business result. It is deliberately not a publisher response. */
export type PapCallbackClaimResult = { state: string; iss: string; code: string } | { state: string; iss: string; error: PapCallbackOAuthError }
export interface PapCallbackRegisterOperation {
  action: 'pap-callback-register'; operationId: string; callback: PapCallbackRegistration
}
export interface PapCallbackClaimOperation {
  action: 'pap-callback-claim'; operationId: string; callback: PapCallbackClaim
}
export type PapCallbackOperation = PapCallbackRegisterOperation | PapCallbackClaimOperation
/** Trusted Host capability limited to registering and claiming the fixed PAP callback relay. */
export interface PapCallbackManagementOperations {
  /** Register public hashes and the already-published fixed callback address.
   * @param input - Closed registration command, without PKCE verifier or business Tokens.
   * @returns Public relay acknowledgement.
   */
  execute(input: PapCallbackRegisterOperation): Promise<PapCallbackRegistrationResult>
  /** Claim exactly once through the original device. No automatic retry or local result cache is allowed.
   * @param input - Claim command containing the independent pickup secret.
   * @returns The private code/error, state and issuer accepted by the relay.
   */
  execute(input: PapCallbackClaimOperation): Promise<PapCallbackClaimResult>
}
export type PapCallbackManagementErrorCode = 'callback_not_ready' | 'callback_claimed' | 'callback_expired' | 'callback_conflict'
  | 'callback_unavailable' | 'callback_limit' | 'callback_redirect_mismatch' | 'callback_claim_not_independent'
  | 'callback_issuer_mismatch' | 'permission_denied' | 'management_auth_required' | 'not_published'
  | 'client_id_conflict' | 'idempotency_conflict'
/** Stable management failure. It contains neither callback business data nor arbitrary server text. */
export class PapCallbackManagementError extends Error {
  readonly name = 'PapCallbackManagementError'
  constructor(readonly code: PapCallbackManagementErrorCode) { super(code) }
}

const transactionId = z.string().regex(/^[A-Za-z0-9_-]{8,128}$/u)
const operationId = z.string().min(1).max(128).regex(/^[^\s\u0000-\u001f\u007f]+$/u)
const url = z.string().min(1).max(2048)
const expiresAt = z.string().regex(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/u).refine(value => {
  const parsed = new Date(value)
  return Number.isFinite(parsed.getTime()) && parsed.toISOString().replace('.000Z', 'Z') === value
})
const registration = z.object({
  transaction_id: transactionId, client_id: url, issuer: url, redirect_uri: url,
  state_sha256: z.string().regex(/^[0-9a-f]{64}$/u), claim_sha256: z.string().regex(/^[0-9a-f]{64}$/u), expires_at: expiresAt,
}).strict().refine(value => value.state_sha256 !== value.claim_sha256)
const claim = z.object({ transaction_id: transactionId,
  claim_secret: z.string().regex(/^[A-Za-z0-9_-]{43}$/u).refine(value => Buffer.from(value, 'base64url').toString('base64url') === value),
}).strict()
export const PapCallbackOperationSchema = z.discriminatedUnion('action', [
  z.object({ action: z.literal('pap-callback-register'), operationId, callback: registration }).strict(),
  z.object({ action: z.literal('pap-callback-claim'), operationId, callback: claim }).strict(),
])
export const PapCallbackRegistrationResultSchema = z.object({
  transaction_id: transactionId, callback_uri: url, expires_at: expiresAt,
}).passthrough()
const state = z.string().min(32).max(512).regex(/^[\x21-\x7e]+$/u)
export const PapCallbackClaimResultSchema = z.union([
  z.object({ state, iss: url, code: z.string().min(1).max(4096).regex(/^[\x20-\x7e]+$/u) }).strict(),
  z.object({ state, iss: url, error: z.enum(['invalid_request', 'unauthorized_client', 'access_denied', 'unsupported_response_type',
    'invalid_scope', 'server_error', 'temporarily_unavailable']) }).strict(),
])
const errors = new Set<PapCallbackManagementErrorCode>(['callback_not_ready', 'callback_claimed', 'callback_expired', 'callback_conflict',
  'callback_unavailable', 'callback_limit', 'callback_redirect_mismatch', 'callback_claim_not_independent', 'callback_issuer_mismatch',
  'permission_denied', 'management_auth_required', 'not_published', 'client_id_conflict', 'idempotency_conflict'])
/** Decode only documented management failures; arbitrary input is never placed in an Error.
 * @param value - Parsed response object from the fixed management endpoint.
 * @returns A stable callback error, or undefined for an incompatible response.
 */
export function papCallbackManagementError(value: Record<string, unknown>): PapCallbackManagementError | undefined {
  const code = value.error === 'device.idempotency_conflict' ? 'idempotency_conflict' : value.error
  return typeof code === 'string' && errors.has(code as PapCallbackManagementErrorCode)
    ? new PapCallbackManagementError(code as PapCallbackManagementErrorCode) : undefined
}
