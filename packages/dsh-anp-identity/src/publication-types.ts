/** Public material state only. Credentials and assertions never enter the catalog. */
import { z } from 'zod'
import type { IdentityReference, OAuthPublicJwk } from '@agent-network-protocol/anp-identity'
import type { ProviderDocumentChangeSession } from '@agent-network-protocol/anp-identity/provider'

const LegacyPublicJwkSchema = z.object({
  kty: z.literal('OKP'), crv: z.literal('Ed25519'), x: z.string().regex(/^[A-Za-z0-9_-]{43}$/u),
  kid: z.string().min(1).max(1024), alg: z.literal('EdDSA'), use: z.literal('sig'),
}).strict()
export const EcPublicJwkSchema = z.object({
  kty: z.literal('EC'), crv: z.literal('P-256'), x: z.string().regex(/^[A-Za-z0-9_-]{43}$/u),
  y: z.string().regex(/^[A-Za-z0-9_-]{43}$/u), kid: z.string().min(1).max(1024),
  alg: z.literal('ES256'), use: z.literal('sig'),
}).strict()
export const PublicJwkSchema = z.union([LegacyPublicJwkSchema, EcPublicJwkSchema])
export type PublicationJwk = z.infer<typeof PublicJwkSchema>
export const PublicationCapabilitiesSchema = z.object({
  mcpMachine: z.boolean(), papSession: z.boolean(), papAccount: z.boolean(),
}).strict().refine(v => (v.mcpMachine || v.papSession) && (!v.papAccount || v.papSession), 'Invalid capability combination')
export type PublicationCapabilities = z.infer<typeof PublicationCapabilitiesSchema>
/** Derive the server profile from actual enabled capabilities. */
export function publicationProfile(v: PublicationCapabilities): string {
  return [v.mcpMachine ? 'mcp_machine' : '', v.papAccount ? 'pap_account' : v.papSession ? 'pap_session' : ''].filter(Boolean).join('_')
}
/** The management wire representation is exclusively snake_case. */
export interface PublicationIntentV2 {
  schema_version: 2; operation_id: string; expected_version: number; client_name: string
  capabilities: { mcp_machine: boolean; pap_session: boolean; pap_account: boolean }
  signing_keys: PublicationJwk[]; active_kid: string; redirect_uris: string[]
}
export const PublicationConfigSchema = z.object({
  backend: z.string().min(1).max(128), documentId: z.string().regex(/^[A-Za-z0-9_-]{1,128}$/u),
  clientName: z.string().trim().min(1).max(128), redirectUris: z.array(z.string().max(2048)).max(8),
  capabilities: PublicationCapabilitiesSchema.optional(), activeKid: z.string().min(1).max(1024).optional(),
}).strict()
export type PublicationConfig = z.infer<typeof PublicationConfigSchema>
export const PublicationRecordSchema = z.object({
  config: PublicationConfigSchema, operationId: z.string().regex(/^[A-Za-z0-9_-]{1,128}$/u),
  expectedVersion: z.number().int().nonnegative(), state: z.enum(['awaiting_configuration', 'publishing', 'published', 'failed']),
  clientId: z.string().max(2048), version: z.number().int().nonnegative(),
  key: PublicJwkSchema,
  metadata: z.string().max(16384).optional(), jwks: z.string().max(16384).optional(),
  metadataSha256: z.string().regex(/^[a-f0-9]{64}$/u).optional(),
  failure: z.enum(['unavailable', 'publication_failed', 'material_mismatch']).optional(),
}).strict().refine(value => value.state !== 'published' ||
  (!!value.metadata && !!value.jwks && !!value.metadataSha256 && value.version > 0), 'Incomplete published materials')
export type PublicationRecord = z.infer<typeof PublicationRecordSchema>
export interface OAuthClientIdentity {
  readonly state: 'local' | 'awaiting_configuration' | 'publishing' | 'published' | 'failed'
  readonly did: string
  readonly clientId?: string
  readonly jwksUri?: string
  readonly keyId?: string
  readonly algorithm?: 'EdDSA' | 'ES256'
  readonly signerMode?: 'local'
  readonly capabilities?: PublicationCapabilities
  readonly version?: number
}
export interface PreparedClientMaterials {
  readonly schema_version?: 2
  readonly profile?: string
  readonly capabilities?: { mcp_machine: boolean; pap_session: boolean; pap_account: boolean }
  readonly active_kid?: string
  readonly key_set_digest?: string
  readonly state: 'awaiting_configuration' | 'prepared' | 'published'
  readonly client_id: string
  readonly version: number
  readonly operation_id?: string
  readonly metadata_sha256?: string
  readonly metadata?: string
  readonly jwks?: string
}
/** Installed by a trusted Host, not consumer request input. */
export interface PublicationBackend {
  readonly origin: string
  clientId(documentId: string): string
  prepare(documentId: string, input: {
    operation_id: string; expected_version: number; client_name: string; key: OAuthPublicJwk; redirect_uris: string[]
  } | PublicationIntentV2): Promise<PreparedClientMaterials>
  activate(documentId: string, operationId: string): Promise<PreparedClientMaterials>
  readPublic(documentId: string, part: 'client.json' | 'jwks.json'): Promise<string>
  /** Drive the existing authorized document-update/reconcile workflow. No unchecked document PUT. */
  publishDocument(reference: IdentityReference, session: ProviderDocumentChangeSession,
    assertActive: () => Promise<void>): Promise<void>
}
