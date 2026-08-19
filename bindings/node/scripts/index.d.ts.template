/// JSON-compatible value accepted by the native binding.
export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue }

export type KeyRole = 'root_control' | 'request_signing' | 'e2ee_signing' | 'e2ee_agreement'
export type KeyOrigin = 'managed' | 'external'
export type KeyState = 'active' | 'retired' | 'revoked'
export type PublicationState = 'prepared' | 'publication_in_flight' | 'publication_uncertain' | 'published'
export type RootKeyProviderKind = 'os_keyring' | 'injected' | 'local_private_file'

export interface Capabilities {
  didWba: boolean
}

export interface ManagedKeySpec {
  fragment: string
  role: KeyRole
}

export interface PublicOkpJwk {
  kty: 'OKP'
  crv: 'Ed25519' | 'X25519'
  x: string
}

export type ExternalPublicKeyMaterial =
  | { format: 'multibase'; value: string; publicKeyJwk?: never }
  | { format: 'jwk'; value?: never; publicKeyJwk: PublicOkpJwk }

export interface ExternalPublicKeySpec {
  kid: string
  role: Exclude<KeyRole, 'root_control'>
  material: ExternalPublicKeyMaterial
}

export interface ServiceSpec {
  id: string
  serviceType: string
  serviceEndpoint: string
  profiles: string[]
  securityProfiles: string[]
}

export interface DeviceManifestEntrySpec {
  deviceId: string
  signingKeyId: string
  e2eeKeyId: string
  profiles: string[]
}

export interface DeviceManifestSpec {
  devices: DeviceManifestEntrySpec[]
}

export type DidExtensionSpec = {
  extensionType: 'device_manifest'
  deviceManifest: DeviceManifestSpec
}

export interface DidCreateSpec {
  profile: 'e1'
  domain: string
  port?: number
  pathSegments: string[]
  capabilities: Capabilities
  managedKeys: ManagedKeySpec[]
  externalKeys: ExternalPublicKeySpec[]
  services: ServiceSpec[]
  agentDescriptionUrl?: string
  extensions: DidExtensionSpec[]
}

export interface IdentitySummary {
  identityId: string
  did: string
  state: 'creating' | 'active'
  createdAt: string
}

export interface KeyMetadata {
  kid: string
  role: KeyRole
  origin: KeyOrigin
  state: KeyState
  /** True only after explicit local crypto-erasure of a managed revoked key. */
  materialErased: boolean
  version: number
  publicKeyMultibase: string
  createdAt: string
}

export interface RootKeyProviderBinding {
  kind: RootKeyProviderKind
  keyId: string
  account?: string
}

export interface StoreManifest {
  schemaVersion: number
  storeId: string
  generation: number
  provider: RootKeyProviderBinding
  rootKeyFingerprint: string
  createdAt: string
  rekeyGeneration: number
}

export interface IdentitySnapshot {
  identityId: string
  did: string
  state: 'creating' | 'active'
  revision: number
  document: JsonValue
  capabilities: Capabilities
  keys: KeyMetadata[]
}

export interface DocumentUpdateSpec {
  requestSigningRotation: {
    oldKid: string
    newFragment: string
  }
  services?: ServiceSpec[]
}

export interface PreparedUpdate {
  revisionId: string
  candidateDocument: JsonValue
  candidateDigest: string
}

export interface PendingRevisionSummary {
  revisionId: string
  parentRevision: number
  candidateDigest: string
  candidateKids: string[]
  state: PublicationState
  generation: number
  createdAt: string
}

export interface Header {
  name: string
  value: string
}

export interface AnpIdentityError extends Error {
  code: string
}

export class DidStore {
  private constructor()
  /** Consumes and overwrites rootKey, including validation-error paths. */
  static initializeInjected(root: string, keyId: string, rootKey: Buffer): Promise<DidStore>
  /** Consumes and overwrites rootKey, including validation-error paths. */
  static openInjected(root: string, keyId: string, rootKey: Buffer): Promise<DidStore>
  /** Reads a base64url-encoded, uniformly random 32-byte root key from envVar. */
  static initializeEnv(root: string, keyId: string, envVar: string): Promise<DidStore>
  /** Reads a base64url-encoded, uniformly random 32-byte root key from envVar. */
  static openEnv(root: string, keyId: string, envVar: string): Promise<DidStore>
  static initializeLocalFile(root: string): Promise<DidStore>
  static openLocalFile(root: string): Promise<DidStore>
  static initializeKeyring(root: string, service: string, account: string, fallbackToLocalFile: boolean): Promise<DidStore>
  static openKeyring(root: string, service: string, account: string): Promise<DidStore>
  generation(): Promise<number>
  manifest(): Promise<StoreManifest>
  /** Takes the store-wide exclusive lock, runs recovery, and refreshes after a conflict. */
  reload(): Promise<void>
  listIdentities(): Promise<IdentitySummary[]>
  createIdentity(spec: DidCreateSpec): Promise<DidIdentity>
  openIdentity(did: string): Promise<DidIdentity>
}

export class DidIdentity {
  private constructor()
  /** Takes the store-wide exclusive lock, runs recovery, and refreshes after a conflict. */
  reload(): Promise<void>
  snapshot(): Promise<IdentitySnapshot>
  pendingRevision(): Promise<PendingRevisionSummary | undefined>
  sign(kid: string, message: Buffer): Promise<Buffer>
  verify(kid: string, message: Buffer, signature: Buffer): Promise<boolean>
  publicKeyBytes(kid: string): Promise<Buffer>
  /** Raw X25519 result; derive a domain-separated session key and overwrite this Buffer. */
  ecdh(kid: string, peerPublic: Buffer): Promise<Buffer>
  legacyDidWbaHeader(kid: string, serviceDomain: string, version: string): Promise<string>
  httpSignatureHeaders(kid: string, requestUrl: string, requestMethod: string, headers?: Header[], body?: Buffer): Promise<Header[]>
  prepareUpdate(spec: DocumentUpdateSpec): Promise<PreparedUpdate>
  beginPublication(revisionId: string): Promise<void>
  markPublicationUncertain(revisionId: string): Promise<void>
  markPublished(revisionId: string): Promise<void>
  commitUpdate(revisionId: string): Promise<void>
  abortUpdate(revisionId: string): Promise<void>
  reconcileUpdate(revisionId: string, observedRemoteDocument: JsonValue): Promise<'remote_old' | 'committed'>
  endRetirement(kid: string): Promise<void>
  deleteRevokedKey(kid: string): Promise<void>
}
