export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue }

export type IdentityState = 'enrolling' | 'active' | 'revoked'
export type KeyAlgorithm = 'ed25519' | 'x25519'
export type KeyPurpose =
  | 'root_control'
  | 'authentication'
  | 'device_assertion'
  | 'application_assertion'
  | 'key_agreement'
export type KeyRole =
  | 'root_control'
  | 'device_signing'
  | 'request_signing'
  | 'e2ee_signing'
  | 'e2ee_agreement'

export interface IdentityReference {
  storeId: string
  identityId: string
  did: string
}

export interface StoreInfo {
  storeId: string
  schemaCompatible: boolean
  identityCount: number
  health: 'ready'
}

export interface RecoveryReport {
  identityCount: number
}

export interface IdentityDescriptor {
  reference: IdentityReference
  state: IdentityState
}

export interface PublicKeyDescriptor {
  kid: string
  algorithm: KeyAlgorithm
  purposes: KeyPurpose[]
}

export interface PublicIdentity {
  reference: IdentityReference
  state: IdentityState
  revision: number
  document: JsonValue
  activeKeys: PublicKeyDescriptor[]
  capabilities: { didWba: boolean }
}

export type RootKeyConfig =
  | { rootKeyKind: 'injected'; keyId: string; rootKey: Buffer }
  | { rootKeyKind: 'environment'; keyId: string; environmentVariable: string }
  | { rootKeyKind: 'local_private_file' }
  | {
      rootKeyKind: 'keyring'
      service: string
      account: string
      fallbackToLocalFile?: boolean
    }

export type IdentityManagerConfig = { stateRoot: string } & RootKeyConfig

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
  | { format: 'multibase'; value: string }
  | { format: 'jwk'; publicKeyJwk: PublicOkpJwk }

export interface ExternalPublicKeySpec {
  kid: string
  role: Exclude<KeyRole, 'root_control'>
  material: ExternalPublicKeyMaterial
}

export interface IdentityService {
  id: string
  serviceType: string
  serviceEndpoint: string
  serviceDid?: string
  profiles?: string[]
  securityProfiles?: string[]
}

export interface DeviceManifestEntry {
  deviceId: string
  signingKeyId: string
  e2eeKeyId: string
  profiles?: string[]
}

export interface CreateIdentityRequest {
  profile: 'e1'
  domain: string
  port?: number
  pathSegments: string[]
  capabilities?: { didWba?: boolean }
  managedKeys: ManagedKeySpec[]
  externalKeys?: ExternalPublicKeySpec[]
  services?: IdentityService[]
  agentDescriptionUrl?: string
  extensions?: Array<{
    type: 'device_manifest'
    value: { devices: DeviceManifestEntry[] }
  }>
}

export type SignRequest =
  | { purpose: 'authentication'; kid?: string; payload: Buffer }
  | { purpose: 'device_assertion'; kid?: string; payload: Buffer }
  | { purpose: 'application_assertion'; domain: string; kid?: string; payload: Buffer }

export interface Signature {
  kid: string
  algorithm: 'ed25519'
  bytes: Buffer
}

export type VerifyRequest =
  | { purpose: 'authentication'; kid: string; payload: Buffer; signature: Buffer }
  | { purpose: 'device_assertion'; kid: string; payload: Buffer; signature: Buffer }
  | {
      purpose: 'application_assertion'
      domain: string
      kid: string
      payload: Buffer
      signature: Buffer
    }

export interface OriginProofRequest {
  method: string
  meta: JsonValue
  body: JsonValue
  kid?: string
  options?: { created?: number; expires?: number; nonce?: string }
}

export interface SignedOriginProof {
  contentDigest: string
  signatureInput: string
  signature: string
}

export interface PublicKeyInput {
  kid: string
  publicKeyMultibase: string
}

export type DocumentChange =
  | { change: 'rotate_signing_key'; oldKid: string; newFragment: string }
  | { change: 'add_authentication_key'; key: PublicKeyInput }
  | { change: 'remove_authentication_key'; kid: string }
  | {
      change: 'add_device'
      device: {
        deviceId: string
        signingKey: PublicKeyInput
        agreementKey: PublicKeyInput
        profiles?: string[]
      }
    }
  | { change: 'remove_device'; deviceId: string }
  | { change: 'replace_services'; services: IdentityService[] }

export interface DocumentChangeRequest {
  changes: DocumentChange[]
}

export interface PreparedDocumentChange {
  operationId: string
  candidateDocument: JsonValue
  candidateDigest: string
}

export interface PublicationAttempt {
  operationId: string
  candidateDigest: string
  publicationGeneration: number
}

export interface VerifiedPublicationEvidence {
  documentVersion: number
  registryVersion: number
  documentDigest: string
}

export type PublicationResult =
  | { result: 'confirmed'; evidence: VerifiedPublicationEvidence }
  | { result: 'rejected_before_acceptance' }
  | { result: 'unknown' }

export interface VerifiedRemoteDocument {
  document: JsonValue
  evidence: VerifiedPublicationEvidence
}

export type DocumentChangeOutcome =
  | { outcome: 'ready_for_publication' }
  | { outcome: 'publication_uncertain' }
  | { outcome: 'committed'; identity: PublicIdentity }
  | { outcome: 'aborted' }

export interface IdentityTransitionRequest {
  expectedCurrentDid: string
  operationId: string
  successor: IdentityReference
  /** Optional externally produced recovery/provider/unverified transition evidence. */
  transitionDocument?: JsonValue
  /** Required only when transitionDocument contains a provider transition assertion. */
  providerDocument?: JsonValue
}

export type TransitionAssurance =
  | 'verified'
  | 'recovery_verified'
  | 'provider_asserted'
  | 'unverified'

export interface PreparedIdentityTransition {
  operationId: string
  expectedCurrentDid: string
  successorDid: string
  predecessorDocument: JsonValue
  successorDocument: JsonValue
  predecessorDigest: string
  successorDigest: string
  assurance: TransitionAssurance
}

export interface IdentityTransitionPublicationAttempt {
  operationId: string
  predecessorDigest: string
  successorDigest: string
  publicationGeneration: number
}

export interface IdentityTransitionPublicationEvidence {
  predecessorDigest: string
  successorDigest: string
}

export type IdentityTransitionPublicationResult =
  | { result: 'confirmed'; evidence: IdentityTransitionPublicationEvidence }
  | { result: 'rejected_before_acceptance' }
  | { result: 'unknown' }

export type IdentityTransitionRemoteObservation =
  | { observation: 'remote_old'; currentDocument: JsonValue }
  | {
      observation: 'published'
      predecessorDocument: JsonValue
      successorDocument: JsonValue
    }

export type IdentityTransitionOutcome =
  | { outcome: 'ready_for_publication' }
  | { outcome: 'publication_uncertain' }
  /** Confirms the publication journal only; it does not mutate a local identity record or remote current-DID registry. */
  | { outcome: 'committed'; currentDid: string }
  | { outcome: 'aborted' }

export interface AnpIdentityError extends Error {
  code:
    | 'invalid_request'
    | 'store_not_found'
    | 'provider_unavailable'
    | 'root_key_mismatch'
    | 'corrupt_state'
    | 'identity_not_found'
    | 'identity_already_exists'
    | 'key_not_found'
    | 'key_unavailable'
    | 'key_purpose_violation'
    | 'ambiguous_key'
    | 'verification_failed'
    | 'pending_document_change'
    | 'document_change_not_found'
    | 'invalid_document_change_state'
    | 'conflict'
    | 'capability_unavailable'
    | 'unsupported_operation'
    | 'storage'
    | 'internal'
}

export class IdentityManager {
  private constructor()
  static initialize(config: IdentityManagerConfig): Promise<IdentityManager>
  static open(config: IdentityManagerConfig): Promise<IdentityManager>
  info(): Promise<StoreInfo>
  list(): Promise<IdentityDescriptor[]>
  create(request: CreateIdentityRequest): Promise<ManagedIdentity>
  get(reference: IdentityReference): Promise<ManagedIdentity>
  delete(reference: IdentityReference): Promise<void>
  /** Acquires the Store-wide exclusive lock and runs recovery. */
  recover(): Promise<RecoveryReport>
  prepareIdentityTransition(request: IdentityTransitionRequest): Promise<IdentityTransitionSession>
  resumeIdentityTransition(expectedCurrentDid: string): Promise<IdentityTransitionSession | undefined>
}

export class ManagedIdentity {
  private constructor()
  reference(): Promise<IdentityReference>
  publicIdentity(): Promise<PublicIdentity>
  sign(request: SignRequest): Promise<Signature>
  verify(request: VerifyRequest): Promise<'valid' | 'invalid'>
  signOriginProof(request: OriginProofRequest): Promise<SignedOriginProof>
  prepareDocumentChange(request: DocumentChangeRequest): Promise<DocumentChangeSession>
  resumeDocumentChange(): Promise<DocumentChangeSession | undefined>
}

export class DocumentChangeSession {
  private constructor()
  candidate(): Promise<PreparedDocumentChange>
  beginPublication(): Promise<PublicationAttempt>
  complete(attempt: PublicationAttempt, result: PublicationResult): Promise<DocumentChangeOutcome>
  reconcile(observation: VerifiedRemoteDocument): Promise<DocumentChangeOutcome>
}

export class IdentityTransitionSession {
  private constructor()
  candidate(): Promise<PreparedIdentityTransition>
  beginPublication(): Promise<IdentityTransitionPublicationAttempt>
  complete(
    attempt: IdentityTransitionPublicationAttempt,
    result: IdentityTransitionPublicationResult,
  ): Promise<IdentityTransitionOutcome>
  reconcile(observation: IdentityTransitionRemoteObservation): Promise<IdentityTransitionOutcome>
}
