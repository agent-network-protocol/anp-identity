import type {
  CreateIdentityRequest,
  DocumentChangeOutcome,
  DocumentChangeRequest,
  IdentityDescriptor,
  IdentityManagerConfig,
  IdentityReference,
  JsonValue,
  OriginProofRequest,
  PreparedDocumentChange,
  PublicIdentity,
  PublicationAttempt,
  PublicationResult,
  SignRequest,
  Signature,
  SignedOriginProof,
  StoreInfo,
  VerifiedRemoteDocument,
  VerifiedPublicationEvidence,
  VerifyRequest,
  RecoveryReport,
} from './index'

export type ProviderCapability =
  | 'IDENTITY_READ'
  | 'IDENTITY_CREATE'
  | 'IDENTITY_IMPORT'
  | 'IDENTITY_SIGN'
  | 'IDENTITY_ECDH_SEALED'
  | 'IDENTITY_DOCUMENT_UPDATE'
  | 'IDENTITY_KEY_LIFECYCLE'
  | 'IDENTITY_DELETE'
  | 'IDENTITY_HTTP_SIGNATURE'
  | 'AWIKI_LEGACY_ROOT_TRANSFER_V1'

export interface ProviderLeaseRequest {
  consumer: string
  capabilities: ProviderCapability[]
  ttlSeconds: number
}

export interface HttpHeader {
  name: string
  value: string
}

export interface ExactHttpSigningRequest {
  identity: IdentityReference
  kid?: string
  url: string
  method: string
  headers: HttpHeader[]
  body?: Buffer
  nonce?: string
  created?: number
  expires?: number
  coveredComponents?: string[]
}

export interface PreparedHttpSignatureAttempt {
  bindingDigest: string
  kid: string
  headerPatch: HttpHeader[]
}

export interface IdentityHostStatus {
  rootCapability: 'absent' | 'pending' | 'active'
  rootKeyFingerprint: string
  checkpoint?: HostDocumentCheckpoint
}

export interface HostDocumentCheckpoint {
  documentVersion: number
  registryVersion: number
  documentDigest: string
}

export interface ObjectProofRequest {
  kid?: string
  document: JsonValue
  issuerDid: string
  created?: string
}

export interface DocumentProofRequest {
  kid?: string
  document: JsonValue
  options?: {
    proofPurpose?: string
    proofType?: string
    cryptosuite?: string
    created?: string
    domain?: string
    challenge?: string
  }
}

export interface LegacyDidWbaRequest {
  kid?: string
  serviceDomain: string
  version: string
}

export interface SealedSecretEnvelope {
  protocol: 'anp-sealed-secret/1'
  suite: 'hpke-base-x25519-hkdf-sha256-chacha20poly1305-v1'
  encappedKey: string
  ciphertext: string
}

export interface SealedSecretDelivery {
  envelope: SealedSecretEnvelope
  authorization: AuthorizationContext
  aad: string
}

export interface SealedKeyAgreementRequest {
  identity: IdentityReference
  kid: string
  peerPublic: Buffer
  recipientPublicKey: Buffer
  requestId: string
}

export interface SealedRootExportRequest {
  identity: IdentityReference
  kid: string
  recipientPublicKey: Buffer
  requestId: string
  userPresenceConfirmed: boolean
}

export interface AuthorizationContext {
  providerInstanceId: string
  parentLeaseId: string
  consumer: string
  capability: ProviderCapability
  storeId: string
  expiresAt: number
}

export interface SealedImportOffer {
  recipientPublicKey: Buffer
  requestId: string
  token: string
  authorization: AuthorizationContext
  aad: string
}

export interface LegacyRootImportEvidence {
  transferId: string
  sourceDid: string
  targetDid: string
  senderDeviceId: string
  recipientDeviceId: string
  recipientAgreementKid: string
  rootKid: string
  checkpoint: {
    documentVersion: number
    registryVersion: number
    documentDigest: string
  }
  acceptedAt: string
}

export interface SealedRootImportPreparation {
  identity: IdentityReference
  evidence: LegacyRootImportEvidence
  encoding: 'raw32' | 'pkcs8_der'
  requestId: string
}

export type MigrationKeyPurpose =
  | 'root_control'
  | 'authentication'
  | 'device_assertion'
  | 'application_assertion'
  | 'key_agreement'

export interface SealedIdentityMaterialKeySpec {
  kid: string
  purpose: MigrationKeyPurpose
  encoding: 'raw32' | 'pkcs8_der'
}

export interface SealedIdentityImportPreparation {
  remote: {
    document: unknown
    evidence: VerifiedPublicationEvidence
  }
  didWba: boolean
  keys: SealedIdentityMaterialKeySpec[]
  requestId: string
}

export interface SealedIdentityMaterialImportOffer extends SealedImportOffer {
  target: IdentityReference
  itemAad: string[]
}

export interface DeviceEnrollmentRequest {
  remote: VerifiedRemoteDocument
  deviceId: string
  deviceSigningFragment: string
  deviceAgreementFragment: string
  profiles?: string[]
  capabilities?: { didWba?: boolean }
}

export interface RequestSigningEnrollmentRequest {
  remote: VerifiedRemoteDocument
  fragment: string
  capabilities?: { didWba?: boolean }
}

export interface EnrollmentPublicKey {
  kid: string
  publicKeyMultibase: string
}

export type EnrollmentProposalKind =
  | {
      kind: 'device'
      deviceId: string
      signingKey: EnrollmentPublicKey
      agreementKey: EnrollmentPublicKey
      profiles: string[]
    }
  | { kind: 'request_signing'; signingKey: EnrollmentPublicKey }

export interface EnrollmentProposal {
  enrollmentId: string
  identity: IdentityReference
  kind: EnrollmentProposalKind
  rootKeyFingerprint: string
  checkpoint: HostDocumentCheckpoint
}

export interface SealedEnrollmentKeyAgreementRequest {
  peerPublic: Buffer
  recipientPublicKey: Buffer
  requestId: string
}

export interface RootTransferContext {
  sourceDid: string
  targetDid: string
  senderDeviceId: string
  recipientDeviceId: string
  recipientAgreementKid: string
  rootKid: string
  checkpoint: HostDocumentCheckpoint
  createdAt: string
  expiresAt: string
}

export interface WrappedRootEnvelope {
  type: 'anp.identity.root-transfer.wrapped'
  version: 1
  context: RootTransferContext
  ephemeralPublic: string
  nonce: string
  ciphertext: string
  signature: string
}

export interface RootPromotionRequest {
  remote: VerifiedRemoteDocument
}

export class IdentityProvider {
  private constructor()
  static initialize(config: IdentityManagerConfig): Promise<IdentityProvider>
  static open(config: IdentityManagerConfig): Promise<IdentityProvider>
  acquireLease(request: ProviderLeaseRequest): ProviderLease
}

export interface ProviderLease {
  dispose(): void
  info(): Promise<StoreInfo>
  recover(): Promise<RecoveryReport>
  list(): Promise<IdentityDescriptor[]>
  publicIdentity(reference: IdentityReference): Promise<PublicIdentity>
  hostStatus(reference: IdentityReference): Promise<IdentityHostStatus>
  recoverIdentity(reference: IdentityReference): Promise<void>
  create(request: CreateIdentityRequest): Promise<PublicIdentity>
  delete(reference: IdentityReference): Promise<void>
  sign(reference: IdentityReference, request: SignRequest): Promise<Signature>
  verify(reference: IdentityReference, request: VerifyRequest): Promise<'valid' | 'invalid'>
  signOriginProof(
    reference: IdentityReference,
    request: OriginProofRequest,
  ): Promise<SignedOriginProof>
  signObjectProof(reference: IdentityReference, request: ObjectProofRequest): Promise<JsonValue>
  signDocumentProof(reference: IdentityReference, request: DocumentProofRequest): Promise<JsonValue>
  prepareHttpSignature(request: ExactHttpSigningRequest): Promise<PreparedHttpSignatureAttempt>
  prepareLegacyDidWba(reference: IdentityReference, request: LegacyDidWbaRequest): Promise<string>
  prepareDocumentChange(
    reference: IdentityReference,
    request: DocumentChangeRequest,
  ): Promise<ProviderDocumentChangeSession>
  resumeDocumentChange(
    reference: IdentityReference,
  ): Promise<ProviderDocumentChangeSession | undefined>
  adoptVerifiedDocument(
    reference: IdentityReference,
    remote: VerifiedRemoteDocument,
  ): Promise<'activated' | 'updated' | 'unchanged' | 'revoked'>
  beginDeviceEnrollment(request: DeviceEnrollmentRequest): Promise<ProviderEnrollmentSession>
  beginRequestSigningEnrollment(
    request: RequestSigningEnrollmentRequest,
  ): Promise<ProviderEnrollmentSession>
  resumeEnrollment(reference: IdentityReference): Promise<ProviderEnrollmentSession | undefined>
  importWrappedRoot(
    reference: IdentityReference,
    envelope: WrappedRootEnvelope,
  ): Promise<'pending' | 'active'>
  confirmRootPromotion(reference: IdentityReference, request: RootPromotionRequest): Promise<void>
  signPendingRootObjectProof(
    reference: IdentityReference,
    request: ObjectProofRequest,
  ): Promise<JsonValue>
  ecdhSealed(request: SealedKeyAgreementRequest): Promise<SealedSecretDelivery>
  exportRootKeySealed(request: SealedRootExportRequest): Promise<SealedSecretDelivery>
  prepareLegacyRootImport(request: SealedRootImportPreparation): Promise<PreparedRootImport>
  prepareIdentityMaterialImport(
    request: SealedIdentityImportPreparation,
  ): Promise<PreparedIdentityMaterialImport>
}

export interface ProviderDocumentChangeSession {
  candidate(): Promise<PreparedDocumentChange>
  hostPhase(): Promise<'prepared' | 'publication_in_flight' | 'publication_uncertain' | 'published'>
  beginPublication(): Promise<PublicationAttempt>
  complete(
    attempt: PublicationAttempt,
    result: PublicationResult,
  ): Promise<DocumentChangeOutcome>
  reconcile(observation: VerifiedRemoteDocument): Promise<DocumentChangeOutcome>
}

export interface ProviderEnrollmentSession {
  proposal(): Promise<EnrollmentProposal>
  signDeviceAssertion(payload: Buffer): Promise<Buffer>
  deriveDeviceSharedSecretSealed(
    request: SealedEnrollmentKeyAgreementRequest,
  ): Promise<SealedSecretDelivery>
  activate(remote: VerifiedRemoteDocument): Promise<'activated'>
  cancel(): Promise<void>
}

export interface PreparedRootImport {
  offer(): SealedImportOffer
  complete(token: string, envelope: SealedSecretEnvelope): Promise<'pending' | 'active'>
}

export interface PreparedIdentityMaterialImport {
  offer(): SealedIdentityMaterialImportOffer
  complete(token: string, envelopes: SealedSecretEnvelope[]): Promise<PublicIdentity>
}
