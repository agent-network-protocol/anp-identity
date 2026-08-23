import type {
  CreateIdentityRequest,
  IdentityDescriptor,
  IdentityReference,
  PublicIdentity,
  RecoveryReport,
  StoreInfo,
} from '@agent-network-protocol/anp-identity'
import type {
  DeviceEnrollmentRequest,
  DocumentProofRequest,
  ExactHttpSigningRequest,
  IdentityHostStatus,
  LegacyDidWbaRequest,
  ObjectProofRequest,
  PreparedHttpSignatureAttempt,
  PreparedIdentityMaterialImport,
  PreparedRootImport,
  ProviderCapability,
  ProviderDocumentChangeSession,
  ProviderEnrollmentSession,
  ProviderLease,
  ProviderLeaseRequest,
  RequestSigningEnrollmentRequest,
  RootPromotionRequest,
  SealedIdentityImportPreparation,
  SealedKeyAgreementRequest,
  SealedRootExportRequest,
  SealedRootImportPreparation,
  SealedSecretDelivery,
  SealedSecretEnvelope,
  WrappedRootEnvelope,
} from '@agent-network-protocol/anp-identity/provider'
import type {
  DocumentChangeOutcome,
  DocumentChangeRequest,
  OriginProofRequest,
  PublicationAttempt,
  PublicationResult,
  SignRequest,
  Signature,
  SignedOriginProof,
  VerifiedRemoteDocument,
  VerifyRequest,
} from './types.js'

export type {
  DeviceEnrollmentRequest,
  DocumentProofRequest,
  ExactHttpSigningRequest,
  IdentityHostStatus,
  LegacyDidWbaRequest,
  ObjectProofRequest,
  PreparedHttpSignatureAttempt,
  PreparedIdentityMaterialImport,
  PreparedRootImport,
  ProviderCapability,
  ProviderDocumentChangeSession,
  ProviderEnrollmentSession,
  ProviderLeaseRequest,
  RequestSigningEnrollmentRequest,
  RootPromotionRequest,
  SealedIdentityImportPreparation,
  SealedKeyAgreementRequest,
  SealedRootExportRequest,
  SealedRootImportPreparation,
  SealedSecretDelivery,
  SealedSecretEnvelope,
  WrappedRootEnvelope,
}

export const ANP_IDENTITY_SERVICE_PROTOCOL = 'anp-identity-service/1' as const
export const ANP_IDENTITY_PROVIDER_PROTOCOL = 'anp-identity-provider-ts/1' as const
export const ANP_IDENTITY_NATIVE_PROVIDER_PROTOCOL = 'anp-identity-node-provider/1' as const

export interface NativeIdentityProvider {
  acquireLease(request: ProviderLeaseRequest): ProviderLease
}

export interface NativeProviderRegistration {
  readonly protocol: typeof ANP_IDENTITY_NATIVE_PROVIDER_PROTOCOL
  readonly provider: NativeIdentityProvider
}

export interface ProviderRequest {
  readonly consumer: string
  readonly capabilities: ProviderCapability[]
  readonly ttlSeconds?: number
}

/** Host-only lease. Never expose it through Remote, Browser, tools, or model APIs. */
export interface HostProviderLease {
  readonly protocol: typeof ANP_IDENTITY_PROVIDER_PROTOCOL
  readonly consumer: string
  readonly capabilities: readonly ProviderCapability[]
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
  signOriginProof(reference: IdentityReference, request: OriginProofRequest): Promise<SignedOriginProof>
  signObjectProof(reference: IdentityReference, request: ObjectProofRequest): Promise<unknown>
  signDocumentProof(reference: IdentityReference, request: DocumentProofRequest): Promise<unknown>
  prepareHttpSignature(request: ExactHttpSigningRequest): Promise<PreparedHttpSignatureAttempt>
  prepareLegacyDidWba(reference: IdentityReference, request: LegacyDidWbaRequest): Promise<string>
  prepareDocumentChange(
    reference: IdentityReference,
    request: DocumentChangeRequest,
  ): Promise<ProviderDocumentChangeSession>
  resumeDocumentChange(reference: IdentityReference): Promise<ProviderDocumentChangeSession | undefined>
  adoptVerifiedDocument(
    reference: IdentityReference,
    remote: VerifiedRemoteDocument,
  ): Promise<'activated' | 'updated' | 'unchanged' | 'revoked'>
  beginDeviceEnrollment(request: DeviceEnrollmentRequest): Promise<ProviderEnrollmentSession>
  beginRequestSigningEnrollment(request: RequestSigningEnrollmentRequest): Promise<ProviderEnrollmentSession>
  resumeEnrollment(reference: IdentityReference): Promise<ProviderEnrollmentSession | undefined>
  importWrappedRoot(reference: IdentityReference, envelope: WrappedRootEnvelope): Promise<'pending' | 'active'>
  confirmRootPromotion(reference: IdentityReference, request: RootPromotionRequest): Promise<void>
  signPendingRootObjectProof(reference: IdentityReference, request: ObjectProofRequest): Promise<unknown>
  ecdhSealed(request: SealedKeyAgreementRequest): Promise<SealedSecretDelivery>
  exportRootKeySealed(request: SealedRootExportRequest): Promise<SealedSecretDelivery>
  prepareLegacyRootImport(request: SealedRootImportPreparation): Promise<PreparedRootImport>
  prepareIdentityMaterialImport(request: SealedIdentityImportPreparation): Promise<PreparedIdentityMaterialImport>
  grantConsumer(reference: IdentityReference, consumer: string): Promise<void>
  revokeConsumer(reference: IdentityReference, consumer: string): Promise<void>
}

export interface AnpIdentityService {
  health(): Promise<import('./types.js').AnpIdentityHealth>
  acquireClient(input: import('./types.js').ClientRequest): Promise<import('./types.js').IdentityClientLease>
  acquireProvider(input: ProviderRequest): HostProviderLease
}

/** Internal registration seam consumed only by the package's `./provider` entry. */
export interface NativeProviderRegistry {
  registerProvider(registration: Promise<NativeProviderRegistration> | NativeProviderRegistration): () => Promise<void>
}

export interface HostDocumentChangeWire {
  candidate(): Promise<import('./types.js').PreparedDocumentChange>
  beginPublication(): Promise<PublicationAttempt>
  complete(attempt: PublicationAttempt, result: PublicationResult): Promise<DocumentChangeOutcome>
  reconcile(observation: VerifiedRemoteDocument): Promise<DocumentChangeOutcome>
}
