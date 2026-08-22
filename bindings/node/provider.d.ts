import type {
  CreateIdentityRequest,
  IdentityDescriptor,
  IdentityManagerConfig,
  IdentityReference,
  OriginProofRequest,
  PublicIdentity,
  SignRequest,
  Signature,
  SignedOriginProof,
  VerifiedPublicationEvidence,
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

export interface SealedSecretEnvelope {
  protocol: 'anp-sealed-secret/1'
  suite: 'hpke-base-x25519-hkdf-sha256-chacha20poly1305-v1'
  encappedKey: string
  ciphertext: string
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

export type ProviderAdoptionTarget =
  | { kind: 'local_private_file' }
  | { kind: 'keyring'; service: string; account: string }

export interface SealedProviderAdoptionPreparation {
  stateRoot: string
  target: ProviderAdoptionTarget
  requestId: string
}

export interface SealedProviderAdoptionOffer extends SealedImportOffer {
  storeId: string
  rootKeyFingerprint: string
}

export interface ProviderAdoptionReport {
  storeId: string
  provider: unknown
  rootKeyFingerprint: string
  generation: number
}

export class IdentityProvider {
  private constructor()
  static initialize(config: IdentityManagerConfig): Promise<IdentityProvider>
  static open(config: IdentityManagerConfig): Promise<IdentityProvider>
  acquireLease(request: ProviderLeaseRequest): Promise<ProviderLease>
}

export class ProviderLease {
  private constructor()
  dispose(): void
  list(): Promise<IdentityDescriptor[]>
  publicIdentity(reference: IdentityReference): Promise<PublicIdentity>
  create(request: CreateIdentityRequest): Promise<PublicIdentity>
  sign(reference: IdentityReference, request: SignRequest): Promise<Signature>
  signOriginProof(
    reference: IdentityReference,
    request: OriginProofRequest,
  ): Promise<SignedOriginProof>
  prepareHttpSignature(request: ExactHttpSigningRequest): Promise<PreparedHttpSignatureAttempt>
  ecdhSealed(request: SealedKeyAgreementRequest): Promise<SealedSecretEnvelope>
  exportRootKeySealed(request: SealedRootExportRequest): Promise<SealedSecretEnvelope>
  prepareLegacyRootImport(request: SealedRootImportPreparation): Promise<PreparedRootImport>
  prepareIdentityMaterialImport(
    request: SealedIdentityImportPreparation,
  ): Promise<PreparedIdentityMaterialImport>
  prepareProviderAdoption(
    request: SealedProviderAdoptionPreparation,
  ): Promise<PreparedProviderAdoption>
}

export class PreparedRootImport {
  private constructor()
  offer(): SealedImportOffer
  complete(token: string, envelope: SealedSecretEnvelope): Promise<'pending' | 'active'>
}

export class PreparedIdentityMaterialImport {
  private constructor()
  offer(): SealedIdentityMaterialImportOffer
  complete(token: string, envelopes: SealedSecretEnvelope[]): Promise<PublicIdentity>
}

export class PreparedProviderAdoption {
  private constructor()
  offer(): SealedProviderAdoptionOffer
  complete(token: string, envelope: SealedSecretEnvelope): Promise<ProviderAdoptionReport>
}
