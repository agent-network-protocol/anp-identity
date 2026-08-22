import type {
  CreateIdentityRequest as NativeCreateIdentityRequest,
  DocumentChangeOutcome,
  DocumentChangeRequest,
  IdentityDescriptor as NativeIdentityDescriptor,
  IdentityReference,
  OriginProofRequest,
  PreparedDocumentChange,
  PublicIdentity,
  PublicationAttempt,
  PublicationResult,
  RecoveryReport as NativeRecoveryReport,
  SignRequest,
  Signature,
  SignedOriginProof,
  VerifiedRemoteDocument,
  VerifyRequest,
} from '@agent-network-protocol/anp-identity'

export type {
  DocumentChangeOutcome,
  DocumentChangeRequest,
  IdentityReference,
  OriginProofRequest,
  PreparedDocumentChange,
  PublicIdentity,
  PublicationAttempt,
  PublicationResult,
  SignRequest,
  Signature,
  SignedOriginProof,
  VerifiedRemoteDocument,
  VerifyRequest,
}

export type ClientCapability =
  | 'identity:read'
  | 'identity:create'
  | 'identity:sign'
  | 'identity:document-update'
  | 'identity:http-auth'
  | 'identity:delete'
  | 'identity:recover'
  | 'identity:handle'

export interface ClientRequest {
  readonly consumer: string
  readonly capabilities: ClientCapability[]
  /** Exact origins requested from the Host-configured allowlist. */
  readonly httpOrigins?: string[]
  readonly ttlSeconds?: number
}

export type IdentityRef = IdentityReference | { readonly handle: string }

export interface ListIdentitiesInput {
  readonly state?: NativeIdentityDescriptor['state']
}

export interface IdentityDescriptor extends NativeIdentityDescriptor {
  readonly label?: string
  readonly handle?: string
  readonly catalogState: 'active' | 'deleting' | 'unclaimed'
}

export interface CreateIdentityRequest {
  readonly identity: NativeCreateIdentityRequest
  readonly requestId?: string
  readonly label?: string
  readonly handle?: string
}

export interface DeleteIdentityRequest {
  /** Deletion remains forbidden while another consumer grant exists. */
  readonly reason?: string
}

export interface RecoveryReport extends NativeRecoveryReport {
  readonly catalogRebuilt: boolean
  readonly unclaimedIdentityCount: number
}

export interface AnpIdentityHealth {
  readonly status: 'ready' | 'unavailable' | 'degraded'
  readonly protocol: 'anp-identity-service/1'
  readonly providerProtocol?: 'anp-identity-provider-ts/1'
  readonly catalog: 'ready' | 'corrupt' | 'unavailable'
}

export type HttpTransport = (request: Request) => Promise<Response>

export interface AuthenticatedHttp {
  dispatch(request: Request, transport: HttpTransport): Promise<Response>
}

export interface DocumentChangeSessionClient {
  candidate(): Promise<PreparedDocumentChange>
  beginPublication(): Promise<PublicationAttempt>
  complete(attempt: PublicationAttempt, result: PublicationResult): Promise<DocumentChangeOutcome>
  reconcile(observation: VerifiedRemoteDocument): Promise<DocumentChangeOutcome>
}

export interface ManagedIdentityClient {
  publicIdentity(): Promise<PublicIdentity>
  sign(request: SignRequest): Promise<Signature>
  signOriginProof(request: OriginProofRequest): Promise<SignedOriginProof>
  verify(request: VerifyRequest): Promise<'valid' | 'invalid'>
  readonly authenticatedHttp: AuthenticatedHttp
  prepareDocumentChange(request: DocumentChangeRequest): Promise<DocumentChangeSessionClient>
  resumeDocumentChange(): Promise<DocumentChangeSessionClient | undefined>
}

export interface IdentityClientLease {
  readonly consumer: string
  readonly capabilities: readonly ClientCapability[]
  list(input?: ListIdentitiesInput): Promise<IdentityDescriptor[]>
  create(input: CreateIdentityRequest): Promise<ManagedIdentityClient>
  get(reference: IdentityRef): Promise<ManagedIdentityClient>
  delete(reference: IdentityRef, input?: DeleteIdentityRequest): Promise<void>
  recover(): Promise<RecoveryReport>
  setHandle(reference: IdentityRef, handle: string | null): Promise<void>
  dispose(): Promise<void>
}
