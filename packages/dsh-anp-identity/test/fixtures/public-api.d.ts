// ===== index.d.ts =====
/** Host-only ANP Identity service for DeepSeek Harness. */
import { Service, type Context } from '@deepseek-ai/cordis';
import z from '@deepseek-ai/schemastery';
import { type AnpIdentityService as AnpIdentityServiceContract, type HostProviderLease, type ProviderRequest } from './provider-api.js';
import type { AnpIdentityHealth, ClientRequest, IdentityClientLease } from './types.js';
export type * from './types.js';
export { AnpIdentityPluginError } from './errors.js';
export type { AnpIdentityPluginErrorCode } from './errors.js';
export { ANP_IDENTITY_HTTP_MAX_BODY_BYTES, } from './http-auth.js';
export { ANP_IDENTITY_PROVIDER_PROTOCOL, ANP_IDENTITY_SERVICE_PROTOCOL, } from './provider-api.js';
export type { AnpIdentityService as AnpIdentityServiceContract, HostProviderLease, ProviderRequest, } from './provider-api.js';
declare module '@deepseek-ai/cordis' {
    interface Context {
        anpIdentity: AnpIdentityServiceContract;
    }
}
export interface Config {
    /** Absolute ANP Identity Store root. Defaults below DSH_HOME. */
    readonly stateRoot?: string;
    /** Exact same-process consumer names permitted to acquire leases. */
    readonly allowConsumers?: string[];
    /** Narrow Host-only consumers permitted to acquire Provider leases. */
    readonly allowProviderConsumers?: string[];
    /** Exact HTTPS origins permitted per consumer for authenticated HTTP. */
    readonly httpAllowedOrigins?: Record<string, string[]>;
    /** Run native Store recovery when a Provider opens. */
    readonly recoveryOnOpen?: boolean;
}
export declare const Config: z<Config>;
/** One multi-DID ANP Identity service with a replaceable native Provider. */
export declare class AnpIdentityService extends Service implements AnpIdentityServiceContract {
    static Config: z<Config>;
    private readonly resolvedConfig;
    private readonly catalogStore;
    private providerSlot;
    constructor(ctx: Context, config: Config);
    health(): Promise<AnpIdentityHealth>;
    private registerProvider;
    acquireClient(input: ClientRequest): Promise<IdentityClientLease>;
    acquireProvider(input: ProviderRequest): HostProviderLease;
    private listForClient;
    private createForClient;
    private getForClient;
    private deleteForClient;
    private recoverForClient;
    private setHandleForClient;
    private assertManagedAccess;
    private grantConsumer;
    private revokeConsumer;
    private createForHost;
    private deleteForHost;
    private removeLease;
    private initializeSlot;
    private reconcile;
    private resolveAuthorized;
    private loadCatalog;
    private assertAllowedConsumer;
    private requireSlot;
    private assertSlot;
    private awaitProvider;
    private disposeSlot;
}
export default AnpIdentityService;

// ===== provider.d.ts =====
/** Native ANP Identity Provider registration for the Host-only DSH service. */
import type { Context } from '@deepseek-ai/cordis';
import z from '@deepseek-ai/schemastery';
import { type NativeProviderRegistration } from './provider-api.js';
export declare const name = "anp-identity-native-provider";
export declare const inject: string[];
export interface Config {
    readonly stateRoot?: string;
    readonly rootKeyProvider: 'keyring' | 'local-file' | 'env' | 'injected';
    /** Keyring uses `service/account`; env uses the variable name; injected uses the key id. */
    readonly rootKeyProviderId?: string;
    readonly keyringFallbackToLocalFile?: boolean;
    /** Programmatic Host injection only. Never place this value in Loader YAML. */
    readonly injectedRootKey?: Buffer;
}
export declare const Config: z<Config>;
export declare function apply(ctx: Context, config: Config): void;
export declare function openNativeProvider(config: Config): Promise<NativeProviderRegistration>;

// ===== provider-api.d.ts =====
import type { CreateIdentityRequest, IdentityDescriptor, IdentityReference, PublicIdentity, RecoveryReport, StoreInfo } from '@agent-network-protocol/anp-identity';
import type { DeviceEnrollmentRequest, DocumentProofRequest, ExactHttpSigningRequest, IdentityHostStatus, LegacyDidWbaRequest, ObjectProofRequest, PreparedHttpSignatureAttempt, PreparedIdentityMaterialImport, PreparedProviderAdoption, PreparedRootImport, ProviderCapability, ProviderDocumentChangeSession, ProviderEnrollmentSession, ProviderLease, ProviderLeaseRequest, RequestSigningEnrollmentRequest, RootPromotionRequest, SealedIdentityImportPreparation, SealedKeyAgreementRequest, SealedProviderAdoptionPreparation, SealedRootExportRequest, SealedRootImportPreparation, SealedSecretDelivery, SealedSecretEnvelope, WrappedRootEnvelope } from '@agent-network-protocol/anp-identity/provider';
import type { DocumentChangeOutcome, DocumentChangeRequest, OriginProofRequest, PublicationAttempt, PublicationResult, SignRequest, Signature, SignedOriginProof, VerifiedRemoteDocument, VerifyRequest } from './types.js';
export type { DeviceEnrollmentRequest, DocumentProofRequest, ExactHttpSigningRequest, IdentityHostStatus, LegacyDidWbaRequest, ObjectProofRequest, PreparedHttpSignatureAttempt, PreparedIdentityMaterialImport, PreparedProviderAdoption, PreparedRootImport, ProviderCapability, ProviderDocumentChangeSession, ProviderEnrollmentSession, ProviderLeaseRequest, RequestSigningEnrollmentRequest, RootPromotionRequest, SealedIdentityImportPreparation, SealedKeyAgreementRequest, SealedProviderAdoptionPreparation, SealedRootExportRequest, SealedRootImportPreparation, SealedSecretDelivery, SealedSecretEnvelope, WrappedRootEnvelope, };
export declare const ANP_IDENTITY_SERVICE_PROTOCOL: "anp-identity-service/1";
export declare const ANP_IDENTITY_PROVIDER_PROTOCOL: "anp-identity-provider-ts/1";
export declare const ANP_IDENTITY_NATIVE_PROVIDER_PROTOCOL: "anp-identity-node-provider/1";
export interface NativeIdentityProvider {
    acquireLease(request: ProviderLeaseRequest): ProviderLease;
}
export interface NativeProviderRegistration {
    readonly protocol: typeof ANP_IDENTITY_NATIVE_PROVIDER_PROTOCOL;
    readonly provider: NativeIdentityProvider;
}
export interface ProviderRequest {
    readonly consumer: string;
    readonly capabilities: ProviderCapability[];
    readonly ttlSeconds?: number;
}
/** Host-only lease. Never expose it through Remote, Browser, tools, or model APIs. */
export interface HostProviderLease {
    readonly protocol: typeof ANP_IDENTITY_PROVIDER_PROTOCOL;
    readonly consumer: string;
    readonly capabilities: readonly ProviderCapability[];
    dispose(): void;
    info(): Promise<StoreInfo>;
    recover(): Promise<RecoveryReport>;
    list(): Promise<IdentityDescriptor[]>;
    publicIdentity(reference: IdentityReference): Promise<PublicIdentity>;
    hostStatus(reference: IdentityReference): Promise<IdentityHostStatus>;
    recoverIdentity(reference: IdentityReference): Promise<void>;
    create(request: CreateIdentityRequest): Promise<PublicIdentity>;
    delete(reference: IdentityReference): Promise<void>;
    sign(reference: IdentityReference, request: SignRequest): Promise<Signature>;
    verify(reference: IdentityReference, request: VerifyRequest): Promise<'valid' | 'invalid'>;
    signOriginProof(reference: IdentityReference, request: OriginProofRequest): Promise<SignedOriginProof>;
    signObjectProof(reference: IdentityReference, request: ObjectProofRequest): Promise<unknown>;
    signDocumentProof(reference: IdentityReference, request: DocumentProofRequest): Promise<unknown>;
    prepareHttpSignature(request: ExactHttpSigningRequest): Promise<PreparedHttpSignatureAttempt>;
    prepareLegacyDidWba(reference: IdentityReference, request: LegacyDidWbaRequest): Promise<string>;
    prepareDocumentChange(reference: IdentityReference, request: DocumentChangeRequest): Promise<ProviderDocumentChangeSession>;
    resumeDocumentChange(reference: IdentityReference): Promise<ProviderDocumentChangeSession | undefined>;
    adoptVerifiedDocument(reference: IdentityReference, remote: VerifiedRemoteDocument): Promise<'activated' | 'updated' | 'unchanged' | 'revoked'>;
    beginDeviceEnrollment(request: DeviceEnrollmentRequest): Promise<ProviderEnrollmentSession>;
    beginRequestSigningEnrollment(request: RequestSigningEnrollmentRequest): Promise<ProviderEnrollmentSession>;
    resumeEnrollment(reference: IdentityReference): Promise<ProviderEnrollmentSession | undefined>;
    importWrappedRoot(reference: IdentityReference, envelope: WrappedRootEnvelope): Promise<'pending' | 'active'>;
    confirmRootPromotion(reference: IdentityReference, request: RootPromotionRequest): Promise<void>;
    signPendingRootObjectProof(reference: IdentityReference, request: ObjectProofRequest): Promise<unknown>;
    ecdhSealed(request: SealedKeyAgreementRequest): Promise<SealedSecretDelivery>;
    exportRootKeySealed(request: SealedRootExportRequest): Promise<SealedSecretDelivery>;
    prepareLegacyRootImport(request: SealedRootImportPreparation): Promise<PreparedRootImport>;
    prepareIdentityMaterialImport(request: SealedIdentityImportPreparation): Promise<PreparedIdentityMaterialImport>;
    prepareProviderAdoption(request: SealedProviderAdoptionPreparation): Promise<PreparedProviderAdoption>;
    grantConsumer(reference: IdentityReference, consumer: string): Promise<void>;
    revokeConsumer(reference: IdentityReference, consumer: string): Promise<void>;
}
export interface AnpIdentityService {
    health(): Promise<import('./types.js').AnpIdentityHealth>;
    acquireClient(input: import('./types.js').ClientRequest): Promise<import('./types.js').IdentityClientLease>;
    acquireProvider(input: ProviderRequest): HostProviderLease;
}
/** Internal registration seam consumed only by the package's `./provider` entry. */
export interface NativeProviderRegistry {
    registerProvider(registration: Promise<NativeProviderRegistration> | NativeProviderRegistration): () => Promise<void>;
}
export interface HostDocumentChangeWire {
    candidate(): Promise<import('./types.js').PreparedDocumentChange>;
    beginPublication(): Promise<PublicationAttempt>;
    complete(attempt: PublicationAttempt, result: PublicationResult): Promise<DocumentChangeOutcome>;
    reconcile(observation: VerifiedRemoteDocument): Promise<DocumentChangeOutcome>;
}

// ===== types.d.ts =====
import type { CreateIdentityRequest as NativeCreateIdentityRequest, DocumentChangeOutcome, DocumentChangeRequest, IdentityDescriptor as NativeIdentityDescriptor, IdentityReference, OriginProofRequest, PreparedDocumentChange, PublicIdentity, PublicationAttempt, PublicationResult, RecoveryReport as NativeRecoveryReport, SignRequest, Signature, SignedOriginProof, VerifiedRemoteDocument, VerifyRequest } from '@agent-network-protocol/anp-identity';
export type { DocumentChangeOutcome, DocumentChangeRequest, IdentityReference, OriginProofRequest, PreparedDocumentChange, PublicIdentity, PublicationAttempt, PublicationResult, SignRequest, Signature, SignedOriginProof, VerifiedRemoteDocument, VerifyRequest, };
export type ClientCapability = 'identity:read' | 'identity:create' | 'identity:sign' | 'identity:document-update' | 'identity:http-auth' | 'identity:delete' | 'identity:recover' | 'identity:handle';
export interface ClientRequest {
    readonly consumer: string;
    readonly capabilities: ClientCapability[];
    /** Exact origins requested from the Host-configured allowlist. */
    readonly httpOrigins?: string[];
    readonly ttlSeconds?: number;
}
export type IdentityRef = IdentityReference | {
    readonly handle: string;
};
export interface ListIdentitiesInput {
    readonly state?: NativeIdentityDescriptor['state'];
}
export interface IdentityDescriptor extends NativeIdentityDescriptor {
    readonly label?: string;
    readonly handle?: string;
    readonly catalogState: 'active' | 'deleting' | 'unclaimed';
}
export interface CreateIdentityRequest {
    readonly identity: NativeCreateIdentityRequest;
    readonly requestId?: string;
    readonly label?: string;
    readonly handle?: string;
}
export interface DeleteIdentityRequest {
    /** Deletion remains forbidden while another consumer grant exists. */
    readonly reason?: string;
}
export interface RecoveryReport extends NativeRecoveryReport {
    readonly catalogRebuilt: boolean;
    readonly unclaimedIdentityCount: number;
}
export interface AnpIdentityHealth {
    readonly status: 'ready' | 'unavailable' | 'degraded';
    readonly protocol: 'anp-identity-service/1';
    readonly providerProtocol?: 'anp-identity-provider-ts/1';
    readonly catalog: 'ready' | 'corrupt' | 'unavailable';
}
export type HttpTransport = (request: Request) => Promise<Response>;
export interface AuthenticatedHttp {
    dispatch(request: Request, transport: HttpTransport): Promise<Response>;
}
export interface DocumentChangeSessionClient {
    candidate(): Promise<PreparedDocumentChange>;
    beginPublication(): Promise<PublicationAttempt>;
    complete(attempt: PublicationAttempt, result: PublicationResult): Promise<DocumentChangeOutcome>;
    reconcile(observation: VerifiedRemoteDocument): Promise<DocumentChangeOutcome>;
}
export interface ManagedIdentityClient {
    publicIdentity(): Promise<PublicIdentity>;
    sign(request: SignRequest): Promise<Signature>;
    signOriginProof(request: OriginProofRequest): Promise<SignedOriginProof>;
    verify(request: VerifyRequest): Promise<'valid' | 'invalid'>;
    readonly authenticatedHttp: AuthenticatedHttp;
    prepareDocumentChange(request: DocumentChangeRequest): Promise<DocumentChangeSessionClient>;
    resumeDocumentChange(): Promise<DocumentChangeSessionClient | undefined>;
}
export interface IdentityClientLease {
    readonly consumer: string;
    readonly capabilities: readonly ClientCapability[];
    list(input?: ListIdentitiesInput): Promise<IdentityDescriptor[]>;
    create(input: CreateIdentityRequest): Promise<ManagedIdentityClient>;
    get(reference: IdentityRef): Promise<ManagedIdentityClient>;
    delete(reference: IdentityRef, input?: DeleteIdentityRequest): Promise<void>;
    recover(): Promise<RecoveryReport>;
    setHandle(reference: IdentityRef, handle: string | null): Promise<void>;
    dispose(): Promise<void>;
}
