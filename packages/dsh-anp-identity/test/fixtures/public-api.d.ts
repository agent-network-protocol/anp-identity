// ===== index.d.ts =====
/** Host-only ANP Identity service for DeepSeek Harness. */
import { Service, type Context } from '@deepseek-ai/cordis';
import z from '@deepseek-ai/schemastery';
import type { UserIdentityClient } from './user-client.js';
import type { IdentityManagement } from './management-types.js';
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
    /** Installed plugin identifiers requiring explicit user decisions instead of legacy access. */
    readonly userConsumers?: string[];
}
export declare const Config: z<Config>;
/** One multi-DID ANP Identity service with a replaceable native Provider. */
export declare class AnpIdentityService extends Service implements AnpIdentityServiceContract {
    static Config: z<Config>;
    private readonly resolvedConfig;
    private readonly catalogStore;
    private providerSlot;
    private readonly users;
    private readonly hostContext;
    private readonly disabledFences;
    private readonly lifecycleWrites;
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
    private assertHostTransitionAccess;
    private grantConsumer;
    private revokeConsumer;
    private createForHost;
    private deleteForHost;
    private createNativeWithRecovery;
    private removeLease;
    private initializeSlot;
    private reconcile;
    private resolveAuthorized;
    private loadCatalog;
    private assertAllowedConsumer;
    private requireSlot;
    private assertSlot;
    private awaitProvider;
    /** Host-bound ordinary facade; request inputs never select a caller. */
    bindUserConsumer(context: Context): UserIdentityClient;
    /** Host-only manager; the ordinary consumer facade never exposes this object. */
    acquireManagement(): IdentityManagement;
    private assertNoHostAssociations;
    private managementIdentities;
    private installedEntries;
    private resolveInstalledCaller;
    private assertInstalledCaller;
    private cancelDisabledRequests;
    private assertLegacyConsumer;
    private assertLegacyCallerContext;
    private withUserNative;
    private userSnapshot;
    private createConfirmed;
    private reconcileConfirmed;
    private recoverConfirmedIntent;
    private assertNoUnresolvedUserCreate;
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
import type { Context } from '@deepseek-ai/cordis';
import type { UserIdentityClient } from './user-client.js';
import type { CreateIdentityRequest, IdentityDescriptor, IdentityReference, IdentityTransitionRequest, PublicIdentity, RecoveryReport, StoreInfo } from '@agent-network-protocol/anp-identity';
import type { DeviceEnrollmentRequest, DocumentProofRequest, ExactHttpSigningRequest, IdentityHostStatus, LegacyDidWbaRequest, ObjectProofRequest, PreparedHttpSignatureAttempt, PreparedIdentityMaterialImport, PreparedRootImport, ProviderCapability, ProviderDocumentChangeSession, ProviderEnrollmentSession, ProviderIdentityTransitionSession, ProviderLease, ProviderLeaseRequest, RequestSigningEnrollmentRequest, RootPromotionRequest, SealedIdentityImportPreparation, SealedKeyAgreementRequest, SealedRootExportRequest, SealedRootImportPreparation, SealedSecretDelivery, SealedSecretEnvelope, WrappedRootEnvelope } from '@agent-network-protocol/anp-identity/provider';
import type { DocumentChangeOutcome, DocumentChangeRequest, OriginProofRequest, PublicationAttempt, PublicationResult, SignRequest, Signature, SignedOriginProof, VerifiedRemoteDocument, VerifyRequest } from './types.js';
export type { DeviceEnrollmentRequest, DocumentProofRequest, ExactHttpSigningRequest, IdentityHostStatus, LegacyDidWbaRequest, ObjectProofRequest, PreparedHttpSignatureAttempt, PreparedIdentityMaterialImport, PreparedRootImport, ProviderCapability, ProviderDocumentChangeSession, ProviderEnrollmentSession, ProviderIdentityTransitionSession, ProviderLeaseRequest, RequestSigningEnrollmentRequest, RootPromotionRequest, SealedIdentityImportPreparation, SealedKeyAgreementRequest, SealedRootExportRequest, SealedRootImportPreparation, SealedSecretDelivery, SealedSecretEnvelope, WrappedRootEnvelope, };
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
    prepareIdentityTransition(request: IdentityTransitionRequest): Promise<ProviderIdentityTransitionSession>;
    resumeIdentityTransition(expectedCurrentDid: string): Promise<ProviderIdentityTransitionSession | undefined>;
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
    grantConsumer(reference: IdentityReference, consumer: string): Promise<void>;
    revokeConsumer(reference: IdentityReference, consumer: string): Promise<void>;
}
export interface AnpIdentityService {
    bindUserConsumer(context: Context): UserIdentityClient;
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

// ===== user-client.d.ts =====
import type { Context } from '@deepseek-ai/cordis';
import type { PublicIdentity, SignRequest, Signature, IdentityReference } from './types.js';
import type { AuthorizationRequest, AuthorizationExecution, RequestCreateInput } from './authorization-types.js';
/** Raw operation input. The Host computes the fingerprint; consumers cannot supply one. */
export type UserOperation = {
    readonly action: 'read';
} | {
    readonly action: 'sign';
    readonly request: SignRequest;
} | {
    readonly action: 'http';
    readonly request: Request;
};
export interface UserAccessRequest {
    readonly requestId: string;
    readonly purpose: string;
    readonly identity?: IdentityReference;
    readonly operation?: UserOperation;
}
/** A caller- and identity-bound object with no management or Provider methods. */
export interface AuthorizedIdentity {
    publicIdentity(executionId?: string): Promise<PublicIdentity>;
    sign(request: SignRequest, executionId?: string): Promise<Signature>;
    readonly authenticatedHttp: {
        dispatch(request: Request, executionId?: string): Promise<Response>;
    };
}
export interface UserIdentityClient {
    requestCreateIdentity(input: RequestCreateInput): Promise<AuthorizationRequest>;
    getCreateRequest(requestId: string): Promise<AuthorizationRequest>;
    cancelCreateRequest(requestId: string, expectedVersion: number): Promise<AuthorizationRequest>;
    requestAccess(input: UserAccessRequest): Promise<AuthorizationRequest>;
    getAccessRequest(requestId: string): Promise<AuthorizationRequest>;
    cancelAccessRequest(requestId: string, expectedVersion: number): Promise<AuthorizationRequest>;
    openAuthorizedIdentity(grantId: string): Promise<AuthorizedIdentity>;
    getExecution(executionId: string): Promise<AuthorizationExecution>;
    subscribeRequestChanges(listener: () => void): () => void;
}
/** Bind using the installed Cordis context, never a consumer string from a request. */
export declare function bindIdentityClient(ctx: Context): UserIdentityClient;

// ===== authorization-types.d.ts =====
import type { IdentityReference } from '@agent-network-protocol/anp-identity';
/** Only the Host may construct this from the installed plugin context. */
export interface VerifiedCaller {
    readonly consumer: string;
    readonly displayName: string;
}
export type OrdinaryCapability = 'identity:read' | 'identity:sign' | 'identity:http-auth';
export interface CapabilitySnapshot {
    readonly version: string;
    readonly capabilities: readonly OrdinaryCapability[];
    readonly signingPurposes: readonly string[];
    readonly httpOrigins: readonly string[];
}
export type AuthorizationMode = 'once' | 'permanent';
export type RequestStatus = 'pending' | 'approved' | 'denied' | 'cancelled' | 'expired';
export interface ControlledOperation {
    readonly capability: OrdinaryCapability;
    readonly fingerprint: string;
    /** Host-produced safe summary, never a signature payload or HTTP body. */
    readonly summary: string;
    readonly signingPurpose?: string;
    readonly httpOrigin?: string;
}
export interface CreateParameters {
    readonly label: string;
    readonly domain: string;
    readonly path: string;
}
export interface CreateResult {
    readonly reference: IdentityReference;
    readonly label: string;
}
interface RequestBase {
    readonly id: string;
    readonly caller: VerifiedCaller;
    readonly purpose: string;
    readonly version: number;
    readonly status: RequestStatus;
    readonly createdAt: number;
    readonly expiresAt: number;
    readonly fingerprint: string;
    readonly prompted: boolean;
    readonly decidedAt?: number;
    readonly retryOf?: string;
}
export interface CreateAuthorizationRequest extends RequestBase {
    readonly kind: 'create';
    readonly parameters: CreateParameters;
    readonly operationId?: string;
    readonly executionStatus?: 'running' | 'succeeded' | 'unknown' | 'deleted';
    readonly result?: CreateResult;
}
export interface AccessAuthorizationRequest extends RequestBase {
    readonly kind: 'access';
    readonly identity?: IdentityReference;
    readonly operation?: ControlledOperation;
    readonly mode?: AuthorizationMode;
    readonly grantId?: string;
}
export type AuthorizationRequest = CreateAuthorizationRequest | AccessAuthorizationRequest;
export interface AuthorizationGrant {
    readonly id: string;
    readonly requestId: string;
    readonly caller: VerifiedCaller;
    readonly identity: IdentityReference;
    readonly snapshot: CapabilitySnapshot;
    readonly mode: AuthorizationMode;
    readonly version: number;
    readonly approvedAt: number;
    readonly status: 'active' | 'consumed' | 'revoked' | 'expired';
    readonly expiresAt?: number;
    readonly operation?: ControlledOperation;
    readonly executionId?: string;
    readonly revokedAt?: number;
}
export interface AuthorizedLease {
    readonly grantId: string;
    readonly consumer: string;
    readonly identity: IdentityReference;
    readonly grantVersion: number;
    readonly expiresAt: number;
}
export interface AuthorizationExecution {
    readonly id: string;
    readonly grantId: string;
    readonly consumer: string;
    readonly fingerprint: string;
    readonly admittedAt: number;
    readonly grantVersion: number;
    readonly operation: ControlledOperation;
    readonly status: 'admitted' | 'succeeded' | 'failed' | 'unknown';
    readonly finishedAt?: number;
}
export interface AuthorizationState {
    readonly schema: 'anp-identity-authorization/1';
    generation: number;
    requests: AuthorizationRequest[];
    grants: AuthorizationGrant[];
    executions: AuthorizationExecution[];
    deletedIdentities: IdentityReference[];
    deletingIdentities: IdentityReference[];
    suppressions: {
        consumer: string;
        kind: 'create' | 'access';
        identity?: IdentityReference;
        requestId: string;
    }[];
}
export interface RequestCreateInput {
    readonly requestId: string;
    readonly purpose: string;
    readonly parameters: CreateParameters;
}
export interface RequestAccessInput {
    readonly requestId: string;
    readonly purpose: string;
    readonly identity?: IdentityReference;
    readonly operation?: ControlledOperation;
}
export interface AuthorizationDecision {
    readonly requestId: string;
    readonly expectedVersion: number;
    readonly decision: 'approve' | 'deny';
    readonly identity?: IdentityReference;
    readonly mode?: AuthorizationMode;
    /** Exact scope shown for the selected identity; access approvals must echo it. */
    readonly reviewedSnapshot?: CapabilitySnapshot;
}
export interface DeletionReconciliation {
    /** Host-sourced durable catalog deletion fences, never arbitrary missing identities. */
    readonly catalogFences: readonly IdentityReference[];
    /** Must positively verify this exact reference is absent from both native storage and catalog. */
    readonly isAbsent: (reference: IdentityReference) => Promise<boolean>;
}
export interface AuthorizationOptions {
    readonly validateCaller: (caller: VerifiedCaller) => Promise<void>;
    readonly resolveSnapshot: (caller: VerifiedCaller, identity: IdentityReference) => Promise<CapabilitySnapshot>;
    /** Must use the native durable create journal and never implicitly grant use. */
    readonly createIdentity: (operationId: string, caller: VerifiedCaller, parameters: CreateParameters) => Promise<CreateResult>;
    /** Only recover an existing operation; undefined must not trigger creation. */
    readonly reconcileCreation?: (operationId: string, caller: VerifiedCaller, parameters: CreateParameters) => Promise<CreateResult | undefined>;
    readonly now?: () => number;
    readonly requestTtlMs?: number;
    readonly onceTtlMs?: number;
    readonly leaseTtlMs?: number;
    readonly fault?: (point: 'before_rename' | 'after_rename') => void;
}
export {};

// ===== management-types.d.ts =====
import type { IdentityReference } from "@agent-network-protocol/anp-identity";
import type { AuthorizationDecision, AuthorizationGrant, AuthorizationRequest, CapabilitySnapshot } from "./authorization-types.js";
import type { IdentityDescriptor } from "./types.js";
/** Public manager presentation. This never carries a native lease or credentials. */
export interface ManagedIdentitySummary extends IdentityDescriptor {
    readonly integrations: readonly {
        readonly consumer: string;
        readonly displayName: string;
        readonly kind: "legacy" | "provider";
    }[];
    readonly deleteBlockedReason?: string;
}
export interface RequestReview {
    readonly request: AuthorizationRequest;
    readonly grant?: AuthorizationGrant;
    readonly identities: readonly ManagedIdentitySummary[];
    readonly snapshot?: CapabilitySnapshot;
    readonly permanentIdentities?: readonly IdentityReference[];
    readonly snapshots?: readonly {
        readonly identity: IdentityReference;
        readonly snapshot: CapabilitySnapshot;
    }[];
    readonly unavailableReason?: string;
}
export interface RequestVersion {
    readonly requestId: string;
    readonly expectedVersion: number;
}
export interface RevokeGrantInput {
    readonly grantId: string;
    readonly expectedVersion: number;
}
export interface DeleteManagedIdentityInput {
    readonly reference: IdentityReference;
    readonly confirmationName: string;
}
/** Host-only manager capability. Ordinary consumer facades must not return this object. */
export interface IdentityManagement {
    listIdentities(): Promise<ManagedIdentitySummary[]>;
    listRequests(history?: boolean): Promise<AuthorizationRequest[]>;
    getRequest(requestId: string): Promise<RequestReview>;
    decide(input: AuthorizationDecision): Promise<AuthorizationRequest>;
    grants(reference: IdentityReference): Promise<AuthorizationGrant[]>;
    revoke(input: RevokeGrantInput): Promise<void>;
    publicDocument(reference: IdentityReference): Promise<unknown>;
    deleteIdentity(input: DeleteManagedIdentityInput): Promise<void>;
    markPrompted(input: RequestVersion): Promise<void>;
    reauthorize(input: RequestVersion): Promise<AuthorizationRequest>;
}

// ===== management-remote.d.ts =====
/** Optional Host manager boundary. Never expose this service to consumer leases. */
import type { Context } from "@deepseek-ai/cordis";
import { TypertRemoteService } from "@deepseek-ai/dsh-typert-protocol";
import type { IdentityReference } from "@agent-network-protocol/anp-identity";
import type { AuthorizationDecision } from "./authorization-types.js";
import type { RequestVersion, RevokeGrantInput, DeleteManagedIdentityInput } from "./management-types.js";
export declare class IdentityManagerRemote extends TypertRemoteService {
    static inject: string[];
    private readonly manager;
    constructor(ctx: Context);
    listIdentities(): Promise<import("./management-types.js").ManagedIdentitySummary[]>;
    listRequests(input?: boolean): Promise<import("./authorization-types.js").AuthorizationRequest[]>;
    getRequest(input: string): Promise<import("./management-types.js").RequestReview>;
    decide(input: AuthorizationDecision): Promise<import("./authorization-types.js").AuthorizationRequest>;
    grants(input: IdentityReference): Promise<import("./authorization-types.js").AuthorizationGrant[]>;
    revoke(input: RevokeGrantInput): Promise<null>;
    publicDocument(input: IdentityReference): Promise<unknown>;
    deleteIdentity(input: DeleteManagedIdentityInput): Promise<null>;
    markPrompted(input: RequestVersion): Promise<null>;
    reauthorize(input: RequestVersion): Promise<import("./authorization-types.js").AuthorizationRequest>;
}
export default IdentityManagerRemote;

// ===== remote.d.ts =====
import type { TypertRemoteContribution } from "@deepseek-ai/dsh-typert-protocol";
declare const contribution: TypertRemoteContribution;
export default contribution;

// ===== client/index.d.ts =====
import type { Context as ClientContext } from "@deepseek-ai/cordis";
import { IdentityController } from "./controller.js";
import { IdentityOverlay, IdentitySettings } from "./views.js";
export declare const inject: string[];
export declare function apply(ctx: ClientContext): Promise<() => Promise<void>>;
export { IdentityController, IdentitySettings, IdentityOverlay };
