// ===== index.d.ts =====
import { type DefaultIdentitySettings, type UpdateDefaultIdentity } from './default-identity-types.js';
import { type ProtocolPolicyClient } from './protocol-policy.js';
import { type ManagedProtocol, type UpdateProtocolPolicy, type ProtocolManagementState } from './protocol-policy-types.js';
import type { RegistrationServiceSettings, UpdateRegistrationServiceSettings } from './registration-service-types.js';
import type { PapCallbackManagementOperations } from './pap-callback.js';
import { type RegistrationInspection, type ManagementCredentialBroker, type LocalRegistrationInput } from './management-driver.js';
import { type DomainAccessConfig, type DomainProfile, type DomainBinding } from './domain-access.js';
import { type AnpDomainReadClient } from './anp-domain.js';
import { type DomainOperationClient } from './domain-consent.js';
import type { ProtocolUsePolicy, ProtocolIdentityClient, PapHostConsumer } from './protocol-client.js';
import type { PublicationBackend } from './publication-types.js';
import { Service, type Context } from '@deepseek-ai/cordis';
import z from '@deepseek-ai/schemastery';
import type { IdentityReference } from '@agent-network-protocol/anp-identity';
import type { UserIdentityClient } from './user-client.js';
import type { IdentityManagement } from './management-types.js';
import { type AnpIdentityService as AnpIdentityServiceContract, type HostProviderLease, type ProviderRequest } from './provider-api.js';
import type { AnpIdentityHealth, ClientRequest, IdentityClientLease } from './types.js';
export type * from './types.js';
export type { DomainAccessConfig, DomainProfile, DomainBinding } from './domain-access.js';
export type { AnpReadEvidence, AnpDomainReadClient } from './anp-domain.js';
export type { DomainOperationClient, DomainConsentCapabilities, DomainMachineIdentity } from './domain-consent.js';
export type { ProtocolPolicyClient, ProtocolTarget, ProtocolAdmission, ProtocolTargetEvidence, ProtocolOperationEvidence } from './protocol-policy.js';
export type { ManagedProtocol, ProtocolEffect, ProtocolDecision, ProtocolPolicy, ProtocolPolicyInput, UpdateProtocolPolicy, ProtocolManagementState, ProtocolClassification, HttpEffectEvidence } from './protocol-policy-types.js';
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
    readonly signerMode?: 'local';
    /** Absolute ANP Identity Store root. Defaults below DSH_HOME. */
    readonly stateRoot?: string;
    /** Exact same-process consumer names permitted to acquire leases. */
    readonly allowConsumers?: string[];
    /** Narrow Host-only consumers permitted to acquire Provider leases. */
    readonly allowProviderConsumers?: string[];
    /** HTTPS origins per consumer; explicit User consumers may opt into '*' with user approval. */
    readonly httpAllowedOrigins?: Record<string, string[]>;
    /** Run native Store recovery when a Provider opens. */
    readonly recoveryOnOpen?: boolean;
    /** Installed plugin identifiers requiring explicit user decisions instead of legacy access. */
    readonly oauthAllowedAudiences?: Record<string, string[]>;
    readonly userConsumers?: string[];
    readonly protocolPolicies?: ProtocolUsePolicy[];
    /** Explicit global domain-access opt-in; no per-domain policies are created by the model. */
    readonly domainAccess?: DomainAccessConfig;
}
export declare const Config: z<Config>;
/** One multi-DID ANP Identity service with a replaceable native Provider. */
export declare class AnpIdentityService extends Service implements AnpIdentityServiceContract {
    static Config: z<Config>;
    private readonly resolvedConfig;
    private readonly registrationSettings;
    private readonly protocolSettings;
    private readonly defaultIdentitySettings;
    private readonly protocolAdapters;
    private readonly catalogStore;
    private providerSlot;
    private readonly publications;
    private readonly publicationBackends;
    private readonly papCallbackAuthorities;
    private readonly protocols;
    private readonly domains;
    private readonly anpReads;
    private readonly anpDomainMode;
    private readonly domainExpiresAt;
    private readonly domainOperations;
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
    bindProtocolConsumer(context: Context): ProtocolIdentityClient;
    /** Bind the installed ANP adapter to exact discovered reads under global Host permission. */
    bindAnpDomainConsumer(context: Context): AnpDomainReadClient;
    /** Bind exact, once-only owner confirmation for the installed PAP/MCP domain adapters. */
    bindDomainOperationConsumer(context: Context): DomainOperationClient;
    /** Installed adapters classify discovered operations; ordinary tools cannot bind or edit owner settings. */
    bindProtocolPolicy(context: Context, protocol: ManagedProtocol): ProtocolPolicyClient;
    /** Resolve a Host-approved default identity and global policy for an installed domain adapter.
     * @param context - Actual Loader-owned adapter context.
     * @param profile - Protocol to connect; PAP account access is intentionally excluded.
     * @returns Non-secret identity, policy and local storage references.
     */
    resolveDomainAccess(context: Context, profile: DomainProfile): Promise<DomainBinding>;
    /** Public discovery never signs or obtains a user identity.
     * @param request - Public HTTPS request, pinned against private DNS destinations.
     * @returns Unauthenticated response without redirect following.
     */
    publicDiscovery(request: Request): Promise<Response>;
    /** Bind the actual installed PAP Host. Private callback access additionally requires its current opaque target.
     * @param context - Original Loader-installed PAP plugin Context.
     * @returns Public identity selection and target-bound, closed callback operations.
     */
    bindPapHostConsumer(context: Context): PapHostConsumer;
    /** Install a real device-authorized backend; the document id comes from authenticated resolve. */
    configureManagedPublicationBackend(context: Context, name: string, input: {
        reference: IdentityReference;
        origin: string;
        credentials: ManagementCredentialBroker;
        fetch?: typeof fetch;
    }): Promise<{
        backend: string;
        documentId: string;
        callbackManagement: PapCallbackManagementOperations;
        dispose: () => void;
    }>;
    /** Register the public local Manifest through User Service and persist its verified management credential. */
    registerLocalIdentity(context: Context, input: {
        reference: IdentityReference;
        origin: string;
        credentials: ManagementCredentialBroker;
        registration: LocalRegistrationInput;
        managementAudience?: string;
        handleDomain?: string;
        fetch?: typeof fetch;
        /** Optional tighter Host lifecycle fence, never a source of management authority. */
        assertActive?: () => void;
    }): Promise<{
        did: string;
        deviceId: string;
        state: 'registered';
    }>;
    /** Read-only diagnosis for the pinned owner registration; this cannot finalize or replay it. */
    inspectLocalRegistration(context: Context, input: {
        reference: IdentityReference;
        origin: string;
        fetch?: typeof fetch;
        assertActive?: () => void;
    }): Promise<RegistrationInspection>;
    /** Private owner storage path, never exposed through a Remote or model tool. */
    registrationBootstrapRoot(context: Context): string;
    /** Manager-only registration preferences; ordinary consumer capabilities never expose these methods. */
    registrationServiceSettings(context: Context): Promise<RegistrationServiceSettings>;
    configureRegistrationService(context: Context, input: UpdateRegistrationServiceSettings, additionalCheck?: () => void): Promise<RegistrationServiceSettings>;
    /** The saved default is shared by all domain adapters, not the manager's selected display row. */
    defaultIdentity(context: Context): Promise<DefaultIdentitySettings>;
    configureDefaultIdentity(context: Context, raw: UpdateDefaultIdentity, additionalCheck?: () => void): Promise<DefaultIdentitySettings>;
    /** Owner-only settings. Binding a policy client never grants access to this mutation surface. */
    protocolManagement(context: Context): Promise<ProtocolManagementState>;
    configureProtocolPolicy(context: Context, input: UpdateProtocolPolicy, additionalCheck?: () => void): Promise<import('./protocol-policy-types.js').ProtocolPolicy>;
    resolveRegistrationServiceOrigin(context: Context, key: string, fingerprint: string): Promise<string>;
    /** Pin the actual ready provider for an approved local identity and the original manager Context.
     * @param context - Original root-installed manager Context.
     * @param reference - Local identity whose current provider is being pinned.
     * @param additionalCheck - Optional stricter Host lifecycle check.
     * @returns A synchronous fence that never switches to a replacement provider.
     */
    pinManagementContext(context: Context, reference: IdentityReference, additionalCheck?: () => void): Promise<() => void>;
    /** Host-only manager; the ordinary consumer facade never exposes this object. */
    registerPublicationBackend(context: Context, name: string, backend: PublicationBackend): () => void;
    private assertManagementContext;
    acquireManagement(context?: Context, additionalCheck?: () => void): IdentityManagement;
    private assertNoHostAssociations;
    private managementIdentities;
    private installedEntries;
    private resolveInstalledCaller;
    private assertInstalledCaller;
    private cancelDisabledRequests;
    private assertLegacyConsumer;
    private assertLegacyCallerContext;
    private withUserNative;
    private withProtocolNative;
    private withPublicationNative;
    private userSnapshot;
    private createConfirmed;
    private reconcileConfirmed;
    private recoverConfirmedIntent;
    private assertNoUnresolvedUserCreate;
    private disposeSlot;
}
export default AnpIdentityService;
export { createPublicationBackend } from './publication-http.js';
export type { PublicationConfig, PublicationBackend, OAuthClientIdentity } from './publication-types.js';
export { EncryptedManagementCredentialBroker } from './management-credentials.js';
export { createManagedPublicationDriver, registerLocalIdentity } from './management-driver.js';
export type { ManagementCredentialBroker, DeviceManagementCredential, LocalRegistrationInput } from './management-driver.js';
export type { PapHostConsumer } from './protocol-client.js';
export { PapCallbackManagementError } from './pap-callback.js';
export type { PapCallbackRegistration, PapCallbackClaim, PapCallbackRegistrationResult, PapCallbackClaimResult, PapCallbackRegisterOperation, PapCallbackClaimOperation, PapCallbackManagementOperations, PapCallbackManagementErrorCode } from './pap-callback.js';

// ===== domain-access.d.ts =====
import type { IdentityReference } from './types.js';
import type { ProtocolUsePolicy } from './protocol-client.js';
export type DomainProfile = 'anp' | 'pap_session' | 'mcp_machine';
export interface DomainAccessConfig {
    enabled: boolean;
    identity?: IdentityReference;
    /** Legacy persistent-read scope set. Additional discovered scopes require the shared owner policy or exact consent. */
    scopes: string[];
    secretStore?: 'keyring' | 'local-file';
    expiresAt?: number;
    /** Signed ANP transport deadline, separate from the owner's confirmation wait. */
    requestTimeoutMs?: number;
}
export interface DomainBinding {
    identityRef: IdentityReference;
    policyRef: string;
    stateRoot: string;
    secretsRoot: string;
    secretStore: 'keyring' | 'local-file';
    scopes: string[];
}
export declare class DomainAccessError extends Error {
    readonly code: string;
    constructor(code: string);
}
/** Resolve only locally published identities and install a Host-owned global policy. */
export declare class DomainAccessResolver {
    private readonly config;
    private readonly root;
    private readonly candidates;
    private readonly install;
    private readonly selection?;
    constructor(config: DomainAccessConfig | undefined, root: string, candidates: (profile: DomainProfile) => Promise<IdentityReference[]>, install: (policy: ProtocolUsePolicy) => void, selection?: (() => Promise<{
        identity: IdentityReference | null;
        version: number;
    }>) | undefined);
    resolve(consumer: string, profile: DomainProfile): Promise<DomainBinding>;
}

// ===== anp-domain.d.ts =====
/** Exact HTTP reads under the Host's global domain-access policy. */
import type { Context } from '@deepseek-ai/cordis';
import type { ProviderLease } from '@agent-network-protocol/anp-identity/provider';
import type { DomainBinding } from './domain-access.js';
import type { ProtocolPolicyClient } from './protocol-policy.js';
import { type HttpEffectEvidence, type ProtocolDecision } from './protocol-policy-types.js';
/** Produced only by the installed discovery adapter, never by model arguments. */
export interface AnpReadEvidence {
    profile: 'anp-discovered/1';
    kind: 'agent' | 'information' | 'interface' | 'operation';
    source: string;
    url: string;
    requiresApproval: boolean;
    discoveryOrigin?: string;
    policyEvidence?: Omit<HttpEffectEvidence, 'method'>;
}
export interface AnpOperationAdmission {
    decision: ProtocolDecision;
    version: number;
}
export interface AnpDomainReadClient {
    dispatchRead(request: Request, evidence: AnpReadEvidence): Promise<Response>;
    prepareOperation(request: Request, evidence: AnpReadEvidence): Promise<AnpOperationAdmission>;
    dispatchOperation(request: Request, evidence: AnpReadEvidence, admission: {
        policyVersion: number;
        grantId?: string;
    }): Promise<Response>;
}
export interface AnpDomainReadHost {
    assertCaller(context: Context): void;
    generation(): unknown;
    resolve(context: Context): Promise<DomainBinding>;
    withNative<T>(operation: (native: ProviderLease) => Promise<T>): Promise<T>;
    dispatch(request: Request, assertBeforeSend: () => Promise<void>, onSend: () => void): Promise<Response>;
    policy(context: Context): ProtocolPolicyClient;
    runApproved<T>(context: Context, grantId: string, request: Request, identity: DomainBinding['identityRef'], effect: (check: () => Promise<void>) => Promise<T>): Promise<T>;
}
/** No raw signature, generic write permission, or caller-provided transport is exposed. */
export declare class AnpDomainReadAuthority {
    private readonly host;
    constructor(host: AnpDomainReadHost);
    bind(context: Context): AnpDomainReadClient;
}

// ===== domain-consent.d.ts =====
/** One owner-approved effect, distinct from global protocol read permission. */
import type { Context } from '@deepseek-ai/cordis';
import type { AccessAuthorizationRequest } from './authorization-types.js';
import type { DomainBinding } from './domain-access.js';
import type { UserIdentityClient } from './user-client.js';
import type { ProtocolIdentityClient, ProtocolSignerLease, ProtocolUsePolicy } from './protocol-client.js';
import type { ProtocolPolicyClient, ProtocolTarget } from './protocol-policy.js';
export declare class DomainConsentError extends Error {
    readonly code: string;
    constructor(code: string);
}
export interface DomainMachineSigner {
    readonly targetRef: object;
    readonly policyGeneration: number;
    assertActive(): Promise<void>;
    getOAuthClientIdentity(): ReturnType<ProtocolSignerLease['getOAuthClientIdentity']>;
    signOAuthClientAssertion(targetRef: object): Promise<string>;
    dispose(): void;
}
export interface DomainMachineIdentity {
    registerValidatedTarget(input: Parameters<ProtocolIdentityClient['registerValidatedTarget']>[0]): Promise<DomainMachineSigner>;
}
export interface DomainConsentCapabilities {
    machineIdentity?: DomainMachineIdentity;
}
export interface DomainOperationClient {
    request(input: {
        requestId: string;
        purpose: string;
        request: Request;
    }): Promise<AccessAuthorizationRequest>;
    status(id: string): Promise<AccessAuthorizationRequest>;
    cancel(id: string, version: number): Promise<AccessAuthorizationRequest>;
    execute<T>(grantId: string, request: Request, effect: (assertActive: () => Promise<void>, capabilities: DomainConsentCapabilities) => Promise<T>): Promise<T>;
    executeAllowed<T>(request: Request, authorization: {
        target: ProtocolTarget;
        policyVersion: number;
        annotations?: unknown;
        metadataOnly: boolean;
    }, effect: (assertActive: () => Promise<void>, capabilities: DomainConsentCapabilities) => Promise<T>): Promise<T>;
}
export interface DomainConsentHost {
    assertCaller(context: Context): string;
    resolve(context: Context): Promise<DomainBinding>;
    user(context: Context): UserIdentityClient;
    run<T>(context: Context, grantId: string, request: Request, identity: DomainBinding['identityRef'], effect: (assertActive: () => Promise<void>) => Promise<T>): Promise<T>;
    protocol(context: Context): ProtocolIdentityClient;
    install(policy: ProtocolUsePolicy): void;
    retire(id: string): void;
    policy(context: Context): ProtocolPolicyClient;
}
/** Only the installed adapters may bind this facade; model tools never receive it. */
export declare class DomainOperationAuthority {
    private readonly host;
    constructor(host: DomainConsentHost);
    bind(context: Context): DomainOperationClient;
}

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
import type { OAuthPublicJwk, OAuthClientAssertionRequest, CreateIdentityRequest, IdentityDescriptor, IdentityReference, IdentityTransitionRequest, PublicIdentity, RecoveryReport, StoreInfo } from '@agent-network-protocol/anp-identity';
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
    /** Version-1 wire fields; backend availability is checked before this projection. */
    info(): Promise<Pick<StoreInfo, 'storeId' | 'schemaCompatible' | 'identityCount' | 'health'>>;
    recover(): Promise<RecoveryReport>;
    list(): Promise<IdentityDescriptor[]>;
    publicIdentity(reference: IdentityReference): Promise<PublicIdentity>;
    hostStatus(reference: IdentityReference): Promise<IdentityHostStatus>;
    recoverIdentity(reference: IdentityReference): Promise<void>;
    create(request: CreateIdentityRequest): Promise<PublicIdentity>;
    delete(reference: IdentityReference): Promise<void>;
    oauthPublicJwk(reference: IdentityReference, kid?: string): Promise<OAuthPublicJwk>;
    signOAuthClientAssertion(reference: IdentityReference, request: OAuthClientAssertionRequest): Promise<string>;
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
    adoptVerifiedSiblingDocument(reference: IdentityReference, remote: VerifiedRemoteDocument): Promise<'activated' | 'updated' | 'unchanged' | 'revoked'>;
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
    bindProtocolConsumer(context: Context): import('./protocol-client.js').ProtocolIdentityClient;
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
import type { OAuthClientIdentity } from './publication-types.js';
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
} | {
    readonly action: 'oauth';
    readonly audience: string;
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
    oauthClientIdentity(executionId?: string): Promise<OAuthClientIdentity>;
    signOAuthClientAssertion(audience: string, executionId?: string): Promise<string>;
    sign(request: SignRequest, executionId?: string): Promise<Signature>;
    readonly authenticatedHttp: {
        dispatch(request: Request, executionId?: string): Promise<Response>;
    };
}
export interface UserIdentityClient {
    /** Reuse only an active permanent grant already covering this exact caller, identity and operation. */
    findAccessGrant?(input: {
        identity: IdentityReference;
        operation: UserOperation;
    }): Promise<string | undefined>;
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

// ===== protocol-client.d.ts =====
/** Host-only protocol identity leases. These objects never cross Remote or tool APIs. */
import type { Context } from '@deepseek-ai/cordis';
import type { IdentityReference } from '@agent-network-protocol/anp-identity';
import type { PapCallbackManagementOperations } from './pap-callback.js';
/** Installed PAP Host capability. Callback operations additionally require a current opaque C target. */
export interface PapHostConsumer {
    resolveBinding(identityRef: IdentityReference, policyRef: string, profile: 'pap_session' | 'pap_account'): Promise<{
        binding: {
            identityRef: IdentityReference;
            ownerRef: string;
            clientId: string;
        };
        redirectUri?: string;
    }>;
    callbackManagementFor(input: {
        identityRef: IdentityReference;
        policyRef: string;
        targetRef: object;
    }): Promise<PapCallbackManagementOperations & {
        dispose(): void;
    }>;
    assertActive(): Promise<void>;
    dispose(): void;
}
export interface ValidatedTargetEvidence {
    profile: 'mcp_machine' | 'pap_session' | 'pap_account';
    issuer: string;
    resource: string;
    tokenEndpoint?: string;
    companyId?: string;
    allowedEndpoints?: string[];
    revocationEndpoint?: string;
    metadataDigest: string;
    expiresAt: number;
    sources: {
        resource: string;
        authorizationServer: string;
    };
}
/** Explicit Host configuration is the management approval; updates reload and revoke old leases. */
export interface ProtocolUsePolicy {
    id: string;
    version: number;
    consumer: string;
    identity: IdentityReference;
    owner: string;
    profiles: ValidatedTargetEvidence['profile'][];
    issuers: string[];
    resources: string[];
    publicTargets: boolean;
    scopes: string[];
    expiresAt: number;
}
export interface ProtocolKeyReference {
    readonly handle: string;
    readonly keyRef: object;
    readonly purpose: 'pap_session' | 'pap_dpop';
    readonly generation: number;
    readonly publicJwk: {
        kty: 'EC';
        crv: 'P-256';
        x: string;
        y: string;
    };
    readonly thumbprint: string;
}
export interface PapSessionSigningInput {
    keyRef: object;
    delegation: string;
    clientId: string;
    sid: string;
    sub: string;
    agentId?: string;
    httpMethod: string;
    httpUri: string;
    accessToken?: string;
}
export interface DpopSigningInput {
    keyRef: object;
    httpMethod: string;
    httpUri: string;
    accessToken?: string;
    nonce?: string;
}
export interface ProtocolSignerLease {
    readonly targetRef: object;
    readonly policyGeneration: number;
    getOAuthClientIdentity(): Promise<{
        clientId: string;
        keyId: string;
        algorithm: 'ES256';
        version: number;
        signerMode: 'local';
        publicJwk: {
            kty: 'EC';
            crv: 'P-256';
            x: string;
            y: string;
        };
        redirectUris: string[];
    }>;
    assertActive(): Promise<void>;
    signOAuthClientAssertion(targetRef: object): Promise<string>;
    bindPapScope(input: {
        userId: string;
        accountSlot?: string;
    }): object;
    restorePapKey(scopeRef: object, input: {
        handle: string;
        generation: number;
        purpose: 'pap_session' | 'pap_dpop';
    }): Promise<ProtocolKeyReference>;
    createDelegatedKey(scopeRef: object, operationId: string): Promise<ProtocolKeyReference>;
    createDpopKey(scopeRef: object, operationId: string): Promise<ProtocolKeyReference>;
    issuePapDelegation(scopeRef: object, input: {
        keyRef: object;
        ttlSeconds: number;
    }): Promise<string>;
    signPapSessionRequest(scopeRef: object, input: PapSessionSigningInput): Promise<string>;
    signDpopProof(scopeRef: object, input: DpopSigningInput): Promise<string>;
    retireTemporaryKey(scopeRef: object, keyRef: object): Promise<void>;
    dispose(): void;
}
export interface ProtocolIdentityClient {
    registerValidatedTarget(input: {
        identityRef: IdentityReference;
        policyRef: string;
        discovery: ValidatedTargetEvidence;
        requestedScopes: string[];
    }): Promise<ProtocolSignerLease>;
}
/** Bind only from the installed discovery adapter's Context. No consumer name is accepted.
 * @param context - Installed trusted Host adapter context.
 * @returns Caller-bound protocol client.
 */
export declare function bindProtocolIdentityClient(context: Context): ProtocolIdentityClient;

// ===== protocol-bootstrap.d.ts =====
/** Optional installed consumer that requests user approval before creating a protocol identity. */
import { Service, type Context } from '@deepseek-ai/cordis';
import type { RequestCreateInput } from './authorization-types.js';
import z from '@deepseek-ai/schemastery';
export declare const PROTOCOL_BOOTSTRAP_CONSUMER = "@agent-network-protocol/dsh-anp-identity/protocol-bootstrap";
export declare const name = "anp-identity-protocol-bootstrap";
export declare const inject: string[];
export interface Config {
    requestId?: string;
    profile: 'e1' | 'web';
    identityOnly: boolean;
    label?: string;
    domain?: string;
    path?: string;
    /** Canonical full Handle shown in the creation approval. */
    handle?: string;
    providerReadyTimeoutMs: number;
}
export declare const Config: z<Config>;
declare module '@deepseek-ai/cordis' {
    interface Context {
        anpIdentityRequester: RegistrationRequester;
    }
}
/** Uses only this real installed ordinary consumer; it cannot approve creation. */
export declare class RegistrationRequester extends Service {
    private readonly owner;
    constructor(ctx: Context);
    available(manager: Context): boolean;
    request(manager: Context, input: RequestCreateInput): Promise<import("./authorization-types.js").AuthorizationRequest>;
}
/** Submit one stable request from this actual installed Context; this never approves or registers it.
 * @param context - Loader-installed ordinary consumer.
 * @param config - Non-secret local creation request and bounded provider startup wait.
 */
export declare function apply(context: Context, config: Config): Promise<void>;

// ===== registration-bootstrap.d.ts =====
/** Private Host orchestration from a real creation approval to verified device publication. */
import type { Context } from '@deepseek-ai/cordis';
import type { IdentityReference } from '@agent-network-protocol/anp-identity';
import type AnpIdentityService from './index.js';
import type { IdentityManagement } from './management-types.js';
import { z } from 'zod';
import type { RegistrationInspection } from './management-driver.js';
export declare const RegistrationBootstrapConfigSchema: z.ZodObject<{
    id: z.ZodString;
    requestId: z.ZodString;
    stateRoot: z.ZodString;
    origin: z.ZodDefault<z.ZodString>;
    email: z.ZodOptional<z.ZodPipe<z.ZodString, z.ZodTransform<string, string>>>;
    phone: z.ZodOptional<z.ZodString>;
    clientName: z.ZodString;
    capabilities: z.ZodDefault<z.ZodObject<{
        mcpMachine: z.ZodBoolean;
        papSession: z.ZodBoolean;
        papAccount: z.ZodBoolean;
    }, z.core.$strict>>;
    redirectUris: z.ZodDefault<z.ZodArray<z.ZodString>>;
    managementAudience: z.ZodDefault<z.ZodString>;
    pollIntervalMs: z.ZodDefault<z.ZodNumber>;
    providerReadyTimeoutMs: z.ZodDefault<z.ZodNumber>;
}, z.core.$strict>;
export type RegistrationBootstrapConfig = z.infer<typeof RegistrationBootstrapConfigSchema>;
export type RegistrationBootstrapInput = z.input<typeof RegistrationBootstrapConfigSchema>;
export type RegistrationBootstrapPhase = 'awaiting_approval' | 'awaiting_email_verification' | 'awaiting_phone_verification' | 'registering' | 'publishing' | 'published' | 'registration_uncertain' | 'blocked' | 'disposed';
export type RegistrationBootstrapReason = 'approval_unavailable' | 'approval_denied' | 'invalid_configuration' | 'credential_unavailable' | 'email_unavailable' | 'phone_unavailable' | 'provider_unavailable' | 'publication_failed' | 'client_upgrade_required' | 'storage_unavailable' | 'identity_deleted';
/** Safe manager/UI projection; no factor, credential, key or remote response is returned. */
export interface RegistrationBootstrapStatus {
    id: string;
    requestId: string;
    phase: RegistrationBootstrapPhase;
    origin?: string;
    clientVersion?: string;
    reason?: RegistrationBootstrapReason;
    reference?: IdentityReference;
    clientId?: string;
    registrationCheck?: RegistrationInspection;
}
export interface RegistrationBootstrapController {
    submitOtp(code: string): void;
    status(): RegistrationBootstrapStatus;
    dispose(): Promise<void>;
}
/** Install the configured manager-owned flow. Its caller supplies the actual management facade and Context.
 * @param options - Non-secret configuration, actual Host management authority and optional HTTP transport.
 * @returns A safe status projection and quiescent disposer.
 */
export declare function startRegistrationBootstrap(options: {
    context: Context;
    service: AnpIdentityService;
    manager: IdentityManagement;
    config: RegistrationBootstrapConfig;
    fetch?: typeof fetch;
    /** Explicit owner retry of a failed SMS challenge, never registration or publication. */
    retryPhoneChallenge?: boolean;
}): RegistrationBootstrapController;

// ===== target-policy.d.ts =====
/** Context-bound protocol authorization with opaque target, scope and temporary-key references. */
import type { Context } from '@deepseek-ai/cordis';
import type { IdentityReference } from '@agent-network-protocol/anp-identity';
import type { ProviderLease } from '@agent-network-protocol/anp-identity/provider';
import type { VerifiedCaller } from './authorization-types.js';
import type { PublicationCoordinator } from './publication.js';
import type { ProtocolUsePolicy, ProtocolIdentityClient, ValidatedTargetEvidence, PapHostConsumer } from './protocol-client.js';
import type { PapCallbackManagementOperations } from './pap-callback.js';
export interface ProtocolAuthorityHost {
    resolveCaller(context: Context): VerifiedCaller;
    assertCaller(caller: VerifiedCaller): void;
    providerGeneration(): unknown;
    withNative<T>(operation: (native: ProviderLease) => Promise<T>): Promise<T>;
    /** Recheck durable default selection for Host-installed domain policies, including retained native leases. */
    assertDomainPolicy?(context: Context, policy: ProtocolUsePolicy, profile: ValidatedTargetEvidence['profile']): Promise<void>;
}
/** Private manager-owned driver and encrypted public transaction bindings. No credential value is returned. */
export interface PapCallbackHostAuthority {
    assertActive(): Promise<void>;
    operations: PapCallbackManagementOperations;
    reserve(transactionId: string, binding: Record<string, unknown>): Promise<Record<string, unknown>>;
    read(transactionId: string): Promise<Record<string, unknown> | undefined>;
}
/** The trusted adapter validates public discovery; this authority enforces identity and permission policy. */
export declare class ProtocolIdentityAuthority {
    private readonly policies;
    private readonly host;
    private readonly publications;
    private readonly targets;
    private readonly domainPolicies;
    /** Called only by the Host's explicitly enabled domain resolver, never by a consumer facade. */
    installDomainPolicy(policy: ProtocolUsePolicy): void;
    /** Retire a Host-owned temporary policy after its exact operation finishes. */
    removeDomainPolicy(id: string): void;
    private allPolicies;
    constructor(policies: readonly ProtocolUsePolicy[], host: ProtocolAuthorityHost, publications: PublicationCoordinator);
    bind(context: Context): ProtocolIdentityClient;
    /** Bind the exact installed PAP plugin; publication and callback data never replace its Host policy. */
    bindPapHost(context: Context, callbackAuthority: (identity: IdentityReference, backend: string) => Promise<PapCallbackHostAuthority>): PapHostConsumer;
    private validateEvidence;
    private validateRequest;
}

// ===== management-driver.d.ts =====
import type { IdentityReference, JsonValue, VerifiedRemoteDocument } from '@agent-network-protocol/anp-identity';
import type { ProviderLease } from '@agent-network-protocol/anp-identity/provider';
import type { PublicationBackend } from './publication-types.js';
import type { PapCallbackManagementOperations } from './pap-callback.js';
export interface DeviceManagementCredential {
    accessToken: string;
    deviceId: string;
    signingKeyId: string;
    audience?: string;
    operationBindings?: Record<string, Record<string, unknown>>;
}
/** Closed read-only evidence; never a registration receipt or a recovery authorization. */
export interface RegistrationInspection {
    outcome: 'verified' | 'rejected' | 'incompatible' | 'unavailable';
    httpStatus?: number;
    rpcCode?: number;
    nativeCode?: 'capability_denied' | 'provider_unavailable' | 'provider_disposed' | 'catalog_conflict';
}
/** The implementation must encrypt secrets at rest and partition by exact identity and service origin. */
export interface ManagementCredentialBroker {
    get(reference: IdentityReference, origin: string): Promise<DeviceManagementCredential | undefined>;
    set(reference: IdentityReference, origin: string, credential: DeviceManagementCredential): Promise<void>;
    reserveOperation(reference: IdentityReference, origin: string, operationId: string, body: Record<string, unknown>): Promise<Record<string, unknown>>;
}
/** Inspect only the current registered device. Never register, adopt a document or save credentials. */
export declare function inspectRegisteredDevice(input: {
    reference: IdentityReference;
    origin: string;
    withNative<T>(operation: (native: ProviderLease) => Promise<T>): Promise<T>;
    fetch?: typeof fetch;
    assertActive: () => void;
}): Promise<RegistrationInspection>;
export interface ManagedPublicationDriver extends PapCallbackManagementOperations {
    readonly documentId: string;
    readonly backend: PublicationBackend;
    readonly reference: IdentityReference;
    readVerifiedDocument(): Promise<VerifiedRemoteDocument>;
}
/** Create a device-authorized publication driver from a live Registry and an authenticated resolve.
 * @param input - Host custody, protected credentials and the fixed User Service origin.
 * @returns A driver bound to the server-resolved document id, never a user-supplied id.
 */
export declare function createManagedPublicationDriver(input: {
    reference: IdentityReference;
    origin: string;
    credentials: ManagementCredentialBroker;
    withNative<T>(operation: (native: ProviderLease) => Promise<T>): Promise<T>;
    fetch?: typeof fetch;
    /** Supplied by the Host installer to revoke this driver with its management Context and provider generation. */
    assertActive?: () => Promise<void>;
    /** Synchronous final epoch check immediately before physical sends and after body/native awaits. */
    assertCurrent?: () => void;
}): Promise<ManagedPublicationDriver>;
/** Registration fields supplied through the trusted Host management flow, never persisted in the catalog. */
export interface LocalRegistrationInput {
    handle: string;
    phone?: string;
    otp_code?: string;
    email?: string;
    invite_code?: string;
    name?: string;
    registration_operation_id?: string;
}
/** Register a locally held E1 Manifest and retain only a live, server-verified device credential.
 * @param input - Local identity, registration confirmation and protected broker.
 * @returns Public registration facts. No Access Token is returned.
 */
export declare function registerLocalIdentity(input: {
    reference: IdentityReference;
    origin: string;
    registration: LocalRegistrationInput;
    credentials: ManagementCredentialBroker;
    withNative<T>(operation: (native: ProviderLease) => Promise<T>): Promise<T>;
    fetch?: typeof fetch;
    managementAudience?: string;
    handleDomain?: string;
    assertActive?: () => void;
}): Promise<{
    did: string;
    deviceId: string;
    state: 'registered';
}>;
/** RFC 8785 serialization for native-produced JSON values.
 * @param value - Finite JSON data, with keys ordered by UTF-16 code units.
 * @returns Canonical UTF-8 text.
 */
export declare function canonicalManagementJson(value: JsonValue): string;
/** Construct the exact Web registration business projection; OTP and proof freshness are excluded.
 * @param input - Public local document and the explicit registration account/profile fields.
 * @returns Projection checked by the local native signer and User Service.
 */
export declare function webRegistrationProjection(input: {
    document: JsonValue;
    registration: LocalRegistrationInput;
    audience: string;
    handleDomain: string;
}): JsonValue;

// ===== pap-callback.d.ts =====
/** Host-only, exact-device PAP callback commands. Claim results must never enter Remote or model output. */
import { z } from 'zod';
export interface PapCallbackRegistration {
    transaction_id: string;
    client_id: string;
    issuer: string;
    redirect_uri: string;
    state_sha256: string;
    claim_sha256: string;
    expires_at: string;
}
export interface PapCallbackClaim {
    transaction_id: string;
    claim_secret: string;
}
export interface PapCallbackRegistrationResult {
    transaction_id: string;
    callback_uri: string;
    expires_at: string;
}
export type PapCallbackOAuthError = 'invalid_request' | 'unauthorized_client' | 'access_denied' | 'unsupported_response_type' | 'invalid_scope' | 'server_error' | 'temporarily_unavailable';
/** A one-shot private business result. It is deliberately not a publisher response. */
export type PapCallbackClaimResult = {
    state: string;
    iss: string;
    code: string;
} | {
    state: string;
    iss: string;
    error: PapCallbackOAuthError;
};
export interface PapCallbackRegisterOperation {
    action: 'pap-callback-register';
    operationId: string;
    callback: PapCallbackRegistration;
}
export interface PapCallbackClaimOperation {
    action: 'pap-callback-claim';
    operationId: string;
    callback: PapCallbackClaim;
}
export type PapCallbackOperation = PapCallbackRegisterOperation | PapCallbackClaimOperation;
/** Trusted Host capability limited to registering and claiming the fixed PAP callback relay. */
export interface PapCallbackManagementOperations {
    /** Register public hashes and the already-published fixed callback address.
     * @param input - Closed registration command, without PKCE verifier or business Tokens.
     * @returns Public relay acknowledgement.
     */
    execute(input: PapCallbackRegisterOperation): Promise<PapCallbackRegistrationResult>;
    /** Claim exactly once through the original device. No automatic retry or local result cache is allowed.
     * @param input - Claim command containing the independent pickup secret.
     * @returns The private code/error, state and issuer accepted by the relay.
     */
    execute(input: PapCallbackClaimOperation): Promise<PapCallbackClaimResult>;
}
export type PapCallbackManagementErrorCode = 'callback_not_ready' | 'callback_claimed' | 'callback_expired' | 'callback_conflict' | 'callback_unavailable' | 'callback_limit' | 'callback_redirect_mismatch' | 'callback_claim_not_independent' | 'callback_issuer_mismatch' | 'permission_denied' | 'management_auth_required' | 'not_published' | 'client_id_conflict' | 'idempotency_conflict';
/** Stable management failure. It contains neither callback business data nor arbitrary server text. */
export declare class PapCallbackManagementError extends Error {
    readonly code: PapCallbackManagementErrorCode;
    readonly name = "PapCallbackManagementError";
    constructor(code: PapCallbackManagementErrorCode);
}
export declare const PapCallbackOperationSchema: z.ZodDiscriminatedUnion<[z.ZodObject<{
    action: z.ZodLiteral<"pap-callback-register">;
    operationId: z.ZodString;
    callback: z.ZodObject<{
        transaction_id: z.ZodString;
        client_id: z.ZodString;
        issuer: z.ZodString;
        redirect_uri: z.ZodString;
        state_sha256: z.ZodString;
        claim_sha256: z.ZodString;
        expires_at: z.ZodString;
    }, z.core.$strict>;
}, z.core.$strict>, z.ZodObject<{
    action: z.ZodLiteral<"pap-callback-claim">;
    operationId: z.ZodString;
    callback: z.ZodObject<{
        transaction_id: z.ZodString;
        claim_secret: z.ZodString;
    }, z.core.$strict>;
}, z.core.$strict>], "action">;
export declare const PapCallbackRegistrationResultSchema: z.ZodObject<{
    transaction_id: z.ZodString;
    callback_uri: z.ZodString;
    expires_at: z.ZodString;
}, z.core.$loose>;
export declare const PapCallbackClaimResultSchema: z.ZodUnion<readonly [z.ZodObject<{
    state: z.ZodString;
    iss: z.ZodString;
    code: z.ZodString;
}, z.core.$strict>, z.ZodObject<{
    state: z.ZodString;
    iss: z.ZodString;
    error: z.ZodEnum<{
        invalid_request: "invalid_request";
        unauthorized_client: "unauthorized_client";
        access_denied: "access_denied";
        unsupported_response_type: "unsupported_response_type";
        invalid_scope: "invalid_scope";
        server_error: "server_error";
        temporarily_unavailable: "temporarily_unavailable";
    }>;
}, z.core.$strict>]>;
/** Decode only documented management failures; arbitrary input is never placed in an Error.
 * @param value - Parsed response object from the fixed management endpoint.
 * @returns A stable callback error, or undefined for an incompatible response.
 */
export declare function papCallbackManagementError(value: Record<string, unknown>): PapCallbackManagementError | undefined;

// ===== management-credentials.d.ts =====
import type { IdentityReference } from '@agent-network-protocol/anp-identity';
import type { ManagementCredentialBroker, DeviceManagementCredential } from './management-driver.js';
/** Each key resolver invocation must return a fresh, owner-controlled 32-byte encryption key. */
export declare class EncryptedManagementCredentialBroker implements ManagementCredentialBroker {
    private readonly root;
    private readonly encryptionKey;
    constructor(root: string, encryptionKey: () => Promise<Buffer>);
    private partition;
    get(reference: IdentityReference, origin: string): Promise<DeviceManagementCredential | undefined>;
    private writeUnlocked;
    set(reference: IdentityReference, origin: string, credential: DeviceManagementCredential): Promise<void>;
    reserveOperation(reference: IdentityReference, origin: string, operationId: string, body: Record<string, unknown>): Promise<Record<string, unknown>>;
    private transaction;
}

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
    /** HTTPS origins, or '*' only when the Host and user explicitly approve all HTTPS origins. */
    readonly httpOrigins: readonly string[];
    readonly oauthAudiences?: readonly string[];
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
    readonly oauthAudience?: string;
}
export interface CreateParameters {
    readonly profile?: 'e1' | 'web';
    readonly usage?: 'ordinary' | 'protocol';
    readonly identityOnly?: boolean;
    readonly label: string;
    readonly domain: string;
    readonly path: string;
    readonly handle?: string;
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
    readonly approvalProfile?: 'exact-operation/1';
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
        operationFingerprint?: string;
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
    readonly approvalProfile?: 'exact-operation/1';
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
import type { OAuthClientIdentity, PublicationConfig } from './publication-types.js';
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
    /** Redacted owner-only preview, retained in Host memory rather than the authorization ledger. */
    readonly operationPreview?: {
        readonly method: string;
        readonly target: string;
        readonly parameters?: unknown;
        readonly bodyDigest: string;
    };
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
    retryPublication(reference: IdentityReference): Promise<OAuthClientIdentity>;
    publicationStatus(reference: IdentityReference): Promise<OAuthClientIdentity>;
    publishIdentity(input: {
        reference: IdentityReference;
        config: PublicationConfig;
    }): Promise<OAuthClientIdentity>;
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

// ===== publication-types.d.ts =====
/** Public material state only. Credentials and assertions never enter the catalog. */
import { z } from 'zod';
import type { IdentityReference, OAuthPublicJwk } from '@agent-network-protocol/anp-identity';
import type { ProviderDocumentChangeSession } from '@agent-network-protocol/anp-identity/provider';
export declare const EcPublicJwkSchema: z.ZodObject<{
    kty: z.ZodLiteral<"EC">;
    crv: z.ZodLiteral<"P-256">;
    x: z.ZodString;
    y: z.ZodString;
    kid: z.ZodString;
    alg: z.ZodLiteral<"ES256">;
    use: z.ZodLiteral<"sig">;
}, z.core.$strict>;
export declare const PublicJwkSchema: z.ZodUnion<readonly [z.ZodObject<{
    kty: z.ZodLiteral<"OKP">;
    crv: z.ZodLiteral<"Ed25519">;
    x: z.ZodString;
    kid: z.ZodString;
    alg: z.ZodLiteral<"EdDSA">;
    use: z.ZodLiteral<"sig">;
}, z.core.$strict>, z.ZodObject<{
    kty: z.ZodLiteral<"EC">;
    crv: z.ZodLiteral<"P-256">;
    x: z.ZodString;
    y: z.ZodString;
    kid: z.ZodString;
    alg: z.ZodLiteral<"ES256">;
    use: z.ZodLiteral<"sig">;
}, z.core.$strict>]>;
export type PublicationJwk = z.infer<typeof PublicJwkSchema>;
export declare const PublicationCapabilitiesSchema: z.ZodObject<{
    mcpMachine: z.ZodBoolean;
    papSession: z.ZodBoolean;
    papAccount: z.ZodBoolean;
}, z.core.$strict>;
export type PublicationCapabilities = z.infer<typeof PublicationCapabilitiesSchema>;
/** Derive the server profile from actual enabled capabilities. */
export declare function publicationProfile(v: PublicationCapabilities): string;
/** The management wire representation is exclusively snake_case. */
export interface PublicationIntentV2 {
    schema_version: 2;
    operation_id: string;
    expected_version: number;
    client_name: string;
    capabilities: {
        mcp_machine: boolean;
        pap_session: boolean;
        pap_account: boolean;
    };
    signing_keys: PublicationJwk[];
    active_kid: string;
    redirect_uris: string[];
}
export declare const PublicationConfigSchema: z.ZodObject<{
    backend: z.ZodString;
    documentId: z.ZodString;
    clientName: z.ZodString;
    redirectUris: z.ZodArray<z.ZodString>;
    capabilities: z.ZodOptional<z.ZodObject<{
        mcpMachine: z.ZodBoolean;
        papSession: z.ZodBoolean;
        papAccount: z.ZodBoolean;
    }, z.core.$strict>>;
    activeKid: z.ZodOptional<z.ZodString>;
}, z.core.$strict>;
export type PublicationConfig = z.infer<typeof PublicationConfigSchema>;
export declare const PublicationRecordSchema: z.ZodObject<{
    config: z.ZodObject<{
        backend: z.ZodString;
        documentId: z.ZodString;
        clientName: z.ZodString;
        redirectUris: z.ZodArray<z.ZodString>;
        capabilities: z.ZodOptional<z.ZodObject<{
            mcpMachine: z.ZodBoolean;
            papSession: z.ZodBoolean;
            papAccount: z.ZodBoolean;
        }, z.core.$strict>>;
        activeKid: z.ZodOptional<z.ZodString>;
    }, z.core.$strict>;
    operationId: z.ZodString;
    expectedVersion: z.ZodNumber;
    state: z.ZodEnum<{
        awaiting_configuration: "awaiting_configuration";
        publishing: "publishing";
        published: "published";
        failed: "failed";
    }>;
    clientId: z.ZodString;
    version: z.ZodNumber;
    key: z.ZodUnion<readonly [z.ZodObject<{
        kty: z.ZodLiteral<"OKP">;
        crv: z.ZodLiteral<"Ed25519">;
        x: z.ZodString;
        kid: z.ZodString;
        alg: z.ZodLiteral<"EdDSA">;
        use: z.ZodLiteral<"sig">;
    }, z.core.$strict>, z.ZodObject<{
        kty: z.ZodLiteral<"EC">;
        crv: z.ZodLiteral<"P-256">;
        x: z.ZodString;
        y: z.ZodString;
        kid: z.ZodString;
        alg: z.ZodLiteral<"ES256">;
        use: z.ZodLiteral<"sig">;
    }, z.core.$strict>]>;
    metadata: z.ZodOptional<z.ZodString>;
    jwks: z.ZodOptional<z.ZodString>;
    metadataSha256: z.ZodOptional<z.ZodString>;
    failure: z.ZodOptional<z.ZodEnum<{
        unavailable: "unavailable";
        publication_failed: "publication_failed";
        material_mismatch: "material_mismatch";
    }>>;
}, z.core.$strict>;
export type PublicationRecord = z.infer<typeof PublicationRecordSchema>;
export interface OAuthClientIdentity {
    readonly state: 'local' | 'awaiting_configuration' | 'publishing' | 'published' | 'failed';
    readonly did: string;
    readonly clientId?: string;
    readonly jwksUri?: string;
    readonly keyId?: string;
    readonly algorithm?: 'EdDSA' | 'ES256';
    readonly signerMode?: 'local';
    readonly capabilities?: PublicationCapabilities;
    readonly version?: number;
}
export interface PreparedClientMaterials {
    readonly schema_version?: 2;
    readonly profile?: string;
    readonly capabilities?: {
        mcp_machine: boolean;
        pap_session: boolean;
        pap_account: boolean;
    };
    readonly active_kid?: string;
    readonly key_set_digest?: string;
    readonly state: 'awaiting_configuration' | 'prepared' | 'published';
    readonly client_id: string;
    readonly version: number;
    readonly operation_id?: string;
    readonly metadata_sha256?: string;
    readonly metadata?: string;
    readonly jwks?: string;
}
/** Installed by a trusted Host, not consumer request input. */
export interface PublicationBackend {
    readonly origin: string;
    clientId(documentId: string): string | Promise<string>;
    prepare(documentId: string, input: {
        operation_id: string;
        expected_version: number;
        client_name: string;
        key: OAuthPublicJwk;
        redirect_uris: string[];
    } | PublicationIntentV2): Promise<PreparedClientMaterials>;
    activate(documentId: string, operationId: string): Promise<PreparedClientMaterials>;
    readPublic(documentId: string, part: 'client.json' | 'jwks.json', url?: string): Promise<string>;
    /** Drive the existing authorized document-update/reconcile workflow. No unchecked document PUT. */
    publishDocument(reference: IdentityReference, session: ProviderDocumentChangeSession, assertActive: () => Promise<void>): Promise<void>;
}

// ===== publication-http.d.ts =====
/** User Service transport. The Host supplies its existing authenticated management channel. */
import type { PublicationBackend, PublicationCapabilities } from './publication-types.js';
export declare function exactHttps(value: string, requirePath?: boolean): string;
/** Validate a declared callback without changing its bytes. HTTP is restricted to V2 PAP account loopback.
 * @param value - Exact configured callback URI.
 * @param capabilities - V2 capabilities; omission preserves the HTTPS-only V1 rule.
 * @returns The unchanged configured URI.
 */
export declare function publicationRedirectUri(value: string, capabilities?: PublicationCapabilities): string;
export declare function createPublicationBackend(input: {
    origin: string;
    /** Credentials stay inside this Host function; outgoing redirects must not be followed. */
    authenticatedFetch(request: Request): Promise<Response>;
    publicFetch?: (request: Request) => Promise<Response>;
    publishDocument: PublicationBackend['publishDocument'];
}): PublicationBackend;
/** Reject duplicate JSON members, including escaped aliases, before using metadata. */
export declare function parsePublicJson(text: string): unknown;

// ===== management-remote.d.ts =====
import { type RegistrationOnboardingInput } from './registration-onboarding-types.js';
import type { UpdateRegistrationServiceSettings } from './registration-service-types.js';
import type { UpdateProtocolPolicy } from './protocol-policy-types.js';
import type { UpdateDefaultIdentity } from './default-identity-types.js';
import type { PublicationConfig } from './publication-types.js';
/** Optional Host manager boundary. Never expose this service to consumer leases. */
import type { Context } from "@deepseek-ai/cordis";
import { TypertRemoteService } from "@deepseek-ai/dsh-typert-protocol";
import type { IdentityReference } from "@agent-network-protocol/anp-identity";
import type { AuthorizationDecision } from "./authorization-types.js";
import type { RequestVersion, RevokeGrantInput, DeleteManagedIdentityInput } from "./management-types.js";
import z from '@deepseek-ai/schemastery';
import type { RegistrationBootstrapInput } from './registration-bootstrap.js';
export interface Config {
    registrationBootstrap?: RegistrationBootstrapInput;
}
export declare const Config: z<Config>;
export declare class IdentityManagerRemote extends TypertRemoteService {
    static inject: string[];
    static Config: z<Config>;
    private readonly manager;
    private readonly managerContext;
    private bootstrap;
    private readonly bootstrapReady;
    private bootstrapError;
    private readonly onboardingStore;
    private readonly configuredBootstrap;
    private onboardingVersion;
    private onboardingArchived;
    private onboardingIntent;
    private startingRegistration;
    constructor(ctx: Context, config?: Config);
    private ensureCreationRequest;
    private publicIdentityStatus;
    registrationOnboardingStatus(): Promise<{
        available: boolean;
        version: number;
        archived: boolean;
        inProgress: boolean;
        intentId?: string;
    }>;
    dismissRegistrationRequest(): null;
    protocolManagement(): Promise<import("./protocol-policy-types.js").ProtocolManagementState>;
    configureProtocolPolicy(input: UpdateProtocolPolicy): Promise<{
        read: {
            mode: "deny" | "ask" | "allow_all" | "whitelist";
            outside: "deny" | "ask";
            domains: {
                domain: string;
                protocols: ("anp" | "pap" | "mcp")[];
            }[];
        };
        write: {
            mode: "deny" | "ask" | "allow_all" | "whitelist";
            outside: "deny" | "ask";
            domains: {
                domain: string;
                protocols: ("anp" | "pap" | "mcp")[];
            }[];
        };
        schema: 1;
        version: number;
    }>;
    defaultIdentity(): Promise<{
        schema: 1;
        version: number;
        identity: {
            storeId: string;
            identityId: string;
            did: string;
        } | null;
    }>;
    configureDefaultIdentity(input: UpdateDefaultIdentity): Promise<{
        schema: 1;
        version: number;
        identity: {
            storeId: string;
            identityId: string;
            did: string;
        } | null;
    }>;
    startIdentityRegistration(raw: RegistrationOnboardingInput): Promise<{
        status: string;
        code: string;
        requestId?: never;
        phase?: never;
        origin?: never;
    } | {
        status: string;
        requestId: string;
        phase: string;
        origin: string;
        code?: never;
    }>;
    registrationBootstrapStatus(): import("./registration-bootstrap.js").RegistrationBootstrapStatus[];
    registrationServiceSettings(): Promise<import("./registration-service-types.js").RegistrationServiceSettings>;
    configureRegistrationService(input: UpdateRegistrationServiceSettings): Promise<import("./registration-service-types.js").RegistrationServiceSettings>;
    /** Accept a user-entered SMS code without persisting or returning it. */
    submitRegistrationOtp(input: {
        code: string;
    }): Promise<null>;
    /** Owner-only retry; an uncertain registration must never be replayed. */
    retryRegistrationSms(): Promise<null>;
    listIdentities(): Promise<import("./management-types.js").ManagedIdentitySummary[]>;
    listRequests(input?: boolean): Promise<import("./authorization-types.js").AuthorizationRequest[]>;
    getRequest(input: string): Promise<import("./management-types.js").RequestReview>;
    decide(input: AuthorizationDecision): Promise<import("./authorization-types.js").AuthorizationRequest>;
    grants(input: IdentityReference): Promise<import("./authorization-types.js").AuthorizationGrant[]>;
    revoke(input: RevokeGrantInput): Promise<null>;
    retryPublication(input: IdentityReference): Promise<import("./publication-types.js").OAuthClientIdentity>;
    publicationStatus(input: IdentityReference): Promise<import("./publication-types.js").OAuthClientIdentity>;
    publishIdentity(input: {
        reference: IdentityReference;
        config: PublicationConfig;
    }): Promise<import("./publication-types.js").OAuthClientIdentity>;
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

// ===== protocol-policy-types.d.ts =====
/** Browser-safe protocol permission settings. Service directories never grant permission. */
import { z } from 'zod';
export declare const protocolNames: readonly ["anp", "pap", "mcp"];
export type ManagedProtocol = typeof protocolNames[number];
export type ProtocolEffect = 'read' | 'write' | 'unknown' | 'payment';
export type ProtocolDecision = 'allow' | 'ask' | 'deny';
export interface ProtocolClassification {
    effect: ProtocolEffect;
    extraPermissions: boolean;
}
export interface HttpEffectEvidence {
    method: string;
    hasRequestBody: boolean;
    security?: unknown;
    declaredEffect?: unknown;
    annotations?: unknown;
}
/** HTTP safety alone is insufficient: body, explicit semantics and authorization declarations all participate. */
export declare function classifyHttpEffect(input: HttpEffectEvidence): ProtocolClassification;
/** MCP uses semantic tool hints, not its POST transport or the tool's name. */
export declare function classifyMcpEffect(raw: unknown): ProtocolClassification;
/** Scope suffixes select credential privilege, never the semantic effect of a business tool. Unknown scopes always ask. */
export declare function classifyMcpScopes(scopes: readonly string[]): ProtocolClassification;
export declare class ProtocolPolicyError extends Error {
    readonly code: string;
    constructor(code: string);
}
/** Exact IDNA hostname, not a URL, suffix pattern, port, or implicit subdomain rule. */
export declare function protocolDomain(input: string): string;
export declare const protocolPolicyInputSchema: z.ZodObject<{
    read: z.ZodObject<{
        mode: z.ZodEnum<{
            deny: "deny";
            ask: "ask";
            allow_all: "allow_all";
            whitelist: "whitelist";
        }>;
        outside: z.ZodEnum<{
            deny: "deny";
            ask: "ask";
        }>;
        domains: z.ZodArray<z.ZodObject<{
            domain: z.ZodPipe<z.ZodString, z.ZodTransform<string, string>>;
            protocols: z.ZodArray<z.ZodEnum<{
                anp: "anp";
                pap: "pap";
                mcp: "mcp";
            }>>;
        }, z.core.$strict>>;
    }, z.core.$strict>;
    write: z.ZodObject<{
        mode: z.ZodEnum<{
            deny: "deny";
            ask: "ask";
            allow_all: "allow_all";
            whitelist: "whitelist";
        }>;
        outside: z.ZodEnum<{
            deny: "deny";
            ask: "ask";
        }>;
        domains: z.ZodArray<z.ZodObject<{
            domain: z.ZodPipe<z.ZodString, z.ZodTransform<string, string>>;
            protocols: z.ZodArray<z.ZodEnum<{
                anp: "anp";
                pap: "pap";
                mcp: "mcp";
            }>>;
        }, z.core.$strict>>;
    }, z.core.$strict>;
}, z.core.$strict>;
export type ProtocolPolicyInput = z.infer<typeof protocolPolicyInputSchema>;
export declare const protocolPolicySchema: z.ZodObject<{
    read: z.ZodObject<{
        mode: z.ZodEnum<{
            deny: "deny";
            ask: "ask";
            allow_all: "allow_all";
            whitelist: "whitelist";
        }>;
        outside: z.ZodEnum<{
            deny: "deny";
            ask: "ask";
        }>;
        domains: z.ZodArray<z.ZodObject<{
            domain: z.ZodPipe<z.ZodString, z.ZodTransform<string, string>>;
            protocols: z.ZodArray<z.ZodEnum<{
                anp: "anp";
                pap: "pap";
                mcp: "mcp";
            }>>;
        }, z.core.$strict>>;
    }, z.core.$strict>;
    write: z.ZodObject<{
        mode: z.ZodEnum<{
            deny: "deny";
            ask: "ask";
            allow_all: "allow_all";
            whitelist: "whitelist";
        }>;
        outside: z.ZodEnum<{
            deny: "deny";
            ask: "ask";
        }>;
        domains: z.ZodArray<z.ZodObject<{
            domain: z.ZodPipe<z.ZodString, z.ZodTransform<string, string>>;
            protocols: z.ZodArray<z.ZodEnum<{
                anp: "anp";
                pap: "pap";
                mcp: "mcp";
            }>>;
        }, z.core.$strict>>;
    }, z.core.$strict>;
    schema: z.ZodLiteral<1>;
    version: z.ZodNumber;
}, z.core.$strict>;
export type ProtocolPolicy = z.infer<typeof protocolPolicySchema>;
export declare const updateProtocolPolicySchema: z.ZodObject<{
    expectedVersion: z.ZodNumber;
    policy: z.ZodObject<{
        read: z.ZodObject<{
            mode: z.ZodEnum<{
                deny: "deny";
                ask: "ask";
                allow_all: "allow_all";
                whitelist: "whitelist";
            }>;
            outside: z.ZodEnum<{
                deny: "deny";
                ask: "ask";
            }>;
            domains: z.ZodArray<z.ZodObject<{
                domain: z.ZodPipe<z.ZodString, z.ZodTransform<string, string>>;
                protocols: z.ZodArray<z.ZodEnum<{
                    anp: "anp";
                    pap: "pap";
                    mcp: "mcp";
                }>>;
            }, z.core.$strict>>;
        }, z.core.$strict>;
        write: z.ZodObject<{
            mode: z.ZodEnum<{
                deny: "deny";
                ask: "ask";
                allow_all: "allow_all";
                whitelist: "whitelist";
            }>;
            outside: z.ZodEnum<{
                deny: "deny";
                ask: "ask";
            }>;
            domains: z.ZodArray<z.ZodObject<{
                domain: z.ZodPipe<z.ZodString, z.ZodTransform<string, string>>;
                protocols: z.ZodArray<z.ZodEnum<{
                    anp: "anp";
                    pap: "pap";
                    mcp: "mcp";
                }>>;
            }, z.core.$strict>>;
        }, z.core.$strict>;
    }, z.core.$strict>;
}, z.core.$strict>;
export type UpdateProtocolPolicy = z.infer<typeof updateProtocolPolicySchema>;
export interface ProtocolManagementState {
    policy: ProtocolPolicy;
    domainAccessEnabled: boolean;
    protocols: {
        protocol: ManagedProtocol;
        installed: boolean;
        enabled: boolean;
        ready: boolean;
        managedAdapters: number;
        unmanagedAdapters: number;
    }[];
}
export declare function initialProtocolPolicy(): ProtocolPolicy;
/** Effects are classified by installed adapters, never by model-provided labels. */
export declare function protocolDecision(policy: ProtocolPolicy, protocol: ManagedProtocol, domain: string, effect: ProtocolEffect, extraPermissions?: boolean): ProtocolDecision;

// ===== protocol-policy.d.ts =====
import { type HttpEffectEvidence, type ProtocolClassification, type ProtocolPolicy, type UpdateProtocolPolicy, type ManagedProtocol, type ProtocolEffect, type ProtocolDecision } from './protocol-policy-types.js';
/** Additive settings file; no identity, key, grant, credential, or legacy connection is migrated. */
export declare class ProtocolPolicyStore {
    private readonly root;
    constructor(stateRoot: string);
    private safe;
    private transaction;
    read(assertActive: () => void): Promise<ProtocolPolicy>;
    update(raw: UpdateProtocolPolicy, assertActive: () => void): Promise<ProtocolPolicy>;
}
/** Created only after an adapter validates its discovery graph. This is not a model tool API. */
export interface ProtocolTargetEvidence {
    discoveryOrigin: string;
    destinations: readonly string[];
}
export interface ProtocolOperationEvidence {
    url: string;
    effect: ProtocolEffect;
    extraPermissions?: boolean;
}
/** An opaque per-adapter handle; neither URLs nor caller identity can be supplied at use time. */
export interface ProtocolTarget {
    readonly protocolTarget: true;
}
export interface ProtocolAdmission {
    readonly decision: ProtocolDecision;
    readonly version: number;
    /** Run after all DNS/token/body awaits and immediately before sending. Any policy edit invalidates this admission. */
    assertActive(): Promise<void>;
}
export interface ProtocolPolicyClient {
    /** Check existing identity-ledger refusals without creating or consuming a grant. */
    assertNoDenial(request: Request): Promise<void>;
    classifyHttp(input: HttpEffectEvidence): ProtocolClassification;
    classifyMcp(annotations: unknown): ProtocolClassification;
    classifyScopes(scopes: readonly string[]): ProtocolClassification;
    register(evidence: ProtocolTargetEvidence): ProtocolTarget;
    forget(target: ProtocolTarget): void;
    evaluate(target: ProtocolTarget, input: ProtocolOperationEvidence): Promise<ProtocolAdmission>;
}
/** Permission never replaces existing destination, identity, consumer, account or credential guards. */
export declare class ProtocolPolicyAuthority implements Omit<ProtocolPolicyClient, 'assertNoDenial'> {
    private readonly store;
    private readonly protocol;
    private readonly assertCaller;
    private readonly targets;
    constructor(store: ProtocolPolicyStore, protocol: ManagedProtocol, assertCaller: () => void);
    classifyHttp(input: HttpEffectEvidence): ProtocolClassification;
    classifyMcp(annotations: unknown): ProtocolClassification;
    classifyScopes(scopes: readonly string[]): ProtocolClassification;
    register(evidence: ProtocolTargetEvidence): ProtocolTarget;
    forget(target: ProtocolTarget): void;
    evaluate(target: ProtocolTarget, input: ProtocolOperationEvidence): Promise<ProtocolAdmission>;
}

// ===== default-identity-types.d.ts =====
/** Browser-safe preferences; selecting a row in the manager is not a default change. */
import { z } from 'zod';
export declare const identityReferenceSchema: z.ZodObject<{
    storeId: z.ZodString;
    identityId: z.ZodString;
    did: z.ZodString;
}, z.core.$strict>;
export declare const defaultIdentitySettingsSchema: z.ZodObject<{
    schema: z.ZodLiteral<1>;
    version: z.ZodNumber;
    identity: z.ZodNullable<z.ZodObject<{
        storeId: z.ZodString;
        identityId: z.ZodString;
        did: z.ZodString;
    }, z.core.$strict>>;
}, z.core.$strict>;
export declare const updateDefaultIdentitySchema: z.ZodObject<{
    expectedVersion: z.ZodNumber;
    identity: z.ZodNullable<z.ZodObject<{
        storeId: z.ZodString;
        identityId: z.ZodString;
        did: z.ZodString;
    }, z.core.$strict>>;
}, z.core.$strict>;
export type DefaultIdentitySettings = z.infer<typeof defaultIdentitySettingsSchema>;
export type UpdateDefaultIdentity = z.infer<typeof updateDefaultIdentitySchema>;

// ===== default-identity-settings.d.ts =====
import { type DefaultIdentitySettings, type UpdateDefaultIdentity } from './default-identity-types.js';
export declare class DefaultIdentitySettingsStore {
    private readonly initialIdentity;
    private readonly root;
    constructor(stateRoot: string, initialIdentity?: DefaultIdentitySettings['identity']);
    private transaction;
    read(assertActive: () => void): Promise<DefaultIdentitySettings>;
    update(raw: UpdateDefaultIdentity, assertActive: () => void): Promise<DefaultIdentitySettings>;
}

// ===== configuration-tools.d.ts =====
/** Purpose-specific Agent settings tools; no manager, signing or lifecycle capability escapes. */
import type { Context } from '@deepseek-ai/cordis';
import type { IdentityReference } from '@agent-network-protocol/anp-identity';
import { type ProtocolManagementState, type UpdateProtocolPolicy, type ProtocolPolicy } from './protocol-policy-types.js';
import type { DefaultIdentitySettings, UpdateDefaultIdentity } from './default-identity-types.js';
import type { RegistrationServiceSettings, UpdateRegistrationServiceSettings } from './registration-service-types.js';
export interface ConfigurationHandlers {
    assertOwner(): void;
    protocols(): Promise<ProtocolManagementState>;
    setProtocols(input: UpdateProtocolPolicy, check: () => void): Promise<ProtocolPolicy>;
    identity(): Promise<{
        defaultIdentity: DefaultIdentitySettings;
        registrationService: RegistrationServiceSettings;
        identities: {
            reference: IdentityReference;
            state: string;
        }[];
    }>;
    setDefault(input: UpdateDefaultIdentity, check: () => void): Promise<DefaultIdentitySettings>;
    setRegistration(input: UpdateRegistrationServiceSettings, check: () => void): Promise<RegistrationServiceSettings>;
}
/** Only the actual installed owner manager registers these definitions. Mutations always ask the owner in-session. */
export declare function registerConfigurationTools(ctx: Context, handlers: ConfigurationHandlers): void;
