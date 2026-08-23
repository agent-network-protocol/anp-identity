//! Stateful E1 DID identity primitives with role-scoped private-key custody.

mod adoption;
mod crypto_ops;
mod document;
mod error;
mod facade;
mod fs_util;
mod identity;
mod input;
#[cfg(feature = "key-import")]
mod key_import;
mod keystore;
mod lifecycle;
mod manifest;
mod namespace;
mod platform;
mod registry;
mod root_transfer;
mod secret;
mod store;
mod store_lock;

pub mod host;

pub(crate) use adoption::{
    canonical_document_digest, AdoptDocumentOutcome, AdoptVerifiedDocumentSpec, EnrollmentSpec,
    PreparedEnrollment, PreparedRequestSigningEnrollment, RequestSigningEnrollmentSpec,
    VerifiedDocumentEvidence,
};
pub(crate) use anp::authentication::HttpSignatureOptions;
pub(crate) use error::{DidError, DidResult};
pub use facade::{
    CreateIdentityCapabilities, CreateIdentityExtension, CreateIdentityProfile,
    CreateIdentityRequest, DeleteIdentityRequest, DeviceInput, DeviceManifestEntryInput,
    DidDocument, DocumentChange, DocumentChangeOutcome, DocumentChangeRequest,
    DocumentChangeSession, ExternalPublicKeyInput, ExternalPublicKeyInputMaterial,
    IdentityDescriptor, IdentityError, IdentityManager, IdentityManagerConfig, IdentityRef,
    IdentityResult, IdentityService, InjectedStoreKey, KeyAlgorithm, KeyPurpose, KeySelector,
    ManagedIdentity, ManagedKeyInput, ManagedKeyRole, OkpPublicJwk, OriginProofOptions,
    OriginProofRequest, PreparedDocumentChange, PublicCapabilities, PublicIdentity,
    PublicIdentityState, PublicKeyDescriptor, PublicKeyInput, PublicationAttempt,
    PublicationResult, RecoveryReport, RootKeySource, SignRequest, Signature, SignedOriginProof,
    SigningPurpose, StoreHealth, StoreInfo, VerificationOutcome, VerifiedPublicationEvidence,
    VerifiedRemoteDocument, VerifyRequest,
};
pub(crate) use identity::{DidIdentity, DidStore};
pub(crate) use input::{
    Capabilities, DeviceManifestEntrySpec, DeviceManifestSpec, DidCreateSpec, DidExtensionSpec,
    DidProfile, ExternalPublicKeyMaterial, ExternalPublicKeySpec, KeyRole, ManagedKeySpec,
    PublicOkpJwk, ServiceSpec,
};
#[cfg(feature = "key-import")]
pub(crate) use key_import::{
    DeviceIdentityImportSpec, IdentityImportSpec, ImportedPrivateKey, PrivateKeyEncoding,
    RequestSigningIdentityImportSpec,
};
pub(crate) use lifecycle::{
    DeviceAddSpec, DeviceMutationSpec, DevicePublicKeySpec, DocumentUpdateSpec,
    PendingRevisionSummary, PublicationState, ReconcileOutcome, RequestSigningMutationSpec,
    RequestSigningPublicKeySpec, RequestSigningRotation,
};
pub(crate) use manifest::{
    RootKeyProviderBinding, RootKeyProviderKind, StoreManifest, STORE_MANIFEST_SCHEMA_VERSION,
};
pub(crate) use registry::{
    DocumentCheckpoint, IdentityState, IdentitySummary, KeyMetadata, KeyOrigin, KeyState,
    RootCapabilityState,
};
#[cfg(feature = "key-import")]
pub(crate) use root_transfer::{LegacyRootTransferEvidence, LegacyRootTransferImportSpec};
pub(crate) use root_transfer::{RootPromotionSpec, RootTransferImportOutcome, WrappedRootEnvelope};
