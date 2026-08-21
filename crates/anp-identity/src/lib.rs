//! Stateful E1 DID identity primitives with a non-exportable private-key API boundary.

mod adoption;
mod crypto_ops;
mod document;
mod error;
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

pub use adoption::{
    canonical_document_digest, AdoptDocumentOutcome, AdoptVerifiedDocumentSpec,
    EnrollmentPublicKey, EnrollmentSpec, PreparedEnrollment, PreparedRequestSigningEnrollment,
    RequestSigningEnrollmentSpec, VerifiedDocumentEvidence,
};
pub use anp::authentication::HttpSignatureOptions;
pub use crypto_ops::SharedSecret;
pub use error::{DidError, DidResult};
pub use identity::{DidIdentity, DidStore};
pub use input::{
    Capabilities, DeviceManifestEntrySpec, DeviceManifestSpec, DidCreateSpec, DidExtensionSpec,
    DidProfile, ExternalPublicKeyMaterial, ExternalPublicKeySpec, KeyRole, ManagedKeySpec,
    PublicOkpJwk, ServiceSpec,
};
#[cfg(feature = "key-import")]
pub use key_import::{IdentityImportSpec, ImportedPrivateKey, PrivateKeyEncoding};
pub use lifecycle::{
    DeviceAddSpec, DeviceMutationSpec, DevicePublicKeySpec, DocumentUpdateSpec,
    PendingRevisionSummary, PreparedUpdate, PublicationState, ReconcileOutcome,
    RequestSigningRotation,
};
pub use manifest::{
    RootKeyProviderBinding, RootKeyProviderKind, StoreManifest, STORE_MANIFEST_SCHEMA_VERSION,
};
pub use registry::{
    DocumentCheckpoint, IdentityState, IdentitySummary, KeyMetadata, KeyOrigin, KeyState,
    RootCapabilityState,
};
#[cfg(feature = "key-import")]
pub use root_transfer::{LegacyRootTransferEvidence, LegacyRootTransferImportSpec};
pub use root_transfer::{
    RootPromotionSpec, RootTransferContext, RootTransferExportSpec, RootTransferImportOutcome,
    WrappedRootEnvelope, WRAPPED_ROOT_ENVELOPE_TYPE, WRAPPED_ROOT_ENVELOPE_VERSION,
};
