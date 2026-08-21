//! Stateful E1 DID identity primitives with a non-exportable private-key API boundary.

mod crypto_ops;
mod document;
mod error;
mod fs_util;
mod identity;
mod input;
mod keystore;
mod lifecycle;
mod manifest;
mod platform;
mod registry;
mod secret;
mod store;
mod store_lock;

pub use anp::authentication::HttpSignatureOptions;
pub use crypto_ops::SharedSecret;
pub use error::{DidError, DidResult};
pub use identity::{DidIdentity, DidStore};
pub use input::{
    Capabilities, DeviceManifestEntrySpec, DeviceManifestSpec, DidCreateSpec, DidExtensionSpec,
    DidProfile, ExternalPublicKeyMaterial, ExternalPublicKeySpec, KeyRole, ManagedKeySpec,
    PublicOkpJwk, ServiceSpec,
};
pub use lifecycle::{
    DocumentUpdateSpec, PendingRevisionSummary, PreparedUpdate, PublicationState, ReconcileOutcome,
    RequestSigningRotation,
};
pub use manifest::{
    RootKeyProviderBinding, RootKeyProviderKind, StoreManifest, STORE_MANIFEST_SCHEMA_VERSION,
};
pub use registry::{IdentityState, IdentitySummary, KeyMetadata, KeyOrigin, KeyState};
