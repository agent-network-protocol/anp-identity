//! Stateful E1 DID identity primitives with a non-exportable private-key API boundary.

mod crypto_ops;
#[allow(dead_code)]
mod document;
mod error;
#[allow(dead_code)]
mod fs_util;
mod identity;
mod input;
#[allow(dead_code)]
mod keystore;
mod lifecycle;
mod manifest;
#[allow(dead_code)]
mod platform;
mod registry;
mod secret;
#[allow(dead_code)]
mod store;
#[allow(dead_code)]
mod store_lock;

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
