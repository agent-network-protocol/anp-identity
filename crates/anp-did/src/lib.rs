//! Stateful E1 DID identity primitives with a non-exportable private-key API boundary.

mod error;
mod input;
mod manifest;
mod secret;

pub use error::{DidError, DidResult};
pub use input::{
    Capabilities, DeviceManifestEntrySpec, DeviceManifestSpec, DidCreateSpec, DidExtensionSpec,
    DidProfile, ExternalPublicKeyMaterial, ExternalPublicKeySpec, KeyRole, ManagedKeySpec,
    PublicOkpJwk, ServiceSpec,
};
pub use manifest::{
    RootKeyProviderBinding, RootKeyProviderKind, StoreManifest, STORE_MANIFEST_SCHEMA_VERSION,
};
