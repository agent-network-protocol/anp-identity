use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use super::IdentityResult;
use crate::{IdentityState, KeyRole, KeyState};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreateIdentityProfile {
    E1,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CreateIdentityCapabilities {
    #[serde(default)]
    pub did_wba: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagedKeyRole {
    RootControl,
    DeviceSigning,
    RequestSigning,
    E2eeSigning,
    E2eeAgreement,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedKeyInput {
    pub fragment: String,
    pub role: ManagedKeyRole,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OkpPublicJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "format", rename_all = "snake_case")]
pub enum ExternalPublicKeyInputMaterial {
    Multibase { value: String },
    Jwk { public_key_jwk: OkpPublicJwk },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExternalPublicKeyInput {
    pub kid: String,
    pub role: ManagedKeyRole,
    pub material: ExternalPublicKeyInputMaterial,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceManifestEntryInput {
    pub device_id: String,
    pub signing_key_id: String,
    pub e2ee_key_id: String,
    #[serde(default)]
    pub profiles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum CreateIdentityExtension {
    DeviceManifest {
        devices: Vec<DeviceManifestEntryInput>,
    },
}

/// High-level input for creating one managed DID identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CreateIdentityRequest {
    pub profile: CreateIdentityProfile,
    pub domain: String,
    pub port: Option<u16>,
    pub path_segments: Vec<String>,
    #[serde(default)]
    pub capabilities: CreateIdentityCapabilities,
    pub managed_keys: Vec<ManagedKeyInput>,
    #[serde(default)]
    pub external_keys: Vec<ExternalPublicKeyInput>,
    #[serde(default)]
    pub services: Vec<super::IdentityService>,
    pub agent_description_url: Option<String>,
    #[serde(default)]
    pub extensions: Vec<CreateIdentityExtension>,
}

impl From<CreateIdentityRequest> for crate::DidCreateSpec {
    fn from(value: CreateIdentityRequest) -> Self {
        Self {
            profile: match value.profile {
                CreateIdentityProfile::E1 => crate::DidProfile::E1,
            },
            domain: value.domain,
            port: value.port,
            path_segments: value.path_segments,
            capabilities: crate::Capabilities {
                did_wba: value.capabilities.did_wba,
            },
            managed_keys: value
                .managed_keys
                .into_iter()
                .map(|key| crate::ManagedKeySpec {
                    fragment: key.fragment,
                    role: key.role.into(),
                })
                .collect(),
            external_keys: value
                .external_keys
                .into_iter()
                .map(|key| crate::ExternalPublicKeySpec {
                    kid: key.kid,
                    role: key.role.into(),
                    material: match key.material {
                        ExternalPublicKeyInputMaterial::Multibase { value } => {
                            crate::ExternalPublicKeyMaterial::Multibase { value }
                        }
                        ExternalPublicKeyInputMaterial::Jwk { public_key_jwk } => {
                            crate::ExternalPublicKeyMaterial::Jwk {
                                public_key_jwk: crate::PublicOkpJwk {
                                    kty: public_key_jwk.kty,
                                    crv: public_key_jwk.crv,
                                    x: public_key_jwk.x,
                                },
                            }
                        }
                    },
                })
                .collect(),
            services: value.services.into_iter().map(Into::into).collect(),
            agent_description_url: value.agent_description_url,
            extensions: value
                .extensions
                .into_iter()
                .map(|extension| match extension {
                    CreateIdentityExtension::DeviceManifest { devices } => {
                        crate::DidExtensionSpec::DeviceManifest(crate::DeviceManifestSpec {
                            devices: devices
                                .into_iter()
                                .map(|device| crate::DeviceManifestEntrySpec {
                                    device_id: device.device_id,
                                    signing_key_id: device.signing_key_id,
                                    e2ee_key_id: device.e2ee_key_id,
                                    profiles: device.profiles,
                                })
                                .collect(),
                        })
                    }
                })
                .collect(),
        }
    }
}

impl From<ManagedKeyRole> for KeyRole {
    fn from(value: ManagedKeyRole) -> Self {
        match value {
            ManagedKeyRole::RootControl => Self::RootControl,
            ManagedKeyRole::DeviceSigning => Self::DeviceSigning,
            ManagedKeyRole::RequestSigning => Self::RequestSigning,
            ManagedKeyRole::E2eeSigning => Self::E2eeSigning,
            ManagedKeyRole::E2eeAgreement => Self::E2eeAgreement,
        }
    }
}

#[derive(Default, Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeleteIdentityRequest {}

pub struct IdentityManagerConfig {
    pub state_root: PathBuf,
    pub root_key: RootKeySource,
}

pub enum RootKeySource {
    Keyring {
        service: String,
        account: String,
        fallback_to_local_file: bool,
    },
    LocalPrivateFile,
    Environment {
        key_id: String,
        variable: String,
    },
    Injected(InjectedStoreKey),
}

/// Consumed Store key input. Secret bytes are zeroized on drop.
pub struct InjectedStoreKey {
    key_id: String,
    bytes: Zeroizing<[u8; 32]>,
}

impl InjectedStoreKey {
    pub fn new(key_id: impl Into<String>, bytes: [u8; 32]) -> Self {
        Self {
            key_id: key_id.into(),
            bytes: Zeroizing::new(bytes),
        }
    }

    pub(crate) fn into_parts(self) -> (String, [u8; 32]) {
        (self.key_id, *self.bytes)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct IdentityRef {
    pub store_id: String,
    pub identity_id: String,
    pub did: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PublicIdentityState {
    Enrolling,
    Active,
    Revoked,
}

impl TryFrom<IdentityState> for PublicIdentityState {
    type Error = crate::facade::IdentityError;

    fn try_from(value: IdentityState) -> Result<Self, Self::Error> {
        match value {
            IdentityState::Enrolling => Ok(Self::Enrolling),
            IdentityState::Active => Ok(Self::Active),
            IdentityState::Revoked => Ok(Self::Revoked),
            IdentityState::Creating => Err(crate::facade::IdentityError::CorruptState),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityDescriptor {
    pub reference: IdentityRef,
    pub state: PublicIdentityState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(transparent)]
pub struct DidDocument(Value);

impl DidDocument {
    pub fn from_value(value: Value) -> Self {
        Self(value)
    }

    pub fn as_value(&self) -> &Value {
        &self.0
    }

    pub fn into_value(self) -> Value {
        self.0
    }

    pub fn canonical_digest(&self) -> IdentityResult<String> {
        crate::canonical_document_digest(&self.0).map_err(Into::into)
    }

    pub(crate) fn from_verified(value: Value) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyAlgorithm {
    Ed25519,
    X25519,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum KeyPurpose {
    RootControl,
    Authentication,
    DeviceAssertion,
    ApplicationAssertion,
    KeyAgreement,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublicKeyDescriptor {
    pub kid: String,
    pub algorithm: KeyAlgorithm,
    pub purposes: Vec<KeyPurpose>,
}

impl PublicKeyDescriptor {
    pub(crate) fn from_metadata(metadata: &crate::KeyMetadata) -> Option<Self> {
        if metadata.state != KeyState::Active || metadata.material_erased {
            return None;
        }
        let (algorithm, purposes) = match metadata.role {
            KeyRole::RootControl => (KeyAlgorithm::Ed25519, vec![KeyPurpose::RootControl]),
            KeyRole::DeviceSigning => (
                KeyAlgorithm::Ed25519,
                vec![KeyPurpose::Authentication, KeyPurpose::DeviceAssertion],
            ),
            KeyRole::RequestSigning => (
                KeyAlgorithm::Ed25519,
                vec![KeyPurpose::Authentication, KeyPurpose::ApplicationAssertion],
            ),
            KeyRole::E2eeSigning => (
                KeyAlgorithm::Ed25519,
                vec![KeyPurpose::ApplicationAssertion],
            ),
            KeyRole::E2eeAgreement => (KeyAlgorithm::X25519, vec![KeyPurpose::KeyAgreement]),
        };
        Some(Self {
            kid: metadata.kid.clone(),
            algorithm,
            purposes,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublicCapabilities {
    pub did_wba: bool,
}

impl From<&crate::Capabilities> for PublicCapabilities {
    fn from(value: &crate::Capabilities) -> Self {
        Self {
            did_wba: value.did_wba,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PublicIdentity {
    pub reference: IdentityRef,
    pub state: PublicIdentityState,
    pub revision: u64,
    pub document: DidDocument,
    pub active_keys: Vec<PublicKeyDescriptor>,
    pub capabilities: PublicCapabilities,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StoreHealth {
    Ready,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StoreInfo {
    pub store_id: String,
    pub schema_compatible: bool,
    pub identity_count: usize,
    pub health: StoreHealth,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecoveryReport {
    pub identity_count: usize,
}
