use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::{Capabilities, DidCreateSpec, IdentityState, KeyRole, KeyState};

/// Existing validated creation DTO under its stable Facade name.
pub type CreateIdentityRequest = DidCreateSpec;

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
    pub fn as_value(&self) -> &Value {
        &self.0
    }

    pub fn into_value(self) -> Value {
        self.0
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

impl From<&Capabilities> for PublicCapabilities {
    fn from(value: &Capabilities) -> Self {
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
