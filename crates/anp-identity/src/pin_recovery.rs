//! Persisted PIN recovery metadata contains no plaintext key material.
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PinRecoveryBinding {
    pub operation_id: String,
    pub account_user_id: String,
    pub target_id: String,
    pub handle: String,
    pub did: String,
    pub domain: String,
    pub binding_generation: String,
    pub recovery_id: String,
    pub backup_epoch: u64,
    pub slot_id: String,
    pub op_jkt: String,
    pub root_kid: String,
    pub root_public_key_multibase: String,
    pub encrypted_package_hash: Option<String>,
    pub config_hash: String,
    pub audience: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PinRecoveryPhase {
    Prepared,
    PublicationUncertain,
    Active,
    SupersededByV4,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PinRecoveryRecord {
    pub(crate) binding: PinRecoveryBinding,
    pub(crate) device_label: String,
    pub(crate) phase: PinRecoveryPhase,
    pub(crate) challenge_id: Option<String>,
    pub(crate) signed_document: Option<Value>,
    pub(crate) signed_payload: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) superseded_by_v4: Option<PinRecoveryV4RetirementRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PinRecoveryV4RetirementRecord {
    pub(crate) source_generation: u64,
    pub(crate) evidence: Value,
    pub(crate) scope: Value,
}

pub(crate) struct PinRootMaterial {
    pub(crate) secret: crate::secret::SecretBytes,
    pub(crate) record: PinRecoveryRecord,
}
