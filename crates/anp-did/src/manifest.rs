use serde::{Deserialize, Serialize};

pub const STORE_MANIFEST_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RootKeyProviderKind {
    OsKeyring,
    Injected,
    LocalPrivateFile,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RootKeyProviderBinding {
    pub kind: RootKeyProviderKind,
    pub key_id: String,
    pub account: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StoreManifest {
    pub schema_version: u32,
    pub store_id: String,
    pub generation: u64,
    pub provider: RootKeyProviderBinding,
    pub root_key_fingerprint: String,
    pub created_at: String,
    pub rekey_generation: u64,
}
