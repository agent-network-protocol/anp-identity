use serde::{Deserialize, Serialize};

use crate::{IdentityResult, ManagedIdentity, RootCapabilityState};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostRootCapability {
    Absent,
    Pending,
    Active,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostDocumentCheckpoint {
    pub document_version: u64,
    pub registry_version: u64,
    pub document_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityHostStatus {
    pub root_capability: HostRootCapability,
    pub root_key_fingerprint: String,
    pub checkpoint: Option<HostDocumentCheckpoint>,
}

pub trait IdentityStatusPort {
    fn host_status(&self) -> IdentityResult<IdentityHostStatus>;
}

impl IdentityStatusPort for ManagedIdentity {
    fn host_status(&self) -> IdentityResult<IdentityHostStatus> {
        let engine = self.lock_engine()?;
        Ok(IdentityHostStatus {
            root_capability: match engine.root_capability() {
                RootCapabilityState::Absent => HostRootCapability::Absent,
                RootCapabilityState::Pending => HostRootCapability::Pending,
                RootCapabilityState::Active => HostRootCapability::Active,
            },
            root_key_fingerprint: engine.root_key_fingerprint().to_owned(),
            checkpoint: engine
                .checkpoint()
                .map(|checkpoint| HostDocumentCheckpoint {
                    document_version: checkpoint.document_version,
                    registry_version: checkpoint.registry_version,
                    document_digest: checkpoint.document_digest.clone(),
                }),
        })
    }
}
