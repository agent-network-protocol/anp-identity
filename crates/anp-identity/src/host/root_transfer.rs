use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(any(feature = "root-export", feature = "key-import"))]
use zeroize::Zeroizing;

use super::convergence::evidence;
#[cfg(feature = "root-export")]
use super::proofs::select_root_key;
use crate::facade::{
    IdentityError, IdentityResult, KeySelector, ManagedIdentity, VerifiedRemoteDocument,
};
use crate::{KeyOrigin, KeyRole, KeyState};

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RootPromotionRequest {
    pub remote: VerifiedRemoteDocument,
}

pub trait RootPromotionPort {
    fn confirm_root_promotion(&mut self, request: RootPromotionRequest) -> IdentityResult<()>;

    fn sign_pending_root_object_proof(
        &self,
        request: PendingRootObjectProofRequest,
    ) -> IdentityResult<Value>;
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PendingRootObjectProofRequest {
    pub key: KeySelector,
    pub document: Value,
    pub issuer_did: String,
    pub created: Option<String>,
}

impl RootPromotionPort for ManagedIdentity {
    fn confirm_root_promotion(&mut self, request: RootPromotionRequest) -> IdentityResult<()> {
        self.lock_engine()?
            .confirm_root_promotion(crate::RootPromotionSpec {
                document: request.remote.document.into_value(),
                evidence: evidence(request.remote.evidence),
            })?;
        Ok(())
    }

    fn sign_pending_root_object_proof(
        &self,
        request: PendingRootObjectProofRequest,
    ) -> IdentityResult<Value> {
        let engine = self.lock_engine()?;
        let kid = select_pending_root_key(&engine, &request.key)?;
        engine
            .sign_pending_root_object_proof(
                &kid,
                &request.document,
                &request.issuer_did,
                request.created,
            )
            .map_err(Into::into)
    }
}

#[cfg(feature = "root-export")]
pub struct UserConfirmedRootExportRequest {
    pub key: KeySelector,
    pub user_presence_confirmed: bool,
}

#[cfg(feature = "root-export")]
pub struct HostExportedRootPrivateKey {
    pkcs8_der: Zeroizing<Vec<u8>>,
}

#[cfg(feature = "root-export")]
impl HostExportedRootPrivateKey {
    pub fn as_pkcs8_der(&self) -> &[u8] {
        self.pkcs8_der.as_slice()
    }
}

#[cfg(feature = "root-export")]
pub trait RootExportPort {
    fn export_root_for_legacy_envelope(
        &self,
        request: UserConfirmedRootExportRequest,
    ) -> IdentityResult<HostExportedRootPrivateKey>;
}

#[cfg(feature = "root-export")]
impl RootExportPort for ManagedIdentity {
    fn export_root_for_legacy_envelope(
        &self,
        request: UserConfirmedRootExportRequest,
    ) -> IdentityResult<HostExportedRootPrivateKey> {
        if !request.user_presence_confirmed {
            return Err(IdentityError::CapabilityUnavailable);
        }
        let engine = self.lock_engine()?;
        let kid = select_root_key(&engine, &request.key)?;
        let exported = engine.export_root_private_key(&kid)?;
        Ok(HostExportedRootPrivateKey {
            pkcs8_der: Zeroizing::new(exported.as_pkcs8_der().to_vec()),
        })
    }
}

#[cfg(feature = "key-import")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootPrivateKeyEncoding {
    Raw32,
    Pkcs8Der,
}

#[cfg(feature = "key-import")]
pub struct LegacyRootImportEvidence {
    pub transfer_id: String,
    pub source_did: String,
    pub target_did: String,
    pub sender_device_id: String,
    pub recipient_device_id: String,
    pub recipient_agreement_kid: String,
    pub root_kid: String,
    pub checkpoint: super::HostDocumentCheckpoint,
    pub accepted_at: String,
}

#[cfg(feature = "key-import")]
pub struct LegacyRootImportRequest {
    pub evidence: LegacyRootImportEvidence,
    pub encoding: RootPrivateKeyEncoding,
    pub root_key: Zeroizing<Vec<u8>>,
}

#[cfg(feature = "key-import")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyRootImportOutcome {
    Pending,
    Active,
}

#[cfg(feature = "key-import")]
pub trait RootImportPort {
    fn import_legacy_root(
        &mut self,
        request: LegacyRootImportRequest,
    ) -> IdentityResult<LegacyRootImportOutcome>;
}

#[cfg(feature = "key-import")]
impl RootImportPort for ManagedIdentity {
    fn import_legacy_root(
        &mut self,
        request: LegacyRootImportRequest,
    ) -> IdentityResult<LegacyRootImportOutcome> {
        let outcome = self.lock_engine()?.import_legacy_root_transfer(
            crate::LegacyRootTransferImportSpec {
                evidence: crate::LegacyRootTransferEvidence {
                    transfer_id: request.evidence.transfer_id,
                    source_did: request.evidence.source_did,
                    target_did: request.evidence.target_did,
                    sender_device_id: request.evidence.sender_device_id,
                    recipient_device_id: request.evidence.recipient_device_id,
                    recipient_agreement_kid: request.evidence.recipient_agreement_kid,
                    root_kid: request.evidence.root_kid,
                    checkpoint: crate::DocumentCheckpoint {
                        document_version: request.evidence.checkpoint.document_version,
                        registry_version: request.evidence.checkpoint.registry_version,
                        document_digest: request.evidence.checkpoint.document_digest,
                    },
                    accepted_at: request.evidence.accepted_at,
                },
                encoding: match request.encoding {
                    RootPrivateKeyEncoding::Raw32 => crate::PrivateKeyEncoding::Raw32,
                    RootPrivateKeyEncoding::Pkcs8Der => crate::PrivateKeyEncoding::Pkcs8Der,
                },
                root_key: request.root_key,
            },
        )?;
        Ok(match outcome {
            crate::RootTransferImportOutcome::Pending => LegacyRootImportOutcome::Pending,
            crate::RootTransferImportOutcome::Active => LegacyRootImportOutcome::Active,
        })
    }
}

fn select_pending_root_key(
    identity: &crate::DidIdentity,
    selector: &KeySelector,
) -> IdentityResult<String> {
    let usable = |metadata: &&crate::KeyMetadata| {
        metadata.role == KeyRole::RootControl
            && metadata.origin == KeyOrigin::Managed
            && metadata.state == KeyState::Pending
            && !metadata.material_erased
    };
    match selector {
        KeySelector::Kid(kid) => {
            let metadata = identity.key_metadata(kid)?;
            if !usable(&metadata) {
                return Err(IdentityError::CapabilityUnavailable);
            }
            Ok(metadata.kid.clone())
        }
        KeySelector::Default => {
            let mut candidates = identity.keys().iter().filter(usable);
            let selected = candidates
                .next()
                .ok_or(IdentityError::CapabilityUnavailable)?;
            if candidates.next().is_some() {
                return Err(IdentityError::AmbiguousKey);
            }
            Ok(selected.kid.clone())
        }
    }
}

#[cfg(all(test, feature = "root-export"))]
mod tests;
