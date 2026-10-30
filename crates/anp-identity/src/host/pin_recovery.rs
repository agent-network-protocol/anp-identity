//! Rust-only, operation-bound PIN backup and recovered-root custody.
mod retirement;
pub use retirement::*;
mod validation;
use super::{
    EnrollmentProposal, EnrollmentProposalKind, EnrollmentPublicKey, HostDocumentCheckpoint,
};
use crate::adoption::{
    persist_state_transition, validate_checkpoint_progression, validate_verified_document,
};
use crate::document::method_root_fingerprint;
pub use crate::pin_recovery::{PinRecoveryBinding, PinRecoveryPhase};
use crate::pin_recovery::{PinRecoveryRecord, PinRootMaterial};
use crate::registry::{read_identity, IdentityRecord};
use crate::{
    IdentityError, IdentityManager, IdentityRef, IdentityResult, IdentityState, KeyOrigin, KeyRole,
    KeyState, ManagedIdentity, RootCapabilityState, VerifiedRemoteDocument,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use validation::*;
use zeroize::Zeroizing;

pub struct PinRootBackupRequest {
    pub expected_generation: u64,
    pub root_kid: String,
    pub user_presence_confirmed: bool,
}
/// Root bytes deliberately implement neither Debug nor serialization.
pub struct PinRootBackup {
    pkcs8_der: Zeroizing<Vec<u8>>,
    pub root_kid: String,
    pub root_public_key_multibase: String,
    pub generation: u64,
}
impl PinRootBackup {
    pub fn as_pkcs8_der(&self) -> &[u8] {
        &self.pkcs8_der
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PinRecoveryChallenge {
    pub payload: Value,
    pub intent: Value,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinBackupPurpose {
    Authorize,
    BackupCommit,
}
pub struct PinBackupIntentRequest {
    pub expected_generation: u64,
    pub binding: PinRecoveryBinding,
    pub purpose: PinBackupPurpose,
    /// Expected intent assembled from authenticated operation state, not copied blindly from the challenge.
    pub expected_intent: Value,
    pub challenge: PinRecoveryChallenge,
    pub user_presence_confirmed: bool,
}
pub trait PinRootBackupPort {
    fn pin_root_generation(&self) -> IdentityResult<u64>;
    fn export_root_for_pin_backup(
        &self,
        request: PinRootBackupRequest,
    ) -> IdentityResult<PinRootBackup>;
    fn sign_pin_recovery_intent(&self, request: PinBackupIntentRequest) -> IdentityResult<String>;
}
pub struct BeginPinRootRecoveryRequest {
    pub binding: PinRecoveryBinding,
    pub remote: VerifiedRemoteDocument,
    pub root_key: Option<Zeroizing<Vec<u8>>>,
    pub profiles: Vec<String>,
    pub device_label: String,
    pub user_presence_confirmed: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PinRecoveryProposal {
    pub identity: IdentityRef,
    pub binding: PinRecoveryBinding,
    pub enrollment: EnrollmentProposal,
    /// Exact Realm DeviceProposal for JCS hashing and submission.
    pub device_proposal: Value,
    pub generation: u64,
    pub phase: PinRecoveryPhase,
}
pub struct PinRootRecoverySession {
    identity: ManagedIdentity,
    proposal: PinRecoveryProposal,
}
pub trait PinRootRecoveryPort {
    fn begin_pin_root_recovery(
        &mut self,
        request: BeginPinRootRecoveryRequest,
    ) -> IdentityResult<PinRootRecoverySession>;
}
pub struct PinRecoverySignRequest {
    pub expected_generation: u64,
    pub challenge: PinRecoveryChallenge,
    pub remote: VerifiedRemoteDocument,
    pub candidate_document: Value,
    pub user_presence_confirmed: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PinRecoverySignedIntent {
    pub challenge: PinRecoveryChallenge,
    pub root_proof: String,
    pub device_proof: String,
    pub signed_document: Value,
    pub generation: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinRecoveryRemoteOutcome {
    Committed,
    NotCommitted,
}
pub struct PinRecoveryCancelRequest {
    pub expected_generation: u64,
    pub binding: PinRecoveryBinding,
}

pub struct PinRecoveryCompletion {
    pub expected_generation: u64,
    pub binding: PinRecoveryBinding,
    pub challenge_id: String,
    pub remote: VerifiedRemoteDocument,
    /// Authenticated status for this exact operation and challenge, verified by the host.
    pub outcome: PinRecoveryRemoteOutcome,
}

impl PinRootBackupPort for ManagedIdentity {
    fn pin_root_generation(&self) -> IdentityResult<u64> {
        let engine = self.lock_engine()?;
        Ok(current_record(&engine, engine.record().generation)?.generation)
    }
    fn export_root_for_pin_backup(
        &self,
        request: PinRootBackupRequest,
    ) -> IdentityResult<PinRootBackup> {
        require_presence(request.user_presence_confirmed)?;
        let engine = self.lock_engine()?;
        let _guard = engine.runtime().acquire_write()?;
        let record = current_record(&engine, request.expected_generation)?;
        let root = active_root(&record, &request.root_kid)?;
        let exported = engine.export_root_private_key(&root.kid)?;
        Ok(PinRootBackup {
            pkcs8_der: Zeroizing::new(exported.as_pkcs8_der().to_vec()),
            root_kid: root.kid.clone(),
            root_public_key_multibase: root.public_key_multibase.clone(),
            generation: record.generation,
        })
    }
    fn sign_pin_recovery_intent(&self, request: PinBackupIntentRequest) -> IdentityResult<String> {
        require_presence(request.user_presence_confirmed)?;
        let engine = self.lock_engine()?;
        let _guard = engine.runtime().acquire_write()?;
        let record = current_record(&engine, request.expected_generation)?;
        let root = active_root(&record, &request.binding.root_kid)?;
        validate_binding(&request.binding, &record.document)?;
        let checkpoint = record
            .checkpoint
            .as_ref()
            .ok_or(IdentityError::InvalidRequest)?;
        let purpose = match request.purpose {
            PinBackupPurpose::Authorize => "awiki.pin-recovery.authorize.v1",
            PinBackupPurpose::BackupCommit => "awiki.pin-recovery.backup-commit.v1",
        };
        validate_challenge(&request.challenge, &request.binding, checkpoint, purpose)?;
        let intent = &request.challenge.intent;
        if *intent != request.expected_intent
            || intent["kind"] != "enable"
            || !intent["expected_active_epoch"].is_null()
            || !intent["new_device_proposal_hash"].is_null()
            || !intent["candidate_document_digest"].is_null()
        {
            return Err(IdentityError::InvalidRequest);
        }
        match request.purpose {
            PinBackupPurpose::Authorize => {
                if !intent["backup_hash"].is_null()
                    || !intent["registration_version"].is_null()
                    || intent["registered_receipt_ids"] != json!([])
                    || intent["verified_receipt_ids"] != json!([])
                {
                    return Err(IdentityError::InvalidRequest);
                }
            }
            PinBackupPurpose::BackupCommit => {
                if request.binding.encrypted_package_hash.is_none()
                    || intent["backup_hash"] != json!(request.binding.encrypted_package_hash)
                    || intent["registration_version"].is_null()
                    || unique_receipts(&intent["registered_receipt_ids"])? != 3
                    || unique_receipts(&intent["verified_receipt_ids"])? < 2
                {
                    return Err(IdentityError::InvalidRequest);
                }
            }
        }
        sign_jws(
            &engine,
            root,
            &request.challenge.payload,
            "awiki-root-authorization+jwt",
        )
    }
}

impl PinRootRecoveryPort for IdentityManager {
    fn begin_pin_root_recovery(
        &mut self,
        request: BeginPinRootRecoveryRequest,
    ) -> IdentityResult<PinRootRecoverySession> {
        require_presence(request.user_presence_confirmed)?;
        let document = request.remote.document.into_value();
        let evidence = super::convergence::evidence(request.remote.evidence);
        validate_verified_document(&document, &evidence)?;
        validate_binding(&request.binding, &document)?;
        if request.binding.encrypted_package_hash.is_none()
            || request.device_label.trim().is_empty()
            || request.device_label.len() > 128
        {
            return Err(IdentityError::InvalidRequest);
        }
        // Sessions advance the registry independently of this manager. Refresh
        // before a new namespace operation; preparation still performs its CAS.
        self.engine.reload()?;
        match self.engine.open_identity(&request.binding.did) {
            Ok(engine) => {
                let pin = engine
                    .record()
                    .pin_recovery
                    .as_ref()
                    .ok_or(IdentityError::IdentityAlreadyExists)?;
                let local = engine
                    .record()
                    .local_authorization
                    .as_ref()
                    .ok_or(IdentityError::CorruptState)?;
                if pin.binding != request.binding
                    || pin.device_label != request.device_label
                    || local.profiles != request.profiles
                {
                    return Err(IdentityError::InvalidRequest);
                }
                if let Some(der) = request.root_key {
                    validate_root_der(&der, &document, &request.binding)?;
                }
                return session(self.wrap(engine));
            }
            Err(crate::DidError::IdentityNotFound) => (),
            Err(error) => return Err(error.into()),
        }
        let der = request.root_key.ok_or(IdentityError::InvalidRequest)?;
        let secret = validate_root_der(&der, &document, &request.binding)?;
        let device_id = crate::identity::random_id();
        let material = PinRootMaterial {
            secret,
            record: PinRecoveryRecord {
                binding: request.binding,
                device_label: request.device_label,
                phase: PinRecoveryPhase::Prepared,
                challenge_id: None,
                signed_document: None,
                signed_payload: None,
                superseded_by_v4: None,
            },
        };
        let (engine, _) = self.engine.prepare_enrollment_with_pin(
            crate::EnrollmentSpec {
                verified_document: document,
                evidence,
                device_id: device_id.clone(),
                device_signing_fragment: format!("pin-{device_id}-sign"),
                device_e2ee_fragment: format!("pin-{device_id}-agree"),
                profiles: request.profiles,
                capabilities: crate::Capabilities { did_wba: true },
            },
            Some(material),
        )?;
        session(self.wrap(engine))
    }
}

impl PinRootRecoverySession {
    /// Discards only this exact Prepared recovery. Unknown or committed remote
    /// outcomes must be reconciled before cancellation is attempted.
    pub fn cancel_pin_root_recovery(
        &mut self,
        request: PinRecoveryCancelRequest,
    ) -> IdentityResult<()> {
        let engine = self.identity.lock_engine()?;
        if engine.record().generation != request.expected_generation {
            return Err(IdentityError::Conflict);
        }
        let pin = engine
            .record()
            .pin_recovery
            .as_ref()
            .ok_or(IdentityError::InvalidDocumentChangeState)?;
        if pin.binding != request.binding || pin.phase != PinRecoveryPhase::Prepared {
            return Err(IdentityError::InvalidDocumentChangeState);
        }
        let mut store = crate::DidStore {
            runtime: std::sync::Arc::clone(engine.runtime()),
            registry_generation: 0,
        };
        // Complete any interrupted prior journal before preparing deletion.
        store.reload()?;
        // A retry after the deletion journal finished is already complete.
        // A replacement identity at the same DID still goes through exact-ID CAS.
        if !crate::registry::read_registry(engine.runtime().root())?
            .identities
            .contains_key(engine.did())
        {
            return Ok(());
        }
        store.discard_pin_recovery_namespace(
            engine.did(),
            engine.identity_id(),
            request.expected_generation,
            &request.binding,
        )?;
        Ok(())
    }

    pub fn proposal(&self) -> &PinRecoveryProposal {
        &self.proposal
    }
    pub fn sign_pin_recovery_intent(
        &mut self,
        request: PinRecoverySignRequest,
    ) -> IdentityResult<PinRecoverySignedIntent> {
        require_presence(request.user_presence_confirmed)?;
        let mut engine = self.identity.lock_engine()?;
        let guard = engine.runtime().acquire_write()?;
        let mut record = current_record(&engine, request.expected_generation)?;
        let pin = record
            .pin_recovery
            .as_ref()
            .ok_or(IdentityError::InvalidRequest)?;
        if pin.phase != PinRecoveryPhase::Prepared {
            return Err(IdentityError::InvalidDocumentChangeState);
        }
        let binding = pin.binding.clone();
        let base = request.remote.document.into_value();
        let evidence = super::convergence::evidence(request.remote.evidence);
        validate_verified_document(&base, &evidence)?;
        validate_checkpoint_progression(record.checkpoint.as_ref(), &evidence)?;
        validate_binding(&binding, &base)?;
        if method_root_fingerprint(&base)? != record.root_key_fingerprint {
            return Err(IdentityError::RootKeyMismatch);
        }
        let expected_candidate = candidate_document(&record, &base)?;
        if without_proof(&request.candidate_document)? != expected_candidate {
            return Err(IdentityError::InvalidRequest);
        }
        let checkpoint = crate::DocumentCheckpoint {
            document_version: evidence.document_version,
            registry_version: evidence.registry_version,
            document_digest: evidence.document_digest,
        };
        validate_challenge(
            &request.challenge,
            &binding,
            &checkpoint,
            "awiki.pin-recovery.device-commit.v1",
        )?;
        let intent = &request.challenge.intent;
        if intent["kind"] != "recover"
            || intent["expected_active_epoch"] != binding.backup_epoch
            || intent["backup_hash"] != json!(binding.encrypted_package_hash)
            || intent["new_device_proposal_hash"] != hash_json(&device_proposal(&record)?)?
            || intent["candidate_document_digest"] != hash_json(&expected_candidate)?
            || intent["registration_version"].is_null()
            || unique_receipts(&intent["verified_receipt_ids"])? < 2
        {
            return Err(IdentityError::InvalidRequest);
        }
        let root = record
            .keys
            .iter()
            .find(|key| key.kid == binding.root_kid)
            .ok_or(IdentityError::KeyUnavailable)?;
        let local = record
            .local_authorization
            .as_ref()
            .ok_or(IdentityError::CorruptState)?;
        let device = record
            .keys
            .iter()
            .find(|key| key.kid == local.signing_kid)
            .ok_or(IdentityError::KeyUnavailable)?;
        if record.state != IdentityState::Enrolling
            || record.root_capability != RootCapabilityState::Pending
            || root.state != KeyState::Pending
            || device.state != KeyState::Pending
        {
            return Err(IdentityError::InvalidDocumentChangeState);
        }
        let root_proof = sign_jws(
            &engine,
            root,
            &request.challenge.payload,
            "awiki-root-authorization+jwt",
        )?;
        let device_proof = sign_jws(
            &engine,
            device,
            &request.challenge.payload,
            "awiki-device-possession+jwt",
        )?;
        let method = anp::authentication::find_verification_method(&base, &root.kid)
            .ok_or(IdentityError::InvalidRequest)?;
        let public = anp::authentication::extract_public_key(&method)
            .map_err(|_| IdentityError::InvalidRequest)?;
        let prepared = anp::proof::prepare_w3c_proof(
            &expected_candidate,
            &public,
            &root.kid,
            anp::proof::ProofGenerationOptions {
                proof_purpose: Some("assertionMethod".to_owned()),
                proof_type: Some(anp::proof::PROOF_TYPE_DATA_INTEGRITY.to_owned()),
                cryptosuite: Some(anp::proof::CRYPTOSUITE_EDDSA_JCS_2022.to_owned()),
                domain: Some(binding.domain.clone()),
                challenge: Some(string(&request.challenge.payload, "challenge_id")?.to_owned()),
                ..Default::default()
            },
        )
        .map_err(|_| IdentityError::Internal)?;
        let signature = engine.sign_prepared(root, prepared.signing_input())?;
        let signed_document = anp::proof::complete_w3c_proof(prepared, &signature)
            .map_err(|_| IdentityError::Internal)?;
        // Persist before exposing proofs: an interrupted HTTP exchange can only reconcile.
        record.document = base;
        record.checkpoint = Some(checkpoint);
        let pin = record.pin_recovery.as_mut().unwrap();
        pin.phase = PinRecoveryPhase::PublicationUncertain;
        pin.challenge_id = Some(string(&request.challenge.payload, "challenge_id")?.to_owned());
        pin.signed_document = Some(signed_document.clone());
        pin.signed_payload = Some(request.challenge.payload.clone());
        persist_state_transition(&engine, &guard, &mut record)?;
        let generation = record.generation;
        drop(guard);
        engine.replace_record(record);
        self.proposal = proposal(&self.identity.reference(), engine.record())?;
        Ok(PinRecoverySignedIntent {
            challenge: request.challenge,
            root_proof,
            device_proof,
            signed_document,
            generation,
        })
    }

    /// Some(identity) means committed activation; None means verified NotCommitted reconciliation.
    pub fn complete_pin_root_recovery(
        &mut self,
        request: PinRecoveryCompletion,
    ) -> IdentityResult<Option<ManagedIdentity>> {
        let mut engine = self.identity.lock_engine()?;
        let guard = engine.runtime().acquire_write()?;
        let mut record = current_record(&engine, request.expected_generation)?;
        let pin = record
            .pin_recovery
            .as_ref()
            .ok_or(IdentityError::InvalidRequest)?;
        if pin.binding != request.binding
            || pin.challenge_id.as_deref() != Some(&request.challenge_id)
        {
            return Err(IdentityError::InvalidRequest);
        }
        let remote = request.remote.document.into_value();
        let evidence = super::convergence::evidence(request.remote.evidence);
        validate_verified_document(&remote, &evidence)?;
        validate_binding(&pin.binding, &remote)?;
        validate_checkpoint_progression(record.checkpoint.as_ref(), &evidence)?;
        match request.outcome {
            PinRecoveryRemoteOutcome::Committed => {
                if pin.signed_document.as_ref() != Some(&remote)
                    || !matches!(
                        pin.phase,
                        PinRecoveryPhase::PublicationUncertain | PinRecoveryPhase::Active
                    )
                {
                    return Err(IdentityError::InvalidRequest);
                }
                if pin.phase == PinRecoveryPhase::PublicationUncertain {
                    let base = record
                        .checkpoint
                        .as_ref()
                        .ok_or(IdentityError::CorruptState)?;
                    if evidence.document_version <= base.document_version
                        || evidence.registry_version <= base.registry_version
                    {
                        return Err(IdentityError::Conflict);
                    }
                }
                record.observe_devices(&remote)?;
                record.document = remote;
                record.checkpoint = Some(crate::DocumentCheckpoint {
                    document_version: evidence.document_version,
                    registry_version: evidence.registry_version,
                    document_digest: evidence.document_digest,
                });
                record.revision = evidence.document_version;
                record.state = IdentityState::Active;
                record.root_capability = RootCapabilityState::Active;
                record.pending_enrollment = None;
                for key in &mut record.keys {
                    if key.state == KeyState::Pending {
                        key.state = KeyState::Active;
                    }
                }
                record.pin_recovery.as_mut().unwrap().phase = PinRecoveryPhase::Active;
            }
            PinRecoveryRemoteOutcome::NotCommitted => {
                if pin.phase != PinRecoveryPhase::PublicationUncertain {
                    return Err(IdentityError::InvalidDocumentChangeState);
                }
                // A different device may have committed while this challenge was in flight.
                // A verified forward base is safe only if our proposed keys/device are absent.
                candidate_document(&record, &remote)?;
                record.observe_devices(&remote)?;
                record.document = remote;
                record.checkpoint = Some(crate::DocumentCheckpoint {
                    document_version: evidence.document_version,
                    registry_version: evidence.registry_version,
                    document_digest: evidence.document_digest,
                });
                let pin = record.pin_recovery.as_mut().unwrap();
                pin.phase = PinRecoveryPhase::Prepared;
                pin.challenge_id = None;
                pin.signed_document = None;
                pin.signed_payload = None;
            }
        }
        persist_state_transition(&engine, &guard, &mut record)?;
        drop(guard);
        engine.replace_record(record);
        self.proposal = proposal(&self.identity.reference(), engine.record())?;
        let active = request.outcome == PinRecoveryRemoteOutcome::Committed;
        drop(engine);
        Ok(active.then(|| ManagedIdentity {
            store_id: self.identity.store_id.clone(),
            reference: self.identity.reference(),
            engine: std::sync::Arc::clone(&self.identity.engine),
        }))
    }
}

fn session(identity: ManagedIdentity) -> IdentityResult<PinRootRecoverySession> {
    let proposal = {
        let engine = identity.lock_engine()?;
        proposal(&identity.reference(), engine.record())?
    };
    Ok(PinRootRecoverySession { identity, proposal })
}
fn proposal(
    reference: &IdentityRef,
    record: &IdentityRecord,
) -> IdentityResult<PinRecoveryProposal> {
    let pin = record
        .pin_recovery
        .as_ref()
        .ok_or(IdentityError::InvalidRequest)?;
    let local = record
        .local_authorization
        .as_ref()
        .ok_or(IdentityError::CorruptState)?;
    let key = |kid: &str| -> IdentityResult<EnrollmentPublicKey> {
        let key = record
            .keys
            .iter()
            .find(|key| key.kid == kid)
            .ok_or(IdentityError::KeyNotFound)?;
        Ok(EnrollmentPublicKey {
            kid: kid.to_owned(),
            public_key_multibase: key.public_key_multibase.clone(),
        })
    };
    let checkpoint = record
        .checkpoint
        .as_ref()
        .ok_or(IdentityError::CorruptState)?;
    Ok(PinRecoveryProposal {
        identity: reference.clone(),
        binding: pin.binding.clone(),
        generation: record.generation,
        phase: pin.phase,
        device_proposal: device_proposal(record)?,
        enrollment: EnrollmentProposal {
            enrollment_id: record
                .pending_enrollment
                .as_ref()
                .map(|p| p.enrollment_id.clone())
                .unwrap_or_else(|| pin.binding.operation_id.clone()),
            identity: reference.clone(),
            root_key_fingerprint: record.root_key_fingerprint.clone(),
            kind: EnrollmentProposalKind::Device {
                device_id: local.device_id.clone(),
                signing_key: key(&local.signing_kid)?,
                agreement_key: key(&local.e2ee_kid)?,
                profiles: local.profiles.clone(),
            },
            checkpoint: HostDocumentCheckpoint {
                document_version: checkpoint.document_version,
                registry_version: checkpoint.registry_version,
                document_digest: checkpoint.document_digest.clone(),
            },
        },
    })
}
#[cfg(test)]
mod tests;
