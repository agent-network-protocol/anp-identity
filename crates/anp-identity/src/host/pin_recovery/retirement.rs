//! A successful V4 can fence only an unprojected, exact PIN-origin namespace.
use super::*;
use crate::pin_recovery::PinRecoveryV4RetirementRecord;
use crate::registry::{
    list_identity_transition_journals, read_registry, IdentityTransitionJournalState,
};

/// The trusted Core must hold its owner lock while checking all current and
/// historical projections and previous_custody references and issuing this scope.
/// These assertions are not independently discoverable inside ANP Identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "scope", rename_all = "snake_case", deny_unknown_fields)]
pub enum PinRecoveryV4RetirementScope {
    UnprojectedPinRecovery {
        never_projected: bool,
        absent_from_previous_custody: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PinRecoveryCurrentBinding {
    pub full_handle: String,
    pub did: String,
    pub binding_generation: String,
}

/// Host-verified evidence from a successful exact V4 and a fresh authoritative
/// Handle read. This is not a replacement for network result authentication.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct VerifiedPinRecoveryV4Supersession {
    pub v4_operation_id: String,
    pub v4_intent_hash: String,
    pub account_user_id: String,
    pub full_handle: String,
    pub previous_did: String,
    pub previous_binding_generation: String,
    pub successor_did: String,
    pub successor_binding_generation: String,
    pub committed_checkpoint: HostDocumentCheckpoint,
    pub current_binding: PinRecoveryCurrentBinding,
    pub current_document: VerifiedRemoteDocument,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PinRecoveryV4RetirementRequest {
    pub identity: IdentityRef,
    pub expected_generation: u64,
    pub binding: PinRecoveryBinding,
    pub scope: PinRecoveryV4RetirementScope,
    pub evidence: VerifiedPinRecoveryV4Supersession,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PinRecoveryV4RetirementOutcome {
    pub identity: IdentityRef,
    pub generation: u64,
}

impl IdentityManager {
    /// Revokes a never-projected PIN namespace before exact ordinary deletion.
    /// Previously projected identities and retained historical custody are outside
    /// this capability even when the remote V4 has succeeded.
    pub fn retire_pin_root_recovery_after_v4(
        &mut self,
        request: PinRecoveryV4RetirementRequest,
    ) -> IdentityResult<PinRecoveryV4RetirementOutcome> {
        if request.identity.store_id != self.store_id()
            || request.identity.did != request.binding.did
            || !matches!(
                request.scope,
                PinRecoveryV4RetirementScope::UnprojectedPinRecovery {
                    never_projected: true,
                    absent_from_previous_custody: true,
                }
            )
        {
            return Err(IdentityError::InvalidRequest);
        }
        self.engine.reload()?;
        let engine = self.engine.open_identity(&request.identity.did)?;
        let runtime = std::sync::Arc::clone(engine.runtime());
        let guard = runtime.acquire_write()?;
        let mut record = read_identity(runtime.root(), engine.identity_id())?;
        if record.identity_id != request.identity.identity_id
            || record.generation != engine.record().generation
        {
            return Err(IdentityError::Conflict);
        }
        let pin = record
            .pin_recovery
            .as_ref()
            .ok_or(IdentityError::CapabilityUnavailable)?;
        if pin.binding != request.binding {
            return Err(IdentityError::InvalidRequest);
        }
        validate_binding(&request.binding, &record.document)?;
        validate_supersession(&request.evidence, &request.binding)?;
        let public_evidence =
            serde_json::to_value(&request.evidence).map_err(|_| IdentityError::InvalidRequest)?;
        let public_scope =
            serde_json::to_value(&request.scope).map_err(|_| IdentityError::InvalidRequest)?;
        if pin.phase == PinRecoveryPhase::SupersededByV4 {
            let previous = pin
                .superseded_by_v4
                .as_ref()
                .ok_or(IdentityError::CorruptState)?;
            if request.expected_generation != previous.source_generation
                && request.expected_generation != record.generation
            {
                return Err(IdentityError::Conflict);
            }
            if immutable_evidence(&previous.evidence) != immutable_evidence(&public_evidence)
                || previous.scope != public_scope
            {
                return Err(IdentityError::Conflict);
            }
            if record.state != IdentityState::Revoked
                || record.root_capability != RootCapabilityState::Absent
                || record.keys.iter().any(|key| key.state != KeyState::Revoked)
            {
                return Err(IdentityError::CorruptState);
            }
            return Ok(PinRecoveryV4RetirementOutcome {
                identity: request.identity,
                generation: record.generation,
            });
        }
        if record.generation != request.expected_generation {
            return Err(IdentityError::Conflict);
        }
        validate_pin_origin(&record)?;
        if list_identity_transition_journals(runtime.root())?
            .iter()
            .any(|journal| {
                (journal.predecessor_identity_id == record.identity_id
                    || journal.successor_identity_id == record.identity_id)
                    && matches!(
                        journal.state,
                        IdentityTransitionJournalState::Prepared
                            | IdentityTransitionJournalState::PublicationInFlight
                            | IdentityTransitionJournalState::PublicationUncertain
                    )
            })
        {
            return Err(IdentityError::Conflict);
        }
        // Fence before deletion: a late PIN completion cannot reactivate this
        // namespace, even if deleting the sealed key files fails or is interrupted.
        record.state = IdentityState::Revoked;
        record.root_capability = RootCapabilityState::Absent;
        record.pending_enrollment = None;
        for key in &mut record.keys {
            key.state = KeyState::Revoked;
        }
        let pin = record.pin_recovery.as_mut().unwrap();
        pin.phase = PinRecoveryPhase::SupersededByV4;
        pin.superseded_by_v4 = Some(PinRecoveryV4RetirementRecord {
            source_generation: request.expected_generation,
            evidence: public_evidence,
            scope: public_scope,
        });
        persist_state_transition(&engine, &guard, &mut record)?;
        self.engine.registry_generation = read_registry(runtime.root())?.generation;
        Ok(PinRecoveryV4RetirementOutcome {
            identity: request.identity,
            generation: record.generation,
        })
    }
}

fn validate_pin_origin(record: &IdentityRecord) -> IdentityResult<()> {
    let pin = record
        .pin_recovery
        .as_ref()
        .ok_or(IdentityError::CapabilityUnavailable)?;
    let key_state = match pin.phase {
        PinRecoveryPhase::Prepared | PinRecoveryPhase::PublicationUncertain
            if record.state == IdentityState::Enrolling
                && record.root_capability == RootCapabilityState::Pending
                && record.pending_enrollment.is_some() =>
        {
            KeyState::Pending
        }
        PinRecoveryPhase::Active
            if record.state == IdentityState::Active
                && record.root_capability == RootCapabilityState::Active
                && record.pending_enrollment.is_none() =>
        {
            KeyState::Active
        }
        _ => return Err(IdentityError::InvalidDocumentChangeState),
    };
    let local = record
        .local_authorization
        .as_ref()
        .ok_or(IdentityError::CorruptState)?;
    if record.pending_revision.is_some()
        || record.pending_root_transfer.is_some()
        || record.pending_request_signing.is_some()
        || record.keys.len() != 3
        || record.keys.iter().any(|key| {
            key.origin != KeyOrigin::Managed || key.state != key_state || key.material_erased
        })
    {
        return Err(IdentityError::InvalidDocumentChangeState);
    }
    for (role, kid) in [
        (KeyRole::RootControl, &pin.binding.root_kid),
        (KeyRole::DeviceSigning, &local.signing_kid),
        (KeyRole::E2eeAgreement, &local.e2ee_kid),
    ] {
        if record
            .keys
            .iter()
            .filter(|key| key.role == role && key.kid == *kid)
            .count()
            != 1
        {
            return Err(IdentityError::InvalidDocumentChangeState);
        }
    }
    Ok(())
}

fn validate_supersession(
    evidence: &VerifiedPinRecoveryV4Supersession,
    old: &PinRecoveryBinding,
) -> IdentityResult<()> {
    let current = &evidence.current_binding;
    if !v4_operation_id(&evidence.v4_operation_id)
        || !evidence
            .v4_intent_hash
            .strip_prefix("sha256:")
            .is_some_and(hash32)
        || evidence.account_user_id != old.account_user_id
        || evidence.full_handle != old.handle
        || evidence.previous_did != old.did
        || evidence.previous_binding_generation != old.binding_generation
        || evidence.successor_did == old.did
        || evidence.successor_did.chars().count() > 640
        || !generation(&evidence.successor_binding_generation)
        || !decimal_greater(
            &evidence.successor_binding_generation,
            &old.binding_generation,
        )
        || current.full_handle != evidence.full_handle
        || current.did != evidence.successor_did
        || current.binding_generation != evidence.successor_binding_generation
    {
        return Err(IdentityError::InvalidRequest);
    }
    let committed = &evidence.committed_checkpoint;
    if committed.document_version == 0
        || committed.registry_version == 0
        || !committed
            .document_digest
            .strip_prefix("sha256:")
            .is_some_and(hash32)
    {
        return Err(IdentityError::InvalidRequest);
    }
    let document = evidence.current_document.document.as_value();
    let current_evidence =
        super::super::convergence::evidence(evidence.current_document.evidence.clone());
    validate_verified_document(document, &current_evidence)?;
    anp::authentication::verify_active_e1_document(&evidence.successor_did, document)
        .map_err(|_| IdentityError::VerificationFailed)?;
    if method_root_fingerprint(document)?.is_none() || document["id"] != evidence.successor_did {
        return Err(IdentityError::InvalidRequest);
    }
    let root_kid = document["proof"]["verificationMethod"]
        .as_str()
        .ok_or(IdentityError::InvalidRequest)?;
    let root_method = anp::authentication::find_verification_method(document, root_kid)
        .ok_or(IdentityError::InvalidRequest)?;
    let root_public = anp::authentication::extract_public_key(&root_method)
        .map_err(|_| IdentityError::InvalidRequest)?;
    if !matches!(root_public, anp::PublicKeyMaterial::Ed25519(_))
        || crate::document::public_key_multibase(&root_public)? == old.root_public_key_multibase
    {
        return Err(IdentityError::RootKeyMismatch);
    }
    let checkpoint = crate::DocumentCheckpoint {
        document_version: committed.document_version,
        registry_version: committed.registry_version,
        document_digest: committed.document_digest.clone(),
    };
    validate_checkpoint_progression(Some(&checkpoint), &current_evidence)?;
    Ok(())
}

fn decimal_greater(next: &str, previous: &str) -> bool {
    next.len() > previous.len() || (next.len() == previous.len() && next > previous)
}

fn immutable_evidence(value: &Value) -> Value {
    let mut value = value.clone();
    if let Some(object) = value.as_object_mut() {
        object.remove("current_document");
    }
    value
}

// Preserve the existing Handle Recovery V4 operation-id contract. Realm PIN
// operation UUIDs are a different wire field and retain their UUID validation.
fn v4_operation_id(value: &str) -> bool {
    let count = value.chars().count();
    (1..=128).contains(&count)
        && !value.chars().any(|character| {
            character.is_whitespace() || character == '\u{7f}' || (character as u32) < 0x20
        })
}
