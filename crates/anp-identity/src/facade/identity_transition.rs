use std::sync::Arc;

use anp::authentication::{verify_active_e1_document, verify_transition_hop, TransitionAssurance};
use anp::proof::{ProofGenerationOptions, CRYPTOSUITE_EDDSA_JCS_2022, PROOF_TYPE_DATA_INTEGRITY};
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

use super::manager::IdentityManager;
use crate::facade::{DidDocument, IdentityError, IdentityRef, IdentityResult};
use crate::registry::{
    list_identity_transition_journals, read_identity, read_identity_transition_journal,
    read_registry, write_identity_transition_journal, IdentityTransitionJournal,
    IdentityTransitionJournalState,
};
use crate::{canonical_document_digest, DidIdentity, KeyOrigin, KeyRole, KeyState};

const MAX_OPERATION_ID_BYTES: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IdentityTransitionRequest {
    pub expected_current_did: String,
    pub operation_id: String,
    pub successor: IdentityRef,
    #[serde(default)]
    pub transition_document: Option<DidDocument>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PreparedIdentityTransition {
    pub operation_id: String,
    pub expected_current_did: String,
    pub successor_did: String,
    pub predecessor_document: DidDocument,
    pub successor_document: DidDocument,
    pub predecessor_digest: String,
    pub successor_digest: String,
    pub assurance: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityTransitionPublicationAttempt {
    operation_id: String,
    predecessor_digest: String,
    successor_digest: String,
    publication_generation: u64,
}

impl IdentityTransitionPublicationAttempt {
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub fn predecessor_digest(&self) -> &str {
        &self.predecessor_digest
    }

    pub fn successor_digest(&self) -> &str {
        &self.successor_digest
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityTransitionPublicationEvidence {
    pub predecessor_digest: String,
    pub successor_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum IdentityTransitionPublicationResult {
    Confirmed {
        evidence: IdentityTransitionPublicationEvidence,
    },
    RejectedBeforeAcceptance,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "observation", rename_all = "snake_case")]
pub enum IdentityTransitionRemoteObservation {
    RemoteOld {
        current_document: DidDocument,
    },
    Published {
        predecessor_document: DidDocument,
        successor_document: DidDocument,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "outcome", rename_all = "snake_case")]
/// Publication-journal outcome for a transition between two existing identities.
///
/// This outcome does not mutate the predecessor identity record, select a Store-wide
/// current DID, or update a remote user registry.
pub enum IdentityTransitionOutcome {
    ReadyForPublication,
    PublicationUncertain,
    /// The exact transition candidate was confirmed as published in the journal.
    Committed {
        current_did: String,
    },
    Aborted,
}

pub struct IdentityTransitionSession {
    runtime: Arc<crate::store::StoreRuntime>,
    journal: IdentityTransitionJournal,
    candidate: PreparedIdentityTransition,
}

impl IdentityManager {
    pub fn prepare_identity_transition(
        &mut self,
        request: IdentityTransitionRequest,
    ) -> IdentityResult<IdentityTransitionSession> {
        validate_request(&request, self.store_id())?;
        let runtime = Arc::clone(&self.engine.runtime);
        let guard = runtime.acquire_write()?;
        let registry = read_registry(runtime.root())?;
        if registry.generation != self.engine.registry_generation {
            return Err(IdentityError::Conflict);
        }

        if let Ok(existing) =
            read_identity_transition_journal(runtime.root(), &request.operation_id)
        {
            if journal_matches_request(&existing, &request) {
                drop(guard);
                return IdentityTransitionSession::from_journal(runtime, existing);
            }
            return Err(IdentityError::Conflict);
        }

        if list_identity_transition_journals(runtime.root())?
            .iter()
            .any(|journal| {
                journal.expected_current_did == request.expected_current_did
                    && journal.state != IdentityTransitionJournalState::Aborted
            })
        {
            return Err(IdentityError::Conflict);
        }

        let predecessor_summary = registry
            .identities
            .get(&request.expected_current_did)
            .ok_or(IdentityError::IdentityNotFound)?;
        let successor_summary = registry
            .identities
            .get(&request.successor.did)
            .ok_or(IdentityError::IdentityNotFound)?;
        if successor_summary.identity_id != request.successor.identity_id
            || predecessor_summary.identity_id == successor_summary.identity_id
        {
            return Err(IdentityError::InvalidRequest);
        }
        let predecessor_record = read_identity(runtime.root(), &predecessor_summary.identity_id)?;
        let successor_record = read_identity(runtime.root(), &successor_summary.identity_id)?;
        verify_active_e1_document(&predecessor_record.did, &predecessor_record.document)
            .map_err(|_| IdentityError::InvalidRequest)?;
        verify_active_e1_document(&successor_record.did, &successor_record.document)
            .map_err(|_| IdentityError::InvalidRequest)?;

        let created_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
        let predecessor_document = match request.transition_document {
            Some(document) => document.into_value(),
            None => create_verified_transition_document(
                &runtime,
                &predecessor_record,
                &successor_record.did,
                &created_at,
            )?,
        };
        let hop = verify_transition_hop(
            &predecessor_document,
            &successor_record.document,
            Some(&predecessor_record.document),
            None,
        )
        .map_err(|_| IdentityError::InvalidRequest)?;
        let predecessor_digest = canonical_document_digest(&predecessor_document)?;
        let successor_digest = canonical_document_digest(&successor_record.document)?;
        let journal = IdentityTransitionJournal::new(
            request.operation_id,
            request.expected_current_did,
            predecessor_record.identity_id,
            predecessor_record.generation,
            successor_record.did,
            successor_record.identity_id,
            successor_record.generation,
            predecessor_record.document,
            predecessor_document,
            successor_record.document,
            predecessor_digest,
            successor_digest,
            assurance_name(hop.assurance).to_string(),
            created_at,
        );
        write_identity_transition_journal(runtime.root(), &guard, &journal)?;
        drop(guard);
        IdentityTransitionSession::from_journal(runtime, journal)
    }

    pub fn resume_identity_transition(
        &mut self,
        expected_current_did: &str,
    ) -> IdentityResult<Option<IdentityTransitionSession>> {
        self.engine.reload()?;
        let runtime = Arc::clone(&self.engine.runtime);
        let mut matching = list_identity_transition_journals(runtime.root())?
            .into_iter()
            .filter(|journal| {
                journal.expected_current_did == expected_current_did
                    && matches!(
                        journal.state,
                        IdentityTransitionJournalState::Prepared
                            | IdentityTransitionJournalState::PublicationInFlight
                            | IdentityTransitionJournalState::PublicationUncertain
                    )
            });
        let journal = matching.next();
        if matching.next().is_some() {
            return Err(IdentityError::CorruptState);
        }
        journal
            .map(|journal| IdentityTransitionSession::from_journal(runtime, journal))
            .transpose()
    }
}

impl IdentityTransitionSession {
    fn from_journal(
        runtime: Arc<crate::store::StoreRuntime>,
        journal: IdentityTransitionJournal,
    ) -> IdentityResult<Self> {
        let candidate = candidate_from_journal(&journal)?;
        Ok(Self {
            runtime,
            journal,
            candidate,
        })
    }

    pub fn candidate(&self) -> &PreparedIdentityTransition {
        &self.candidate
    }

    pub fn begin_publication(&mut self) -> IdentityResult<IdentityTransitionPublicationAttempt> {
        let guard = self.runtime.acquire_write()?;
        let mut journal = self.reload_and_validate()?;
        match journal.state {
            IdentityTransitionJournalState::Prepared => {
                journal.state = IdentityTransitionJournalState::PublicationInFlight;
                journal.generation = next_generation(journal.generation)?;
                write_identity_transition_journal(self.runtime.root(), &guard, &journal)?;
            }
            IdentityTransitionJournalState::PublicationInFlight => {}
            _ => return Err(IdentityError::InvalidDocumentChangeState),
        }
        let attempt = attempt_from_journal(&journal);
        self.journal = journal;
        Ok(attempt)
    }

    pub fn complete(
        &mut self,
        attempt: IdentityTransitionPublicationAttempt,
        result: IdentityTransitionPublicationResult,
    ) -> IdentityResult<IdentityTransitionOutcome> {
        let guard = self.runtime.acquire_write()?;
        let mut journal = self.reload_and_validate()?;
        validate_attempt(&attempt, &journal)?;
        if journal.state != IdentityTransitionJournalState::PublicationInFlight {
            return Err(IdentityError::InvalidDocumentChangeState);
        }
        let outcome = match result {
            IdentityTransitionPublicationResult::Confirmed { evidence } => {
                validate_evidence(&evidence, &journal)?;
                journal.state = IdentityTransitionJournalState::Committed;
                IdentityTransitionOutcome::Committed {
                    current_did: journal.successor_did.clone(),
                }
            }
            IdentityTransitionPublicationResult::RejectedBeforeAcceptance => {
                journal.state = IdentityTransitionJournalState::Aborted;
                IdentityTransitionOutcome::Aborted
            }
            IdentityTransitionPublicationResult::Unknown => {
                journal.state = IdentityTransitionJournalState::PublicationUncertain;
                IdentityTransitionOutcome::PublicationUncertain
            }
        };
        journal.generation = next_generation(journal.generation)?;
        write_identity_transition_journal(self.runtime.root(), &guard, &journal)?;
        self.journal = journal;
        Ok(outcome)
    }

    pub fn reconcile(
        &mut self,
        observation: IdentityTransitionRemoteObservation,
    ) -> IdentityResult<IdentityTransitionOutcome> {
        let guard = self.runtime.acquire_write()?;
        let mut journal = self.reload_and_validate()?;
        if journal.state != IdentityTransitionJournalState::PublicationUncertain {
            return Err(IdentityError::InvalidDocumentChangeState);
        }
        let outcome = match observation {
            IdentityTransitionRemoteObservation::RemoteOld { current_document } => {
                verify_active_e1_document(
                    &journal.expected_current_did,
                    current_document.as_value(),
                )
                .map_err(|_| IdentityError::VerificationFailed)?;
                if canonical_document_digest(current_document.as_value())?
                    != canonical_document_digest(&journal.trusted_predecessor_document)?
                {
                    return Err(IdentityError::VerificationFailed);
                }
                journal.state = IdentityTransitionJournalState::Prepared;
                IdentityTransitionOutcome::ReadyForPublication
            }
            IdentityTransitionRemoteObservation::Published {
                predecessor_document,
                successor_document,
            } => {
                if canonical_document_digest(predecessor_document.as_value())?
                    != journal.predecessor_digest
                    || canonical_document_digest(successor_document.as_value())?
                        != journal.successor_digest
                {
                    return Err(IdentityError::VerificationFailed);
                }
                let hop = verify_transition_hop(
                    predecessor_document.as_value(),
                    successor_document.as_value(),
                    Some(&journal.trusted_predecessor_document),
                    None,
                )
                .map_err(|_| IdentityError::VerificationFailed)?;
                if assurance_name(hop.assurance) != journal.assurance {
                    return Err(IdentityError::VerificationFailed);
                }
                journal.state = IdentityTransitionJournalState::Committed;
                IdentityTransitionOutcome::Committed {
                    current_did: journal.successor_did.clone(),
                }
            }
        };
        journal.generation = next_generation(journal.generation)?;
        write_identity_transition_journal(self.runtime.root(), &guard, &journal)?;
        self.journal = journal;
        Ok(outcome)
    }

    fn reload_and_validate(&self) -> IdentityResult<IdentityTransitionJournal> {
        let journal =
            read_identity_transition_journal(self.runtime.root(), &self.journal.operation_id)?;
        if journal.generation != self.journal.generation
            || journal.expected_current_did != self.journal.expected_current_did
            || journal.successor_did != self.journal.successor_did
            || journal.predecessor_digest != self.journal.predecessor_digest
            || journal.successor_digest != self.journal.successor_digest
        {
            return Err(IdentityError::Conflict);
        }
        let predecessor = read_identity(self.runtime.root(), &journal.predecessor_identity_id)?;
        let successor = read_identity(self.runtime.root(), &journal.successor_identity_id)?;
        if predecessor.generation != journal.predecessor_generation
            || predecessor.did != journal.expected_current_did
            || successor.generation != journal.successor_generation
            || successor.did != journal.successor_did
        {
            return Err(IdentityError::Conflict);
        }
        Ok(journal)
    }
}

fn validate_request(request: &IdentityTransitionRequest, store_id: &str) -> IdentityResult<()> {
    if request.expected_current_did.is_empty()
        || request.operation_id.is_empty()
        || request.operation_id.len() > MAX_OPERATION_ID_BYTES
        || request.operation_id.as_bytes().contains(&0)
        || request.successor.store_id != store_id
        || request.successor.did == request.expected_current_did
    {
        return Err(IdentityError::InvalidRequest);
    }
    Ok(())
}

fn journal_matches_request(
    journal: &IdentityTransitionJournal,
    request: &IdentityTransitionRequest,
) -> bool {
    let supplied_transition_matches = match request.transition_document.as_ref() {
        Some(document) => canonical_document_digest(document.as_value())
            .map(|digest| digest == journal.predecessor_digest)
            .unwrap_or(false),
        None => true,
    };
    journal.operation_id == request.operation_id
        && journal.expected_current_did == request.expected_current_did
        && journal.successor_did == request.successor.did
        && journal.successor_identity_id == request.successor.identity_id
        && supplied_transition_matches
}

fn candidate_from_journal(
    journal: &IdentityTransitionJournal,
) -> IdentityResult<PreparedIdentityTransition> {
    if canonical_document_digest(&journal.predecessor_document)? != journal.predecessor_digest
        || canonical_document_digest(&journal.successor_document)? != journal.successor_digest
    {
        return Err(IdentityError::CorruptState);
    }
    Ok(PreparedIdentityTransition {
        operation_id: journal.operation_id.clone(),
        expected_current_did: journal.expected_current_did.clone(),
        successor_did: journal.successor_did.clone(),
        predecessor_document: DidDocument::from_verified(journal.predecessor_document.clone()),
        successor_document: DidDocument::from_verified(journal.successor_document.clone()),
        predecessor_digest: journal.predecessor_digest.clone(),
        successor_digest: journal.successor_digest.clone(),
        assurance: journal.assurance.clone(),
    })
}

fn attempt_from_journal(
    journal: &IdentityTransitionJournal,
) -> IdentityTransitionPublicationAttempt {
    IdentityTransitionPublicationAttempt {
        operation_id: journal.operation_id.clone(),
        predecessor_digest: journal.predecessor_digest.clone(),
        successor_digest: journal.successor_digest.clone(),
        publication_generation: journal.generation,
    }
}

fn validate_attempt(
    attempt: &IdentityTransitionPublicationAttempt,
    journal: &IdentityTransitionJournal,
) -> IdentityResult<()> {
    if attempt.operation_id != journal.operation_id
        || attempt.predecessor_digest != journal.predecessor_digest
        || attempt.successor_digest != journal.successor_digest
        || attempt.publication_generation != journal.generation
    {
        return Err(IdentityError::Conflict);
    }
    Ok(())
}

fn validate_evidence(
    evidence: &IdentityTransitionPublicationEvidence,
    journal: &IdentityTransitionJournal,
) -> IdentityResult<()> {
    if evidence.predecessor_digest != journal.predecessor_digest
        || evidence.successor_digest != journal.successor_digest
    {
        return Err(IdentityError::VerificationFailed);
    }
    Ok(())
}

fn next_generation(generation: u64) -> IdentityResult<u64> {
    generation.checked_add(1).ok_or(IdentityError::Conflict)
}

fn create_verified_transition_document(
    runtime: &Arc<crate::store::StoreRuntime>,
    predecessor_record: &crate::registry::IdentityRecord,
    successor_did: &str,
    created_at: &str,
) -> IdentityResult<serde_json::Value> {
    let mut unsigned = predecessor_record.document.clone();
    let object = unsigned
        .as_object_mut()
        .ok_or(IdentityError::CorruptState)?;
    object.remove("proof");
    object.insert("deactivated".to_string(), serde_json::Value::Bool(true));
    object.insert(
        "successorDid".to_string(),
        serde_json::Value::String(successor_did.to_string()),
    );
    let identity = DidIdentity {
        runtime: Arc::clone(runtime),
        record: predecessor_record.clone(),
    };
    let root_kid = predecessor_record
        .keys
        .iter()
        .find(|key| {
            key.role == KeyRole::RootControl
                && key.origin == KeyOrigin::Managed
                && key.state == KeyState::Active
                && !key.material_erased
        })
        .map(|key| key.kid.clone())
        .ok_or(IdentityError::KeyUnavailable)?;
    identity
        .sign_document_proof(
            &unsigned,
            &root_kid,
            ProofGenerationOptions {
                proof_purpose: Some("assertionMethod".to_string()),
                proof_type: Some(PROOF_TYPE_DATA_INTEGRITY.to_string()),
                cryptosuite: Some(CRYPTOSUITE_EDDSA_JCS_2022.to_string()),
                created: Some(created_at.to_string()),
                domain: None,
                challenge: None,
            },
        )
        .map_err(Into::into)
}

fn assurance_name(assurance: TransitionAssurance) -> &'static str {
    match assurance {
        TransitionAssurance::Verified => "verified",
        TransitionAssurance::RecoveryVerified => "recovery_verified",
        TransitionAssurance::ProviderAsserted => "provider_asserted",
        TransitionAssurance::Unverified => "unverified",
    }
}

#[cfg(test)]
mod tests;
