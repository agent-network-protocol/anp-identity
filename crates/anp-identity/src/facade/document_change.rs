use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};

use super::identity::project_public_identity;
use crate::facade::{
    DidDocument, IdentityError, IdentityRef, IdentityResult, ManagedIdentity, PublicIdentity,
};
use crate::{
    DeviceAddSpec, DeviceMutationSpec, DevicePublicKeySpec, DidIdentity, DocumentUpdateSpec,
    PublicationState, ReconcileOutcome, RequestSigningMutationSpec, RequestSigningPublicKeySpec,
    RequestSigningRotation, ServiceSpec,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DocumentChangeRequest {
    pub changes: Vec<DocumentChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "change", rename_all = "snake_case")]
pub enum DocumentChange {
    RotateSigningKey {
        old_kid: String,
        new_fragment: String,
    },
    AddAuthenticationKey {
        key: PublicKeyInput,
    },
    RemoveAuthenticationKey {
        kid: String,
    },
    AddDevice {
        device: DeviceInput,
    },
    RemoveDevice {
        device_id: String,
    },
    ReplaceServices {
        services: Vec<IdentityService>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublicKeyInput {
    pub kid: String,
    pub public_key_multibase: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceInput {
    pub device_id: String,
    pub signing_key: PublicKeyInput,
    pub agreement_key: PublicKeyInput,
    pub profiles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityService {
    pub id: String,
    pub service_type: String,
    pub service_endpoint: String,
    pub service_did: Option<String>,
    #[serde(default)]
    pub profiles: Vec<String>,
    #[serde(default)]
    pub security_profiles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PreparedDocumentChange {
    pub operation_id: String,
    pub candidate_document: DidDocument,
    pub candidate_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerifiedPublicationEvidence {
    pub document_version: u64,
    pub registry_version: u64,
    pub document_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct VerifiedRemoteDocument {
    pub document: DidDocument,
    pub evidence: VerifiedPublicationEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublicationAttempt {
    operation_id: String,
    candidate_digest: String,
    publication_generation: u64,
}

impl PublicationAttempt {
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub fn candidate_digest(&self) -> &str {
        &self.candidate_digest
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum PublicationResult {
    Confirmed {
        evidence: VerifiedPublicationEvidence,
    },
    RejectedBeforeAcceptance,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum DocumentChangeOutcome {
    ReadyForPublication,
    PublicationUncertain,
    Committed { identity: PublicIdentity },
    Aborted,
}

pub struct DocumentChangeSession {
    store_id: String,
    reference: IdentityRef,
    engine: Arc<Mutex<DidIdentity>>,
    candidate: PreparedDocumentChange,
}

impl ManagedIdentity {
    pub fn prepare_document_change(
        &mut self,
        request: DocumentChangeRequest,
    ) -> IdentityResult<DocumentChangeSession> {
        let spec = request.into_engine_spec()?;
        let prepared = self.lock_engine()?.prepare_update(spec)?;
        Ok(DocumentChangeSession::new(
            self.store_id.clone(),
            self.reference.clone(),
            Arc::clone(&self.engine),
            PreparedDocumentChange {
                operation_id: prepared.revision_id,
                candidate_document: DidDocument::from_verified(prepared.candidate_document),
                candidate_digest: prepared.candidate_digest,
            },
        ))
    }

    pub fn resume_document_change(&mut self) -> IdentityResult<Option<DocumentChangeSession>> {
        let pending = self.lock_engine()?.pending_revision();
        Ok(pending.map(|pending| {
            DocumentChangeSession::new(
                self.store_id.clone(),
                self.reference.clone(),
                Arc::clone(&self.engine),
                PreparedDocumentChange {
                    operation_id: pending.revision_id,
                    candidate_document: DidDocument::from_verified(pending.candidate_document),
                    candidate_digest: pending.candidate_digest,
                },
            )
        }))
    }
}

impl DocumentChangeSession {
    fn new(
        store_id: String,
        reference: IdentityRef,
        engine: Arc<Mutex<DidIdentity>>,
        candidate: PreparedDocumentChange,
    ) -> Self {
        Self {
            store_id,
            reference,
            engine,
            candidate,
        }
    }

    pub fn candidate(&self) -> &PreparedDocumentChange {
        &self.candidate
    }

    pub fn begin_publication(&mut self) -> IdentityResult<PublicationAttempt> {
        let mut engine = self.lock_engine()?;
        let pending = self.required_pending(&engine)?;
        match pending.state {
            PublicationState::Prepared => {
                engine.begin_publication(&self.candidate.operation_id)?;
            }
            PublicationState::PublicationInFlight | PublicationState::Published => {}
            PublicationState::PublicationUncertain => {
                return Err(IdentityError::InvalidDocumentChangeState);
            }
        }
        let pending = self.required_pending(&engine)?;
        Ok(PublicationAttempt {
            operation_id: self.candidate.operation_id.clone(),
            candidate_digest: self.candidate.candidate_digest.clone(),
            publication_generation: pending.generation,
        })
    }

    pub fn complete(
        &mut self,
        attempt: PublicationAttempt,
        result: PublicationResult,
    ) -> IdentityResult<DocumentChangeOutcome> {
        let mut engine = self.lock_engine()?;
        let pending = self.required_pending(&engine)?;
        self.validate_attempt(&attempt, &pending)?;

        match result {
            PublicationResult::Confirmed { evidence } => {
                validate_evidence(&evidence, &self.candidate.candidate_digest)?;
                match pending.state {
                    PublicationState::PublicationInFlight => {
                        engine.mark_published(&self.candidate.operation_id)?;
                    }
                    PublicationState::Published => {}
                    PublicationState::Prepared | PublicationState::PublicationUncertain => {
                        return Err(IdentityError::InvalidDocumentChangeState);
                    }
                }
                engine.commit_update(&self.candidate.operation_id)?;
                Ok(DocumentChangeOutcome::Committed {
                    identity: project_public_identity(&self.store_id, &engine)?,
                })
            }
            PublicationResult::RejectedBeforeAcceptance => {
                if pending.state != PublicationState::PublicationInFlight {
                    return Err(IdentityError::InvalidDocumentChangeState);
                }
                engine.reject_publication_before_acceptance(&self.candidate.operation_id)?;
                engine.abort_update(&self.candidate.operation_id)?;
                Ok(DocumentChangeOutcome::Aborted)
            }
            PublicationResult::Unknown => {
                if pending.state != PublicationState::PublicationInFlight {
                    return Err(IdentityError::InvalidDocumentChangeState);
                }
                engine.mark_publication_uncertain(&self.candidate.operation_id)?;
                Ok(DocumentChangeOutcome::PublicationUncertain)
            }
        }
    }

    pub fn reconcile(
        &mut self,
        observation: VerifiedRemoteDocument,
    ) -> IdentityResult<DocumentChangeOutcome> {
        validate_evidence(
            &observation.evidence,
            &crate::canonical_document_digest(observation.document.as_value())?,
        )?;
        let mut engine = self.lock_engine()?;
        let pending = self.required_pending(&engine)?;
        if pending.state != PublicationState::PublicationUncertain {
            return Err(IdentityError::InvalidDocumentChangeState);
        }
        match engine.reconcile_update(
            &self.candidate.operation_id,
            observation.document.as_value(),
        )? {
            ReconcileOutcome::RemoteOld => Ok(DocumentChangeOutcome::ReadyForPublication),
            ReconcileOutcome::Committed => Ok(DocumentChangeOutcome::Committed {
                identity: project_public_identity(&self.store_id, &engine)?,
            }),
        }
    }

    fn lock_engine(&self) -> IdentityResult<MutexGuard<'_, DidIdentity>> {
        self.engine.lock().map_err(|_| IdentityError::Internal)
    }

    fn required_pending(
        &self,
        engine: &DidIdentity,
    ) -> IdentityResult<crate::PendingRevisionSummary> {
        let pending = engine
            .pending_revision()
            .ok_or(IdentityError::DocumentChangeNotFound)?;
        if pending.revision_id != self.candidate.operation_id
            || pending.candidate_digest != self.candidate.candidate_digest
            || engine.identity_id() != self.reference.identity_id
            || engine.did() != self.reference.did
        {
            return Err(IdentityError::Conflict);
        }
        Ok(pending)
    }

    fn validate_attempt(
        &self,
        attempt: &PublicationAttempt,
        pending: &crate::PendingRevisionSummary,
    ) -> IdentityResult<()> {
        if attempt.operation_id != self.candidate.operation_id
            || attempt.candidate_digest != self.candidate.candidate_digest
            || attempt.publication_generation != pending.generation
        {
            return Err(IdentityError::Conflict);
        }
        Ok(())
    }
}

impl DocumentChangeRequest {
    fn into_engine_spec(self) -> IdentityResult<DocumentUpdateSpec> {
        if self.changes.is_empty() {
            return Err(IdentityError::InvalidRequest);
        }
        let mut request_signing_rotation = None;
        let mut request_signing_mutations = Vec::new();
        let mut device_mutations = Vec::new();
        let mut services = None;

        for change in self.changes {
            match change {
                DocumentChange::RotateSigningKey {
                    old_kid,
                    new_fragment,
                } => {
                    if request_signing_rotation.is_some() {
                        return Err(IdentityError::InvalidRequest);
                    }
                    request_signing_rotation = Some(RequestSigningRotation {
                        old_kid,
                        new_fragment,
                    });
                }
                DocumentChange::AddAuthenticationKey { key } => {
                    request_signing_mutations.push(RequestSigningMutationSpec::Add {
                        key: RequestSigningPublicKeySpec {
                            kid: key.kid,
                            public_key_multibase: key.public_key_multibase,
                        },
                    });
                }
                DocumentChange::RemoveAuthenticationKey { kid } => {
                    request_signing_mutations.push(RequestSigningMutationSpec::Remove { kid });
                }
                DocumentChange::AddDevice { device } => {
                    device_mutations.push(DeviceMutationSpec::Add {
                        device: DeviceAddSpec {
                            device_id: device.device_id,
                            signing_key: DevicePublicKeySpec {
                                kid: device.signing_key.kid,
                                public_key_multibase: device.signing_key.public_key_multibase,
                            },
                            e2ee_key: DevicePublicKeySpec {
                                kid: device.agreement_key.kid,
                                public_key_multibase: device.agreement_key.public_key_multibase,
                            },
                            profiles: device.profiles,
                        },
                    });
                }
                DocumentChange::RemoveDevice { device_id } => {
                    device_mutations.push(DeviceMutationSpec::Remove { device_id });
                }
                DocumentChange::ReplaceServices {
                    services: replacements,
                } => {
                    if services.is_some() {
                        return Err(IdentityError::InvalidRequest);
                    }
                    services = Some(replacements.into_iter().map(Into::into).collect());
                }
            }
        }

        Ok(DocumentUpdateSpec {
            request_signing_rotation,
            request_signing_mutations,
            device_mutations,
            services,
        })
    }
}

impl From<IdentityService> for ServiceSpec {
    fn from(value: IdentityService) -> Self {
        Self {
            id: value.id,
            service_type: value.service_type,
            service_endpoint: value.service_endpoint,
            service_did: value.service_did,
            profiles: value.profiles,
            security_profiles: value.security_profiles,
        }
    }
}

fn validate_evidence(
    evidence: &VerifiedPublicationEvidence,
    expected_digest: &str,
) -> IdentityResult<()> {
    if evidence.document_version == 0
        || evidence.registry_version == 0
        || evidence.document_digest != expected_digest
    {
        return Err(IdentityError::InvalidRequest);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
