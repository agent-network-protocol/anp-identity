use serde::{Deserialize, Serialize};

use super::convergence::evidence;
use super::{ConvergenceOutcome, ConvergenceWorkflow, HostDocumentCheckpoint};
use crate::facade::{
    IdentityError, IdentityManager, IdentityRef, IdentityResult, ManagedIdentity,
    VerifiedRemoteDocument,
};
use crate::{
    Capabilities, EnrollmentSpec, PreparedEnrollment, PreparedRequestSigningEnrollment,
    RequestSigningEnrollmentSpec,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentCapabilities {
    pub did_wba: bool,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DeviceEnrollmentRequest {
    pub remote: VerifiedRemoteDocument,
    pub device_id: String,
    pub device_signing_fragment: String,
    pub device_agreement_fragment: String,
    pub profiles: Vec<String>,
    #[serde(default)]
    pub capabilities: EnrollmentCapabilities,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RequestSigningEnrollmentRequest {
    pub remote: VerifiedRemoteDocument,
    pub fragment: String,
    #[serde(default)]
    pub capabilities: EnrollmentCapabilities,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentPublicKey {
    pub kid: String,
    pub public_key_multibase: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EnrollmentProposalKind {
    Device {
        device_id: String,
        signing_key: EnrollmentPublicKey,
        agreement_key: EnrollmentPublicKey,
        profiles: Vec<String>,
    },
    RequestSigning {
        signing_key: EnrollmentPublicKey,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentProposal {
    pub enrollment_id: String,
    pub identity: IdentityRef,
    pub kind: EnrollmentProposalKind,
    pub root_key_fingerprint: String,
    pub checkpoint: HostDocumentCheckpoint,
}

pub struct EnrollmentSession {
    identity: ManagedIdentity,
    proposal: EnrollmentProposal,
}

pub trait EnrollmentWorkflow {
    fn begin_device_enrollment(
        &mut self,
        request: DeviceEnrollmentRequest,
    ) -> IdentityResult<EnrollmentSession>;

    fn begin_request_signing_enrollment(
        &mut self,
        request: RequestSigningEnrollmentRequest,
    ) -> IdentityResult<EnrollmentSession>;

    fn resume_enrollment(
        &self,
        reference: &IdentityRef,
    ) -> IdentityResult<Option<EnrollmentSession>>;
}

impl EnrollmentWorkflow for IdentityManager {
    fn begin_device_enrollment(
        &mut self,
        request: DeviceEnrollmentRequest,
    ) -> IdentityResult<EnrollmentSession> {
        let (engine, prepared) = self.engine_mut().prepare_enrollment(EnrollmentSpec {
            verified_document: request.remote.document.into_value(),
            evidence: evidence(request.remote.evidence),
            device_id: request.device_id,
            device_signing_fragment: request.device_signing_fragment,
            device_e2ee_fragment: request.device_agreement_fragment,
            profiles: request.profiles,
            capabilities: Capabilities {
                did_wba: request.capabilities.did_wba,
            },
        })?;
        let identity = self.wrap(engine);
        let proposal = device_proposal(identity.reference(), prepared);
        Ok(EnrollmentSession { identity, proposal })
    }

    fn begin_request_signing_enrollment(
        &mut self,
        request: RequestSigningEnrollmentRequest,
    ) -> IdentityResult<EnrollmentSession> {
        let (engine, prepared) =
            self.engine_mut()
                .prepare_request_signing_enrollment(RequestSigningEnrollmentSpec {
                    verified_document: request.remote.document.into_value(),
                    evidence: evidence(request.remote.evidence),
                    fragment: request.fragment,
                    capabilities: Capabilities {
                        did_wba: request.capabilities.did_wba,
                    },
                })?;
        let identity = self.wrap(engine);
        let proposal = request_signing_proposal(identity.reference(), prepared);
        Ok(EnrollmentSession { identity, proposal })
    }

    fn resume_enrollment(
        &self,
        reference: &IdentityRef,
    ) -> IdentityResult<Option<EnrollmentSession>> {
        let identity = self.get(reference)?;
        let proposal = {
            let engine = identity.lock_engine()?;
            if let Some(prepared) = engine.pending_enrollment() {
                Some(device_proposal(reference.clone(), prepared))
            } else {
                engine
                    .pending_request_signing_enrollment()
                    .map(|prepared| request_signing_proposal(reference.clone(), prepared))
            }
        };
        Ok(proposal.map(|proposal| EnrollmentSession { identity, proposal }))
    }
}

impl EnrollmentSession {
    pub fn proposal(&self) -> &EnrollmentProposal {
        &self.proposal
    }

    pub fn sign_device_assertion(&self, payload: &[u8]) -> IdentityResult<Vec<u8>> {
        let EnrollmentProposalKind::Device { signing_key, .. } = &self.proposal.kind else {
            return Err(IdentityError::CapabilityUnavailable);
        };
        self.identity
            .lock_engine()?
            .sign_pending_enrollment(&self.proposal.enrollment_id, &signing_key.kid, payload)
            .map_err(Into::into)
    }

    pub fn derive_device_shared_secret(
        &self,
        peer_public: [u8; 32],
    ) -> IdentityResult<super::ZeroizingSharedSecret> {
        let EnrollmentProposalKind::Device { agreement_key, .. } = &self.proposal.kind else {
            return Err(IdentityError::CapabilityUnavailable);
        };
        let shared = self.identity.lock_engine()?.ecdh_pending_enrollment(
            &self.proposal.enrollment_id,
            &agreement_key.kid,
            &peer_public,
        )?;
        Ok(super::ZeroizingSharedSecret::new(*shared.as_bytes()))
    }

    pub fn activate(
        &mut self,
        remote: VerifiedRemoteDocument,
    ) -> IdentityResult<ConvergenceOutcome> {
        let outcome = self.identity.adopt_verified_document(remote)?;
        if outcome != ConvergenceOutcome::Activated {
            return Err(IdentityError::InvalidDocumentChangeState);
        }
        Ok(outcome)
    }

    pub fn cancel(self, manager: &mut IdentityManager) -> IdentityResult<()> {
        if manager.store_id() != self.proposal.identity.store_id {
            return Err(IdentityError::IdentityNotFound);
        }
        let generation = manager.engine_mut().generation();
        manager.engine_mut().discard_unpublished_enrollment(
            &self.proposal.identity.did,
            &self.proposal.identity.identity_id,
            generation,
        )?;
        Ok(())
    }
}

fn device_proposal(identity: IdentityRef, prepared: PreparedEnrollment) -> EnrollmentProposal {
    EnrollmentProposal {
        enrollment_id: prepared.enrollment_id,
        identity,
        kind: EnrollmentProposalKind::Device {
            device_id: prepared.device_id,
            signing_key: EnrollmentPublicKey {
                kid: prepared.device_signing_key.kid,
                public_key_multibase: prepared.device_signing_key.public_key_multibase,
            },
            agreement_key: EnrollmentPublicKey {
                kid: prepared.device_e2ee_key.kid,
                public_key_multibase: prepared.device_e2ee_key.public_key_multibase,
            },
            profiles: prepared.profiles,
        },
        root_key_fingerprint: prepared.root_key_fingerprint,
        checkpoint: HostDocumentCheckpoint {
            document_version: prepared.checkpoint.document_version,
            registry_version: prepared.checkpoint.registry_version,
            document_digest: prepared.checkpoint.document_digest,
        },
    }
}

fn request_signing_proposal(
    identity: IdentityRef,
    prepared: PreparedRequestSigningEnrollment,
) -> EnrollmentProposal {
    EnrollmentProposal {
        enrollment_id: prepared.enrollment_id,
        identity,
        kind: EnrollmentProposalKind::RequestSigning {
            signing_key: EnrollmentPublicKey {
                kid: prepared.request_signing_key.kid,
                public_key_multibase: prepared.request_signing_key.public_key_multibase,
            },
        },
        root_key_fingerprint: prepared.root_key_fingerprint,
        checkpoint: HostDocumentCheckpoint {
            document_version: prepared.checkpoint.document_version,
            registry_version: prepared.checkpoint.registry_version,
            document_digest: prepared.checkpoint.document_digest,
        },
    }
}

#[cfg(test)]
mod tests;
