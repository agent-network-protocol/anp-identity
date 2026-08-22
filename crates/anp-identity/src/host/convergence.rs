use serde::{Deserialize, Serialize};

use crate::{
    AdoptDocumentOutcome, AdoptVerifiedDocumentSpec, IdentityResult, ManagedIdentity,
    VerifiedDocumentEvidence,
};

use crate::facade::{VerifiedPublicationEvidence, VerifiedRemoteDocument};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConvergenceOutcome {
    Activated,
    Updated,
    Unchanged,
    Revoked,
}

pub trait ConvergenceWorkflow {
    fn adopt_verified_document(
        &mut self,
        remote: VerifiedRemoteDocument,
    ) -> IdentityResult<ConvergenceOutcome>;
}

impl ConvergenceWorkflow for ManagedIdentity {
    fn adopt_verified_document(
        &mut self,
        remote: VerifiedRemoteDocument,
    ) -> IdentityResult<ConvergenceOutcome> {
        let outcome = self
            .lock_engine()?
            .adopt_verified_document(AdoptVerifiedDocumentSpec {
                document: remote.document.into_value(),
                evidence: evidence(remote.evidence),
            })?;
        Ok(match outcome {
            AdoptDocumentOutcome::Activated => ConvergenceOutcome::Activated,
            AdoptDocumentOutcome::Updated => ConvergenceOutcome::Updated,
            AdoptDocumentOutcome::Unchanged => ConvergenceOutcome::Unchanged,
            AdoptDocumentOutcome::Revoked => ConvergenceOutcome::Revoked,
        })
    }
}

pub(crate) fn evidence(value: VerifiedPublicationEvidence) -> VerifiedDocumentEvidence {
    VerifiedDocumentEvidence {
        document_version: value.document_version,
        registry_version: value.registry_version,
        document_digest: value.document_digest,
    }
}
