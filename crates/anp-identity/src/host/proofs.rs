use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::facade::signing::select_key;
use crate::{
    IdentityError, IdentityResult, KeyOrigin, KeyRole, KeySelector, KeyState, ManagedIdentity,
};

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ObjectProofRequest {
    pub key: KeySelector,
    pub document: Value,
    pub issuer_did: String,
    pub created: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct DocumentProofOptions {
    pub proof_purpose: Option<String>,
    pub proof_type: Option<String>,
    pub cryptosuite: Option<String>,
    pub created: Option<String>,
    pub domain: Option<String>,
    pub challenge: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DocumentProofRequest {
    pub key: KeySelector,
    pub document: Value,
    #[serde(default)]
    pub options: DocumentProofOptions,
}

pub trait TypedProofPort {
    fn sign_object_proof(&self, request: ObjectProofRequest) -> IdentityResult<Value>;
    fn sign_document_proof(&self, request: DocumentProofRequest) -> IdentityResult<Value>;
}

impl TypedProofPort for ManagedIdentity {
    fn sign_object_proof(&self, request: ObjectProofRequest) -> IdentityResult<Value> {
        let engine = self.lock_engine()?;
        let metadata = select_key(&engine, &request.key, KeyRole::DeviceSigning)?;
        engine
            .sign_object_proof(
                &metadata.kid,
                &request.document,
                &request.issuer_did,
                request.created,
            )
            .map_err(Into::into)
    }

    fn sign_document_proof(&self, request: DocumentProofRequest) -> IdentityResult<Value> {
        let engine = self.lock_engine()?;
        let kid = select_root_key(&engine, &request.key)?;
        engine
            .sign_document_proof(
                &request.document,
                &kid,
                anp::proof::ProofGenerationOptions {
                    proof_purpose: request.options.proof_purpose,
                    proof_type: request.options.proof_type,
                    cryptosuite: request.options.cryptosuite,
                    created: request.options.created,
                    domain: request.options.domain,
                    challenge: request.options.challenge,
                },
            )
            .map_err(Into::into)
    }
}

pub(crate) fn select_root_key(
    identity: &crate::DidIdentity,
    selector: &KeySelector,
) -> IdentityResult<String> {
    let usable = |metadata: &&crate::KeyMetadata| {
        metadata.role == KeyRole::RootControl
            && metadata.origin == KeyOrigin::Managed
            && metadata.state == KeyState::Active
            && !metadata.material_erased
    };
    match selector {
        KeySelector::Kid(kid) => {
            let metadata = identity.key_metadata(kid)?;
            if !usable(&metadata) {
                return Err(if metadata.role == KeyRole::RootControl {
                    IdentityError::KeyUnavailable
                } else {
                    IdentityError::KeyPurposeViolation
                });
            }
            Ok(metadata.kid.clone())
        }
        KeySelector::Default => {
            let mut candidates = identity.keys().iter().filter(usable);
            let selected = candidates.next().ok_or(IdentityError::KeyUnavailable)?;
            if candidates.next().is_some() {
                return Err(IdentityError::AmbiguousKey);
            }
            Ok(selected.kid.clone())
        }
    }
}

#[cfg(test)]
mod tests;
