use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::facade::{IdentityError, IdentityResult, KeyAlgorithm, ManagedIdentity};
use crate::{DidError, KeyMetadata, KeyOrigin, KeyRole, KeyState};

const APPLICATION_ASSERTION_PREFIX: &[u8] = b"anp.identity.application-assertion.v1\0";
const MAX_DOMAIN_BYTES: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeySelector {
    Default,
    Kid(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "purpose", rename_all = "snake_case")]
pub enum SigningPurpose {
    Authentication,
    DeviceAssertion,
    ApplicationAssertion { domain: String },
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignRequest {
    pub purpose: SigningPurpose,
    pub key: KeySelector,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    pub kid: String,
    pub algorithm: KeyAlgorithm,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerifyRequest {
    pub purpose: SigningPurpose,
    pub kid: String,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VerificationOutcome {
    Valid,
    Invalid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct OriginProofOptions {
    pub created: Option<i64>,
    pub expires: Option<i64>,
    pub nonce: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OriginProofRequest {
    pub method: String,
    pub meta: Value,
    pub body: Value,
    pub key: KeySelector,
    #[serde(default)]
    pub options: OriginProofOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SignedOriginProof {
    pub content_digest: String,
    pub signature_input: String,
    pub signature: String,
}

impl ManagedIdentity {
    pub fn sign(&self, request: SignRequest) -> IdentityResult<Signature> {
        let role = purpose_role(&request.purpose)?;
        let payload = payload_for_purpose(&request.purpose, &request.payload)?;
        let engine = self.lock_engine()?;
        let metadata = select_key(&engine, &request.key, role)?;
        let bytes = engine.sign(&metadata.kid, &payload)?;
        Ok(Signature {
            kid: metadata.kid.clone(),
            algorithm: KeyAlgorithm::Ed25519,
            bytes,
        })
    }

    pub fn sign_origin_proof(
        &self,
        request: OriginProofRequest,
    ) -> IdentityResult<SignedOriginProof> {
        let engine = self.lock_engine()?;
        let metadata = select_origin_proof_key(&engine, &request.key)?;
        let proof = engine.sign_origin_proof(
            &request.method,
            &request.meta,
            &request.body,
            &metadata.kid,
            anp::proof::Rfc9421OriginProofGenerationOptions {
                created: request.options.created,
                expires: request.options.expires,
                nonce: request.options.nonce,
                label: None,
            },
        )?;
        Ok(SignedOriginProof {
            content_digest: proof.content_digest,
            signature_input: proof.signature_input,
            signature: proof.signature,
        })
    }

    pub fn verify(&self, request: VerifyRequest) -> IdentityResult<VerificationOutcome> {
        let role = purpose_role(&request.purpose)?;
        let engine = self.lock_engine()?;
        let metadata = engine.key_metadata(&request.kid)?;
        require_role(metadata, role)?;
        require_relationship(&engine, metadata, role)?;
        if metadata.state == KeyState::Revoked || metadata.material_erased {
            return Err(IdentityError::KeyUnavailable);
        }
        let payload = payload_for_purpose(&request.purpose, &request.payload)?;
        match engine.verify(&metadata.kid, &payload, &request.signature) {
            Ok(()) => Ok(VerificationOutcome::Valid),
            Err(DidError::VerificationFailed) => Ok(VerificationOutcome::Invalid),
            Err(error) => Err(error.into()),
        }
    }
}

fn select_origin_proof_key<'a>(
    identity: &'a crate::DidIdentity,
    selector: &KeySelector,
) -> IdentityResult<&'a KeyMetadata> {
    match selector {
        KeySelector::Kid(kid) => {
            let metadata = identity.key_metadata(kid)?;
            require_origin_proof_key(identity, metadata)?;
            Ok(metadata)
        }
        KeySelector::Default => {
            let mut candidates = identity
                .keys()
                .iter()
                .filter(|metadata| require_origin_proof_key(identity, metadata).is_ok());
            let selected = candidates.next().ok_or(IdentityError::KeyUnavailable)?;
            if candidates.next().is_some() {
                return Err(IdentityError::AmbiguousKey);
            }
            Ok(selected)
        }
    }
}

fn require_origin_proof_key(
    identity: &crate::DidIdentity,
    metadata: &KeyMetadata,
) -> IdentityResult<()> {
    if !matches!(
        metadata.role,
        KeyRole::DeviceSigning | KeyRole::RequestSigning
    ) {
        return Err(IdentityError::KeyPurposeViolation);
    }
    require_relationship(identity, metadata, metadata.role)?;
    if metadata.origin != KeyOrigin::Managed
        || metadata.state != KeyState::Active
        || metadata.material_erased
    {
        return Err(IdentityError::KeyUnavailable);
    }
    Ok(())
}

pub(crate) fn select_key<'a>(
    identity: &'a crate::DidIdentity,
    selector: &KeySelector,
    role: KeyRole,
) -> IdentityResult<&'a KeyMetadata> {
    match selector {
        KeySelector::Kid(kid) => {
            let metadata = identity.key_metadata(kid)?;
            require_role(metadata, role)?;
            require_relationship(identity, metadata, role)?;
            if metadata.origin != KeyOrigin::Managed
                || metadata.state != KeyState::Active
                || metadata.material_erased
            {
                return Err(IdentityError::KeyUnavailable);
            }
            Ok(metadata)
        }
        KeySelector::Default => {
            let mut candidates = identity.keys().iter().filter(|metadata| {
                metadata.role == role
                    && metadata.origin == KeyOrigin::Managed
                    && metadata.state == KeyState::Active
                    && !metadata.material_erased
                    && relationship_authorizes(identity, metadata, role)
            });
            let selected = candidates.next().ok_or(IdentityError::KeyUnavailable)?;
            if candidates.next().is_some() {
                return Err(IdentityError::AmbiguousKey);
            }
            Ok(selected)
        }
    }
}

fn require_role(metadata: &KeyMetadata, role: KeyRole) -> IdentityResult<()> {
    if metadata.role != role {
        return Err(IdentityError::KeyPurposeViolation);
    }
    Ok(())
}

fn require_relationship(
    identity: &crate::DidIdentity,
    metadata: &KeyMetadata,
    role: KeyRole,
) -> IdentityResult<()> {
    if !relationship_authorizes(identity, metadata, role) {
        return Err(IdentityError::KeyPurposeViolation);
    }
    Ok(())
}

fn relationship_authorizes(
    identity: &crate::DidIdentity,
    metadata: &KeyMetadata,
    role: KeyRole,
) -> bool {
    match role {
        KeyRole::RequestSigning => {
            anp::authentication::is_authentication_authorized(identity.document(), &metadata.kid)
        }
        KeyRole::DeviceSigning | KeyRole::E2eeSigning => {
            anp::authentication::is_assertion_method_authorized(identity.document(), &metadata.kid)
        }
        KeyRole::RootControl | KeyRole::E2eeAgreement => false,
    }
}

fn purpose_role(purpose: &SigningPurpose) -> IdentityResult<KeyRole> {
    match purpose {
        SigningPurpose::Authentication => Ok(KeyRole::RequestSigning),
        SigningPurpose::DeviceAssertion => Ok(KeyRole::DeviceSigning),
        SigningPurpose::ApplicationAssertion { domain } => {
            validate_domain(domain)?;
            Ok(KeyRole::E2eeSigning)
        }
    }
}

fn payload_for_purpose(purpose: &SigningPurpose, payload: &[u8]) -> IdentityResult<Vec<u8>> {
    let SigningPurpose::ApplicationAssertion { domain } = purpose else {
        return Ok(payload.to_vec());
    };
    validate_domain(domain)?;
    let domain_bytes = domain.as_bytes();
    let mut separated = Vec::with_capacity(
        APPLICATION_ASSERTION_PREFIX.len() + 2 + domain_bytes.len() + payload.len(),
    );
    separated.extend_from_slice(APPLICATION_ASSERTION_PREFIX);
    separated.extend_from_slice(&(domain_bytes.len() as u16).to_be_bytes());
    separated.extend_from_slice(domain_bytes);
    separated.extend_from_slice(payload);
    Ok(separated)
}

fn validate_domain(domain: &str) -> IdentityResult<()> {
    if domain.is_empty()
        || domain.trim() != domain
        || domain.len() > MAX_DOMAIN_BYTES
        || domain.as_bytes().contains(&0)
    {
        return Err(IdentityError::InvalidRequest);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
