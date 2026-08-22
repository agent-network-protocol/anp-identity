use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::provider_authorization::ConsumedOneTimeAuthorization;
use super::{
    capability, recipient_public_key_digest, IssuedAuthorizationContext, KeyAgreementPort,
    KeyAgreementRequest, OneTimeCapabilityToken, OneTimeOperationBinding, ProviderAuthorization,
    ProviderAuthorizationError,
};
use crate::{IdentityError, IdentityRef, KeySelector, ManagedIdentity};

pub const SEALED_SECRET_PROTOCOL: &str = "anp-sealed-secret/1";
pub const SEALED_SECRET_INFO: &[u8] = b"anp.identity.sealed-secret.v1";
const ECDH_SEALED_OPERATION: &str = "ecdh_sealed";
#[cfg(feature = "root-export")]
const ROOT_EXPORT_SEALED_OPERATION: &str = "export_root_key_sealed";
#[cfg(feature = "key-import")]
const ROOT_IMPORT_SEALED_OPERATION: &str = "import_legacy_root_transfer_sealed";

/// HPKE ciphertext safe to carry across the TypeScript bridge.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SealedSecretEnvelope {
    pub protocol: String,
    pub suite: String,
    pub encapped_key_b64u: String,
    pub ciphertext_b64u: String,
}

impl SealedSecretEnvelope {
    pub fn from_handoff(handoff: &anp::sealed_handoff::SealedHandoff) -> Self {
        Self {
            protocol: SEALED_SECRET_PROTOCOL.to_owned(),
            suite: anp::sealed_handoff::SEALED_HANDOFF_SUITE.to_owned(),
            encapped_key_b64u: URL_SAFE_NO_PAD.encode(handoff.encapped_key()),
            ciphertext_b64u: URL_SAFE_NO_PAD.encode(handoff.ciphertext()),
        }
    }

    pub fn to_handoff(&self) -> Result<anp::sealed_handoff::SealedHandoff, SealedProviderError> {
        if self.protocol != SEALED_SECRET_PROTOCOL
            || self.suite != anp::sealed_handoff::SEALED_HANDOFF_SUITE
        {
            return Err(SealedProviderError::EnvelopeInvalid);
        }
        let encapped = URL_SAFE_NO_PAD
            .decode(&self.encapped_key_b64u)
            .map_err(|_| SealedProviderError::EnvelopeInvalid)?;
        let ciphertext = URL_SAFE_NO_PAD
            .decode(&self.ciphertext_b64u)
            .map_err(|_| SealedProviderError::EnvelopeInvalid)?;
        anp::sealed_handoff::SealedHandoff::from_parts(&encapped, ciphertext)
            .map_err(|_| SealedProviderError::EnvelopeInvalid)
    }
}

/// Exact, token-bound request for External Provider ECDH.
pub struct SealedKeyAgreementRequest {
    pub identity: IdentityRef,
    pub kid: String,
    pub peer_public: [u8; 32],
    pub recipient_public_key: [u8; 32],
    pub request_id: String,
    pub token: OneTimeCapabilityToken,
}

/// Exact, user-confirmed request for the legacy AWiki Root Transfer sender.
#[cfg(feature = "root-export")]
pub struct SealedRootExportRequest {
    pub identity: IdentityRef,
    pub kid: String,
    pub recipient_public_key: [u8; 32],
    pub request_id: String,
    pub user_presence_confirmed: bool,
    pub token: OneTimeCapabilityToken,
}

#[cfg(feature = "key-import")]
pub struct SealedRootImportPreparation {
    pub identity: IdentityRef,
    pub evidence: super::LegacyRootImportEvidence,
    pub encoding: super::RootPrivateKeyEncoding,
    pub request_id: String,
}

/// Offer safe to cross TypeScript. The corresponding private recipient key stays in
/// [`PreparedSealedRootImport`].
#[cfg(feature = "key-import")]
pub struct SealedImportOffer {
    pub recipient_public_key: [u8; 32],
    pub request_id: String,
    pub token: OneTimeCapabilityToken,
    pub authorization: IssuedAuthorizationContext,
    pub aad_b64u: String,
}

#[cfg(feature = "key-import")]
pub struct PreparedSealedRootImport {
    recipient: anp::sealed_handoff::SealedHandoffRecipient,
    preparation: SealedRootImportPreparation,
    binding: OneTimeOperationBinding,
    aad: Vec<u8>,
}

#[cfg(feature = "key-import")]
impl PreparedSealedRootImport {
    pub fn prepare(
        authorization: &ProviderAuthorization,
        lease: &super::ProviderCapabilityLease,
        preparation: SealedRootImportPreparation,
        ttl_seconds: i64,
    ) -> Result<(Self, SealedImportOffer), SealedProviderError> {
        let recipient = anp::sealed_handoff::SealedHandoffRecipient::generate();
        let binding = sealed_root_import_binding(&preparation, recipient.public_key())?;
        let issued = authorization.issue_one_time_with_context(lease, &binding, ttl_seconds)?;
        let aad = sealed_operation_aad(&issued.context, &binding, &preparation.identity)?;
        let offer = SealedImportOffer {
            recipient_public_key: *recipient.public_key(),
            request_id: preparation.request_id.clone(),
            token: issued.token,
            authorization: issued.context,
            aad_b64u: URL_SAFE_NO_PAD.encode(&aad),
        };
        Ok((
            Self {
                recipient,
                preparation,
                binding,
                aad,
            },
            offer,
        ))
    }

    pub fn complete(
        self,
        identity: &mut ManagedIdentity,
        authorization: &ProviderAuthorization,
        token: OneTimeCapabilityToken,
        envelope: &SealedSecretEnvelope,
    ) -> Result<super::LegacyRootImportOutcome, SealedProviderError> {
        use super::{LegacyRootImportRequest, RootImportPort};

        let consumed = authorization.consume_for_operation(&token, &self.binding)?;
        validate_identity_binding(&identity.reference(), &self.preparation.identity, &consumed)?;
        let expected_aad = sealed_aad(
            ROOT_IMPORT_SEALED_OPERATION,
            &self.preparation.identity,
            &self.preparation.evidence.root_kid,
            &self.preparation.request_id,
            &self.binding.operation_input_digest,
            self.recipient.public_key(),
            &consumed,
        )?;
        if expected_aad != self.aad {
            return Err(SealedProviderError::Authorization);
        }
        let root_key = self
            .recipient
            .open(&envelope.to_handoff()?, SEALED_SECRET_INFO, &self.aad)
            .map_err(|_| SealedProviderError::EnvelopeInvalid)?;
        identity
            .import_legacy_root(LegacyRootImportRequest {
                evidence: self.preparation.evidence,
                encoding: self.preparation.encoding,
                root_key,
            })
            .map_err(Into::into)
    }
}

#[cfg(feature = "root-export")]
impl SealedRootExportRequest {
    pub fn operation_binding(&self) -> Result<OneTimeOperationBinding, SealedProviderError> {
        sealed_root_export_binding(
            &self.identity,
            &self.kid,
            &self.recipient_public_key,
            &self.request_id,
            self.user_presence_confirmed,
        )
    }
}

impl SealedKeyAgreementRequest {
    pub fn operation_binding(&self) -> Result<OneTimeOperationBinding, SealedProviderError> {
        sealed_key_agreement_binding(
            &self.identity,
            &self.kid,
            &self.peer_public,
            &self.recipient_public_key,
            &self.request_id,
        )
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum SealedProviderError {
    #[error("the provider authorization is invalid")]
    Authorization,
    #[error("the sealed provider request does not match the identity")]
    IdentityBinding,
    #[error("the sealed provider request is invalid")]
    InvalidRequest,
    #[error("the identity operation failed")]
    Identity,
    #[error("the sealed envelope is invalid")]
    EnvelopeInvalid,
}

impl From<ProviderAuthorizationError> for SealedProviderError {
    fn from(_: ProviderAuthorizationError) -> Self {
        Self::Authorization
    }
}

impl From<IdentityError> for SealedProviderError {
    fn from(_: IdentityError) -> Self {
        Self::Identity
    }
}

pub trait SealedKeyAgreementPort {
    fn derive_shared_secret_sealed(
        &self,
        authorization: &ProviderAuthorization,
        request: SealedKeyAgreementRequest,
    ) -> Result<SealedSecretEnvelope, SealedProviderError>;
}

#[cfg(feature = "root-export")]
pub trait SealedRootExportPort {
    fn export_root_key_sealed(
        &self,
        authorization: &ProviderAuthorization,
        request: SealedRootExportRequest,
    ) -> Result<SealedSecretEnvelope, SealedProviderError>;
}

impl SealedKeyAgreementPort for ManagedIdentity {
    fn derive_shared_secret_sealed(
        &self,
        authorization: &ProviderAuthorization,
        request: SealedKeyAgreementRequest,
    ) -> Result<SealedSecretEnvelope, SealedProviderError> {
        let binding = request.operation_binding()?;
        let consumed = authorization.consume_for_operation(&request.token, &binding)?;
        validate_identity_binding(&self.reference(), &request.identity, &consumed)?;
        let shared = self.derive_shared_secret(KeyAgreementRequest {
            key: KeySelector::Kid(request.kid.clone()),
            peer_public: request.peer_public,
        })?;
        let aad = sealed_aad(
            ECDH_SEALED_OPERATION,
            &request.identity,
            &request.kid,
            &request.request_id,
            &binding.operation_input_digest,
            &request.recipient_public_key,
            &consumed,
        )?;
        let sealed = anp::sealed_handoff::SealedHandoff::seal(
            &request.recipient_public_key,
            SEALED_SECRET_INFO,
            &aad,
            shared.as_bytes(),
        )
        .map_err(|_| SealedProviderError::EnvelopeInvalid)?;
        Ok(SealedSecretEnvelope::from_handoff(&sealed))
    }
}

#[cfg(feature = "root-export")]
impl SealedRootExportPort for ManagedIdentity {
    fn export_root_key_sealed(
        &self,
        authorization: &ProviderAuthorization,
        request: SealedRootExportRequest,
    ) -> Result<SealedSecretEnvelope, SealedProviderError> {
        use super::{RootExportPort, UserConfirmedRootExportRequest};

        let binding = request.operation_binding()?;
        let consumed = authorization.consume_for_operation(&request.token, &binding)?;
        validate_identity_binding(&self.reference(), &request.identity, &consumed)?;
        let exported = self.export_root_for_legacy_envelope(UserConfirmedRootExportRequest {
            key: KeySelector::Kid(request.kid.clone()),
            user_presence_confirmed: request.user_presence_confirmed,
        })?;
        let aad = sealed_aad(
            ROOT_EXPORT_SEALED_OPERATION,
            &request.identity,
            &request.kid,
            &request.request_id,
            &binding.operation_input_digest,
            &request.recipient_public_key,
            &consumed,
        )?;
        let sealed = anp::sealed_handoff::SealedHandoff::seal(
            &request.recipient_public_key,
            SEALED_SECRET_INFO,
            &aad,
            exported.as_pkcs8_der(),
        )
        .map_err(|_| SealedProviderError::EnvelopeInvalid)?;
        Ok(SealedSecretEnvelope::from_handoff(&sealed))
    }
}

pub fn sealed_key_agreement_binding(
    identity: &IdentityRef,
    kid: &str,
    peer_public: &[u8; 32],
    recipient_public_key: &[u8; 32],
    request_id: &str,
) -> Result<OneTimeOperationBinding, SealedProviderError> {
    validate_request(identity, kid, request_id)?;
    #[derive(Serialize)]
    struct DigestInput<'a> {
        protocol: &'static str,
        operation: &'static str,
        store_id: &'a str,
        identity_id: &'a str,
        did: &'a str,
        kid: &'a str,
        algorithm: &'static str,
        peer_public_b64u: String,
        recipient_public_key_digest: String,
        request_id: &'a str,
    }
    let input = DigestInput {
        protocol: SEALED_SECRET_PROTOCOL,
        operation: ECDH_SEALED_OPERATION,
        store_id: &identity.store_id,
        identity_id: &identity.identity_id,
        did: &identity.did,
        kid,
        algorithm: "X25519",
        peer_public_b64u: URL_SAFE_NO_PAD.encode(peer_public),
        recipient_public_key_digest: recipient_public_key_digest(recipient_public_key),
        request_id,
    };
    Ok(OneTimeOperationBinding {
        capability: capability::IDENTITY_ECDH_SEALED.to_owned(),
        identity_id: identity.identity_id.clone(),
        operation: ECDH_SEALED_OPERATION.to_owned(),
        kid: Some(kid.to_owned()),
        request_id: request_id.to_owned(),
        recipient_public_key: *recipient_public_key,
        operation_input_digest: canonical_digest(&input)?,
    })
}

#[cfg(feature = "root-export")]
pub fn sealed_root_export_binding(
    identity: &IdentityRef,
    kid: &str,
    recipient_public_key: &[u8; 32],
    request_id: &str,
    user_presence_confirmed: bool,
) -> Result<OneTimeOperationBinding, SealedProviderError> {
    validate_request(identity, kid, request_id)?;
    if !user_presence_confirmed {
        return Err(SealedProviderError::Authorization);
    }
    #[derive(Serialize)]
    struct DigestInput<'a> {
        protocol: &'static str,
        operation: &'static str,
        store_id: &'a str,
        identity_id: &'a str,
        did: &'a str,
        kid: &'a str,
        recipient_public_key_digest: String,
        request_id: &'a str,
        user_presence_confirmed: bool,
    }
    let input = DigestInput {
        protocol: SEALED_SECRET_PROTOCOL,
        operation: ROOT_EXPORT_SEALED_OPERATION,
        store_id: &identity.store_id,
        identity_id: &identity.identity_id,
        did: &identity.did,
        kid,
        recipient_public_key_digest: recipient_public_key_digest(recipient_public_key),
        request_id,
        user_presence_confirmed,
    };
    Ok(OneTimeOperationBinding {
        capability: capability::AWIKI_LEGACY_ROOT_TRANSFER_V1.to_owned(),
        identity_id: identity.identity_id.clone(),
        operation: ROOT_EXPORT_SEALED_OPERATION.to_owned(),
        kid: Some(kid.to_owned()),
        request_id: request_id.to_owned(),
        recipient_public_key: *recipient_public_key,
        operation_input_digest: canonical_digest(&input)?,
    })
}

#[cfg(feature = "key-import")]
pub fn sealed_root_import_binding(
    preparation: &SealedRootImportPreparation,
    recipient_public_key: &[u8; 32],
) -> Result<OneTimeOperationBinding, SealedProviderError> {
    validate_request(
        &preparation.identity,
        &preparation.evidence.root_kid,
        &preparation.request_id,
    )?;
    if preparation.evidence.target_did != preparation.identity.did {
        return Err(SealedProviderError::IdentityBinding);
    }
    #[derive(Serialize)]
    struct DigestInput<'a> {
        protocol: &'static str,
        operation: &'static str,
        store_id: &'a str,
        identity_id: &'a str,
        did: &'a str,
        request_id: &'a str,
        recipient_public_key_digest: String,
        encoding: super::RootPrivateKeyEncoding,
        evidence: &'a super::LegacyRootImportEvidence,
    }
    let input = DigestInput {
        protocol: SEALED_SECRET_PROTOCOL,
        operation: ROOT_IMPORT_SEALED_OPERATION,
        store_id: &preparation.identity.store_id,
        identity_id: &preparation.identity.identity_id,
        did: &preparation.identity.did,
        request_id: &preparation.request_id,
        recipient_public_key_digest: recipient_public_key_digest(recipient_public_key),
        encoding: preparation.encoding,
        evidence: &preparation.evidence,
    };
    Ok(OneTimeOperationBinding {
        capability: capability::AWIKI_LEGACY_ROOT_TRANSFER_V1.to_owned(),
        identity_id: preparation.identity.identity_id.clone(),
        operation: ROOT_IMPORT_SEALED_OPERATION.to_owned(),
        kid: Some(preparation.evidence.root_kid.clone()),
        request_id: preparation.request_id.clone(),
        recipient_public_key: *recipient_public_key,
        operation_input_digest: canonical_digest(&input)?,
    })
}

fn validate_identity_binding(
    actual: &IdentityRef,
    requested: &IdentityRef,
    consumed: &ConsumedOneTimeAuthorization,
) -> Result<(), SealedProviderError> {
    if actual != requested || consumed.store_id != requested.store_id {
        return Err(SealedProviderError::IdentityBinding);
    }
    Ok(())
}

fn sealed_aad(
    operation: &'static str,
    identity: &IdentityRef,
    kid: &str,
    request_id: &str,
    operation_input_digest: &str,
    recipient_public_key: &[u8; 32],
    consumed: &ConsumedOneTimeAuthorization,
) -> Result<Vec<u8>, SealedProviderError> {
    sealed_aad_values(
        operation,
        identity,
        kid,
        request_id,
        operation_input_digest,
        recipient_public_key,
        &consumed.provider_instance_id,
        &consumed.parent_lease_id,
        &consumed.consumer,
        &consumed.capability,
    )
}

pub fn sealed_operation_aad(
    context: &IssuedAuthorizationContext,
    binding: &OneTimeOperationBinding,
    identity: &IdentityRef,
) -> Result<Vec<u8>, SealedProviderError> {
    if context.store_id != identity.store_id || context.capability != binding.capability {
        return Err(SealedProviderError::IdentityBinding);
    }
    let kid = binding
        .kid
        .as_deref()
        .ok_or(SealedProviderError::InvalidRequest)?;
    sealed_aad_values(
        binding.operation.as_str(),
        identity,
        kid,
        &binding.request_id,
        &binding.operation_input_digest,
        &binding.recipient_public_key,
        &context.provider_instance_id,
        &context.parent_lease_id,
        &context.consumer,
        &context.capability,
    )
}

#[allow(clippy::too_many_arguments)]
fn sealed_aad_values(
    operation: &str,
    identity: &IdentityRef,
    kid: &str,
    request_id: &str,
    operation_input_digest: &str,
    recipient_public_key: &[u8; 32],
    provider_instance_id: &str,
    parent_lease_id: &str,
    consumer: &str,
    capability: &str,
) -> Result<Vec<u8>, SealedProviderError> {
    #[derive(Serialize)]
    struct Aad<'a> {
        protocol_version: &'static str,
        operation: &'a str,
        provider_instance_id: &'a str,
        parent_lease_id: &'a str,
        consumer: &'a str,
        capability: &'a str,
        store_id: &'a str,
        identity_id: &'a str,
        kid: &'a str,
        request_id: &'a str,
        recipient_public_key_digest: String,
        canonical_request_digest: &'a str,
    }
    serde_json_canonicalizer::to_vec(&Aad {
        protocol_version: SEALED_SECRET_PROTOCOL,
        operation,
        provider_instance_id,
        parent_lease_id,
        consumer,
        capability,
        store_id: &identity.store_id,
        identity_id: &identity.identity_id,
        kid,
        request_id,
        recipient_public_key_digest: recipient_public_key_digest(recipient_public_key),
        canonical_request_digest: operation_input_digest,
    })
    .map_err(|_| SealedProviderError::InvalidRequest)
}

fn canonical_digest(value: &impl Serialize) -> Result<String, SealedProviderError> {
    let canonical =
        serde_json_canonicalizer::to_vec(value).map_err(|_| SealedProviderError::InvalidRequest)?;
    let mut digest = Sha256::new();
    digest.update(b"anp.identity.sealed-operation.v1\0");
    digest.update(canonical);
    Ok(format!(
        "sha256:{}",
        URL_SAFE_NO_PAD.encode(digest.finalize())
    ))
}

fn validate_request(
    identity: &IdentityRef,
    kid: &str,
    request_id: &str,
) -> Result<(), SealedProviderError> {
    if identity.store_id.trim().is_empty()
        || identity.identity_id.trim().is_empty()
        || identity.did.trim().is_empty()
        || kid.trim().is_empty()
        || request_id.trim().is_empty()
    {
        return Err(SealedProviderError::InvalidRequest);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anp::sealed_handoff::SealedHandoffRecipient;

    fn create_identity() -> (tempfile::TempDir, ManagedIdentity) {
        let root = tempfile::tempdir().unwrap();
        let mut manager = crate::IdentityManager::initialize(crate::IdentityManagerConfig {
            state_root: root.path().to_path_buf(),
            root_key: crate::RootKeySource::Injected(crate::InjectedStoreKey::new(
                "sealed-ecdh",
                [0x51; 32],
            )),
        })
        .unwrap();
        let identity = manager
            .create(crate::CreateIdentityRequest {
                profile: crate::DidProfile::E1,
                domain: "example.com".to_owned(),
                port: None,
                path_segments: vec!["sealed-ecdh".to_owned()],
                capabilities: crate::Capabilities { did_wba: true },
                managed_keys: vec![
                    crate::ManagedKeySpec {
                        fragment: "root".to_owned(),
                        role: crate::KeyRole::RootControl,
                    },
                    crate::ManagedKeySpec {
                        fragment: "request".to_owned(),
                        role: crate::KeyRole::RequestSigning,
                    },
                    crate::ManagedKeySpec {
                        fragment: "agreement".to_owned(),
                        role: crate::KeyRole::E2eeAgreement,
                    },
                ],
                external_keys: Vec::new(),
                services: Vec::new(),
                agent_description_url: None,
                extensions: Vec::new(),
            })
            .unwrap();
        (root, identity)
    }

    #[test]
    fn sealed_ecdh_roundtrips_and_binds_token_request_and_aad() {
        let (_root, identity) = create_identity();
        let reference = identity.reference();
        let kid = format!("{}#agreement", reference.did);
        let authority = ProviderAuthorization::new();
        let lease = authority
            .acquire_lease(
                "dsh-awiki".to_owned(),
                [capability::IDENTITY_ECDH_SEALED.to_owned()],
                reference.store_id.clone(),
                600,
            )
            .unwrap();
        let recipient = SealedHandoffRecipient::generate();
        let binding = sealed_key_agreement_binding(
            &reference,
            &kid,
            &x25519_dalek::X25519_BASEPOINT_BYTES,
            recipient.public_key(),
            "request-1",
        )
        .unwrap();
        let token = authority.issue_one_time(&lease, &binding, 60).unwrap();
        let envelope = identity
            .derive_shared_secret_sealed(
                &authority,
                SealedKeyAgreementRequest {
                    identity: reference.clone(),
                    kid: kid.clone(),
                    peer_public: x25519_dalek::X25519_BASEPOINT_BYTES,
                    recipient_public_key: *recipient.public_key(),
                    request_id: "request-1".to_owned(),
                    token,
                },
            )
            .unwrap();
        let consumed = ConsumedOneTimeAuthorization {
            provider_instance_id: authority.provider_instance_id().to_owned(),
            parent_lease_id: lease.lease_id().to_owned(),
            consumer: "dsh-awiki".to_owned(),
            capability: capability::IDENTITY_ECDH_SEALED.to_owned(),
            store_id: reference.store_id.clone(),
        };
        let aad = sealed_aad(
            ECDH_SEALED_OPERATION,
            &reference,
            &kid,
            "request-1",
            &binding.operation_input_digest,
            recipient.public_key(),
            &consumed,
        )
        .unwrap();
        let plaintext = recipient
            .open(&envelope.to_handoff().unwrap(), SEALED_SECRET_INFO, &aad)
            .unwrap();
        assert_eq!(plaintext.len(), 32);

        let mut wrong_aad = aad;
        wrong_aad.push(0);
        assert!(recipient
            .open(
                &envelope.to_handoff().unwrap(),
                SEALED_SECRET_INFO,
                &wrong_aad,
            )
            .is_err());
    }

    #[test]
    fn sealed_ecdh_rejects_peer_key_substitution_before_key_use() {
        let (_root, identity) = create_identity();
        let reference = identity.reference();
        let kid = format!("{}#agreement", reference.did);
        let authority = ProviderAuthorization::new();
        let lease = authority
            .acquire_lease(
                "dsh-awiki".to_owned(),
                [capability::IDENTITY_ECDH_SEALED.to_owned()],
                reference.store_id.clone(),
                600,
            )
            .unwrap();
        let recipient = SealedHandoffRecipient::generate();
        let binding = sealed_key_agreement_binding(
            &reference,
            &kid,
            &x25519_dalek::X25519_BASEPOINT_BYTES,
            recipient.public_key(),
            "request-1",
        )
        .unwrap();
        let token = authority.issue_one_time(&lease, &binding, 60).unwrap();
        let error = identity
            .derive_shared_secret_sealed(
                &authority,
                SealedKeyAgreementRequest {
                    identity: reference,
                    kid,
                    peer_public: [0x31; 32],
                    recipient_public_key: *recipient.public_key(),
                    request_id: "request-1".to_owned(),
                    token,
                },
            )
            .unwrap_err();
        assert_eq!(error, SealedProviderError::Authorization);
    }

    #[cfg(feature = "root-export")]
    #[test]
    fn sealed_root_export_requires_confirmation_and_roundtrips_only_as_ciphertext() {
        use ed25519_dalek::pkcs8::DecodePrivateKey;

        let (_root, identity) = create_identity();
        let reference = identity.reference();
        let kid = format!("{}#root", reference.did);
        let authority = ProviderAuthorization::new();
        let lease = authority
            .acquire_lease(
                "dsh-awiki".to_owned(),
                [capability::AWIKI_LEGACY_ROOT_TRANSFER_V1.to_owned()],
                reference.store_id.clone(),
                600,
            )
            .unwrap();
        let recipient = SealedHandoffRecipient::generate();
        assert_eq!(
            sealed_root_export_binding(
                &reference,
                &kid,
                recipient.public_key(),
                "root-transfer-1",
                false,
            )
            .unwrap_err(),
            SealedProviderError::Authorization
        );
        let binding = sealed_root_export_binding(
            &reference,
            &kid,
            recipient.public_key(),
            "root-transfer-1",
            true,
        )
        .unwrap();
        let token = authority.issue_one_time(&lease, &binding, 60).unwrap();
        let envelope = identity
            .export_root_key_sealed(
                &authority,
                SealedRootExportRequest {
                    identity: reference.clone(),
                    kid: kid.clone(),
                    recipient_public_key: *recipient.public_key(),
                    request_id: "root-transfer-1".to_owned(),
                    user_presence_confirmed: true,
                    token,
                },
            )
            .unwrap();
        assert!(!envelope.ciphertext_b64u.contains("PRIVATE"));
        let consumed = ConsumedOneTimeAuthorization {
            provider_instance_id: authority.provider_instance_id().to_owned(),
            parent_lease_id: lease.lease_id().to_owned(),
            consumer: "dsh-awiki".to_owned(),
            capability: capability::AWIKI_LEGACY_ROOT_TRANSFER_V1.to_owned(),
            store_id: reference.store_id.clone(),
        };
        let aad = sealed_aad(
            ROOT_EXPORT_SEALED_OPERATION,
            &reference,
            &kid,
            "root-transfer-1",
            &binding.operation_input_digest,
            recipient.public_key(),
            &consumed,
        )
        .unwrap();
        let plaintext = recipient
            .open(&envelope.to_handoff().unwrap(), SEALED_SECRET_INFO, &aad)
            .unwrap();
        ed25519_dalek::SigningKey::from_pkcs8_der(&plaintext).unwrap();
    }

    #[cfg(all(feature = "key-import", feature = "root-export"))]
    #[test]
    fn sealed_legacy_root_import_roundtrips_without_bridge_plaintext() {
        use super::super::{
            DeviceEnrollmentRequest, EnrollmentCapabilities, EnrollmentProposalKind,
            EnrollmentWorkflow, IdentityStatusPort, RootExportPort, UserConfirmedRootExportRequest,
        };

        let source_root = tempfile::tempdir().unwrap();
        let mut source_manager = crate::IdentityManager::initialize(crate::IdentityManagerConfig {
            state_root: source_root.path().to_path_buf(),
            root_key: crate::RootKeySource::Injected(crate::InjectedStoreKey::new(
                "source", [0x73; 32],
            )),
        })
        .unwrap();
        let mut source = source_manager.create(create_spec_for_import()).unwrap();
        let source_public = source.public_identity().unwrap();
        let source_status = source.host_status().unwrap();
        let checkpoint = source_status.checkpoint.unwrap();
        let root_kid = format!("{}#root", source.reference().did);
        let exported = source
            .export_root_for_legacy_envelope(UserConfirmedRootExportRequest {
                key: KeySelector::Kid(root_kid.clone()),
                user_presence_confirmed: true,
            })
            .unwrap();

        let target_root = tempfile::tempdir().unwrap();
        let mut target_manager = crate::IdentityManager::initialize(crate::IdentityManagerConfig {
            state_root: target_root.path().to_path_buf(),
            root_key: crate::RootKeySource::Injected(crate::InjectedStoreKey::new(
                "target", [0x74; 32],
            )),
        })
        .unwrap();
        let mut enrollment = target_manager
            .begin_device_enrollment(DeviceEnrollmentRequest {
                remote: crate::VerifiedRemoteDocument {
                    document: source_public.document.clone(),
                    evidence: crate::VerifiedPublicationEvidence {
                        document_version: checkpoint.document_version,
                        registry_version: checkpoint.registry_version,
                        document_digest: checkpoint.document_digest.clone(),
                    },
                },
                device_id: "target-device".to_owned(),
                device_signing_fragment: "target-signing".to_owned(),
                device_agreement_fragment: "target-agreement".to_owned(),
                profiles: vec!["anp.core.binding.v1".to_owned()],
                capabilities: EnrollmentCapabilities { did_wba: true },
            })
            .unwrap();
        let proposal = enrollment.proposal().clone();
        let EnrollmentProposalKind::Device {
            signing_key,
            agreement_key,
            profiles,
            ..
        } = &proposal.kind
        else {
            panic!("device enrollment expected")
        };
        let mut change = source
            .prepare_document_change(crate::DocumentChangeRequest {
                changes: vec![crate::DocumentChange::AddDevice {
                    device: crate::DeviceInput {
                        device_id: "target-device".to_owned(),
                        signing_key: crate::PublicKeyInput {
                            kid: signing_key.kid.clone(),
                            public_key_multibase: signing_key.public_key_multibase.clone(),
                        },
                        agreement_key: crate::PublicKeyInput {
                            kid: agreement_key.kid.clone(),
                            public_key_multibase: agreement_key.public_key_multibase.clone(),
                        },
                        profiles: profiles.clone(),
                    },
                }],
            })
            .unwrap();
        let accepted = change.candidate().clone();
        let attempt = change.begin_publication().unwrap();
        let accepted_document = accepted.candidate_document;
        let publication_evidence = crate::VerifiedPublicationEvidence {
            document_version: checkpoint.document_version + 1,
            registry_version: checkpoint.registry_version + 1,
            document_digest: accepted.candidate_digest,
        };
        let accepted_remote = crate::VerifiedRemoteDocument {
            document: accepted_document.clone(),
            evidence: crate::VerifiedPublicationEvidence {
                document_version: checkpoint.document_version + 1,
                registry_version: checkpoint.registry_version + 1,
                document_digest: crate::canonical_document_digest(accepted_document.as_value())
                    .unwrap(),
            },
        };
        change
            .complete(
                attempt,
                crate::PublicationResult::Confirmed {
                    evidence: publication_evidence,
                },
            )
            .unwrap();
        assert_eq!(
            accepted_remote
                .document
                .as_value()
                .get("id")
                .and_then(serde_json::Value::as_str),
            Some(proposal.identity.did.as_str())
        );
        assert!(anp::authentication::validate_did_document_binding(
            accepted_remote.document.as_value(),
            true,
        ));
        assert_eq!(
            crate::canonical_document_digest(accepted_remote.document.as_value()).unwrap(),
            accepted_remote.evidence.document_digest
        );
        enrollment.activate(accepted_remote).unwrap();
        let mut target = target_manager.get(&proposal.identity).unwrap();
        target.recover_identity().unwrap();
        let target_checkpoint = target.host_status().unwrap().checkpoint.unwrap();
        let preparation = SealedRootImportPreparation {
            identity: proposal.identity.clone(),
            evidence: super::super::LegacyRootImportEvidence {
                transfer_id: "legacy-transfer-1".to_owned(),
                source_did: proposal.identity.did.clone(),
                target_did: proposal.identity.did.clone(),
                sender_device_id: "source-device".to_owned(),
                recipient_device_id: "target-device".to_owned(),
                recipient_agreement_kid: agreement_key.kid.clone(),
                root_kid,
                checkpoint: target_checkpoint,
                accepted_at: chrono::Utc::now().to_rfc3339(),
            },
            encoding: super::super::RootPrivateKeyEncoding::Pkcs8Der,
            request_id: "legacy-transfer-1".to_owned(),
        };
        let authority = ProviderAuthorization::new();
        let lease = authority
            .acquire_lease(
                "dsh-awiki".to_owned(),
                [capability::AWIKI_LEGACY_ROOT_TRANSFER_V1.to_owned()],
                proposal.identity.store_id.clone(),
                600,
            )
            .unwrap();
        let (prepared, offer) =
            PreparedSealedRootImport::prepare(&authority, &lease, preparation, 60).unwrap();
        let aad = URL_SAFE_NO_PAD.decode(&offer.aad_b64u).unwrap();
        let sealed = anp::sealed_handoff::SealedHandoff::seal(
            &offer.recipient_public_key,
            SEALED_SECRET_INFO,
            &aad,
            exported.as_pkcs8_der(),
        )
        .unwrap();
        let envelope = SealedSecretEnvelope::from_handoff(&sealed);
        let outcome = prepared
            .complete(&mut target, &authority, offer.token, &envelope)
            .unwrap();
        assert_eq!(outcome, super::super::LegacyRootImportOutcome::Pending);
    }

    #[cfg(all(feature = "key-import", feature = "root-export"))]
    fn create_spec_for_import() -> crate::CreateIdentityRequest {
        crate::CreateIdentityRequest {
            profile: crate::DidProfile::E1,
            domain: "example.com".to_owned(),
            port: None,
            path_segments: vec!["sealed-root-import".to_owned()],
            capabilities: crate::Capabilities { did_wba: true },
            managed_keys: vec![
                crate::ManagedKeySpec {
                    fragment: "root".to_owned(),
                    role: crate::KeyRole::RootControl,
                },
                crate::ManagedKeySpec {
                    fragment: "source-sign".to_owned(),
                    role: crate::KeyRole::DeviceSigning,
                },
                crate::ManagedKeySpec {
                    fragment: "source-e2ee".to_owned(),
                    role: crate::KeyRole::E2eeAgreement,
                },
            ],
            external_keys: Vec::new(),
            services: Vec::new(),
            agent_description_url: None,
            extensions: vec![crate::DidExtensionSpec::DeviceManifest(
                crate::DeviceManifestSpec {
                    devices: vec![crate::DeviceManifestEntrySpec {
                        device_id: "source-device".to_owned(),
                        signing_key_id: "#source-sign".to_owned(),
                        e2ee_key_id: "#source-e2ee".to_owned(),
                        profiles: vec!["anp.core.binding.v1".to_owned()],
                    }],
                },
            )],
        }
    }
}
