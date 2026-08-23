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

pub const SEALED_SECRET_PROTOCOL: &str = anp::sealed_handoff::IDENTITY_SEALED_SECRET_PROTOCOL;
pub const SEALED_SECRET_INFO: &[u8] = anp::sealed_handoff::IDENTITY_SEALED_SECRET_INFO;
const ECDH_SEALED_OPERATION: &str = anp::sealed_handoff::IDENTITY_ECDH_OPERATION;
const ENROLLMENT_ECDH_SEALED_OPERATION: &str =
    anp::sealed_handoff::IDENTITY_ENROLLMENT_ECDH_OPERATION;
#[cfg(feature = "root-export")]
const ROOT_EXPORT_SEALED_OPERATION: &str = anp::sealed_handoff::IDENTITY_ROOT_EXPORT_OPERATION;
#[cfg(feature = "key-import")]
const ROOT_IMPORT_SEALED_OPERATION: &str = anp::sealed_handoff::IDENTITY_ROOT_IMPORT_OPERATION;
#[cfg(feature = "key-import")]
const IDENTITY_MATERIAL_IMPORT_SEALED_OPERATION: &str = "import_identity_material_sealed";
const PROVIDER_ADOPTION_SEALED_OPERATION: &str = "adopt_store_root_key_provider_sealed";

/// HPKE ciphertext safe to carry across the TypeScript bridge.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SealedSecretEnvelope {
    pub protocol: String,
    pub suite: String,
    pub encapped_key_b64u: String,
    pub ciphertext_b64u: String,
}

/// Token-bound HPKE delivery returned from an External Provider to its native host.
///
/// `aad` is the unpadded base64url encoding of the exact AAD used to seal
/// `envelope`. The host validates it against `authorization` and its request
/// before opening the ciphertext.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SealedSecretDelivery {
    pub envelope: SealedSecretEnvelope,
    pub authorization: IssuedAuthorizationContext,
    pub aad: String,
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

/// Exact, token-bound request for ECDH with a pending device-enrollment key.
pub struct SealedEnrollmentKeyAgreementRequest {
    pub identity: IdentityRef,
    pub enrollment_id: String,
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SealedIdentityMaterialKeySpec {
    pub kid: String,
    pub purpose: super::MigrationKeyPurpose,
    pub encoding: super::MigrationPrivateKeyEncoding,
}

#[cfg(feature = "key-import")]
pub struct SealedIdentityMaterialImportPreparation {
    pub remote: crate::VerifiedRemoteDocument,
    pub did_wba: bool,
    pub keys: Vec<SealedIdentityMaterialKeySpec>,
    pub request_id: String,
}

/// Public metadata needed by the legacy native custodian to seal each private key.
#[cfg(feature = "key-import")]
pub struct SealedIdentityMaterialImportOffer {
    pub target: IdentityRef,
    pub recipient_public_key: [u8; 32],
    pub request_id: String,
    pub token: OneTimeCapabilityToken,
    pub authorization: IssuedAuthorizationContext,
    pub item_aad_b64u: Vec<String>,
}

#[cfg(feature = "key-import")]
pub struct PreparedSealedIdentityMaterialImport {
    recipient: anp::sealed_handoff::SealedHandoffRecipient,
    target: IdentityRef,
    preparation: SealedIdentityMaterialImportPreparation,
    binding: OneTimeOperationBinding,
    item_aad: Vec<Vec<u8>>,
}

pub struct SealedProviderAdoptionPreparation {
    pub state_root: std::path::PathBuf,
    pub target: super::ProviderAdoptionTarget,
    pub request_id: String,
}

/// Store-level offer whose root key can only be supplied as an HPKE ciphertext.
pub struct SealedProviderAdoptionOffer {
    pub store_id: String,
    pub root_key_fingerprint: String,
    pub recipient_public_key: [u8; 32],
    pub request_id: String,
    pub token: OneTimeCapabilityToken,
    pub authorization: IssuedAuthorizationContext,
    pub aad_b64u: String,
}

pub struct PreparedSealedProviderAdoption {
    recipient: anp::sealed_handoff::SealedHandoffRecipient,
    preparation: SealedProviderAdoptionPreparation,
    manifest: crate::StoreManifest,
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

#[cfg(feature = "key-import")]
impl PreparedSealedIdentityMaterialImport {
    pub fn prepare(
        manager: &crate::IdentityManager,
        authorization: &ProviderAuthorization,
        lease: &super::ProviderCapabilityLease,
        preparation: SealedIdentityMaterialImportPreparation,
        ttl_seconds: i64,
    ) -> Result<(Self, SealedIdentityMaterialImportOffer), SealedProviderError> {
        let did = preparation
            .remote
            .document
            .as_value()
            .get("id")
            .and_then(serde_json::Value::as_str)
            .ok_or(SealedProviderError::InvalidRequest)?
            .to_owned();
        let target = IdentityRef {
            store_id: manager.store_id().to_owned(),
            identity_id: crate::identity::random_id(),
            did,
        };
        let recipient = anp::sealed_handoff::SealedHandoffRecipient::generate();
        let binding =
            sealed_identity_material_import_binding(&target, &preparation, recipient.public_key())?;
        let issued = authorization.issue_one_time_with_context(lease, &binding, ttl_seconds)?;
        let item_aad = preparation
            .keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                sealed_identity_material_item_aad(
                    &issued.context,
                    &binding,
                    &target,
                    index,
                    &key.kid,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let offer = SealedIdentityMaterialImportOffer {
            target: target.clone(),
            recipient_public_key: *recipient.public_key(),
            request_id: preparation.request_id.clone(),
            token: issued.token,
            authorization: issued.context,
            item_aad_b64u: item_aad
                .iter()
                .map(|aad| URL_SAFE_NO_PAD.encode(aad))
                .collect(),
        };
        Ok((
            Self {
                recipient,
                target,
                preparation,
                binding,
                item_aad,
            },
            offer,
        ))
    }

    pub fn complete(
        self,
        manager: &mut crate::IdentityManager,
        authorization: &ProviderAuthorization,
        token: OneTimeCapabilityToken,
        envelopes: &[SealedSecretEnvelope],
    ) -> Result<ManagedIdentity, SealedProviderError> {
        use super::{FullIdentityImportRequest, MigrationPrivateKey};

        let consumed = authorization.consume_for_operation(&token, &self.binding)?;
        if manager.store_id() != self.target.store_id
            || consumed.store_id != self.target.store_id
            || envelopes.len() != self.preparation.keys.len()
        {
            return Err(SealedProviderError::IdentityBinding);
        }
        let private_keys = self
            .preparation
            .keys
            .into_iter()
            .zip(self.item_aad)
            .zip(envelopes)
            .map(|((key, aad), envelope)| {
                let secret = self
                    .recipient
                    .open(&envelope.to_handoff()?, SEALED_SECRET_INFO, &aad)
                    .map_err(|_| SealedProviderError::EnvelopeInvalid)?;
                Ok(MigrationPrivateKey {
                    kid: key.kid,
                    purpose: key.purpose,
                    encoding: key.encoding,
                    secret,
                })
            })
            .collect::<Result<Vec<_>, SealedProviderError>>()?;
        let imported = manager.import_full_identity_with_id(
            self.target.identity_id.clone(),
            FullIdentityImportRequest {
                remote: self.preparation.remote,
                did_wba: self.preparation.did_wba,
                private_keys,
            },
        )?;
        if imported.reference() != self.target {
            return Err(SealedProviderError::IdentityBinding);
        }
        Ok(imported)
    }
}

impl PreparedSealedProviderAdoption {
    pub fn prepare(
        authorization: &ProviderAuthorization,
        lease: &super::ProviderCapabilityLease,
        preparation: SealedProviderAdoptionPreparation,
        ttl_seconds: i64,
    ) -> Result<(Self, SealedProviderAdoptionOffer), SealedProviderError> {
        if preparation.request_id.trim().is_empty() {
            return Err(SealedProviderError::InvalidRequest);
        }
        let manifest = crate::store::StoreRuntime::manifest_at(&preparation.state_root)
            .map_err(IdentityError::from)?;
        let recipient = anp::sealed_handoff::SealedHandoffRecipient::generate();
        let binding =
            sealed_provider_adoption_binding(&preparation, &manifest, recipient.public_key())?;
        let issued = authorization.issue_one_time_with_context(lease, &binding, ttl_seconds)?;
        let identity = store_adoption_identity(&manifest);
        let aad = sealed_aad_values(
            PROVIDER_ADOPTION_SEALED_OPERATION,
            &identity,
            "store-root-key",
            &preparation.request_id,
            &binding.operation_input_digest,
            recipient.public_key(),
            &issued.context.provider_instance_id,
            &issued.context.parent_lease_id,
            &issued.context.consumer,
            &issued.context.capability,
            issued.context.expires_at,
        )?;
        let offer = SealedProviderAdoptionOffer {
            store_id: manifest.store_id.clone(),
            root_key_fingerprint: manifest.root_key_fingerprint.clone(),
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
                manifest,
                binding,
                aad,
            },
            offer,
        ))
    }

    pub fn complete(
        self,
        authorization: &ProviderAuthorization,
        token: OneTimeCapabilityToken,
        envelope: &SealedSecretEnvelope,
    ) -> Result<super::ProviderAdoptionReport, SealedProviderError> {
        let consumed = authorization.consume_for_operation(&token, &self.binding)?;
        let current = crate::store::StoreRuntime::manifest_at(&self.preparation.state_root)
            .map_err(IdentityError::from)?;
        if consumed.store_id != self.manifest.store_id || current != self.manifest {
            return Err(SealedProviderError::IdentityBinding);
        }
        let root_key = self
            .recipient
            .open(&envelope.to_handoff()?, SEALED_SECRET_INFO, &self.aad)
            .map_err(|_| SealedProviderError::EnvelopeInvalid)?;
        let root_key: [u8; 32] = root_key
            .as_slice()
            .try_into()
            .map_err(|_| SealedProviderError::EnvelopeInvalid)?;
        let report = super::adopt_store_root_key_provider(super::AdoptStoreRootKeyRequest {
            state_root: self.preparation.state_root,
            existing_root_key: zeroize::Zeroizing::new(root_key),
            target: self.preparation.target,
        })?;
        if report.store_id != self.manifest.store_id
            || report.root_key_fingerprint != self.manifest.root_key_fingerprint
        {
            return Err(SealedProviderError::IdentityBinding);
        }
        Ok(report)
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

impl SealedEnrollmentKeyAgreementRequest {
    pub fn operation_binding(&self) -> Result<OneTimeOperationBinding, SealedProviderError> {
        sealed_enrollment_key_agreement_binding(
            &self.identity,
            &self.enrollment_id,
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
    ) -> Result<SealedSecretDelivery, SealedProviderError>;
}

pub trait SealedEnrollmentKeyAgreementPort {
    fn derive_device_shared_secret_sealed(
        &self,
        authorization: &ProviderAuthorization,
        request: SealedEnrollmentKeyAgreementRequest,
    ) -> Result<SealedSecretDelivery, SealedProviderError>;
}

#[cfg(feature = "root-export")]
pub trait SealedRootExportPort {
    fn export_root_key_sealed(
        &self,
        authorization: &ProviderAuthorization,
        request: SealedRootExportRequest,
    ) -> Result<SealedSecretDelivery, SealedProviderError>;
}

impl SealedKeyAgreementPort for ManagedIdentity {
    fn derive_shared_secret_sealed(
        &self,
        authorization: &ProviderAuthorization,
        request: SealedKeyAgreementRequest,
    ) -> Result<SealedSecretDelivery, SealedProviderError> {
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
        Ok(sealed_delivery(&sealed, &aad, consumed))
    }
}

impl SealedEnrollmentKeyAgreementPort for super::EnrollmentSession {
    fn derive_device_shared_secret_sealed(
        &self,
        authorization: &ProviderAuthorization,
        request: SealedEnrollmentKeyAgreementRequest,
    ) -> Result<SealedSecretDelivery, SealedProviderError> {
        let binding = request.operation_binding()?;
        let consumed = authorization.consume_for_operation(&request.token, &binding)?;
        let proposal = self.proposal();
        let super::EnrollmentProposalKind::Device { agreement_key, .. } = &proposal.kind else {
            return Err(SealedProviderError::IdentityBinding);
        };
        if proposal.identity != request.identity
            || proposal.enrollment_id != request.enrollment_id
            || agreement_key.kid != request.kid
        {
            return Err(SealedProviderError::IdentityBinding);
        }
        validate_identity_binding(&proposal.identity, &request.identity, &consumed)?;
        let shared = self.derive_device_shared_secret(request.peer_public)?;
        let aad = sealed_aad(
            ENROLLMENT_ECDH_SEALED_OPERATION,
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
        Ok(sealed_delivery(&sealed, &aad, consumed))
    }
}

#[cfg(feature = "root-export")]
impl SealedRootExportPort for ManagedIdentity {
    fn export_root_key_sealed(
        &self,
        authorization: &ProviderAuthorization,
        request: SealedRootExportRequest,
    ) -> Result<SealedSecretDelivery, SealedProviderError> {
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
        Ok(sealed_delivery(&sealed, &aad, consumed))
    }
}

fn sealed_delivery(
    sealed: &anp::sealed_handoff::SealedHandoff,
    aad: &[u8],
    consumed: ConsumedOneTimeAuthorization,
) -> SealedSecretDelivery {
    SealedSecretDelivery {
        envelope: SealedSecretEnvelope::from_handoff(sealed),
        authorization: IssuedAuthorizationContext {
            provider_instance_id: consumed.provider_instance_id,
            parent_lease_id: consumed.parent_lease_id,
            consumer: consumed.consumer,
            capability: consumed.capability,
            store_id: consumed.store_id,
            expires_at: consumed.expires_at,
        },
        aad: URL_SAFE_NO_PAD.encode(aad),
    }
}

pub fn sealed_key_agreement_binding(
    identity: &IdentityRef,
    kid: &str,
    peer_public: &[u8; 32],
    recipient_public_key: &[u8; 32],
    request_id: &str,
) -> Result<OneTimeOperationBinding, SealedProviderError> {
    anp::sealed_handoff::identity_ecdh_binding(
        &sealed_identity_context(identity),
        kid,
        peer_public,
        recipient_public_key,
        request_id,
    )
    .map(shared_operation_binding)
    .map_err(|_| SealedProviderError::InvalidRequest)
}

pub fn sealed_enrollment_key_agreement_binding(
    identity: &IdentityRef,
    enrollment_id: &str,
    kid: &str,
    peer_public: &[u8; 32],
    recipient_public_key: &[u8; 32],
    request_id: &str,
) -> Result<OneTimeOperationBinding, SealedProviderError> {
    anp::sealed_handoff::identity_enrollment_ecdh_binding(
        &sealed_identity_context(identity),
        enrollment_id,
        kid,
        peer_public,
        recipient_public_key,
        request_id,
    )
    .map(shared_operation_binding)
    .map_err(|_| SealedProviderError::InvalidRequest)
}

#[cfg(feature = "root-export")]
pub fn sealed_root_export_binding(
    identity: &IdentityRef,
    kid: &str,
    recipient_public_key: &[u8; 32],
    request_id: &str,
    user_presence_confirmed: bool,
) -> Result<OneTimeOperationBinding, SealedProviderError> {
    anp::sealed_handoff::identity_root_export_binding(
        &sealed_identity_context(identity),
        kid,
        recipient_public_key,
        request_id,
        user_presence_confirmed,
    )
    .map(shared_operation_binding)
    .map_err(|_| {
        if user_presence_confirmed {
            SealedProviderError::InvalidRequest
        } else {
            SealedProviderError::Authorization
        }
    })
}

#[cfg(feature = "key-import")]
pub fn sealed_root_import_binding(
    preparation: &SealedRootImportPreparation,
    recipient_public_key: &[u8; 32],
) -> Result<OneTimeOperationBinding, SealedProviderError> {
    let evidence = anp::sealed_handoff::SealedLegacyRootImportEvidence {
        transfer_id: preparation.evidence.transfer_id.clone(),
        source_did: preparation.evidence.source_did.clone(),
        target_did: preparation.evidence.target_did.clone(),
        sender_device_id: preparation.evidence.sender_device_id.clone(),
        recipient_device_id: preparation.evidence.recipient_device_id.clone(),
        recipient_agreement_kid: preparation.evidence.recipient_agreement_kid.clone(),
        root_kid: preparation.evidence.root_kid.clone(),
        checkpoint: anp::sealed_handoff::SealedDocumentCheckpoint {
            document_version: preparation.evidence.checkpoint.document_version,
            registry_version: preparation.evidence.checkpoint.registry_version,
            document_digest: preparation.evidence.checkpoint.document_digest.clone(),
        },
        accepted_at: preparation.evidence.accepted_at.clone(),
    };
    let encoding = match preparation.encoding {
        super::RootPrivateKeyEncoding::Raw32 => {
            anp::sealed_handoff::SealedPrivateKeyEncoding::Raw32
        }
        super::RootPrivateKeyEncoding::Pkcs8Der => {
            anp::sealed_handoff::SealedPrivateKeyEncoding::Pkcs8Der
        }
    };
    anp::sealed_handoff::identity_root_import_binding(
        &sealed_identity_context(&preparation.identity),
        &evidence,
        encoding,
        recipient_public_key,
        &preparation.request_id,
    )
    .map(shared_operation_binding)
    .map_err(|_| {
        if preparation.evidence.target_did != preparation.identity.did {
            SealedProviderError::IdentityBinding
        } else {
            SealedProviderError::InvalidRequest
        }
    })
}

#[cfg(feature = "key-import")]
pub fn sealed_identity_material_import_binding(
    target: &IdentityRef,
    preparation: &SealedIdentityMaterialImportPreparation,
    recipient_public_key: &[u8; 32],
) -> Result<OneTimeOperationBinding, SealedProviderError> {
    if target.store_id.trim().is_empty()
        || target.identity_id.trim().is_empty()
        || target.did.trim().is_empty()
        || preparation.request_id.trim().is_empty()
        || preparation.keys.is_empty()
        || preparation.keys.iter().any(|key| key.kid.trim().is_empty())
    {
        return Err(SealedProviderError::InvalidRequest);
    }
    let document = preparation.remote.document.as_value();
    if document.get("id").and_then(serde_json::Value::as_str) != Some(target.did.as_str())
        || crate::canonical_document_digest(document).map_err(IdentityError::from)?
            != preparation.remote.evidence.document_digest
    {
        return Err(SealedProviderError::IdentityBinding);
    }
    let unique_kids = preparation
        .keys
        .iter()
        .map(|key| key.kid.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    if unique_kids.len() != preparation.keys.len() {
        return Err(SealedProviderError::InvalidRequest);
    }
    #[derive(Serialize)]
    struct DigestInput<'a> {
        protocol: &'static str,
        operation: &'static str,
        target: &'a IdentityRef,
        request_id: &'a str,
        recipient_public_key_digest: String,
        did_wba: bool,
        document_digest: &'a str,
        document_version: u64,
        registry_version: u64,
        keys: &'a [SealedIdentityMaterialKeySpec],
    }
    let input = DigestInput {
        protocol: SEALED_SECRET_PROTOCOL,
        operation: IDENTITY_MATERIAL_IMPORT_SEALED_OPERATION,
        target,
        request_id: &preparation.request_id,
        recipient_public_key_digest: recipient_public_key_digest(recipient_public_key),
        did_wba: preparation.did_wba,
        document_digest: &preparation.remote.evidence.document_digest,
        document_version: preparation.remote.evidence.document_version,
        registry_version: preparation.remote.evidence.registry_version,
        keys: &preparation.keys,
    };
    Ok(OneTimeOperationBinding {
        capability: capability::IDENTITY_IMPORT.to_owned(),
        identity_id: target.identity_id.clone(),
        operation: IDENTITY_MATERIAL_IMPORT_SEALED_OPERATION.to_owned(),
        kid: None,
        request_id: preparation.request_id.clone(),
        recipient_public_key: *recipient_public_key,
        operation_input_digest: canonical_digest(&input)?,
    })
}

#[cfg(feature = "key-import")]
fn sealed_identity_material_item_aad(
    context: &IssuedAuthorizationContext,
    binding: &OneTimeOperationBinding,
    target: &IdentityRef,
    index: usize,
    kid: &str,
) -> Result<Vec<u8>, SealedProviderError> {
    if context.store_id != target.store_id || context.capability != binding.capability {
        return Err(SealedProviderError::IdentityBinding);
    }
    sealed_aad_values(
        &binding.operation,
        target,
        kid,
        &format!("{}:{index}", binding.request_id),
        &binding.operation_input_digest,
        &binding.recipient_public_key,
        &context.provider_instance_id,
        &context.parent_lease_id,
        &context.consumer,
        &context.capability,
        context.expires_at,
    )
}

pub fn sealed_provider_adoption_binding(
    preparation: &SealedProviderAdoptionPreparation,
    manifest: &crate::StoreManifest,
    recipient_public_key: &[u8; 32],
) -> Result<OneTimeOperationBinding, SealedProviderError> {
    if preparation.request_id.trim().is_empty()
        || manifest.store_id.trim().is_empty()
        || manifest.root_key_fingerprint.trim().is_empty()
    {
        return Err(SealedProviderError::InvalidRequest);
    }
    #[derive(Serialize)]
    struct DigestInput<'a> {
        protocol: &'static str,
        operation: &'static str,
        store_id: &'a str,
        state_root: &'a std::path::Path,
        original_provider: &'a crate::RootKeyProviderBinding,
        target_provider: &'a super::ProviderAdoptionTarget,
        root_key_fingerprint: &'a str,
        generation: u64,
        request_id: &'a str,
        recipient_public_key_digest: String,
    }
    let input = DigestInput {
        protocol: SEALED_SECRET_PROTOCOL,
        operation: PROVIDER_ADOPTION_SEALED_OPERATION,
        store_id: &manifest.store_id,
        state_root: &preparation.state_root,
        original_provider: &manifest.provider,
        target_provider: &preparation.target,
        root_key_fingerprint: &manifest.root_key_fingerprint,
        generation: manifest.generation,
        request_id: &preparation.request_id,
        recipient_public_key_digest: recipient_public_key_digest(recipient_public_key),
    };
    Ok(OneTimeOperationBinding {
        capability: capability::IDENTITY_IMPORT.to_owned(),
        identity_id: manifest.store_id.clone(),
        operation: PROVIDER_ADOPTION_SEALED_OPERATION.to_owned(),
        kid: Some("store-root-key".to_owned()),
        request_id: preparation.request_id.clone(),
        recipient_public_key: *recipient_public_key,
        operation_input_digest: canonical_digest(&input)?,
    })
}

fn store_adoption_identity(manifest: &crate::StoreManifest) -> IdentityRef {
    IdentityRef {
        store_id: manifest.store_id.clone(),
        identity_id: manifest.store_id.clone(),
        did: format!("store:{}", manifest.store_id),
    }
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
        consumed.expires_at,
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
        context.expires_at,
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
    expires_at: i64,
) -> Result<Vec<u8>, SealedProviderError> {
    anp::sealed_handoff::identity_operation_aad(
        &anp::sealed_handoff::SealedAuthorizationContext {
            provider_instance_id: provider_instance_id.to_owned(),
            parent_lease_id: parent_lease_id.to_owned(),
            consumer: consumer.to_owned(),
            capability: capability.to_owned(),
            store_id: identity.store_id.clone(),
            expires_at,
        },
        &anp::sealed_handoff::SealedOperationBinding {
            capability: capability.to_owned(),
            identity_id: identity.identity_id.clone(),
            operation: operation.to_owned(),
            kid: kid.to_owned(),
            request_id: request_id.to_owned(),
            recipient_public_key: *recipient_public_key,
            operation_input_digest: operation_input_digest.to_owned(),
        },
        &sealed_identity_context(identity),
    )
    .map_err(|_| SealedProviderError::InvalidRequest)
}

fn sealed_identity_context(identity: &IdentityRef) -> anp::sealed_handoff::SealedIdentityContext {
    anp::sealed_handoff::SealedIdentityContext {
        store_id: identity.store_id.clone(),
        identity_id: identity.identity_id.clone(),
        did: identity.did.clone(),
    }
}

fn shared_operation_binding(
    binding: anp::sealed_handoff::SealedOperationBinding,
) -> OneTimeOperationBinding {
    OneTimeOperationBinding {
        capability: binding.capability,
        identity_id: binding.identity_id,
        operation: binding.operation,
        kid: Some(binding.kid),
        request_id: binding.request_id,
        recipient_public_key: binding.recipient_public_key,
        operation_input_digest: binding.operation_input_digest,
    }
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
        let delivery = identity
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
        let aad = sealed_operation_aad(&delivery.authorization, &binding, &reference).unwrap();
        assert_eq!(delivery.aad, URL_SAFE_NO_PAD.encode(&aad));
        let plaintext = recipient
            .open(
                &delivery.envelope.to_handoff().unwrap(),
                SEALED_SECRET_INFO,
                &aad,
            )
            .unwrap();
        assert_eq!(plaintext.len(), 32);

        let mut wrong_aad = aad;
        wrong_aad.push(0);
        assert!(recipient
            .open(
                &delivery.envelope.to_handoff().unwrap(),
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

    #[cfg(feature = "key-import")]
    #[test]
    fn sealed_identity_material_import_matches_each_document_key() {
        use super::super::IdentityStatusPort;

        let (_source_root, source) = create_identity();
        let source_public = source.public_identity().unwrap();
        let checkpoint = source.host_status().unwrap().checkpoint.unwrap();
        let key_specs = source
            .lock_engine()
            .unwrap()
            .keys()
            .iter()
            .filter(|key| key.origin == crate::KeyOrigin::Managed)
            .map(|key| SealedIdentityMaterialKeySpec {
                kid: key.kid.clone(),
                purpose: match key.role {
                    crate::KeyRole::RootControl => super::super::MigrationKeyPurpose::RootControl,
                    crate::KeyRole::RequestSigning => {
                        super::super::MigrationKeyPurpose::Authentication
                    }
                    crate::KeyRole::DeviceSigning => {
                        super::super::MigrationKeyPurpose::DeviceAssertion
                    }
                    crate::KeyRole::E2eeSigning => {
                        super::super::MigrationKeyPurpose::ApplicationAssertion
                    }
                    crate::KeyRole::E2eeAgreement => {
                        super::super::MigrationKeyPurpose::KeyAgreement
                    }
                },
                encoding: super::super::MigrationPrivateKeyEncoding::Raw32,
            })
            .collect::<Vec<_>>();

        let target_root = tempfile::tempdir().unwrap();
        let mut target_manager = crate::IdentityManager::initialize(crate::IdentityManagerConfig {
            state_root: target_root.path().to_path_buf(),
            root_key: crate::RootKeySource::Injected(crate::InjectedStoreKey::new(
                "sealed-migration-target",
                [0x52; 32],
            )),
        })
        .unwrap();
        let authority = ProviderAuthorization::new();
        let lease = authority
            .acquire_lease(
                "dsh-awiki".to_owned(),
                [capability::IDENTITY_IMPORT.to_owned()],
                target_manager.store_id().to_owned(),
                600,
            )
            .unwrap();
        let preparation = || SealedIdentityMaterialImportPreparation {
            remote: crate::VerifiedRemoteDocument {
                document: source_public.document.clone(),
                evidence: crate::VerifiedPublicationEvidence {
                    document_version: checkpoint.document_version,
                    registry_version: checkpoint.registry_version,
                    document_digest: checkpoint.document_digest.clone(),
                },
            },
            did_wba: true,
            keys: key_specs.clone(),
            request_id: "legacy-migration-1".to_owned(),
        };
        let (bad_prepared, bad_offer) = PreparedSealedIdentityMaterialImport::prepare(
            &target_manager,
            &authority,
            &lease,
            preparation(),
            60,
        )
        .unwrap();
        let bad_envelopes = seal_migration_test_keys(&source, &key_specs, &bad_offer, true);
        let error = match bad_prepared.complete(
            &mut target_manager,
            &authority,
            bad_offer.token,
            &bad_envelopes,
        ) {
            Ok(_) => panic!("mismatched private material must fail"),
            Err(error) => error,
        };
        assert_eq!(error, SealedProviderError::Identity);
        assert!(target_manager.list().unwrap().is_empty());

        let (prepared, offer) = PreparedSealedIdentityMaterialImport::prepare(
            &target_manager,
            &authority,
            &lease,
            preparation(),
            60,
        )
        .unwrap();
        let envelopes = seal_migration_test_keys(&source, &key_specs, &offer, false);

        let imported = prepared
            .complete(&mut target_manager, &authority, offer.token, &envelopes)
            .unwrap();
        assert_eq!(imported.reference(), offer.target);
        assert_eq!(
            imported.public_identity().unwrap().document,
            source_public.document
        );
        assert_eq!(
            imported.host_status().unwrap().root_capability,
            super::super::HostRootCapability::Active
        );
    }

    #[test]
    fn sealed_provider_adoption_never_exposes_store_root_key_to_bridge() {
        let root = tempfile::tempdir().unwrap();
        let root_key = [0x6A; 32];
        let mut manager = crate::IdentityManager::initialize(crate::IdentityManagerConfig {
            state_root: root.path().to_path_buf(),
            root_key: crate::RootKeySource::Injected(crate::InjectedStoreKey::new(
                "awiki-vault",
                root_key,
            )),
        })
        .unwrap();
        let identity = manager
            .create(crate::CreateIdentityRequest {
                profile: crate::DidProfile::E1,
                domain: "example.com".to_owned(),
                port: None,
                path_segments: vec!["sealed-provider-adoption".to_owned()],
                capabilities: crate::Capabilities { did_wba: false },
                managed_keys: vec![crate::ManagedKeySpec {
                    fragment: "root".to_owned(),
                    role: crate::KeyRole::RootControl,
                }],
                external_keys: Vec::new(),
                services: Vec::new(),
                agent_description_url: None,
                extensions: Vec::new(),
            })
            .unwrap();
        let reference = identity.reference();
        let authority = ProviderAuthorization::new();
        let lease = authority
            .acquire_lease(
                "dsh-awiki".to_owned(),
                [capability::IDENTITY_IMPORT.to_owned()],
                reference.store_id.clone(),
                600,
            )
            .unwrap();
        let (prepared, offer) = PreparedSealedProviderAdoption::prepare(
            &authority,
            &lease,
            SealedProviderAdoptionPreparation {
                state_root: root.path().to_path_buf(),
                target: super::super::ProviderAdoptionTarget::LocalPrivateFile,
                request_id: "provider-adoption-1".to_owned(),
            },
            60,
        )
        .unwrap();
        let aad = URL_SAFE_NO_PAD.decode(&offer.aad_b64u).unwrap();
        let sealed = anp::sealed_handoff::SealedHandoff::seal(
            &offer.recipient_public_key,
            SEALED_SECRET_INFO,
            &aad,
            &root_key,
        )
        .unwrap();
        let report = prepared
            .complete(
                &authority,
                offer.token,
                &SealedSecretEnvelope::from_handoff(&sealed),
            )
            .unwrap();
        assert_eq!(report.store_id, reference.store_id);
        assert_eq!(
            report.provider.kind,
            crate::RootKeyProviderKind::LocalPrivateFile
        );
        assert!(crate::IdentityManager::open(crate::IdentityManagerConfig {
            state_root: root.path().to_path_buf(),
            root_key: crate::RootKeySource::Injected(crate::InjectedStoreKey::new(
                "awiki-vault",
                root_key,
            )),
        })
        .is_err());
        let reopened = crate::IdentityManager::open(crate::IdentityManagerConfig {
            state_root: root.path().to_path_buf(),
            root_key: crate::RootKeySource::LocalPrivateFile,
        })
        .unwrap();
        assert_eq!(reopened.get(&reference).unwrap().reference(), reference);
    }

    #[cfg(feature = "key-import")]
    fn seal_migration_test_keys(
        source: &ManagedIdentity,
        key_specs: &[SealedIdentityMaterialKeySpec],
        offer: &SealedIdentityMaterialImportOffer,
        corrupt_first: bool,
    ) -> Vec<SealedSecretEnvelope> {
        let engine = source.lock_engine().unwrap();
        key_specs
            .iter()
            .zip(&offer.item_aad_b64u)
            .enumerate()
            .map(|(index, (key, aad_b64u))| {
                let metadata = engine.key_metadata(&key.kid).unwrap();
                let secret = engine.load_managed_secret(metadata).unwrap();
                let aad = URL_SAFE_NO_PAD.decode(aad_b64u).unwrap();
                let wrong_secret = [0xA5; 32];
                let plaintext = if corrupt_first && index == 0 {
                    wrong_secret.as_slice()
                } else {
                    secret.expose()
                };
                let sealed = anp::sealed_handoff::SealedHandoff::seal(
                    &offer.recipient_public_key,
                    SEALED_SECRET_INFO,
                    &aad,
                    plaintext,
                )
                .unwrap();
                SealedSecretEnvelope::from_handoff(&sealed)
            })
            .collect()
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
        let delivery = identity
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
        assert!(!delivery.envelope.ciphertext_b64u.contains("PRIVATE"));
        let aad = sealed_operation_aad(&delivery.authorization, &binding, &reference).unwrap();
        assert_eq!(delivery.aad, URL_SAFE_NO_PAD.encode(&aad));
        let plaintext = recipient
            .open(
                &delivery.envelope.to_handoff().unwrap(),
                SEALED_SECRET_INFO,
                &aad,
            )
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
