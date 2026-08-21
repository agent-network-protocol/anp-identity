use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::document::{public_key_from_secret, public_keys_equal, root_key_fingerprint};
use crate::keystore::{SealIfAbsent, SecretRef};
use crate::registry::{
    read_identity, read_registry, write_identity, write_journal, write_registry, CreationJournal,
    DocumentCheckpoint, IdentityRecord, KeyOrigin, KeyState, RootCapabilityState,
};
use crate::secret::SecretBytes;
use crate::{DidError, DidIdentity, DidResult, IdentityState, KeyRole, VerifiedDocumentEvidence};

pub const WRAPPED_ROOT_ENVELOPE_TYPE: &str = "anp.identity.root-transfer.wrapped";
pub const WRAPPED_ROOT_ENVELOPE_VERSION: u32 = 1;
const MAX_TTL_SECONDS: i64 = 600;
const CLOCK_SKEW_SECONDS: i64 = 120;
const NONCE_LEN: usize = 12;
const MAX_REPLAY_RECORDS: usize = 256;
const KDF_SALT_LABEL: &[u8] = b"anp-identity:root-transfer:salt:v1\0";
const KDF_INFO_LABEL: &[u8] = b"anp-identity:root-transfer:aead:v1\0";
const SIGNATURE_LABEL: &[u8] = b"anp-identity:root-transfer:signature:v1\0";
#[cfg(feature = "root-export")]
const ED25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RootTransferContext {
    pub source_did: String,
    pub target_did: String,
    pub sender_device_id: String,
    pub recipient_device_id: String,
    pub recipient_agreement_kid: String,
    pub root_kid: String,
    pub checkpoint: DocumentCheckpoint,
    pub created_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WrappedRootEnvelope {
    #[serde(rename = "type")]
    pub envelope_type: String,
    pub version: u32,
    pub context: RootTransferContext,
    pub ephemeral_public_b64u: String,
    pub nonce_b64u: String,
    pub ciphertext_b64u: String,
    pub signature_b64u: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootTransferExportSpec {
    pub target_did: String,
    pub sender_device_id: String,
    pub recipient_device_id: String,
    pub recipient_agreement_kid: String,
    pub recipient_agreement_public: [u8; 32],
    pub root_kid: String,
    pub ttl_seconds: u32,
}

/// Zeroizing PKCS#8 DER returned only for a user-confirmed root transfer.
///
/// This value is intentionally non-serializable, non-cloneable, and does not
/// implement `Debug`. Callers must not persist it or use it as a backup API.
#[cfg(feature = "root-export")]
pub struct ExportedRootPrivateKey {
    pkcs8_der: Zeroizing<Vec<u8>>,
}

#[cfg(feature = "root-export")]
impl ExportedRootPrivateKey {
    pub fn as_pkcs8_der(&self) -> &[u8] {
        self.pkcs8_der.as_slice()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RootPromotionSpec {
    pub document: Value,
    pub evidence: VerifiedDocumentEvidence,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RootTransferImportOutcome {
    Pending,
    Active,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingRootTransferRecord {
    pub(crate) transfer_digest: String,
    pub(crate) root_kid: String,
    pub(crate) imported_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RootTransferReplayRecord {
    pub(crate) nonce: String,
    pub(crate) transfer_digest: String,
    pub(crate) expires_at: String,
}

#[cfg(feature = "key-import")]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LegacyRootTransferEvidence {
    pub transfer_id: String,
    pub source_did: String,
    pub target_did: String,
    pub sender_device_id: String,
    pub recipient_device_id: String,
    pub recipient_agreement_kid: String,
    pub root_kid: String,
    pub checkpoint: DocumentCheckpoint,
    pub accepted_at: String,
}

#[cfg(feature = "key-import")]
pub struct LegacyRootTransferImportSpec {
    pub evidence: LegacyRootTransferEvidence,
    pub encoding: crate::PrivateKeyEncoding,
    pub root_key: Zeroizing<Vec<u8>>,
}

impl DidIdentity {
    /// Exports the active managed root-control key for `RootKeyEnvelopeV1`.
    ///
    /// The host is responsible for enforcing its user-confirmation interaction
    /// before calling this method and for immediately passing the returned DER
    /// to an end-to-end encrypted root-transfer envelope.
    #[cfg(feature = "root-export")]
    pub fn export_root_private_key(&self, root_kid: &str) -> DidResult<ExportedRootPrivateKey> {
        if self.state() != IdentityState::Active
            || self.root_capability() != RootCapabilityState::Active
        {
            return Err(DidError::RootCapabilityUnavailable);
        }
        let root = self.managed_key_metadata(root_kid)?;
        if root.role != KeyRole::RootControl || root.state != KeyState::Active {
            return Err(DidError::RootCapabilityUnavailable);
        }
        let secret = self.load_managed_secret(root)?;
        if secret.expose().len() != 32 {
            return Err(DidError::InvalidIdentity);
        }
        let mut pkcs8_der = Zeroizing::new(Vec::with_capacity(
            ED25519_PKCS8_PREFIX.len() + secret.expose().len(),
        ));
        pkcs8_der.extend_from_slice(&ED25519_PKCS8_PREFIX);
        pkcs8_der.extend_from_slice(secret.expose());
        Ok(ExportedRootPrivateKey { pkcs8_der })
    }

    pub fn export_wrapped_root(
        &self,
        spec: RootTransferExportSpec,
    ) -> DidResult<WrappedRootEnvelope> {
        let now = Utc::now();
        let mut ephemeral = x25519_dalek::StaticSecret::random_from_rng(OsRng).to_bytes();
        let mut nonce = [0_u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let result = self.export_wrapped_root_inner(spec, now, ephemeral, nonce);
        ephemeral.fill(0);
        nonce.fill(0);
        result
    }

    pub fn import_wrapped_root(
        &mut self,
        envelope: &WrappedRootEnvelope,
    ) -> DidResult<RootTransferImportOutcome> {
        self.import_wrapped_root_at(envelope, Utc::now())
    }

    pub fn confirm_root_promotion(&mut self, spec: RootPromotionSpec) -> DidResult<()> {
        crate::adoption::validate_verified_document(&spec.document, &spec.evidence)?;
        if spec.document.get("id").and_then(Value::as_str) != Some(self.did())
            || root_key_fingerprint(&spec.document)? != self.root_key_fingerprint()
        {
            return Err(DidError::InvalidRootTransfer);
        }
        let guard = self.runtime().acquire_write()?;
        let mut record = read_identity(self.runtime().root(), self.identity_id())?;
        if record.generation != self.record().generation {
            return Err(DidError::Conflict);
        }
        if record.root_capability == RootCapabilityState::Active
            && record.pending_root_transfer.is_none()
        {
            return Ok(());
        }
        if record.root_capability != RootCapabilityState::Pending
            || record.pending_root_transfer.is_none()
        {
            return Err(DidError::RootCapabilityUnavailable);
        }
        validate_checkpoint_progression(record.checkpoint.as_ref(), &spec.evidence)?;
        let root = record
            .keys
            .iter_mut()
            .find(|key| key.role == KeyRole::RootControl && key.origin == KeyOrigin::Managed)
            .ok_or(DidError::RootCapabilityUnavailable)?;
        root.state = KeyState::Active;
        record.root_capability = RootCapabilityState::Active;
        record.pending_root_transfer = None;
        record.document = spec.document;
        record.checkpoint = Some(DocumentCheckpoint {
            document_version: spec.evidence.document_version,
            registry_version: spec.evidence.registry_version,
            document_digest: spec.evidence.document_digest,
        });
        record.revision = record
            .checkpoint
            .as_ref()
            .map(|checkpoint| checkpoint.document_version)
            .ok_or(DidError::InvalidIdentity)?;
        crate::adoption::persist_state_transition(self, &guard, &mut record)?;
        drop(guard);
        self.replace_record(record);
        Ok(())
    }

    #[cfg(feature = "key-import")]
    pub fn import_legacy_root_transfer(
        &mut self,
        spec: LegacyRootTransferImportSpec,
    ) -> DidResult<RootTransferImportOutcome> {
        validate_legacy_evidence(self, &spec.evidence)?;
        let material = crate::key_import::parse_private_key(
            KeyRole::RootControl,
            spec.encoding,
            &spec.root_key,
        )?;
        let public = material.public_key();
        let raw = crate::key_import::raw_private_key(material, KeyRole::RootControl)?;
        let digest = digest_serialized(&spec.evidence)?;
        self.commit_pending_root(
            &spec.evidence.root_kid,
            raw,
            public,
            format!("legacy:{}", spec.evidence.transfer_id),
            digest,
            spec.evidence.accepted_at.clone(),
        )
    }

    fn export_wrapped_root_inner(
        &self,
        spec: RootTransferExportSpec,
        created_at: DateTime<Utc>,
        ephemeral_bytes: [u8; 32],
        nonce: [u8; NONCE_LEN],
    ) -> DidResult<WrappedRootEnvelope> {
        if self.state() != IdentityState::Active
            || self.root_capability() != RootCapabilityState::Active
            || spec.ttl_seconds == 0
            || i64::from(spec.ttl_seconds) > MAX_TTL_SECONDS
            || spec.target_did != self.did()
            || spec.sender_device_id.trim().is_empty()
            || spec.recipient_device_id.trim().is_empty()
        {
            return Err(DidError::RootCapabilityUnavailable);
        }
        let root = self.managed_key_metadata(&spec.root_kid)?;
        if root.role != KeyRole::RootControl || root.state != KeyState::Active {
            return Err(DidError::RootCapabilityUnavailable);
        }
        let checkpoint = self
            .checkpoint()
            .cloned()
            .ok_or(DidError::InvalidIdentity)?;
        let context = RootTransferContext {
            source_did: self.did().to_string(),
            target_did: spec.target_did.clone(),
            sender_device_id: spec.sender_device_id.clone(),
            recipient_device_id: spec.recipient_device_id.clone(),
            recipient_agreement_kid: spec.recipient_agreement_kid.clone(),
            root_kid: root.kid.clone(),
            checkpoint,
            created_at: timestamp(created_at),
            expires_at: timestamp(created_at + Duration::seconds(i64::from(spec.ttl_seconds))),
        };
        let ephemeral = x25519_dalek::StaticSecret::from(ephemeral_bytes);
        let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral).to_bytes();
        let shared = Zeroizing::new(
            ephemeral
                .diffie_hellman(&x25519_dalek::PublicKey::from(
                    spec.recipient_agreement_public,
                ))
                .to_bytes(),
        );
        if shared.iter().all(|byte| *byte == 0) {
            return Err(DidError::InvalidPeerKey);
        }
        validate_export_recipient(self, &spec)?;
        let aad = envelope_aad(&context, &ephemeral_public, &nonce)?;
        let key = derive_transfer_key(shared.as_slice(), &aad)?;
        let cipher =
            ChaCha20Poly1305::new_from_slice(key.as_slice()).map_err(|_| DidError::Crypto)?;
        let root_secret = self.load_managed_secret(root)?;
        let nonce_value = Nonce::from(nonce);
        let ciphertext = cipher
            .encrypt(
                &nonce_value,
                Payload {
                    msg: root_secret.expose(),
                    aad: &aad,
                },
            )
            .map_err(|_| DidError::Crypto)?;
        let mut envelope = WrappedRootEnvelope {
            envelope_type: WRAPPED_ROOT_ENVELOPE_TYPE.to_string(),
            version: WRAPPED_ROOT_ENVELOPE_VERSION,
            context,
            ephemeral_public_b64u: URL_SAFE_NO_PAD.encode(ephemeral_public),
            nonce_b64u: URL_SAFE_NO_PAD.encode(nonce),
            ciphertext_b64u: URL_SAFE_NO_PAD.encode(ciphertext),
            signature_b64u: String::new(),
        };
        let signature_input = envelope_signature_input(&envelope)?;
        let signing_key = root_signing_key(&root_secret)?;
        use ed25519_dalek::Signer;
        envelope.signature_b64u =
            URL_SAFE_NO_PAD.encode(signing_key.sign(&signature_input).to_bytes());
        Ok(envelope)
    }

    fn import_wrapped_root_at(
        &mut self,
        envelope: &WrappedRootEnvelope,
        now: DateTime<Utc>,
    ) -> DidResult<RootTransferImportOutcome> {
        let digest = digest_serialized(envelope)?;
        let known_replay =
            self.record().root_transfer_replays.iter().any(|replay| {
                replay.nonce == envelope.nonce_b64u && replay.transfer_digest == digest
            });
        validate_wrapped_envelope(self, envelope, now, known_replay)?;
        let ephemeral_public: [u8; 32] = decode_fixed(&envelope.ephemeral_public_b64u)?;
        let nonce: [u8; NONCE_LEN] = decode_fixed(&envelope.nonce_b64u)?;
        let ciphertext = URL_SAFE_NO_PAD
            .decode(&envelope.ciphertext_b64u)
            .map_err(|_| DidError::InvalidRootTransfer)?;
        let agreement = self.managed_key_metadata(&envelope.context.recipient_agreement_kid)?;
        if agreement.role != KeyRole::E2eeAgreement || agreement.state != KeyState::Active {
            return Err(DidError::KeyRoleViolation);
        }
        let agreement_secret = self.load_managed_secret(agreement)?;
        let private = x25519_private(&agreement_secret)?;
        let shared = Zeroizing::new(
            private
                .diffie_hellman(&x25519_dalek::PublicKey::from(ephemeral_public))
                .to_bytes(),
        );
        if shared.iter().all(|byte| *byte == 0) {
            return Err(DidError::InvalidPeerKey);
        }
        let aad = envelope_aad(&envelope.context, &ephemeral_public, &nonce)?;
        let key = derive_transfer_key(shared.as_slice(), &aad)?;
        let cipher =
            ChaCha20Poly1305::new_from_slice(key.as_slice()).map_err(|_| DidError::Crypto)?;
        let nonce_value = Nonce::from(nonce);
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &nonce_value,
                    Payload {
                        msg: &ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| DidError::InvalidRootTransfer)?,
        );
        let raw: [u8; 32] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| DidError::InvalidRootTransfer)?;
        let raw = Zeroizing::new(raw);
        let public = anp::PublicKeyMaterial::Ed25519(
            ed25519_dalek::SigningKey::from_bytes(&raw).verifying_key(),
        );
        self.commit_pending_root(
            &envelope.context.root_kid,
            raw,
            public,
            envelope.nonce_b64u.clone(),
            digest,
            envelope.context.expires_at.clone(),
        )
    }

    fn commit_pending_root(
        &mut self,
        root_kid: &str,
        raw: Zeroizing<[u8; 32]>,
        public: anp::PublicKeyMaterial,
        replay_nonce: String,
        transfer_digest: String,
        replay_expires_at: String,
    ) -> DidResult<RootTransferImportOutcome> {
        let guard = self.runtime().acquire_write()?;
        let mut record = read_identity(self.runtime().root(), self.identity_id())?;
        if record.generation != self.record().generation || record.state != IdentityState::Active {
            return Err(DidError::Conflict);
        }
        if record.pending_revision.is_some() {
            return Err(DidError::PendingRevisionExists);
        }
        if let Some(replay) = record
            .root_transfer_replays
            .iter()
            .find(|replay| replay.nonce == replay_nonce)
        {
            if replay.transfer_digest != transfer_digest {
                return Err(DidError::InvalidRootTransfer);
            }
            return match record.root_capability {
                RootCapabilityState::Pending => Ok(RootTransferImportOutcome::Pending),
                RootCapabilityState::Active => Ok(RootTransferImportOutcome::Active),
                RootCapabilityState::Absent => Err(DidError::InvalidIdentity),
            };
        }
        if record.root_capability == RootCapabilityState::Active {
            verify_root_public(&record, root_kid, &public)?;
            push_replay(
                &mut record,
                replay_nonce,
                transfer_digest,
                replay_expires_at,
            );
            crate::adoption::persist_state_transition(self, &guard, &mut record)?;
            drop(guard);
            self.replace_record(record);
            return Ok(RootTransferImportOutcome::Active);
        }
        if let Some(pending) = &record.pending_root_transfer {
            return if pending.transfer_digest == transfer_digest {
                Ok(RootTransferImportOutcome::Pending)
            } else {
                Err(DidError::PendingRootTransferExists)
            };
        }
        if record.root_capability != RootCapabilityState::Absent {
            return Err(DidError::RootCapabilityUnavailable);
        }
        verify_root_public(&record, root_kid, &public)?;
        let root_index = record
            .keys
            .iter()
            .position(|key| key.role == KeyRole::RootControl && key.kid == root_kid)
            .ok_or(DidError::KeyNotFound)?;
        let secret_ref = SecretRef {
            identity_id: record.identity_id.clone(),
            key_id: root_kid.to_string(),
            role: KeyRole::RootControl,
            version: record.keys[root_index].version,
        };
        let transaction_id = crate::identity::random_id();
        let imported_at = timestamp(Utc::now());
        let journal = CreationJournal::new_root_import(
            transaction_id.clone(),
            record.identity_id.clone(),
            record.did.clone(),
            vec![secret_ref.clone()],
            imported_at.clone(),
        );
        write_journal(self.runtime().root(), &guard, &journal)?;
        let sealed = self.runtime().key_store().seal_if_absent(
            &guard,
            self.runtime().root_key(),
            secret_ref.clone(),
            SecretBytes::new(raw.to_vec()),
        )?;
        if sealed == SealIfAbsent::AlreadyExists {
            let persisted = self
                .runtime()
                .key_store()
                .open(self.runtime().root_key(), &secret_ref)?;
            let actual = public_key_from_secret(KeyRole::RootControl, &persisted)?;
            if !public_keys_equal(&actual, &public) {
                return Err(DidError::InvalidIdentity);
            }
        }
        record.keys[root_index].origin = KeyOrigin::Managed;
        record.keys[root_index].state = KeyState::Pending;
        record.root_capability = RootCapabilityState::Pending;
        record.pending_root_transfer = Some(PendingRootTransferRecord {
            transfer_digest: transfer_digest.clone(),
            root_kid: root_kid.to_string(),
            imported_at,
        });
        push_replay(
            &mut record,
            replay_nonce,
            transfer_digest,
            replay_expires_at,
        );
        record.generation = record.generation.checked_add(1).ok_or(DidError::Conflict)?;
        write_identity(self.runtime().root(), &guard, &record)?;
        let mut registry = read_registry(self.runtime().root())?;
        let summary = registry
            .identities
            .get_mut(&record.did)
            .filter(|summary| summary.identity_id == record.identity_id)
            .ok_or(DidError::IdentityNotFound)?;
        *summary = record.summary();
        registry.generation = registry
            .generation
            .checked_add(1)
            .ok_or(DidError::Conflict)?;
        write_registry(self.runtime().root(), &guard, &registry)?;
        crate::registry::remove_journal(self.runtime().root(), &guard, &transaction_id)?;
        drop(guard);
        self.replace_record(record);
        Ok(RootTransferImportOutcome::Pending)
    }
}

fn validate_export_recipient(
    identity: &DidIdentity,
    spec: &RootTransferExportSpec,
) -> DidResult<()> {
    let canonical_kid =
        crate::input::canonicalize_kid(identity.did(), &spec.recipient_agreement_kid)?;
    if canonical_kid != spec.recipient_agreement_kid {
        return Err(DidError::InvalidRootTransfer);
    }
    if identity
        .record()
        .local_authorization
        .as_ref()
        .is_some_and(|local| local.device_id != spec.sender_device_id)
    {
        return Err(DidError::InvalidRootTransfer);
    }
    let method = anp::authentication::find_verification_method(
        identity.document(),
        &spec.recipient_agreement_kid,
    )
    .ok_or(DidError::InvalidRootTransfer)?;
    let expected =
        anp::authentication::extract_public_key(&method).map_err(|_| DidError::InvalidPublicKey)?;
    if !public_keys_equal(
        &expected,
        &anp::PublicKeyMaterial::X25519(spec.recipient_agreement_public),
    ) || !relationship_contains(
        identity.document(),
        "keyAgreement",
        &spec.recipient_agreement_kid,
    ) {
        return Err(DidError::InvalidRootTransfer);
    }
    let manifest = anp::authentication::validate_device_manifest(identity.document())
        .map_err(|_| DidError::InvalidRootTransfer)?
        .ok_or(DidError::InvalidRootTransfer)?;
    let matches = manifest
        .devices
        .iter()
        .filter(|device| device.device_id == spec.recipient_device_id)
        .collect::<Vec<_>>();
    if matches.len() != 1 || matches[0].e2ee_key_id != spec.recipient_agreement_kid {
        return Err(DidError::InvalidRootTransfer);
    }
    Ok(())
}

fn push_replay(
    record: &mut IdentityRecord,
    nonce: String,
    transfer_digest: String,
    expires_at: String,
) {
    record.root_transfer_replays.push(RootTransferReplayRecord {
        nonce,
        transfer_digest,
        expires_at,
    });
    if record.root_transfer_replays.len() > MAX_REPLAY_RECORDS {
        let remove = record.root_transfer_replays.len() - MAX_REPLAY_RECORDS;
        record.root_transfer_replays.drain(..remove);
    }
}

fn relationship_contains(document: &Value, name: &str, kid: &str) -> bool {
    document
        .get(name)
        .and_then(Value::as_array)
        .is_some_and(|values| {
            values.iter().any(|value| {
                value.as_str() == Some(kid) || value.get("id").and_then(Value::as_str) == Some(kid)
            })
        })
}

fn validate_wrapped_envelope(
    identity: &DidIdentity,
    envelope: &WrappedRootEnvelope,
    now: DateTime<Utc>,
    allow_stale_checkpoint_for_known_replay: bool,
) -> DidResult<()> {
    if envelope.envelope_type != WRAPPED_ROOT_ENVELOPE_TYPE
        || envelope.version != WRAPPED_ROOT_ENVELOPE_VERSION
        || envelope.context.source_did != identity.did()
        || envelope.context.target_did != identity.did()
        || envelope.context.sender_device_id.trim().is_empty()
        || envelope.context.recipient_device_id.trim().is_empty()
    {
        return Err(DidError::InvalidRootTransfer);
    }
    let local = identity
        .record()
        .local_authorization
        .as_ref()
        .ok_or(DidError::InvalidRootTransfer)?;
    if local.device_id != envelope.context.recipient_device_id
        || local.e2ee_kid != envelope.context.recipient_agreement_kid
        || (!allow_stale_checkpoint_for_known_replay
            && identity.checkpoint() != Some(&envelope.context.checkpoint))
    {
        return Err(DidError::InvalidRootTransfer);
    }
    validate_time_window(&envelope.context, now)?;
    let root = identity.key_metadata(&envelope.context.root_kid)?;
    if root.role != KeyRole::RootControl {
        return Err(DidError::KeyRoleViolation);
    }
    let method = anp::authentication::find_verification_method(identity.document(), &root.kid)
        .ok_or(DidError::InvalidIdentity)?;
    let public =
        anp::authentication::extract_public_key(&method).map_err(|_| DidError::InvalidPublicKey)?;
    let signature = URL_SAFE_NO_PAD
        .decode(&envelope.signature_b64u)
        .map_err(|_| DidError::InvalidRootTransfer)?;
    public
        .verify_message(&envelope_signature_input(envelope)?, &signature)
        .map_err(|_| DidError::InvalidRootTransfer)
}

#[cfg(feature = "key-import")]
fn validate_legacy_evidence(
    identity: &DidIdentity,
    evidence: &LegacyRootTransferEvidence,
) -> DidResult<()> {
    let local = identity
        .record()
        .local_authorization
        .as_ref()
        .ok_or(DidError::InvalidRootTransfer)?;
    if evidence.transfer_id.trim().is_empty()
        || evidence.source_did != identity.did()
        || evidence.target_did != identity.did()
        || evidence.sender_device_id.trim().is_empty()
        || evidence.recipient_device_id != local.device_id
        || evidence.recipient_agreement_kid != local.e2ee_kid
        || identity.checkpoint() != Some(&evidence.checkpoint)
        || DateTime::parse_from_rfc3339(&evidence.accepted_at).is_err()
    {
        return Err(DidError::InvalidRootTransfer);
    }
    let root = identity.key_metadata(&evidence.root_kid)?;
    if root.role != KeyRole::RootControl {
        return Err(DidError::KeyRoleViolation);
    }
    Ok(())
}

fn verify_root_public(
    record: &IdentityRecord,
    root_kid: &str,
    public: &anp::PublicKeyMaterial,
) -> DidResult<()> {
    let method = anp::authentication::find_verification_method(&record.document, root_kid)
        .ok_or(DidError::KeyNotFound)?;
    let expected =
        anp::authentication::extract_public_key(&method).map_err(|_| DidError::InvalidPublicKey)?;
    if !public_keys_equal(public, &expected)
        || root_key_fingerprint(&record.document)? != record.root_key_fingerprint
    {
        return Err(DidError::InvalidPublicKey);
    }
    Ok(())
}

fn validate_checkpoint_progression(
    current: Option<&DocumentCheckpoint>,
    next: &VerifiedDocumentEvidence,
) -> DidResult<()> {
    let current = current.ok_or(DidError::InvalidIdentity)?;
    if next.document_version < current.document_version
        || next.registry_version < current.registry_version
        || (next.document_version == current.document_version
            && next.document_digest != current.document_digest)
    {
        return Err(DidError::Conflict);
    }
    Ok(())
}

fn validate_time_window(context: &RootTransferContext, now: DateTime<Utc>) -> DidResult<()> {
    let created = parse_timestamp(&context.created_at)?;
    let expires = parse_timestamp(&context.expires_at)?;
    let ttl = expires.signed_duration_since(created).num_seconds();
    if ttl <= 0
        || ttl > MAX_TTL_SECONDS
        || now < created - Duration::seconds(CLOCK_SKEW_SECONDS)
        || now > expires + Duration::seconds(CLOCK_SKEW_SECONDS)
    {
        return Err(DidError::RootTransferExpired);
    }
    Ok(())
}

fn envelope_aad(
    context: &RootTransferContext,
    ephemeral_public: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
) -> DidResult<Vec<u8>> {
    #[derive(Serialize)]
    struct Aad<'a> {
        #[serde(rename = "type")]
        envelope_type: &'a str,
        version: u32,
        context: &'a RootTransferContext,
        ephemeral_public_b64u: String,
        nonce_b64u: String,
    }
    canonical(&Aad {
        envelope_type: WRAPPED_ROOT_ENVELOPE_TYPE,
        version: WRAPPED_ROOT_ENVELOPE_VERSION,
        context,
        ephemeral_public_b64u: URL_SAFE_NO_PAD.encode(ephemeral_public),
        nonce_b64u: URL_SAFE_NO_PAD.encode(nonce),
    })
}

fn envelope_signature_input(envelope: &WrappedRootEnvelope) -> DidResult<Vec<u8>> {
    #[derive(Serialize)]
    struct Unsigned<'a> {
        #[serde(rename = "type")]
        envelope_type: &'a str,
        version: u32,
        context: &'a RootTransferContext,
        ephemeral_public_b64u: &'a str,
        nonce_b64u: &'a str,
        ciphertext_b64u: &'a str,
    }
    let canonical = canonical(&Unsigned {
        envelope_type: &envelope.envelope_type,
        version: envelope.version,
        context: &envelope.context,
        ephemeral_public_b64u: &envelope.ephemeral_public_b64u,
        nonce_b64u: &envelope.nonce_b64u,
        ciphertext_b64u: &envelope.ciphertext_b64u,
    })?;
    let mut input = SIGNATURE_LABEL.to_vec();
    input.extend_from_slice(&canonical);
    Ok(input)
}

fn derive_transfer_key(shared: &[u8], aad: &[u8]) -> DidResult<Zeroizing<[u8; 32]>> {
    let mut salt = Sha256::new();
    salt.update(KDF_SALT_LABEL);
    salt.update(aad);
    let salt = salt.finalize();
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut info = KDF_INFO_LABEL.to_vec();
    info.extend_from_slice(aad);
    let mut key = Zeroizing::new([0_u8; 32]);
    hkdf.expand(&info, key.as_mut())
        .map_err(|_| DidError::Crypto)?;
    Ok(key)
}

fn root_signing_key(secret: &SecretBytes) -> DidResult<ed25519_dalek::SigningKey> {
    let raw: [u8; 32] = secret
        .expose()
        .try_into()
        .map_err(|_| DidError::InvalidIdentity)?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&raw))
}

fn x25519_private(secret: &SecretBytes) -> DidResult<x25519_dalek::StaticSecret> {
    let raw: [u8; 32] = secret
        .expose()
        .try_into()
        .map_err(|_| DidError::InvalidIdentity)?;
    Ok(x25519_dalek::StaticSecret::from(raw))
}

fn parse_timestamp(value: &str) -> DidResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| DidError::InvalidRootTransfer)
}

fn timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn canonical(value: &impl Serialize) -> DidResult<Vec<u8>> {
    serde_json_canonicalizer::to_vec(value)
        .map_err(|error| DidError::Serialization(error.to_string()))
}

fn digest_serialized(value: &impl Serialize) -> DidResult<String> {
    Ok(format!(
        "sha256:{}",
        URL_SAFE_NO_PAD.encode(Sha256::digest(canonical(value)?))
    ))
}

fn decode_fixed<const N: usize>(value: &str) -> DidResult<[u8; N]> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| DidError::InvalidRootTransfer)?
        .try_into()
        .map_err(|_| DidError::InvalidRootTransfer)
}

#[cfg(test)]
mod tests;
