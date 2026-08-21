use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use anp::authentication::{
    find_verification_method, is_assertion_method_authorized, is_authentication_authorized,
    validate_device_manifest, validate_did_document_binding,
};

use crate::document::{
    document_digest, key_metadata, key_metadata_from_public, public_key_from_secret,
    public_keys_equal, root_key_fingerprint, ManagedPrivateKey,
};
use crate::input::{canonicalize_kid, validate_fragment};
use crate::keystore::{SealIfAbsent, SecretRef};
use crate::registry::{
    new_identity_record, read_identity, read_registry, write_identity, write_journal,
    write_registry, CreationJournal, DocumentCheckpoint, IdentityRecord, IdentityState,
    KeyMetadata, KeyOrigin, KeyState, NewIdentityRecord, RootCapabilityState,
};
use crate::{Capabilities, DidError, DidIdentity, DidResult, DidStore, KeyRole};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerifiedDocumentEvidence {
    pub document_version: u64,
    pub registry_version: u64,
    pub document_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentSpec {
    pub verified_document: Value,
    pub evidence: VerifiedDocumentEvidence,
    pub device_id: String,
    pub device_signing_fragment: String,
    pub device_e2ee_fragment: String,
    pub profiles: Vec<String>,
    #[serde(default)]
    pub capabilities: Capabilities,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentPublicKey {
    pub kid: String,
    pub role: KeyRole,
    pub public_key_multibase: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedEnrollment {
    pub enrollment_id: String,
    pub identity_id: String,
    pub did: String,
    pub device_id: String,
    pub device_signing_key: EnrollmentPublicKey,
    pub device_e2ee_key: EnrollmentPublicKey,
    pub profiles: Vec<String>,
    pub root_key_fingerprint: String,
    pub checkpoint: DocumentCheckpoint,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RequestSigningEnrollmentSpec {
    pub verified_document: Value,
    pub evidence: VerifiedDocumentEvidence,
    pub fragment: String,
    #[serde(default)]
    pub capabilities: Capabilities,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedRequestSigningEnrollment {
    pub enrollment_id: String,
    pub identity_id: String,
    pub did: String,
    pub request_signing_key: EnrollmentPublicKey,
    pub root_key_fingerprint: String,
    pub checkpoint: DocumentCheckpoint,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AdoptVerifiedDocumentSpec {
    pub document: Value,
    pub evidence: VerifiedDocumentEvidence,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdoptDocumentOutcome {
    Activated,
    Updated,
    Unchanged,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct LocalAuthorizationRecord {
    pub(crate) device_id: String,
    pub(crate) signing_kid: String,
    pub(crate) e2ee_kid: String,
    pub(crate) profiles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingEnrollmentRecord {
    pub(crate) enrollment_id: String,
    pub(crate) local_authorization: LocalAuthorizationRecord,
    pub(crate) created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingRequestSigningRecord {
    pub(crate) enrollment_id: String,
    pub(crate) request_signing_kid: String,
    pub(crate) created_at: String,
}

impl DidStore {
    pub fn prepare_enrollment(
        &mut self,
        spec: EnrollmentSpec,
    ) -> DidResult<(DidIdentity, PreparedEnrollment)> {
        validate_enrollment_spec(&spec)?;
        let did = spec
            .verified_document
            .get("id")
            .and_then(Value::as_str)
            .ok_or(DidError::InvalidIdentity)?
            .to_string();
        let signing_kid = canonicalize_kid(&did, &spec.device_signing_fragment)?;
        let e2ee_kid = canonicalize_kid(&did, &spec.device_e2ee_fragment)?;
        if signing_kid == e2ee_kid
            || find_verification_method(&spec.verified_document, &signing_kid).is_some()
            || find_verification_method(&spec.verified_document, &e2ee_kid).is_some()
        {
            return Err(DidError::DuplicateKid);
        }

        let guard = self.runtime.acquire_write()?;
        let mut registry = read_registry(self.runtime.root())?;
        if registry.generation != self.registry_generation {
            return Err(DidError::Conflict);
        }
        if registry.identities.contains_key(&did) {
            return Err(DidError::DuplicateIdentity);
        }

        let identity_id = crate::identity::random_id();
        let enrollment_id = crate::identity::random_id();
        let transaction_id = crate::identity::random_id();
        let created_at = Utc::now().to_rfc3339();
        let signing_key = ManagedPrivateKey::generate(
            spec.device_signing_fragment.clone(),
            KeyRole::DeviceSigning,
        );
        let e2ee_key =
            ManagedPrivateKey::generate(spec.device_e2ee_fragment.clone(), KeyRole::E2eeAgreement);
        let secret_refs = vec![
            SecretRef {
                identity_id: identity_id.clone(),
                key_id: signing_kid.clone(),
                role: KeyRole::DeviceSigning,
                version: 1,
            },
            SecretRef {
                identity_id: identity_id.clone(),
                key_id: e2ee_kid.clone(),
                role: KeyRole::E2eeAgreement,
                version: 1,
            },
        ];
        let journal = CreationJournal::new(
            transaction_id.clone(),
            identity_id.clone(),
            did.clone(),
            secret_refs.clone(),
            created_at.clone(),
        );
        write_journal(self.runtime.root(), &guard, &journal)?;

        for (key, secret_ref) in [
            (&signing_key, &secret_refs[0]),
            (&e2ee_key, &secret_refs[1]),
        ] {
            let sealed = self.runtime.key_store().seal_if_absent(
                &guard,
                self.runtime.root_key(),
                secret_ref.clone(),
                key.secret_bytes(),
            )?;
            if sealed == SealIfAbsent::AlreadyExists {
                let persisted = self
                    .runtime
                    .key_store()
                    .open(self.runtime.root_key(), secret_ref)?;
                let actual = public_key_from_secret(secret_ref.role, &persisted)?;
                if !public_keys_equal(&actual, &key.public_key()) {
                    return Err(DidError::InvalidIdentity);
                }
            }
        }

        let root_kid = root_kid(&spec.verified_document)?;
        let root_metadata = key_metadata(
            &spec.verified_document,
            &root_kid,
            KeyRole::RootControl,
            KeyOrigin::External,
            &created_at,
        )?;
        let signing_metadata = key_metadata_from_public(
            &signing_kid,
            KeyRole::DeviceSigning,
            KeyOrigin::Managed,
            KeyState::Pending,
            &signing_key.public_key(),
            &created_at,
        )?;
        let e2ee_metadata = key_metadata_from_public(
            &e2ee_kid,
            KeyRole::E2eeAgreement,
            KeyOrigin::Managed,
            KeyState::Pending,
            &e2ee_key.public_key(),
            &created_at,
        )?;
        let checkpoint = checkpoint(&spec.evidence);
        let local_authorization = LocalAuthorizationRecord {
            device_id: spec.device_id.clone(),
            signing_kid: signing_kid.clone(),
            e2ee_kid: e2ee_kid.clone(),
            profiles: spec.profiles.clone(),
        };
        let root_fingerprint = root_key_fingerprint(&spec.verified_document)?;
        let mut record = new_identity_record(NewIdentityRecord {
            identity_id: identity_id.clone(),
            did: did.clone(),
            document: spec.verified_document,
            keys: vec![
                root_metadata,
                signing_metadata.clone(),
                e2ee_metadata.clone(),
            ],
            capabilities: spec.capabilities,
            root_capability: RootCapabilityState::Absent,
            root_key_fingerprint: root_fingerprint.clone(),
            checkpoint: checkpoint.clone(),
            local_authorization: Some(local_authorization.clone()),
            created_at: created_at.clone(),
        });
        record.state = IdentityState::Enrolling;
        record.pending_enrollment = Some(PendingEnrollmentRecord {
            enrollment_id: enrollment_id.clone(),
            local_authorization,
            created_at,
        });
        write_identity(self.runtime.root(), &guard, &record)?;
        let next_generation = registry
            .generation
            .checked_add(1)
            .ok_or(DidError::Conflict)?;
        registry.identities.insert(did.clone(), record.summary());
        registry.generation = next_generation;
        write_registry(self.runtime.root(), &guard, &registry)?;
        crate::registry::remove_journal(self.runtime.root(), &guard, &transaction_id)?;
        drop(guard);
        self.registry_generation = next_generation;

        let prepared = PreparedEnrollment {
            enrollment_id,
            identity_id,
            did,
            device_id: spec.device_id,
            device_signing_key: EnrollmentPublicKey {
                kid: signing_kid,
                role: KeyRole::DeviceSigning,
                public_key_multibase: signing_metadata.public_key_multibase,
            },
            device_e2ee_key: EnrollmentPublicKey {
                kid: e2ee_kid,
                role: KeyRole::E2eeAgreement,
                public_key_multibase: e2ee_metadata.public_key_multibase,
            },
            profiles: spec.profiles,
            root_key_fingerprint: root_fingerprint,
            checkpoint,
        };
        Ok((
            DidIdentity {
                runtime: std::sync::Arc::clone(&self.runtime),
                record,
            },
            prepared,
        ))
    }

    pub fn prepare_request_signing_enrollment(
        &mut self,
        spec: RequestSigningEnrollmentSpec,
    ) -> DidResult<(DidIdentity, PreparedRequestSigningEnrollment)> {
        validate_verified_document(&spec.verified_document, &spec.evidence)?;
        validate_fragment(&spec.fragment)?;
        let did = spec
            .verified_document
            .get("id")
            .and_then(Value::as_str)
            .ok_or(DidError::InvalidIdentity)?
            .to_string();
        let kid = canonicalize_kid(&did, &spec.fragment)?;
        if find_verification_method(&spec.verified_document, &kid).is_some() {
            return Err(DidError::DuplicateKid);
        }
        let guard = self.runtime.acquire_write()?;
        let mut registry = read_registry(self.runtime.root())?;
        if registry.generation != self.registry_generation {
            return Err(DidError::Conflict);
        }
        if registry.identities.contains_key(&did) {
            return Err(DidError::DuplicateIdentity);
        }

        let identity_id = crate::identity::random_id();
        let enrollment_id = crate::identity::random_id();
        let transaction_id = crate::identity::random_id();
        let created_at = Utc::now().to_rfc3339();
        let request_key = ManagedPrivateKey::generate(spec.fragment, KeyRole::RequestSigning);
        let secret_ref = SecretRef {
            identity_id: identity_id.clone(),
            key_id: kid.clone(),
            role: KeyRole::RequestSigning,
            version: 1,
        };
        let journal = CreationJournal::new(
            transaction_id.clone(),
            identity_id.clone(),
            did.clone(),
            vec![secret_ref.clone()],
            created_at.clone(),
        );
        write_journal(self.runtime.root(), &guard, &journal)?;
        let sealed = self.runtime.key_store().seal_if_absent(
            &guard,
            self.runtime.root_key(),
            secret_ref.clone(),
            request_key.secret_bytes(),
        )?;
        if sealed == SealIfAbsent::AlreadyExists {
            let persisted = self
                .runtime
                .key_store()
                .open(self.runtime.root_key(), &secret_ref)?;
            let actual = public_key_from_secret(KeyRole::RequestSigning, &persisted)?;
            if !public_keys_equal(&actual, &request_key.public_key()) {
                return Err(DidError::InvalidIdentity);
            }
        }
        let root_metadata = key_metadata(
            &spec.verified_document,
            &root_kid(&spec.verified_document)?,
            KeyRole::RootControl,
            KeyOrigin::External,
            &created_at,
        )?;
        let request_metadata = key_metadata_from_public(
            &kid,
            KeyRole::RequestSigning,
            KeyOrigin::Managed,
            KeyState::Pending,
            &request_key.public_key(),
            &created_at,
        )?;
        let checkpoint = checkpoint(&spec.evidence);
        let root_fingerprint = root_key_fingerprint(&spec.verified_document)?;
        let mut record = new_identity_record(NewIdentityRecord {
            identity_id: identity_id.clone(),
            did: did.clone(),
            document: spec.verified_document,
            keys: vec![root_metadata, request_metadata.clone()],
            capabilities: spec.capabilities,
            root_capability: RootCapabilityState::Absent,
            root_key_fingerprint: root_fingerprint.clone(),
            checkpoint: checkpoint.clone(),
            local_authorization: None,
            created_at: created_at.clone(),
        });
        record.state = IdentityState::Enrolling;
        record.local_request_signing_kid = Some(kid.clone());
        record.pending_request_signing = Some(PendingRequestSigningRecord {
            enrollment_id: enrollment_id.clone(),
            request_signing_kid: kid.clone(),
            created_at,
        });
        write_identity(self.runtime.root(), &guard, &record)?;
        let next_generation = registry
            .generation
            .checked_add(1)
            .ok_or(DidError::Conflict)?;
        registry.identities.insert(did.clone(), record.summary());
        registry.generation = next_generation;
        write_registry(self.runtime.root(), &guard, &registry)?;
        crate::registry::remove_journal(self.runtime.root(), &guard, &transaction_id)?;
        drop(guard);
        self.registry_generation = next_generation;
        let prepared = PreparedRequestSigningEnrollment {
            enrollment_id,
            identity_id,
            did,
            request_signing_key: EnrollmentPublicKey {
                kid,
                role: KeyRole::RequestSigning,
                public_key_multibase: request_metadata.public_key_multibase,
            },
            root_key_fingerprint: root_fingerprint,
            checkpoint,
        };
        Ok((
            DidIdentity {
                runtime: std::sync::Arc::clone(&self.runtime),
                record,
            },
            prepared,
        ))
    }
}

impl DidIdentity {
    pub fn root_capability(&self) -> RootCapabilityState {
        self.record().root_capability
    }

    pub fn root_key_fingerprint(&self) -> &str {
        &self.record().root_key_fingerprint
    }

    pub fn checkpoint(&self) -> Option<&DocumentCheckpoint> {
        self.record().checkpoint.as_ref()
    }

    pub fn adopt_verified_document(
        &mut self,
        spec: AdoptVerifiedDocumentSpec,
    ) -> DidResult<AdoptDocumentOutcome> {
        validate_verified_document(&spec.document, &spec.evidence)?;
        if spec.document.get("id").and_then(Value::as_str) != Some(self.did()) {
            return Err(DidError::InvalidIdentity);
        }
        let guard = self.runtime().acquire_write()?;
        let mut record = read_identity(self.runtime().root(), self.identity_id())?;
        if record.generation != self.record().generation {
            return Err(DidError::Conflict);
        }
        if record.pending_revision.is_some() {
            return Err(DidError::PendingRevisionExists);
        }
        validate_checkpoint_progression(record.checkpoint.as_ref(), &spec.evidence)?;
        if root_key_fingerprint(&spec.document)? != record.root_key_fingerprint {
            return Err(DidError::RootKeyMismatch);
        }
        let checkpoint_unchanged = record.checkpoint.as_ref().is_some_and(|current| {
            current.document_version == spec.evidence.document_version
                && current.registry_version == spec.evidence.registry_version
                && current.document_digest == spec.evidence.document_digest
        });

        let local_authorized = if let Some(local) = record.local_authorization.as_ref() {
            local_authorization_matches(&record, &spec.document, local).is_ok()
        } else if let Some(kid) = record.local_request_signing_kid.as_deref() {
            request_signing_authorization_matches(&record, &spec.document, kid).is_ok()
        } else {
            true
        };
        let outcome =
            match record.state {
                IdentityState::Creating => return Err(DidError::InvalidIdentity),
                IdentityState::Enrolling => {
                    if !local_authorized
                        || (record.pending_enrollment.is_none()
                            && record.pending_request_signing.is_none())
                    {
                        return Err(DidError::InvalidIdentity);
                    }
                    for key in &mut record.keys {
                        if key.state == KeyState::Pending {
                            key.state = KeyState::Active;
                        }
                    }
                    record.pending_enrollment = None;
                    record.pending_request_signing = None;
                    record.state = IdentityState::Active;
                    AdoptDocumentOutcome::Activated
                }
                IdentityState::Active if !local_authorized => {
                    revoke_local_authorization(&mut record);
                    record.state = IdentityState::Revoked;
                    AdoptDocumentOutcome::Revoked
                }
                IdentityState::Active => {
                    if record.checkpoint.as_ref().is_some_and(|current| {
                        current.document_digest == spec.evidence.document_digest
                    }) {
                        AdoptDocumentOutcome::Unchanged
                    } else {
                        AdoptDocumentOutcome::Updated
                    }
                }
                IdentityState::Revoked => AdoptDocumentOutcome::Revoked,
            };

        if outcome == AdoptDocumentOutcome::Unchanged && checkpoint_unchanged {
            return Ok(outcome);
        }

        record.document = spec.document;
        record.checkpoint = Some(checkpoint(&spec.evidence));
        record.revision = spec.evidence.document_version;
        persist_state_transition(self, &guard, &mut record)?;
        drop(guard);
        self.replace_record(record);
        Ok(outcome)
    }
}

pub fn canonical_document_digest(document: &Value) -> DidResult<String> {
    document_digest(document)
}

pub(crate) fn infer_local_authorization(
    document: &Value,
    keys: &[KeyMetadata],
) -> DidResult<Option<LocalAuthorizationRecord>> {
    let Some(manifest) =
        validate_device_manifest(document).map_err(|_| DidError::InvalidExtension)?
    else {
        return Ok(None);
    };
    let matches = manifest
        .devices
        .iter()
        .filter(|device| {
            keys.iter().any(|key| {
                key.origin == KeyOrigin::Managed
                    && key.role == KeyRole::DeviceSigning
                    && key.kid == device.signing_key_id
            }) && keys.iter().any(|key| {
                key.origin == KeyOrigin::Managed
                    && key.role == KeyRole::E2eeAgreement
                    && key.kid == device.e2ee_key_id
            })
        })
        .collect::<Vec<_>>();
    if matches.len() > 1 {
        return Err(DidError::InvalidExtension);
    }
    Ok(matches.first().map(|device| LocalAuthorizationRecord {
        device_id: device.device_id.clone(),
        signing_kid: device.signing_key_id.clone(),
        e2ee_kid: device.e2ee_key_id.clone(),
        profiles: device.profiles.clone(),
    }))
}

fn validate_enrollment_spec(spec: &EnrollmentSpec) -> DidResult<()> {
    validate_verified_document(&spec.verified_document, &spec.evidence)?;
    validate_fragment(&spec.device_signing_fragment)?;
    validate_fragment(&spec.device_e2ee_fragment)?;
    if spec.device_id.trim().is_empty()
        || spec.device_id.trim() != spec.device_id
        || spec.profiles.is_empty()
        || spec
            .profiles
            .iter()
            .any(|profile| profile.trim().is_empty())
    {
        return Err(DidError::InvalidExtension);
    }
    Ok(())
}

pub(crate) fn validate_verified_document(
    document: &Value,
    evidence: &VerifiedDocumentEvidence,
) -> DidResult<()> {
    if evidence.document_version == 0
        || evidence.registry_version == 0
        || !validate_did_document_binding(document, true)
        || document_digest(document)? != evidence.document_digest
    {
        return Err(DidError::InvalidIdentity);
    }
    validate_device_manifest(document).map_err(|_| DidError::InvalidExtension)?;
    root_key_fingerprint(document)?;
    Ok(())
}

fn validate_checkpoint_progression(
    current: Option<&DocumentCheckpoint>,
    next: &VerifiedDocumentEvidence,
) -> DidResult<()> {
    let Some(current) = current else {
        return Ok(());
    };
    if next.document_version < current.document_version
        || next.registry_version < current.registry_version
        || (next.document_version == current.document_version
            && next.document_digest != current.document_digest)
    {
        return Err(DidError::Conflict);
    }
    Ok(())
}

fn checkpoint(evidence: &VerifiedDocumentEvidence) -> DocumentCheckpoint {
    DocumentCheckpoint {
        document_version: evidence.document_version,
        registry_version: evidence.registry_version,
        document_digest: evidence.document_digest.clone(),
    }
}

fn root_kid(document: &Value) -> DidResult<String> {
    document
        .get("proof")
        .and_then(Value::as_object)
        .and_then(|proof| proof.get("verificationMethod"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or(DidError::InvalidIdentity)
}

fn local_authorization_matches(
    record: &IdentityRecord,
    document: &Value,
    local: &LocalAuthorizationRecord,
) -> DidResult<()> {
    let signing = record
        .keys
        .iter()
        .find(|key| key.kid == local.signing_kid)
        .ok_or(DidError::KeyNotFound)?;
    let e2ee = record
        .keys
        .iter()
        .find(|key| key.kid == local.e2ee_kid)
        .ok_or(DidError::KeyNotFound)?;
    key_matches_document(document, signing)?;
    key_matches_document(document, e2ee)?;
    if !is_authentication_authorized(document, &signing.kid)
        || !is_assertion_method_authorized(document, &signing.kid)
        || !relationship_contains(document, "keyAgreement", &e2ee.kid)
    {
        return Err(DidError::KeyRoleViolation);
    }
    let manifest = validate_device_manifest(document)
        .map_err(|_| DidError::InvalidExtension)?
        .ok_or(DidError::InvalidExtension)?;
    let matches = manifest
        .devices
        .iter()
        .filter(|device| device.device_id == local.device_id)
        .collect::<Vec<_>>();
    if matches.len() != 1
        || matches[0].signing_key_id != local.signing_kid
        || matches[0].e2ee_key_id != local.e2ee_kid
        || matches[0].profiles != local.profiles
    {
        return Err(DidError::InvalidExtension);
    }
    Ok(())
}

fn key_matches_document(document: &Value, metadata: &KeyMetadata) -> DidResult<()> {
    let method =
        find_verification_method(document, &metadata.kid).ok_or(DidError::InvalidIdentity)?;
    let observed =
        anp::authentication::extract_public_key(&method).map_err(|_| DidError::InvalidPublicKey)?;
    let expected_multibase = crate::document::public_key_multibase(&observed)?;
    if expected_multibase != metadata.public_key_multibase {
        return Err(DidError::InvalidPublicKey);
    }
    Ok(())
}

fn request_signing_authorization_matches(
    record: &IdentityRecord,
    document: &Value,
    kid: &str,
) -> DidResult<()> {
    let metadata = record
        .keys
        .iter()
        .find(|key| key.kid == kid && key.role == KeyRole::RequestSigning)
        .ok_or(DidError::KeyNotFound)?;
    key_matches_document(document, metadata)?;
    if !is_authentication_authorized(document, kid) || is_assertion_method_authorized(document, kid)
    {
        return Err(DidError::KeyRoleViolation);
    }
    Ok(())
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

fn revoke_local_authorization(record: &mut IdentityRecord) {
    let signing_kid = record
        .local_authorization
        .as_ref()
        .map(|local| local.signing_kid.as_str())
        .or(record.local_request_signing_kid.as_deref());
    let e2ee_kid = record
        .local_authorization
        .as_ref()
        .map(|local| local.e2ee_kid.as_str());
    for key in &mut record.keys {
        if signing_kid == Some(key.kid.as_str()) || e2ee_kid == Some(key.kid.as_str()) {
            key.state = KeyState::Revoked;
        }
    }
}

pub(crate) fn persist_state_transition(
    identity: &DidIdentity,
    guard: &crate::store_lock::StoreWriteGuard,
    record: &mut IdentityRecord,
) -> DidResult<()> {
    let transaction_id = crate::identity::random_id();
    let journal = CreationJournal::new_state_transition(
        transaction_id.clone(),
        record.identity_id.clone(),
        record.did.clone(),
        Utc::now().to_rfc3339(),
    );
    write_journal(identity.runtime().root(), guard, &journal)?;
    record.generation = record.generation.checked_add(1).ok_or(DidError::Conflict)?;
    write_identity(identity.runtime().root(), guard, record)?;
    let mut registry = read_registry(identity.runtime().root())?;
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
    write_registry(identity.runtime().root(), guard, &registry)?;
    crate::registry::remove_journal(identity.runtime().root(), guard, &transaction_id)
}

#[cfg(test)]
mod tests;
