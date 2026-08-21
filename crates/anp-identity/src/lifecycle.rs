use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use anp::authentication::{validate_device_manifest, validate_did_document_binding};

use crate::document::{
    ed25519_public_multibase, key_metadata, public_keys_equal, service_json, sign_root_document,
    ManagedPrivateKey,
};
use crate::input::{canonicalize_kid, validate_fragment};
use crate::keystore::{SealIfAbsent, SecretRef};
use crate::registry::{
    list_update_journals, read_identity, remove_update_journal, write_identity,
    write_update_journal, IdentityRecord, KeyMetadata, UpdateJournal, UpdateJournalKind,
};
use crate::store::StoreRuntime;
use crate::store_lock::StoreWriteGuard;
use crate::{DidError, DidIdentity, DidResult, KeyOrigin, KeyRole, KeyState, ServiceSpec};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PublicationState {
    Prepared,
    PublicationInFlight,
    PublicationUncertain,
    Published,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RequestSigningRotation {
    pub old_kid: String,
    pub new_fragment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DevicePublicKeySpec {
    pub kid: String,
    pub public_key_multibase: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceAddSpec {
    pub device_id: String,
    pub signing_key: DevicePublicKeySpec,
    pub e2ee_key: DevicePublicKeySpec,
    pub profiles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum DeviceMutationSpec {
    Add { device: DeviceAddSpec },
    Remove { device_id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DocumentUpdateSpec {
    #[serde(default)]
    pub request_signing_rotation: Option<RequestSigningRotation>,
    #[serde(default)]
    pub device_mutations: Vec<DeviceMutationSpec>,
    pub services: Option<Vec<ServiceSpec>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PreparedUpdate {
    pub revision_id: String,
    pub candidate_document: Value,
    pub candidate_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReconcileOutcome {
    RemoteOld,
    Committed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PendingRevisionSummary {
    pub revision_id: String,
    pub parent_revision: u64,
    pub candidate_digest: String,
    pub candidate_kids: Vec<String>,
    pub state: PublicationState,
    pub generation: u64,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingRevisionRecord {
    pub(crate) revision_id: String,
    pub(crate) parent_revision: u64,
    pub(crate) candidate_document: Value,
    pub(crate) candidate_digest: String,
    pub(crate) candidate_kids: Vec<String>,
    pub(crate) pending_secret_refs: Vec<SecretRef>,
    pub(crate) new_key_metadata: Vec<KeyMetadata>,
    pub(crate) retired_kids: Vec<String>,
    pub(crate) state: PublicationState,
    pub(crate) generation: u64,
    pub(crate) created_at: String,
}

impl PendingRevisionRecord {
    fn summary(&self) -> PendingRevisionSummary {
        PendingRevisionSummary {
            revision_id: self.revision_id.clone(),
            parent_revision: self.parent_revision,
            candidate_digest: self.candidate_digest.clone(),
            candidate_kids: self.candidate_kids.clone(),
            state: self.state,
            generation: self.generation,
            created_at: self.created_at.clone(),
        }
    }
}

impl DidIdentity {
    pub fn pending_revision(&self) -> Option<PendingRevisionSummary> {
        self.record()
            .pending_revision
            .as_ref()
            .map(PendingRevisionRecord::summary)
    }

    pub fn prepare_update(&mut self, spec: DocumentUpdateSpec) -> DidResult<PreparedUpdate> {
        self.prepare_update_inner(spec, None)
    }

    pub fn begin_publication(&mut self, revision_id: &str) -> DidResult<()> {
        self.transition_publication(
            revision_id,
            PublicationState::Prepared,
            PublicationState::PublicationInFlight,
        )
    }

    pub fn mark_publication_uncertain(&mut self, revision_id: &str) -> DidResult<()> {
        self.transition_publication(
            revision_id,
            PublicationState::PublicationInFlight,
            PublicationState::PublicationUncertain,
        )
    }

    pub fn mark_published(&mut self, revision_id: &str) -> DidResult<()> {
        self.transition_publication(
            revision_id,
            PublicationState::PublicationInFlight,
            PublicationState::Published,
        )
    }

    pub fn commit_update(&mut self, revision_id: &str) -> DidResult<()> {
        self.commit_pending(revision_id, false)
    }

    pub fn abort_update(&mut self, revision_id: &str) -> DidResult<()> {
        self.abort_update_inner(revision_id, None)
    }

    pub fn reconcile_update(
        &mut self,
        revision_id: &str,
        observed_remote_document: &Value,
    ) -> DidResult<ReconcileOutcome> {
        let pending = required_pending(self.record(), revision_id)?;
        if pending.state != PublicationState::PublicationUncertain {
            return Err(DidError::InvalidPublicationState);
        }
        if observed_remote_document.get("id").and_then(Value::as_str) != Some(self.did())
            || !validate_did_document_binding(observed_remote_document, true)
        {
            return Err(DidError::InvalidIdentity);
        }
        let observed_digest = canonical_digest(observed_remote_document)?;
        if observed_digest == pending.candidate_digest {
            self.commit_pending(revision_id, true)?;
            return Ok(ReconcileOutcome::Committed);
        }
        if observed_digest == canonical_digest(self.document())? {
            self.transition_publication(
                revision_id,
                PublicationState::PublicationUncertain,
                PublicationState::Prepared,
            )?;
            return Ok(ReconcileOutcome::RemoteOld);
        }
        Err(DidError::Conflict)
    }

    pub fn end_retirement(&mut self, kid: &str) -> DidResult<()> {
        let kid = canonicalize_kid(self.did(), kid)?;
        let guard = self.runtime().acquire_write()?;
        let mut record = self.current_record_for_mutation()?;
        reject_uncertain_mutation(&record)?;
        let metadata = record
            .keys
            .iter_mut()
            .find(|metadata| metadata.kid == kid)
            .ok_or(DidError::KeyNotFound)?;
        if metadata.role == KeyRole::RootControl {
            return Err(DidError::UnsupportedOperation);
        }
        if metadata.state != KeyState::Retired {
            return Err(DidError::KeyNotUsable);
        }
        metadata.state = KeyState::Revoked;
        persist_record(self.runtime(), &guard, &mut record)?;
        drop(guard);
        self.replace_record(record);
        Ok(())
    }

    pub fn delete_revoked_key(&mut self, kid: &str) -> DidResult<()> {
        let kid = canonicalize_kid(self.did(), kid)?;
        let guard = self.runtime().acquire_write()?;
        let mut record = self.current_record_for_mutation()?;
        reject_uncertain_mutation(&record)?;
        let metadata_index = record
            .keys
            .iter()
            .position(|metadata| metadata.kid == kid)
            .ok_or(DidError::KeyNotFound)?;
        let metadata = &record.keys[metadata_index];
        if metadata.origin == KeyOrigin::External {
            return Err(DidError::ExternalKeyOperation);
        }
        if metadata.role == KeyRole::RootControl {
            return Err(DidError::UnsupportedOperation);
        }
        if metadata.state != KeyState::Revoked {
            return Err(DidError::KeyNotUsable);
        }
        if metadata.material_erased {
            return Err(DidError::KeyMaterialErased);
        }
        let secret_ref = SecretRef {
            identity_id: self.identity_id().to_string(),
            key_id: metadata.kid.clone(),
            role: metadata.role,
            version: metadata.version,
        };
        self.runtime().key_store().delete(&guard, &secret_ref)?;
        record.keys[metadata_index].material_erased = true;
        persist_record(self.runtime(), &guard, &mut record)?;
        drop(guard);
        self.replace_record(record);
        Ok(())
    }

    fn prepare_update_inner(
        &mut self,
        spec: DocumentUpdateSpec,
        failure: Option<LifecycleFailurePoint>,
    ) -> DidResult<PreparedUpdate> {
        if spec.request_signing_rotation.is_none()
            && spec.device_mutations.is_empty()
            && spec.services.is_none()
        {
            return Err(DidError::UnsupportedOperation);
        }
        for service in spec.services.as_deref().unwrap_or_default() {
            service.validate()?;
        }
        let guard = self.runtime().acquire_write()?;
        let mut record = self.current_record_for_mutation()?;
        if let Some(pending) = &record.pending_revision {
            return Err(if pending.state == PublicationState::PublicationUncertain {
                DidError::InvalidPublicationState
            } else {
                DidError::PendingRevisionExists
            });
        }
        let rotation = spec
            .request_signing_rotation
            .as_ref()
            .map(|rotation| prepare_rotation(&record, rotation))
            .transpose()?;
        let changes = build_candidate_document(
            self,
            &record,
            rotation.as_ref(),
            &spec.device_mutations,
            spec.services.as_deref(),
        )?;
        let candidate = changes.document;
        let created_at = Utc::now().to_rfc3339();
        let mut new_metadata = changes
            .added_keys
            .iter()
            .map(|(kid, role)| {
                key_metadata(&candidate, kid, *role, KeyOrigin::External, &created_at)
            })
            .collect::<DidResult<Vec<_>>>()?;
        let mut secret_refs = Vec::new();
        if let Some(rotation) = &rotation {
            let metadata = key_metadata(
                &candidate,
                &rotation.new_kid,
                KeyRole::RequestSigning,
                KeyOrigin::Managed,
                &created_at,
            )?;
            secret_refs.push(SecretRef {
                identity_id: record.identity_id.clone(),
                key_id: rotation.new_kid.clone(),
                role: KeyRole::RequestSigning,
                version: metadata.version,
            });
            new_metadata.push(metadata);
        }
        let revision_id = random_revision_id();
        let update_journal = UpdateJournal::new(
            revision_id.clone(),
            record.identity_id.clone(),
            secret_refs.clone(),
            UpdateJournalKind::Prepare,
            created_at.clone(),
        );
        write_update_journal(self.runtime().root(), &guard, &update_journal)?;
        maybe_fail(failure, LifecycleFailurePoint::PrepareJournalPersisted)?;
        if let (Some(rotation), Some(secret_ref)) = (&rotation, secret_refs.first()) {
            let sealed = self.runtime().key_store().seal_if_absent(
                &guard,
                self.runtime().root_key(),
                secret_ref.clone(),
                rotation.new_key.secret_bytes(),
            )?;
            if sealed == SealIfAbsent::AlreadyExists {
                let stored = self
                    .runtime()
                    .key_store()
                    .open(self.runtime().root_key(), secret_ref)?;
                let actual =
                    crate::document::public_key_from_secret(KeyRole::RequestSigning, &stored)?;
                if !public_keys_equal(&actual, &rotation.new_key.public_key()) {
                    return Err(DidError::InvalidIdentity);
                }
            }
        }
        maybe_fail(failure, LifecycleFailurePoint::PendingSecretPersisted)?;

        let candidate_digest = canonical_digest(&candidate)?;
        let mut candidate_kids = changes
            .added_keys
            .into_iter()
            .map(|(kid, _)| kid)
            .collect::<Vec<_>>();
        if let Some(rotation) = &rotation {
            candidate_kids.push(rotation.new_kid.clone());
        }
        let mut retired_kids = changes.retired_kids;
        if let Some(rotation) = &rotation {
            retired_kids.push(rotation.old_kid.clone());
        }
        let pending = PendingRevisionRecord {
            revision_id: revision_id.clone(),
            parent_revision: record.revision,
            candidate_document: candidate.clone(),
            candidate_digest: candidate_digest.clone(),
            candidate_kids,
            pending_secret_refs: secret_refs,
            new_key_metadata: new_metadata,
            retired_kids,
            state: PublicationState::Prepared,
            generation: 1,
            created_at,
        };
        record.pending_revision = Some(pending);
        persist_record(self.runtime(), &guard, &mut record)?;
        maybe_fail(failure, LifecycleFailurePoint::PendingIdentityPersisted)?;
        remove_update_journal(self.runtime().root(), &guard, &revision_id)?;
        drop(guard);
        self.replace_record(record);
        Ok(PreparedUpdate {
            revision_id,
            candidate_document: candidate,
            candidate_digest,
        })
    }

    fn transition_publication(
        &mut self,
        revision_id: &str,
        expected: PublicationState,
        next: PublicationState,
    ) -> DidResult<()> {
        let guard = self.runtime().acquire_write()?;
        let mut record = self.current_record_for_mutation()?;
        let pending = required_pending_mut(&mut record, revision_id)?;
        if pending.state != expected {
            return Err(DidError::InvalidPublicationState);
        }
        pending.state = next;
        pending.generation = pending
            .generation
            .checked_add(1)
            .ok_or(DidError::Conflict)?;
        persist_record(self.runtime(), &guard, &mut record)?;
        drop(guard);
        self.replace_record(record);
        Ok(())
    }

    fn commit_pending(&mut self, revision_id: &str, from_reconcile: bool) -> DidResult<()> {
        let guard = self.runtime().acquire_write()?;
        let mut record = self.current_record_for_mutation()?;
        let pending = required_pending(&record, revision_id)?.clone();
        let allowed = pending.state == PublicationState::Published
            || (from_reconcile && pending.state == PublicationState::PublicationUncertain);
        if !allowed || pending.parent_revision != record.revision {
            return Err(DidError::InvalidPublicationState);
        }
        for retired_kid in &pending.retired_kids {
            if let Some(replaced) = record
                .keys
                .iter_mut()
                .find(|metadata| metadata.kid == *retired_kid)
            {
                replaced.state = KeyState::Retired;
            }
        }
        record.keys.extend(pending.new_key_metadata);
        record.document = pending.candidate_document;
        record.revision = record.revision.checked_add(1).ok_or(DidError::Conflict)?;
        record.pending_revision = None;
        persist_record(self.runtime(), &guard, &mut record)?;
        drop(guard);
        self.replace_record(record);
        Ok(())
    }

    fn abort_update_inner(
        &mut self,
        revision_id: &str,
        failure: Option<LifecycleFailurePoint>,
    ) -> DidResult<()> {
        let guard = self.runtime().acquire_write()?;
        let mut record = self.current_record_for_mutation()?;
        let pending = required_pending(&record, revision_id)?.clone();
        if pending.state != PublicationState::Prepared {
            return Err(DidError::InvalidPublicationState);
        }
        let journal = UpdateJournal::new(
            pending.revision_id.clone(),
            record.identity_id.clone(),
            pending.pending_secret_refs.clone(),
            UpdateJournalKind::Cleanup,
            Utc::now().to_rfc3339(),
        );
        write_update_journal(self.runtime().root(), &guard, &journal)?;
        maybe_fail(failure, LifecycleFailurePoint::CleanupJournalPersisted)?;
        record.pending_revision = None;
        persist_record(self.runtime(), &guard, &mut record)?;
        maybe_fail(failure, LifecycleFailurePoint::PendingIdentityCleared)?;
        for secret_ref in &pending.pending_secret_refs {
            self.runtime().key_store().delete(&guard, secret_ref)?;
        }
        maybe_fail(failure, LifecycleFailurePoint::PendingSecretsDeleted)?;
        remove_update_journal(self.runtime().root(), &guard, revision_id)?;
        drop(guard);
        self.replace_record(record);
        Ok(())
    }

    fn current_record_for_mutation(&self) -> DidResult<IdentityRecord> {
        let record = read_identity(self.runtime().root(), self.identity_id())?;
        if record.generation != self.record().generation
            || record.state != crate::IdentityState::Active
        {
            return Err(DidError::Conflict);
        }
        Ok(record)
    }
}

pub(crate) fn recover_update_journals(
    runtime: &StoreRuntime,
    guard: &StoreWriteGuard,
) -> DidResult<()> {
    for journal in list_update_journals(runtime.root())? {
        let mut record = read_identity(runtime.root(), &journal.identity_id)?;
        match journal.kind {
            UpdateJournalKind::Prepare => {
                let committed = record
                    .pending_revision
                    .as_ref()
                    .is_some_and(|pending| pending.revision_id == journal.revision_id);
                if !committed {
                    for secret_ref in &journal.secret_refs {
                        runtime.key_store().delete(guard, secret_ref)?;
                    }
                }
            }
            UpdateJournalKind::Cleanup => {
                if record
                    .pending_revision
                    .as_ref()
                    .is_some_and(|pending| pending.revision_id == journal.revision_id)
                {
                    record.pending_revision = None;
                    persist_record(runtime, guard, &mut record)?;
                }
                for secret_ref in &journal.secret_refs {
                    runtime.key_store().delete(guard, secret_ref)?;
                }
            }
        }
        remove_update_journal(runtime.root(), guard, &journal.revision_id)?;
    }
    Ok(())
}

struct PreparedRotation {
    old_kid: String,
    new_kid: String,
    new_key: ManagedPrivateKey,
}

struct CandidateChanges {
    document: Value,
    added_keys: Vec<(String, KeyRole)>,
    retired_kids: Vec<String>,
}

struct DeviceChanges {
    added_keys: Vec<(String, KeyRole)>,
    retired_kids: Vec<String>,
}

fn prepare_rotation(
    record: &IdentityRecord,
    rotation: &RequestSigningRotation,
) -> DidResult<PreparedRotation> {
    let old_kid = canonicalize_kid(&record.did, &rotation.old_kid)?;
    let old_metadata = record
        .keys
        .iter()
        .find(|metadata| metadata.kid == old_kid)
        .ok_or(DidError::KeyNotFound)?;
    if old_metadata.origin == KeyOrigin::External {
        return Err(DidError::ExternalKeyOperation);
    }
    if old_metadata.role == KeyRole::RootControl {
        return Err(DidError::UnsupportedOperation);
    }
    if old_metadata.role != KeyRole::RequestSigning {
        return Err(DidError::KeyRoleViolation);
    }
    if old_metadata.state != KeyState::Active {
        return Err(DidError::KeyNotUsable);
    }
    validate_fragment(&rotation.new_fragment)?;
    let new_kid = canonicalize_kid(&record.did, &rotation.new_fragment)?;
    if record.keys.iter().any(|metadata| metadata.kid == new_kid) {
        return Err(DidError::DuplicateKid);
    }
    Ok(PreparedRotation {
        old_kid,
        new_kid,
        new_key: ManagedPrivateKey::generate(
            rotation.new_fragment.clone(),
            KeyRole::RequestSigning,
        ),
    })
}

fn build_candidate_document(
    identity: &DidIdentity,
    record: &IdentityRecord,
    rotation: Option<&PreparedRotation>,
    device_mutations: &[DeviceMutationSpec],
    services: Option<&[ServiceSpec]>,
) -> DidResult<CandidateChanges> {
    let mut document = record.document.clone();
    let object = document.as_object_mut().ok_or(DidError::InvalidIdentity)?;
    let proof_domain = object
        .get("proof")
        .and_then(|proof| proof.get("domain"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    object.remove("proof");
    if let Some(rotation) = rotation {
        let methods = object
            .get_mut("verificationMethod")
            .and_then(Value::as_array_mut)
            .ok_or(DidError::InvalidIdentity)?;
        methods.push(json!({
            "id": rotation.new_kid,
            "type": "Multikey",
            "controller": record.did,
            "publicKeyMultibase": ed25519_public_multibase(&rotation.new_key.public_key())?,
        }));
        let authentication = object
            .get_mut("authentication")
            .and_then(Value::as_array_mut)
            .ok_or(DidError::InvalidIdentity)?;
        authentication.retain(|entry| entry.as_str() != Some(&rotation.old_kid));
        authentication.push(Value::String(rotation.new_kid.clone()));
    }
    let device_changes = apply_device_mutations(object, record, device_mutations)?;
    if let Some(services) = services {
        let mut output = object
            .get("service")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|service| {
                service.get("type").and_then(Value::as_str) == Some("AgentDescription")
            })
            .cloned()
            .collect::<Vec<_>>();
        for service in services {
            let mut value = service_json(service);
            if let Some(id) = value.get("id").and_then(Value::as_str) {
                if id.starts_with('#') {
                    value["id"] = Value::String(format!("{}{}", record.did, id));
                }
            }
            output.push(value);
        }
        object.insert("service".to_string(), Value::Array(output));
    }
    let root = record
        .keys
        .iter()
        .find(|metadata| metadata.role == KeyRole::RootControl)
        .ok_or(DidError::InvalidIdentity)?;
    let root_secret = identity.load_managed_secret(root)?;
    let signed = sign_root_document(&document, &root.kid, &root_secret, proof_domain)?;
    if !validate_did_document_binding(&signed, true) {
        return Err(DidError::InvalidIdentity);
    }
    validate_device_manifest(&signed).map_err(|_| DidError::InvalidExtension)?;
    Ok(CandidateChanges {
        document: signed,
        added_keys: device_changes.added_keys,
        retired_kids: device_changes.retired_kids,
    })
}

fn apply_device_mutations(
    object: &mut serde_json::Map<String, Value>,
    record: &IdentityRecord,
    mutations: &[DeviceMutationSpec],
) -> DidResult<DeviceChanges> {
    let mut manifest = object
        .get("deviceManifest")
        .cloned()
        .map(serde_json::from_value::<anp::authentication::DeviceManifest>)
        .transpose()
        .map_err(|_| DidError::InvalidExtension)?;
    let mut added_keys = Vec::new();
    let mut retired_kids = Vec::new();
    for mutation in mutations {
        match mutation {
            DeviceMutationSpec::Add { device } => {
                validate_device_add(device)?;
                let signing_kid = canonicalize_kid(&record.did, &device.signing_key.kid)?;
                let e2ee_kid = canonicalize_kid(&record.did, &device.e2ee_key.kid)?;
                if signing_kid == e2ee_kid
                    || record
                        .keys
                        .iter()
                        .any(|key| key.kid == signing_kid || key.kid == e2ee_kid)
                    || method_exists(object, &signing_kid)
                    || method_exists(object, &e2ee_kid)
                    || manifest.as_ref().is_some_and(|manifest| {
                        manifest
                            .devices
                            .iter()
                            .any(|entry| entry.device_id == device.device_id)
                    })
                {
                    return Err(DidError::DuplicateKid);
                }
                validate_device_public_key(
                    &signing_kid,
                    &device.signing_key.public_key_multibase,
                    KeyRole::DeviceSigning,
                )?;
                validate_device_public_key(
                    &e2ee_kid,
                    &device.e2ee_key.public_key_multibase,
                    KeyRole::E2eeAgreement,
                )?;
                methods_mut(object)?.extend([
                    json!({
                        "id": signing_kid,
                        "type": "Multikey",
                        "controller": record.did,
                        "publicKeyMultibase": device.signing_key.public_key_multibase,
                    }),
                    json!({
                        "id": e2ee_kid,
                        "type": "X25519KeyAgreementKey2019",
                        "controller": record.did,
                        "publicKeyMultibase": device.e2ee_key.public_key_multibase,
                    }),
                ]);
                relationship_mut(object, "authentication")?
                    .push(Value::String(signing_kid.clone()));
                relationship_mut(object, "assertionMethod")?
                    .push(Value::String(signing_kid.clone()));
                relationship_mut(object, "keyAgreement")?.push(Value::String(e2ee_kid.clone()));
                manifest
                    .get_or_insert_with(|| anp::authentication::DeviceManifest {
                        manifest_type: anp::authentication::DEVICE_MANIFEST_TYPE.to_string(),
                        devices: Vec::new(),
                    })
                    .devices
                    .push(anp::authentication::DeviceManifestEntry {
                        device_id: device.device_id.clone(),
                        signing_key_id: signing_kid.clone(),
                        e2ee_key_id: e2ee_kid.clone(),
                        profiles: device.profiles.clone(),
                    });
                added_keys.extend([
                    (signing_kid, KeyRole::DeviceSigning),
                    (e2ee_kid, KeyRole::E2eeAgreement),
                ]);
            }
            DeviceMutationSpec::Remove { device_id } => {
                if device_id.trim().is_empty() || device_id.trim() != device_id {
                    return Err(DidError::InvalidExtension);
                }
                if record
                    .local_authorization
                    .as_ref()
                    .is_some_and(|local| local.device_id == *device_id)
                {
                    return Err(DidError::UnsupportedOperation);
                }
                let current = manifest.as_mut().ok_or(DidError::KeyNotFound)?;
                let index = current
                    .devices
                    .iter()
                    .position(|entry| entry.device_id == *device_id)
                    .ok_or(DidError::KeyNotFound)?;
                let removed = current.devices.remove(index);
                methods_mut(object)?.retain(|method| {
                    method.get("id").and_then(Value::as_str)
                        != Some(removed.signing_key_id.as_str())
                        && method.get("id").and_then(Value::as_str)
                            != Some(removed.e2ee_key_id.as_str())
                });
                for relationship in ["authentication", "assertionMethod"] {
                    relationship_mut(object, relationship)?
                        .retain(|entry| entry.as_str() != Some(removed.signing_key_id.as_str()));
                }
                relationship_mut(object, "keyAgreement")?
                    .retain(|entry| entry.as_str() != Some(removed.e2ee_key_id.as_str()));
                retired_kids.extend([removed.signing_key_id, removed.e2ee_key_id]);
            }
        }
    }
    match manifest {
        Some(manifest) if manifest.devices.is_empty() => {
            object.remove("deviceManifest");
        }
        Some(manifest) => {
            object.insert(
                "deviceManifest".to_string(),
                serde_json::to_value(manifest).map_err(|_| DidError::InvalidExtension)?,
            );
        }
        None => {}
    }
    Ok(DeviceChanges {
        added_keys,
        retired_kids,
    })
}

fn validate_device_add(device: &DeviceAddSpec) -> DidResult<()> {
    if device.device_id.trim().is_empty()
        || device.device_id.trim() != device.device_id
        || device.profiles.is_empty()
        || device
            .profiles
            .iter()
            .any(|profile| profile.trim().is_empty())
    {
        return Err(DidError::InvalidExtension);
    }
    Ok(())
}

fn validate_device_public_key(kid: &str, multibase: &str, role: KeyRole) -> DidResult<()> {
    let method = match role {
        KeyRole::DeviceSigning => json!({
            "id": kid,
            "type": "Multikey",
            "publicKeyMultibase": multibase,
        }),
        KeyRole::E2eeAgreement => json!({
            "id": kid,
            "type": "X25519KeyAgreementKey2019",
            "publicKeyMultibase": multibase,
        }),
        _ => return Err(DidError::KeyRoleViolation),
    };
    let public =
        anp::authentication::extract_public_key(&method).map_err(|_| DidError::InvalidPublicKey)?;
    if matches!(
        (role, public),
        (KeyRole::DeviceSigning, anp::PublicKeyMaterial::Ed25519(_))
            | (KeyRole::E2eeAgreement, anp::PublicKeyMaterial::X25519(_))
    ) {
        Ok(())
    } else {
        Err(DidError::InvalidPublicKey)
    }
}

fn methods_mut(object: &mut serde_json::Map<String, Value>) -> DidResult<&mut Vec<Value>> {
    object
        .get_mut("verificationMethod")
        .and_then(Value::as_array_mut)
        .ok_or(DidError::InvalidIdentity)
}

fn relationship_mut<'a>(
    object: &'a mut serde_json::Map<String, Value>,
    name: &str,
) -> DidResult<&'a mut Vec<Value>> {
    object
        .get_mut(name)
        .and_then(Value::as_array_mut)
        .ok_or(DidError::InvalidIdentity)
}

fn method_exists(object: &serde_json::Map<String, Value>, kid: &str) -> bool {
    object
        .get("verificationMethod")
        .and_then(Value::as_array)
        .is_some_and(|methods| {
            methods
                .iter()
                .any(|method| method.get("id").and_then(Value::as_str) == Some(kid))
        })
}

fn required_pending<'a>(
    record: &'a IdentityRecord,
    revision_id: &str,
) -> DidResult<&'a PendingRevisionRecord> {
    record
        .pending_revision
        .as_ref()
        .filter(|pending| pending.revision_id == revision_id)
        .ok_or(DidError::PendingRevisionNotFound)
}

fn reject_uncertain_mutation(record: &IdentityRecord) -> DidResult<()> {
    if record
        .pending_revision
        .as_ref()
        .is_some_and(|pending| pending.state == PublicationState::PublicationUncertain)
    {
        return Err(DidError::InvalidPublicationState);
    }
    Ok(())
}

fn required_pending_mut<'a>(
    record: &'a mut IdentityRecord,
    revision_id: &str,
) -> DidResult<&'a mut PendingRevisionRecord> {
    record
        .pending_revision
        .as_mut()
        .filter(|pending| pending.revision_id == revision_id)
        .ok_or(DidError::PendingRevisionNotFound)
}

fn persist_record(
    runtime: &StoreRuntime,
    guard: &StoreWriteGuard,
    record: &mut IdentityRecord,
) -> DidResult<()> {
    record.generation = record.generation.checked_add(1).ok_or(DidError::Conflict)?;
    write_identity(runtime.root(), guard, record)
}

fn canonical_digest(document: &Value) -> DidResult<String> {
    let canonical =
        serde_json_canonicalizer::to_vec(document).map_err(|_| DidError::InvalidIdentity)?;
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(canonical)))
}

fn random_revision_id() -> String {
    use rand::RngCore;

    let mut bytes = [0_u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LifecycleFailurePoint {
    PrepareJournalPersisted,
    PendingSecretPersisted,
    PendingIdentityPersisted,
    CleanupJournalPersisted,
    PendingIdentityCleared,
    PendingSecretsDeleted,
}

fn maybe_fail(
    configured: Option<LifecycleFailurePoint>,
    current: LifecycleFailurePoint,
) -> DidResult<()> {
    if configured == Some(current) {
        return Err(DidError::Io("injected lifecycle failure".to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
