use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::adoption::{
    LocalAuthorizationRecord, PendingEnrollmentRecord, PendingRequestSigningRecord,
};
use crate::fs_util::{ensure_private_dir, write_atomic_private};
use crate::keystore::SecretRef;
use crate::lifecycle::PendingRevisionRecord;
use crate::root_transfer::{PendingRootTransferRecord, RootTransferReplayRecord};
use crate::store_lock::StoreWriteGuard;
use crate::{Capabilities, DidError, DidResult, KeyRole};

const REGISTRY_SCHEMA_VERSION: u32 = 1;
const IDENTITY_SCHEMA_VERSION: u32 = 1;
const JOURNAL_SCHEMA_VERSION: u32 = 1;
const UPDATE_JOURNAL_SCHEMA_VERSION: u32 = 1;
const IDENTITY_TRANSITION_JOURNAL_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyOrigin {
    Managed,
    External,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyState {
    Pending,
    Active,
    Retired,
    Revoked,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdentityState {
    Creating,
    Enrolling,
    Active,
    Revoked,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RootCapabilityState {
    Absent,
    Pending,
    Active,
}

impl Default for RootCapabilityState {
    fn default() -> Self {
        Self::Active
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DocumentCheckpoint {
    pub document_version: u64,
    pub registry_version: u64,
    pub document_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KeyMetadata {
    pub kid: String,
    pub role: KeyRole,
    pub origin: KeyOrigin,
    pub state: KeyState,
    #[serde(default)]
    pub material_erased: bool,
    pub version: u32,
    pub public_key_multibase: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentitySummary {
    pub identity_id: String,
    pub did: String,
    pub state: IdentityState,
    #[serde(default)]
    pub root_capability: RootCapabilityState,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct IdentityRecord {
    pub(crate) schema_version: u32,
    pub(crate) identity_id: String,
    pub(crate) did: String,
    pub(crate) state: IdentityState,
    pub(crate) revision: u64,
    pub(crate) generation: u64,
    pub(crate) document: Value,
    pub(crate) keys: Vec<KeyMetadata>,
    pub(crate) capabilities: Capabilities,
    #[serde(default)]
    pub(crate) root_capability: RootCapabilityState,
    #[serde(default)]
    pub(crate) root_key_fingerprint: String,
    #[serde(default)]
    pub(crate) checkpoint: Option<DocumentCheckpoint>,
    #[serde(default)]
    pub(crate) local_authorization: Option<LocalAuthorizationRecord>,
    #[serde(default)]
    pub(crate) local_request_signing_kid: Option<String>,
    #[serde(default)]
    pub(crate) pending_enrollment: Option<PendingEnrollmentRecord>,
    #[serde(default)]
    pub(crate) pending_request_signing: Option<PendingRequestSigningRecord>,
    #[serde(default)]
    pub(crate) pending_root_transfer: Option<PendingRootTransferRecord>,
    #[serde(default)]
    pub(crate) root_transfer_replays: Vec<RootTransferReplayRecord>,
    pub(crate) created_at: String,
    #[serde(default)]
    pub(crate) pending_revision: Option<PendingRevisionRecord>,
}

impl IdentityRecord {
    pub(crate) fn summary(&self) -> IdentitySummary {
        IdentitySummary {
            identity_id: self.identity_id.clone(),
            did: self.did.clone(),
            state: self.state,
            root_capability: self.root_capability,
            created_at: self.created_at.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreationJournal {
    schema_version: u32,
    #[serde(default)]
    pub(crate) kind: CreationJournalKind,
    pub(crate) transaction_id: String,
    pub(crate) identity_id: String,
    pub(crate) did: String,
    pub(crate) secret_refs: Vec<SecretRef>,
    pub(crate) created_at: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CreationJournalKind {
    #[default]
    Create,
    StateTransition,
    RootImport,
    NamespaceDelete,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UpdateJournalKind {
    Prepare,
    Cleanup,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpdateJournal {
    schema_version: u32,
    pub(crate) revision_id: String,
    pub(crate) identity_id: String,
    pub(crate) secret_refs: Vec<SecretRef>,
    pub(crate) kind: UpdateJournalKind,
    pub(crate) created_at: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum IdentityTransitionJournalState {
    Prepared,
    PublicationInFlight,
    PublicationUncertain,
    Committed,
    Aborted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct IdentityTransitionJournal {
    schema_version: u32,
    pub(crate) operation_id: String,
    pub(crate) expected_current_did: String,
    pub(crate) predecessor_identity_id: String,
    pub(crate) predecessor_generation: u64,
    pub(crate) successor_did: String,
    pub(crate) successor_identity_id: String,
    pub(crate) successor_generation: u64,
    pub(crate) trusted_predecessor_document: Value,
    pub(crate) predecessor_document: Value,
    pub(crate) successor_document: Value,
    pub(crate) provider_document: Option<Value>,
    pub(crate) predecessor_digest: String,
    pub(crate) successor_digest: String,
    pub(crate) assurance: String,
    pub(crate) state: IdentityTransitionJournalState,
    pub(crate) generation: u64,
    pub(crate) created_at: String,
}

impl IdentityTransitionJournal {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        operation_id: String,
        expected_current_did: String,
        predecessor_identity_id: String,
        predecessor_generation: u64,
        successor_did: String,
        successor_identity_id: String,
        successor_generation: u64,
        trusted_predecessor_document: Value,
        predecessor_document: Value,
        successor_document: Value,
        provider_document: Option<Value>,
        predecessor_digest: String,
        successor_digest: String,
        assurance: String,
        created_at: String,
    ) -> Self {
        Self {
            schema_version: IDENTITY_TRANSITION_JOURNAL_SCHEMA_VERSION,
            operation_id,
            expected_current_did,
            predecessor_identity_id,
            predecessor_generation,
            successor_did,
            successor_identity_id,
            successor_generation,
            trusted_predecessor_document,
            predecessor_document,
            successor_document,
            provider_document,
            predecessor_digest,
            successor_digest,
            assurance,
            state: IdentityTransitionJournalState::Prepared,
            generation: 1,
            created_at,
        }
    }
}

impl UpdateJournal {
    pub(crate) fn new(
        revision_id: String,
        identity_id: String,
        secret_refs: Vec<SecretRef>,
        kind: UpdateJournalKind,
        created_at: String,
    ) -> Self {
        Self {
            schema_version: UPDATE_JOURNAL_SCHEMA_VERSION,
            revision_id,
            identity_id,
            secret_refs,
            kind,
            created_at,
        }
    }
}

impl CreationJournal {
    pub(crate) fn new(
        transaction_id: String,
        identity_id: String,
        did: String,
        secret_refs: Vec<SecretRef>,
        created_at: String,
    ) -> Self {
        Self {
            schema_version: JOURNAL_SCHEMA_VERSION,
            kind: CreationJournalKind::Create,
            transaction_id,
            identity_id,
            did,
            secret_refs,
            created_at,
        }
    }

    pub(crate) fn new_state_transition(
        transaction_id: String,
        identity_id: String,
        did: String,
        created_at: String,
    ) -> Self {
        Self {
            schema_version: JOURNAL_SCHEMA_VERSION,
            kind: CreationJournalKind::StateTransition,
            transaction_id,
            identity_id,
            did,
            secret_refs: Vec::new(),
            created_at,
        }
    }

    pub(crate) fn new_root_import(
        transaction_id: String,
        identity_id: String,
        did: String,
        secret_refs: Vec<SecretRef>,
        created_at: String,
    ) -> Self {
        Self {
            schema_version: JOURNAL_SCHEMA_VERSION,
            kind: CreationJournalKind::RootImport,
            transaction_id,
            identity_id,
            did,
            secret_refs,
            created_at,
        }
    }

    pub(crate) fn new_namespace_delete(
        transaction_id: String,
        identity_id: String,
        did: String,
        secret_refs: Vec<SecretRef>,
        created_at: String,
    ) -> Self {
        Self {
            schema_version: JOURNAL_SCHEMA_VERSION,
            kind: CreationJournalKind::NamespaceDelete,
            transaction_id,
            identity_id,
            did,
            secret_refs,
            created_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct IdentityRegistry {
    schema_version: u32,
    pub(crate) generation: u64,
    pub(crate) identities: BTreeMap<String, IdentitySummary>,
}

impl Default for IdentityRegistry {
    fn default() -> Self {
        Self {
            schema_version: REGISTRY_SCHEMA_VERSION,
            generation: 0,
            identities: BTreeMap::new(),
        }
    }
}

pub(crate) fn read_registry(root: &Path) -> DidResult<IdentityRegistry> {
    let path = registry_path(root);
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(IdentityRegistry::default());
        }
        Err(error) => return Err(DidError::Io(error.to_string())),
    };
    let registry: IdentityRegistry =
        serde_json::from_slice(&bytes).map_err(|_| DidError::InvalidIdentity)?;
    if registry.schema_version != REGISTRY_SCHEMA_VERSION {
        return Err(DidError::InvalidIdentity);
    }
    Ok(registry)
}

pub(crate) fn write_registry(
    root: &Path,
    guard: &StoreWriteGuard,
    registry: &IdentityRegistry,
) -> DidResult<()> {
    guard.require_store(root)?;
    let bytes = serde_json::to_vec_pretty(registry).map_err(|_| DidError::InvalidIdentity)?;
    write_atomic_private(&registry_path(root), &bytes)
}

pub(crate) fn read_identity(root: &Path, identity_id: &str) -> DidResult<IdentityRecord> {
    let bytes = fs::read(identity_path(root, identity_id)).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            DidError::IdentityNotFound
        } else {
            DidError::Io(error.to_string())
        }
    })?;
    let mut record: IdentityRecord =
        serde_json::from_slice(&bytes).map_err(|_| DidError::InvalidIdentity)?;
    if record.schema_version != IDENTITY_SCHEMA_VERSION || record.identity_id != identity_id {
        return Err(DidError::InvalidIdentity);
    }
    if record.root_key_fingerprint.is_empty() {
        record.root_key_fingerprint = crate::document::root_key_fingerprint(&record.document)?;
    }
    if record.checkpoint.is_none() {
        record.checkpoint = Some(DocumentCheckpoint {
            document_version: record.revision,
            registry_version: 1,
            document_digest: crate::document::document_digest(&record.document)?,
        });
    }
    if record.local_authorization.is_none() {
        record.local_authorization =
            crate::adoption::infer_local_authorization(&record.document, &record.keys)?;
    }
    Ok(record)
}

pub(crate) fn write_identity(
    root: &Path,
    guard: &StoreWriteGuard,
    record: &IdentityRecord,
) -> DidResult<()> {
    guard.require_store(root)?;
    ensure_private_dir(&root.join("identities"))?;
    let bytes = serde_json::to_vec_pretty(record).map_err(|_| DidError::InvalidIdentity)?;
    write_atomic_private(&identity_path(root, &record.identity_id), &bytes)
}

pub(crate) fn remove_identity(
    root: &Path,
    guard: &StoreWriteGuard,
    identity_id: &str,
) -> DidResult<()> {
    guard.require_store(root)?;
    remove_if_exists(&identity_path(root, identity_id))
}

pub(crate) fn write_journal(
    root: &Path,
    guard: &StoreWriteGuard,
    journal: &CreationJournal,
) -> DidResult<()> {
    guard.require_store(root)?;
    ensure_private_dir(&root.join("transactions"))?;
    let bytes = serde_json::to_vec_pretty(journal).map_err(|_| DidError::InvalidIdentity)?;
    write_atomic_private(&journal_path(root, &journal.transaction_id), &bytes)
}

pub(crate) fn list_journals(root: &Path) -> DidResult<Vec<CreationJournal>> {
    let entries = match fs::read_dir(root.join("transactions")) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(DidError::Io(error.to_string())),
    };
    let mut journals = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| DidError::Io(error.to_string()))?;
        if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let bytes = fs::read(entry.path()).map_err(|_| DidError::InvalidIdentity)?;
        let journal: CreationJournal =
            serde_json::from_slice(&bytes).map_err(|_| DidError::InvalidIdentity)?;
        if journal.schema_version != JOURNAL_SCHEMA_VERSION {
            return Err(DidError::InvalidIdentity);
        }
        journals.push(journal);
    }
    journals.sort_by(|left, right| left.transaction_id.cmp(&right.transaction_id));
    Ok(journals)
}

pub(crate) fn remove_journal(
    root: &Path,
    guard: &StoreWriteGuard,
    transaction_id: &str,
) -> DidResult<()> {
    guard.require_store(root)?;
    remove_if_exists(&journal_path(root, transaction_id))
}

pub(crate) fn write_update_journal(
    root: &Path,
    guard: &StoreWriteGuard,
    journal: &UpdateJournal,
) -> DidResult<()> {
    guard.require_store(root)?;
    ensure_private_dir(&root.join("update-transactions"))?;
    let bytes = serde_json::to_vec_pretty(journal).map_err(|_| DidError::InvalidIdentity)?;
    write_atomic_private(&update_journal_path(root, &journal.revision_id), &bytes)
}

pub(crate) fn list_update_journals(root: &Path) -> DidResult<Vec<UpdateJournal>> {
    let entries = match fs::read_dir(root.join("update-transactions")) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(DidError::Io(error.to_string())),
    };
    let mut journals = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| DidError::Io(error.to_string()))?;
        if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let bytes = fs::read(entry.path()).map_err(|_| DidError::InvalidIdentity)?;
        let journal: UpdateJournal =
            serde_json::from_slice(&bytes).map_err(|_| DidError::InvalidIdentity)?;
        if journal.schema_version != UPDATE_JOURNAL_SCHEMA_VERSION {
            return Err(DidError::InvalidIdentity);
        }
        journals.push(journal);
    }
    journals.sort_by(|left, right| left.revision_id.cmp(&right.revision_id));
    Ok(journals)
}

pub(crate) fn remove_update_journal(
    root: &Path,
    guard: &StoreWriteGuard,
    revision_id: &str,
) -> DidResult<()> {
    guard.require_store(root)?;
    remove_if_exists(&update_journal_path(root, revision_id))
}

pub(crate) fn write_identity_transition_journal(
    root: &Path,
    guard: &StoreWriteGuard,
    journal: &IdentityTransitionJournal,
) -> DidResult<()> {
    guard.require_store(root)?;
    ensure_private_dir(&root.join("identity-transitions"))?;
    let bytes = serde_json::to_vec_pretty(journal).map_err(|_| DidError::InvalidIdentity)?;
    write_atomic_private(
        &identity_transition_journal_path(root, &journal.operation_id),
        &bytes,
    )
}

pub(crate) fn read_identity_transition_journal(
    root: &Path,
    operation_id: &str,
) -> DidResult<IdentityTransitionJournal> {
    let bytes =
        fs::read(identity_transition_journal_path(root, operation_id)).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                DidError::PendingRevisionNotFound
            } else {
                DidError::Io(error.to_string())
            }
        })?;
    let journal: IdentityTransitionJournal =
        serde_json::from_slice(&bytes).map_err(|_| DidError::InvalidIdentity)?;
    if journal.schema_version != IDENTITY_TRANSITION_JOURNAL_SCHEMA_VERSION
        || journal.operation_id != operation_id
    {
        return Err(DidError::InvalidIdentity);
    }
    Ok(journal)
}

pub(crate) fn list_identity_transition_journals(
    root: &Path,
) -> DidResult<Vec<IdentityTransitionJournal>> {
    let entries = match fs::read_dir(root.join("identity-transitions")) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(DidError::Io(error.to_string())),
    };
    let mut journals = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| DidError::Io(error.to_string()))?;
        if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let bytes = fs::read(entry.path()).map_err(|_| DidError::InvalidIdentity)?;
        let journal: IdentityTransitionJournal =
            serde_json::from_slice(&bytes).map_err(|_| DidError::InvalidIdentity)?;
        if journal.schema_version != IDENTITY_TRANSITION_JOURNAL_SCHEMA_VERSION {
            return Err(DidError::InvalidIdentity);
        }
        journals.push(journal);
    }
    journals.sort_by(|left, right| left.operation_id.cmp(&right.operation_id));
    Ok(journals)
}

pub(crate) struct NewIdentityRecord {
    pub(crate) identity_id: String,
    pub(crate) did: String,
    pub(crate) document: Value,
    pub(crate) keys: Vec<KeyMetadata>,
    pub(crate) capabilities: Capabilities,
    pub(crate) root_capability: RootCapabilityState,
    pub(crate) root_key_fingerprint: String,
    pub(crate) checkpoint: DocumentCheckpoint,
    pub(crate) local_authorization: Option<LocalAuthorizationRecord>,
    pub(crate) created_at: String,
}

pub(crate) fn new_identity_record(input: NewIdentityRecord) -> IdentityRecord {
    IdentityRecord {
        schema_version: IDENTITY_SCHEMA_VERSION,
        identity_id: input.identity_id,
        did: input.did,
        state: IdentityState::Creating,
        revision: 1,
        generation: 1,
        document: input.document,
        keys: input.keys,
        capabilities: input.capabilities,
        root_capability: input.root_capability,
        root_key_fingerprint: input.root_key_fingerprint,
        checkpoint: Some(input.checkpoint),
        local_authorization: input.local_authorization,
        local_request_signing_kid: None,
        pending_enrollment: None,
        pending_request_signing: None,
        pending_root_transfer: None,
        root_transfer_replays: Vec::new(),
        created_at: input.created_at,
        pending_revision: None,
    }
}

fn registry_path(root: &Path) -> PathBuf {
    root.join("registry.json")
}

fn identity_path(root: &Path, identity_id: &str) -> PathBuf {
    root.join("identities")
        .join(format!("{}.json", storage_key(identity_id)))
}

fn journal_path(root: &Path, transaction_id: &str) -> PathBuf {
    root.join("transactions")
        .join(format!("{}.json", storage_key(transaction_id)))
}

fn update_journal_path(root: &Path, revision_id: &str) -> PathBuf {
    root.join("update-transactions")
        .join(format!("{}.json", storage_key(revision_id)))
}

fn identity_transition_journal_path(root: &Path, operation_id: &str) -> PathBuf {
    root.join("identity-transitions")
        .join(format!("{}.json", storage_key(operation_id)))
}

fn storage_key(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
}

fn remove_if_exists(path: &Path) -> DidResult<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(DidError::Io(error.to_string())),
    }
}
