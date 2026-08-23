use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::Value;
use zeroize::Zeroize;

use crate::document::{build_identity, public_key_from_secret, public_keys_equal, BuiltIdentity};
use crate::keystore::{SealIfAbsent, SecretRef};
use crate::platform::{
    default_file_root_key_path, FileRootKeyProvider, InjectedRootKeyProvider,
    KeyringRootKeyProvider,
};
use crate::registry::{
    list_journals, new_identity_record, read_identity, read_registry, remove_identity,
    remove_journal, write_identity, write_journal, write_registry, CreationJournal,
    CreationJournalKind, DocumentCheckpoint, IdentityRecord, IdentityRegistry, NewIdentityRecord,
    RootCapabilityState,
};
use crate::store::{ProviderInitialization, StoreRuntime};
use crate::{DidCreateSpec, DidError, DidResult, IdentityState, IdentitySummary, KeyMetadata};

pub struct DidStore {
    pub(crate) runtime: Arc<StoreRuntime>,
    pub(crate) registry_generation: u64,
}

impl fmt::Debug for DidStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DidStore")
            .field("root", &self.runtime.root())
            .field("registry_generation", &self.registry_generation)
            .field("root_key", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone)]
pub struct DidIdentity {
    pub(crate) runtime: Arc<StoreRuntime>,
    pub(crate) record: IdentityRecord,
}

impl fmt::Debug for DidIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DidIdentity")
            .field("identity_id", &self.record.identity_id)
            .field("did", &self.record.did)
            .field("state", &self.record.state)
            .field("revision", &self.record.revision)
            .field("root_key", &"[REDACTED]")
            .finish()
    }
}

impl DidStore {
    pub fn initialize_injected(
        root: impl Into<PathBuf>,
        key_id: impl Into<String>,
        mut root_key: [u8; 32],
    ) -> DidResult<Self> {
        let provider = InjectedRootKeyProvider::new(key_id, root_key);
        root_key.zeroize();
        let runtime = StoreRuntime::initialize(root, ProviderInitialization::Required(&provider))?;
        Self::from_runtime(runtime)
    }

    pub fn open_injected(
        root: impl Into<PathBuf>,
        key_id: impl Into<String>,
        mut root_key: [u8; 32],
    ) -> DidResult<Self> {
        let provider = InjectedRootKeyProvider::new(key_id, root_key);
        root_key.zeroize();
        let runtime = StoreRuntime::open(root, &[&provider])?;
        Self::from_runtime(runtime)
    }

    pub fn initialize_env(
        root: impl Into<PathBuf>,
        key_id: impl Into<String>,
        env_var: &str,
    ) -> DidResult<Self> {
        let provider = InjectedRootKeyProvider::from_env(key_id, env_var)?;
        let runtime = StoreRuntime::initialize(root, ProviderInitialization::Required(&provider))?;
        Self::from_runtime(runtime)
    }

    pub fn open_env(
        root: impl Into<PathBuf>,
        key_id: impl Into<String>,
        env_var: &str,
    ) -> DidResult<Self> {
        let provider = InjectedRootKeyProvider::from_env(key_id, env_var)?;
        let runtime = StoreRuntime::open(root, &[&provider])?;
        Self::from_runtime(runtime)
    }

    pub fn initialize_local_file(root: impl Into<PathBuf>) -> DidResult<Self> {
        let root = root.into();
        let provider =
            FileRootKeyProvider::new("local-private-file", default_file_root_key_path(&root));
        let runtime = StoreRuntime::initialize(root, ProviderInitialization::Required(&provider))?;
        Self::from_runtime(runtime)
    }

    pub fn open_local_file(root: impl Into<PathBuf>) -> DidResult<Self> {
        let root = root.into();
        let provider =
            FileRootKeyProvider::new("local-private-file", default_file_root_key_path(&root));
        let runtime = StoreRuntime::open(root, &[&provider])?;
        Self::from_runtime(runtime)
    }

    pub fn initialize_keyring(
        root: impl Into<PathBuf>,
        service: impl Into<String>,
        account: impl Into<String>,
        fallback_to_local_file: bool,
    ) -> DidResult<Self> {
        let root = root.into();
        let keyring = KeyringRootKeyProvider::new(service, account);
        let file =
            FileRootKeyProvider::new("local-private-file", default_file_root_key_path(&root));
        let initialization = if fallback_to_local_file {
            ProviderInitialization::Preferred {
                primary: &keyring,
                fallback: &file,
            }
        } else {
            ProviderInitialization::Required(&keyring)
        };
        let runtime = StoreRuntime::initialize(root, initialization)?;
        Self::from_runtime(runtime)
    }

    pub fn generation(&self) -> u64 {
        self.registry_generation
    }

    pub fn manifest(&self) -> &crate::StoreManifest {
        self.runtime.manifest()
    }

    pub fn reload(&mut self) -> DidResult<()> {
        self.registry_generation = recover(&self.runtime)?.generation;
        Ok(())
    }

    pub fn list_identities(&self) -> DidResult<Vec<IdentitySummary>> {
        Ok(read_registry(self.runtime.root())?
            .identities
            .into_values()
            .collect())
    }

    pub fn open_identity(&self, did: &str) -> DidResult<DidIdentity> {
        let registry = read_registry(self.runtime.root())?;
        let summary = registry
            .identities
            .get(did)
            .ok_or(DidError::IdentityNotFound)?;
        let record = read_identity(self.runtime.root(), &summary.identity_id)?;
        if record.did != did
            || record.state == IdentityState::Creating
            || record.state != summary.state
        {
            return Err(DidError::InvalidIdentity);
        }
        Ok(DidIdentity {
            runtime: Arc::clone(&self.runtime),
            record,
        })
    }

    pub fn create_identity(&mut self, spec: DidCreateSpec) -> DidResult<DidIdentity> {
        self.create_identity_inner(spec, None)
    }

    pub(crate) fn from_runtime(runtime: StoreRuntime) -> DidResult<Self> {
        let runtime = Arc::new(runtime);
        let registry = recover(&runtime)?;
        Ok(Self {
            runtime,
            registry_generation: registry.generation,
        })
    }

    fn create_identity_inner(
        &mut self,
        spec: DidCreateSpec,
        failure: Option<CreationFailurePoint>,
    ) -> DidResult<DidIdentity> {
        let guard = self.runtime.acquire_write()?;
        let mut registry = read_registry(self.runtime.root())?;
        if registry.generation != self.registry_generation {
            return Err(DidError::Conflict);
        }
        if !list_journals(self.runtime.root())?.is_empty() {
            return Err(DidError::Conflict);
        }

        let built = build_identity(&spec)?;
        if registry.identities.contains_key(&built.did) {
            return Err(DidError::DuplicateIdentity);
        }
        let identity_id = random_id();
        let transaction_id = random_id();
        let secret_refs = built
            .managed_keys
            .iter()
            .map(|key| SecretRef {
                identity_id: identity_id.clone(),
                key_id: format!("{}#{}", built.did, key.fragment),
                role: key.role,
                version: 1,
            })
            .collect::<Vec<_>>();
        let journal = CreationJournal::new(
            transaction_id.clone(),
            identity_id.clone(),
            built.did.clone(),
            secret_refs.clone(),
            built.created_at.clone(),
        );
        write_journal(self.runtime.root(), &guard, &journal)?;
        maybe_fail(failure, CreationFailurePoint::JournalPersisted)?;

        for (index, (managed, secret_ref)) in built
            .managed_keys
            .iter()
            .zip(secret_refs.iter())
            .enumerate()
        {
            let result = self.runtime.key_store().seal_if_absent(
                &guard,
                self.runtime.root_key(),
                secret_ref.clone(),
                managed.secret_bytes(),
            )?;
            if result == SealIfAbsent::AlreadyExists {
                verify_persisted_key(&self.runtime, secret_ref, &managed.public_key())?;
            }
            maybe_fail(failure, CreationFailurePoint::SecretPersisted(index))?;
        }
        verify_all_persisted_keys(&self.runtime, &built, &secret_refs)?;

        let root_key_fingerprint = crate::document::root_key_fingerprint(&built.document)?;
        let checkpoint = DocumentCheckpoint {
            document_version: 1,
            registry_version: 1,
            document_digest: crate::document::document_digest(&built.document)?,
        };
        let local_authorization =
            crate::adoption::infer_local_authorization(&built.document, &built.metadata)?;
        let mut record = new_identity_record(NewIdentityRecord {
            identity_id,
            did: built.did.clone(),
            document: built.document,
            keys: built.metadata,
            capabilities: spec.capabilities,
            root_capability: RootCapabilityState::Active,
            root_key_fingerprint,
            checkpoint,
            local_authorization,
            created_at: built.created_at,
        });
        write_identity(self.runtime.root(), &guard, &record)?;
        maybe_fail(failure, CreationFailurePoint::IdentityCreatingPersisted)?;

        let next_generation = registry
            .generation
            .checked_add(1)
            .ok_or(DidError::Conflict)?;
        let mut summary = record.summary();
        summary.state = IdentityState::Active;
        registry.identities.insert(record.did.clone(), summary);
        registry.generation = next_generation;
        write_registry(self.runtime.root(), &guard, &registry)?;
        maybe_fail(failure, CreationFailurePoint::RegistryCommitted)?;

        record.state = IdentityState::Active;
        write_identity(self.runtime.root(), &guard, &record)?;
        maybe_fail(failure, CreationFailurePoint::IdentityActivated)?;
        remove_journal(self.runtime.root(), &guard, &transaction_id)?;
        drop(guard);

        self.registry_generation = next_generation;
        Ok(DidIdentity {
            runtime: Arc::clone(&self.runtime),
            record,
        })
    }
}

impl DidIdentity {
    pub fn reload(&mut self) -> DidResult<()> {
        let identity_id = self.identity_id().to_string();
        let did = self.did().to_string();
        let registry = recover(&self.runtime)?;
        if registry
            .identities
            .get(&did)
            .is_none_or(|summary| summary.identity_id != identity_id)
        {
            return Err(DidError::IdentityNotFound);
        }
        let record = read_identity(self.runtime.root(), &identity_id)?;
        let summary = registry
            .identities
            .get(&did)
            .ok_or(DidError::IdentityNotFound)?;
        if record.did != did
            || record.state == IdentityState::Creating
            || record.state != summary.state
        {
            return Err(DidError::InvalidIdentity);
        }
        self.record = record;
        Ok(())
    }

    pub fn identity_id(&self) -> &str {
        &self.record.identity_id
    }

    pub fn did(&self) -> &str {
        &self.record.did
    }

    pub fn state(&self) -> IdentityState {
        self.record.state
    }

    pub fn revision(&self) -> u64 {
        self.record.revision
    }

    pub fn document(&self) -> &Value {
        &self.record.document
    }

    pub fn keys(&self) -> &[KeyMetadata] {
        &self.record.keys
    }

    pub fn capabilities(&self) -> &crate::Capabilities {
        &self.record.capabilities
    }

    pub fn managed_key_metadata(&self, kid: &str) -> DidResult<&KeyMetadata> {
        let metadata = self.key_metadata(kid)?;
        if metadata.origin == crate::KeyOrigin::External {
            return Err(DidError::ExternalKeyOperation);
        }
        Ok(metadata)
    }

    pub fn key_metadata(&self, kid: &str) -> DidResult<&KeyMetadata> {
        let kid = crate::input::canonicalize_kid(&self.record.did, kid)?;
        self.record
            .keys
            .iter()
            .find(|metadata| metadata.kid == kid)
            .ok_or(DidError::KeyNotFound)
    }

    #[cfg(test)]
    pub fn public_key_bytes(&self, kid: &str) -> DidResult<Vec<u8>> {
        let metadata = self.key_metadata(kid)?;
        let method = anp::authentication::find_verification_method(self.document(), &metadata.kid)
            .ok_or(DidError::InvalidIdentity)?;
        match anp::authentication::extract_public_key(&method)
            .map_err(|_| DidError::InvalidPublicKey)?
        {
            anp::PublicKeyMaterial::Ed25519(key) => Ok(key.to_bytes().to_vec()),
            anp::PublicKeyMaterial::X25519(key) => Ok(key.to_vec()),
            _ => Err(DidError::InvalidPublicKey),
        }
    }

    pub(crate) fn runtime(&self) -> &Arc<StoreRuntime> {
        &self.runtime
    }

    pub(crate) fn record(&self) -> &IdentityRecord {
        &self.record
    }

    pub(crate) fn replace_record(&mut self, record: IdentityRecord) {
        self.record = record;
    }

    pub(crate) fn load_managed_secret(
        &self,
        metadata: &KeyMetadata,
    ) -> DidResult<crate::secret::SecretBytes> {
        let secret_ref = SecretRef {
            identity_id: self.identity_id().to_string(),
            key_id: metadata.kid.clone(),
            role: metadata.role,
            version: metadata.version,
        };
        self.runtime
            .key_store()
            .open(self.runtime.root_key(), &secret_ref)
    }
}

fn recover(runtime: &Arc<StoreRuntime>) -> DidResult<IdentityRegistry> {
    let guard = runtime.acquire_write()?;
    let mut registry = read_registry(runtime.root())?;
    for journal in list_journals(runtime.root())? {
        if journal.kind == CreationJournalKind::StateTransition {
            let record = read_identity(runtime.root(), &journal.identity_id)?;
            if record.did != journal.did {
                return Err(DidError::InvalidIdentity);
            }
            if registry.identities.get(&journal.did) != Some(&record.summary()) {
                registry
                    .identities
                    .insert(journal.did.clone(), record.summary());
                registry.generation = registry
                    .generation
                    .checked_add(1)
                    .ok_or(DidError::Conflict)?;
                write_registry(runtime.root(), &guard, &registry)?;
            }
            remove_journal(runtime.root(), &guard, &journal.transaction_id)?;
            continue;
        }
        if journal.kind == CreationJournalKind::RootImport {
            let record = read_identity(runtime.root(), &journal.identity_id)?;
            if record.did != journal.did {
                return Err(DidError::InvalidIdentity);
            }
            let committed = matches!(
                record.root_capability,
                RootCapabilityState::Pending | RootCapabilityState::Active
            ) && record.keys.iter().any(|key| {
                key.role == crate::KeyRole::RootControl
                    && key.origin == crate::KeyOrigin::Managed
                    && !key.material_erased
            });
            if committed {
                if registry.identities.get(&journal.did) != Some(&record.summary()) {
                    registry
                        .identities
                        .insert(journal.did.clone(), record.summary());
                    registry.generation = registry
                        .generation
                        .checked_add(1)
                        .ok_or(DidError::Conflict)?;
                    write_registry(runtime.root(), &guard, &registry)?;
                }
            } else {
                for secret_ref in &journal.secret_refs {
                    runtime.key_store().delete(&guard, secret_ref)?;
                }
            }
            remove_journal(runtime.root(), &guard, &journal.transaction_id)?;
            continue;
        }
        if journal.kind == CreationJournalKind::NamespaceDelete {
            for secret_ref in &journal.secret_refs {
                runtime.key_store().delete(&guard, secret_ref)?;
            }
            remove_identity(runtime.root(), &guard, &journal.identity_id)?;
            if registry
                .identities
                .get(&journal.did)
                .is_some_and(|summary| summary.identity_id == journal.identity_id)
            {
                registry.identities.remove(&journal.did);
                registry.generation = registry
                    .generation
                    .checked_add(1)
                    .ok_or(DidError::Conflict)?;
                write_registry(runtime.root(), &guard, &registry)?;
            }
            remove_journal(runtime.root(), &guard, &journal.transaction_id)?;
            continue;
        }
        let committed = registry
            .identities
            .get(&journal.did)
            .is_some_and(|summary| summary.identity_id == journal.identity_id);
        if committed {
            let mut record = read_identity(runtime.root(), &journal.identity_id)?;
            if record.did != journal.did {
                return Err(DidError::InvalidIdentity);
            }
            if record.state == IdentityState::Creating {
                record.state = IdentityState::Active;
                write_identity(runtime.root(), &guard, &record)?;
            }
        } else {
            for secret_ref in &journal.secret_refs {
                runtime.key_store().delete(&guard, secret_ref)?;
            }
            remove_identity(runtime.root(), &guard, &journal.identity_id)?;
        }
        remove_journal(runtime.root(), &guard, &journal.transaction_id)?;
    }
    crate::lifecycle::recover_update_journals(runtime, &guard)?;
    drop(guard);
    read_registry(runtime.root())
}

fn verify_all_persisted_keys(
    runtime: &StoreRuntime,
    built: &BuiltIdentity,
    secret_refs: &[SecretRef],
) -> DidResult<()> {
    for (managed, secret_ref) in built.managed_keys.iter().zip(secret_refs) {
        verify_persisted_key(runtime, secret_ref, &managed.public_key())?;
    }
    Ok(())
}

fn verify_persisted_key(
    runtime: &StoreRuntime,
    secret_ref: &SecretRef,
    expected: &anp::PublicKeyMaterial,
) -> DidResult<()> {
    let secret = runtime.key_store().open(runtime.root_key(), secret_ref)?;
    let actual = public_key_from_secret(secret_ref.role, &secret)?;
    if !public_keys_equal(&actual, expected) {
        return Err(DidError::InvalidIdentity);
    }
    Ok(())
}

pub(crate) fn random_id() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CreationFailurePoint {
    JournalPersisted,
    SecretPersisted(usize),
    IdentityCreatingPersisted,
    RegistryCommitted,
    IdentityActivated,
}

fn maybe_fail(
    configured: Option<CreationFailurePoint>,
    current: CreationFailurePoint,
) -> DidResult<()> {
    if configured == Some(current) {
        return Err(DidError::Io("injected creation failure".to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
