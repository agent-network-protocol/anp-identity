use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::fs_util::{remove_file_and_sync, write_atomic_private};
use crate::keystore::FileKeyStore;
use crate::platform::{root_key_fingerprint, RootKey, RootKeyProvider};
use crate::store_lock::{StoreLock, StoreWriteGuard};
use crate::{DidError, DidResult, StoreManifest, STORE_MANIFEST_SCHEMA_VERSION};

const PROVIDER_ADOPTION_SCHEMA_VERSION: u32 = 1;
const PROVIDER_ADOPTION_JOURNAL: &str = "provider-adoption-v1.json";

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderAdoptionJournal {
    schema_version: u32,
    store_id: String,
    original_provider: crate::RootKeyProviderBinding,
    target_provider: crate::RootKeyProviderBinding,
    root_key_fingerprint: String,
    original_generation: u64,
    phase: ProviderAdoptionPhase,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ProviderAdoptionPhase {
    TargetKeyImported,
    ManifestSwitched,
}

#[derive(Clone, Copy)]
pub(crate) enum ProviderInitialization<'a> {
    Required(&'a dyn RootKeyProvider),
    Preferred {
        primary: &'a dyn RootKeyProvider,
        fallback: &'a dyn RootKeyProvider,
    },
}

pub(crate) struct StoreRuntime {
    root: PathBuf,
    lock: StoreLock,
    root_key: RootKey,
    manifest: StoreManifest,
    key_store: FileKeyStore,
}

impl StoreRuntime {
    pub(crate) fn manifest_at(root: &Path) -> DidResult<StoreManifest> {
        read_manifest(root)
    }

    pub(crate) fn initialize(
        root: impl Into<PathBuf>,
        initialization: ProviderInitialization<'_>,
    ) -> DidResult<Self> {
        let root = root.into();
        let lock = StoreLock::new(&root);
        let guard = lock.acquire_exclusive()?;
        let manifest_path = manifest_path(&root);
        if manifest_path.exists() {
            return Err(DidError::Conflict);
        }
        let (provider, root_key) = match initialization {
            ProviderInitialization::Required(provider) => {
                (provider, provider.create_if_missing(&guard)?)
            }
            ProviderInitialization::Preferred { primary, fallback } => {
                match primary.create_if_missing(&guard) {
                    Ok(root_key) => (primary, root_key),
                    Err(DidError::ProviderUnavailable) => {
                        (fallback, fallback.create_if_missing(&guard)?)
                    }
                    Err(error) => return Err(error),
                }
            }
        };
        let manifest = StoreManifest {
            schema_version: STORE_MANIFEST_SCHEMA_VERSION,
            store_id: random_store_id(),
            generation: 1,
            provider: provider.binding(),
            root_key_fingerprint: root_key_fingerprint(&root_key),
            created_at: Utc::now().to_rfc3339(),
            rekey_generation: 0,
        };
        write_manifest(&root, &guard, &manifest)?;
        drop(guard);
        Ok(Self {
            root: root.clone(),
            lock,
            root_key,
            manifest,
            key_store: FileKeyStore::new(root),
        })
    }

    pub(crate) fn open(
        root: impl Into<PathBuf>,
        providers: &[&dyn RootKeyProvider],
    ) -> DidResult<Self> {
        let root = root.into();
        let manifest = read_manifest(&root)?;
        let provider = providers
            .iter()
            .find(|provider| provider.binding() == manifest.provider)
            .ok_or(DidError::ProviderUnavailable)?;
        let root_key = provider.load_existing()?;
        if root_key_fingerprint(&root_key) != manifest.root_key_fingerprint {
            return Err(DidError::RootKeyMismatch);
        }
        Ok(Self {
            root: root.clone(),
            lock: StoreLock::new(&root),
            root_key,
            manifest,
            key_store: FileKeyStore::new(root),
        })
    }

    pub(crate) fn adopt_root_key_provider(
        root: impl Into<PathBuf>,
        root_key: RootKey,
        target: &dyn RootKeyProvider,
    ) -> DidResult<Self> {
        let root = root.into();
        let lock = StoreLock::new(&root);
        let guard = lock.acquire_exclusive()?;
        let mut manifest = read_manifest(&root)?;
        let supplied_fingerprint = root_key_fingerprint(&root_key);
        if supplied_fingerprint != manifest.root_key_fingerprint {
            return Err(DidError::RootKeyMismatch);
        }
        let target_binding = target.binding();
        let journal_path = provider_adoption_journal_path(&root);
        if manifest.provider == target_binding && !journal_path.exists() {
            target.import_existing(&guard, &root_key)?;
            drop(guard);
            return Self::open(root, &[target]);
        }
        let mut journal = if journal_path.exists() {
            read_provider_adoption_journal(&journal_path)?
        } else {
            ProviderAdoptionJournal {
                schema_version: PROVIDER_ADOPTION_SCHEMA_VERSION,
                store_id: manifest.store_id.clone(),
                original_provider: manifest.provider.clone(),
                target_provider: target_binding.clone(),
                root_key_fingerprint: manifest.root_key_fingerprint.clone(),
                original_generation: manifest.generation,
                phase: ProviderAdoptionPhase::TargetKeyImported,
            }
        };
        validate_provider_adoption_journal(&journal, &manifest, &target_binding)?;
        target.import_existing(&guard, &root_key)?;
        write_provider_adoption_journal(&root, &journal)?;

        if manifest.provider == journal.original_provider
            && manifest.generation == journal.original_generation
        {
            manifest.provider = target_binding.clone();
            manifest.generation = manifest
                .generation
                .checked_add(1)
                .ok_or(DidError::Conflict)?;
            write_manifest(&root, &guard, &manifest)?;
        } else if manifest.provider != target_binding
            || manifest.generation
                != journal
                    .original_generation
                    .checked_add(1)
                    .ok_or(DidError::Conflict)?
        {
            return Err(DidError::Conflict);
        }
        journal.phase = ProviderAdoptionPhase::ManifestSwitched;
        write_provider_adoption_journal(&root, &journal)?;
        drop(guard);
        Self::open(root, &[target])
    }

    pub(crate) fn complete_root_key_provider_adoption(&self) -> DidResult<()> {
        let guard = self.acquire_write()?;
        let journal_path = provider_adoption_journal_path(&self.root);
        if !journal_path.exists() {
            return Ok(());
        }
        let journal = read_provider_adoption_journal(&journal_path)?;
        if journal.phase != ProviderAdoptionPhase::ManifestSwitched
            || journal.store_id != self.manifest.store_id
            || journal.target_provider != self.manifest.provider
            || journal.root_key_fingerprint != self.manifest.root_key_fingerprint
        {
            return Err(DidError::Conflict);
        }
        guard.require_store(&self.root)?;
        remove_file_and_sync(&journal_path)
    }

    pub(crate) fn acquire_write(&self) -> DidResult<StoreWriteGuard> {
        self.lock.acquire_exclusive()
    }

    pub(crate) fn manifest(&self) -> &StoreManifest {
        &self.manifest
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn root_key(&self) -> &RootKey {
        &self.root_key
    }

    pub(crate) fn key_store(&self) -> &FileKeyStore {
        &self.key_store
    }
}

fn read_manifest(root: &Path) -> DidResult<StoreManifest> {
    let bytes = std::fs::read(manifest_path(root)).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            DidError::StoreNotFound
        } else {
            DidError::Io(error.to_string())
        }
    })?;
    let manifest: StoreManifest = serde_json::from_slice(&bytes)
        .map_err(|error| DidError::Serialization(error.to_string()))?;
    if manifest.schema_version != STORE_MANIFEST_SCHEMA_VERSION {
        return Err(DidError::Serialization(
            "unsupported store manifest schema".to_string(),
        ));
    }
    Ok(manifest)
}

fn write_manifest(root: &Path, guard: &StoreWriteGuard, manifest: &StoreManifest) -> DidResult<()> {
    guard.require_store(root)?;
    let bytes = serde_json::to_vec_pretty(manifest)
        .map_err(|error| DidError::Serialization(error.to_string()))?;
    write_atomic_private(&manifest_path(root), &bytes)
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("manifest.json")
}

fn provider_adoption_journal_path(root: &Path) -> PathBuf {
    root.join(PROVIDER_ADOPTION_JOURNAL)
}

fn read_provider_adoption_journal(path: &Path) -> DidResult<ProviderAdoptionJournal> {
    let bytes = std::fs::read(path).map_err(|error| DidError::Io(error.to_string()))?;
    let journal: ProviderAdoptionJournal = serde_json::from_slice(&bytes)
        .map_err(|error| DidError::Serialization(error.to_string()))?;
    if journal.schema_version != PROVIDER_ADOPTION_SCHEMA_VERSION {
        return Err(DidError::Serialization(
            "unsupported provider adoption journal schema".to_owned(),
        ));
    }
    Ok(journal)
}

fn write_provider_adoption_journal(
    root: &Path,
    journal: &ProviderAdoptionJournal,
) -> DidResult<()> {
    let bytes = serde_json::to_vec_pretty(journal)
        .map_err(|error| DidError::Serialization(error.to_string()))?;
    write_atomic_private(&provider_adoption_journal_path(root), &bytes)
}

fn validate_provider_adoption_journal(
    journal: &ProviderAdoptionJournal,
    manifest: &StoreManifest,
    target: &crate::RootKeyProviderBinding,
) -> DidResult<()> {
    if journal.store_id != manifest.store_id
        || &journal.target_provider != target
        || journal.root_key_fingerprint != manifest.root_key_fingerprint
        || journal.original_provider == journal.target_provider
    {
        return Err(DidError::Conflict);
    }
    match journal.phase {
        ProviderAdoptionPhase::TargetKeyImported => {
            let before_switch = manifest.provider == journal.original_provider
                && manifest.generation == journal.original_generation;
            let after_switch = manifest.provider == journal.target_provider
                && manifest.generation == journal.original_generation.checked_add(1).unwrap_or(0);
            if !before_switch && !after_switch {
                return Err(DidError::Conflict);
            }
        }
        ProviderAdoptionPhase::ManifestSwitched => {
            if manifest.provider != journal.target_provider
                || manifest.generation != journal.original_generation.checked_add(1).unwrap_or(0)
            {
                return Err(DidError::Conflict);
            }
        }
    }
    Ok(())
}

fn random_store_id() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{
        default_file_root_key_path, FileRootKeyProvider, InjectedRootKeyProvider,
        MemoryRootKeyProvider, UnavailableRootKeyProvider,
    };
    use crate::RootKeyProviderKind;

    #[test]
    fn provider_initialization_falls_back_only_for_a_new_store() {
        let root = tempfile::tempdir().unwrap();
        let unavailable =
            UnavailableRootKeyProvider::new(RootKeyProviderKind::OsKeyring, "keyring");
        let file = FileRootKeyProvider::new("local-file", default_file_root_key_path(root.path()));
        let runtime = StoreRuntime::initialize(
            root.path(),
            ProviderInitialization::Preferred {
                primary: &unavailable,
                fallback: &file,
            },
        )
        .unwrap();
        assert_eq!(
            runtime.manifest().provider.kind,
            RootKeyProviderKind::LocalPrivateFile
        );
        drop(runtime);

        let reopened = StoreRuntime::open(root.path(), &[&file]).unwrap();
        assert_eq!(reopened.manifest().generation, 1);
        let alternate = InjectedRootKeyProvider::new("alternate", [9_u8; 32]);
        assert_eq!(
            StoreRuntime::open(root.path(), &[&alternate]).err(),
            Some(DidError::ProviderUnavailable)
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            for path in [
                root.path().join("manifest.json"),
                root.path().join(".anp-identity.lock"),
                default_file_root_key_path(root.path()),
            ] {
                assert_eq!(
                    std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
            assert_eq!(
                std::fs::metadata(root.path()).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
    }

    #[test]
    fn preferred_initialization_uses_available_keyring_mock_without_fallback() {
        let root = tempfile::tempdir().unwrap();
        let keyring =
            MemoryRootKeyProvider::new(RootKeyProviderKind::OsKeyring, "keyring", [7_u8; 32]);
        let file_path = default_file_root_key_path(root.path());
        let fallback = FileRootKeyProvider::new("fallback", &file_path);
        let runtime = StoreRuntime::initialize(
            root.path(),
            ProviderInitialization::Preferred {
                primary: &keyring,
                fallback: &fallback,
            },
        )
        .unwrap();

        assert_eq!(
            runtime.manifest().provider.kind,
            RootKeyProviderKind::OsKeyring
        );
        assert!(!file_path.exists());
        drop(runtime);
        assert!(StoreRuntime::open(root.path(), &[&keyring]).is_ok());
    }

    #[test]
    fn existing_store_never_falls_back_or_creates_a_new_root_key() {
        let root = tempfile::tempdir().unwrap();
        let injected = InjectedRootKeyProvider::new("host", [7_u8; 32]);
        StoreRuntime::initialize(root.path(), ProviderInitialization::Required(&injected)).unwrap();
        let file_path = default_file_root_key_path(root.path());
        let fallback = FileRootKeyProvider::new("fallback", &file_path);

        assert_eq!(
            StoreRuntime::open(root.path(), &[&fallback]).err(),
            Some(DidError::ProviderUnavailable)
        );
        assert!(!file_path.exists());
    }

    #[test]
    #[cfg(unix)]
    fn file_provider_rejects_an_existing_root_key_with_broad_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let file_path = default_file_root_key_path(root.path());
        let file = FileRootKeyProvider::new("local-file", &file_path);
        StoreRuntime::initialize(root.path(), ProviderInitialization::Required(&file)).unwrap();
        std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o644)).unwrap();

        assert_eq!(
            StoreRuntime::open(root.path(), &[&file]).err(),
            Some(DidError::ProviderUnavailable)
        );
    }

    #[test]
    fn required_unavailable_provider_fails_without_manifest() {
        let root = tempfile::tempdir().unwrap();
        let unavailable =
            UnavailableRootKeyProvider::new(RootKeyProviderKind::OsKeyring, "keyring");

        assert_eq!(
            StoreRuntime::initialize(root.path(), ProviderInitialization::Required(&unavailable))
                .err(),
            Some(DidError::ProviderUnavailable)
        );
        assert!(!root.path().join("manifest.json").exists());
    }

    #[test]
    fn missing_store_is_distinct_from_an_unavailable_provider() {
        let root = tempfile::tempdir().unwrap();
        let injected = InjectedRootKeyProvider::new("host", [7_u8; 32]);
        assert_eq!(
            StoreRuntime::open(root.path(), &[&injected]).err(),
            Some(DidError::StoreNotFound)
        );
    }

    #[test]
    fn provider_pin_distinguishes_wrong_root_key_from_corrupt_record() {
        let root = tempfile::tempdir().unwrap();
        let provider = InjectedRootKeyProvider::new("host", [7_u8; 32]);
        StoreRuntime::initialize(root.path(), ProviderInitialization::Required(&provider)).unwrap();
        let wrong = InjectedRootKeyProvider::new("host", [8_u8; 32]);
        assert_eq!(
            StoreRuntime::open(root.path(), &[&wrong]).err(),
            Some(DidError::RootKeyMismatch)
        );
    }

    #[test]
    #[ignore = "requires a real desktop keyring or Secret Service"]
    fn real_keyring_backend_roundtrips_when_available() {
        let root = tempfile::tempdir().unwrap();
        let guard = StoreLock::new(root.path()).acquire_exclusive().unwrap();
        let provider = crate::platform::KeyringRootKeyProvider::new(
            "anp-identity-integration-test",
            "root-key",
        );
        let created = provider.create_if_missing(&guard).unwrap();
        let loaded = provider.load_existing().unwrap();
        assert_eq!(created.expose(), loaded.expose());
    }
}
