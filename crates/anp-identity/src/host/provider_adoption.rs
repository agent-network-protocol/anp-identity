use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::keystore::SecretRef;
use crate::platform::{
    default_file_root_key_path, FileRootKeyProvider, KeyringRootKeyProvider, RootKey,
    RootKeyProvider,
};
use crate::store::StoreRuntime;
use crate::{DidStore, IdentityError, IdentityResult, KeyOrigin, RootKeyProviderBinding};

/// Destination for same-key provider adoption. The Store Root Key bytes do not rotate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ProviderAdoptionTarget {
    LocalPrivateFile,
    Keyring { service: String, account: String },
}

/// Plaintext exists only in trusted Rust memory; Node exposes only the sealed wrapper.
pub struct AdoptStoreRootKeyRequest {
    pub state_root: PathBuf,
    pub existing_root_key: Zeroizing<[u8; 32]>,
    pub target: ProviderAdoptionTarget,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderAdoptionReport {
    pub store_id: String,
    pub provider: RootKeyProviderBinding,
    pub root_key_fingerprint: String,
    pub generation: u64,
}

pub fn adopt_store_root_key_provider(
    request: AdoptStoreRootKeyRequest,
) -> IdentityResult<ProviderAdoptionReport> {
    let root_key = RootKey::from_bytes(*request.existing_root_key);
    match request.target {
        ProviderAdoptionTarget::LocalPrivateFile => {
            let provider = FileRootKeyProvider::new(
                "local-private-file",
                default_file_root_key_path(&request.state_root),
            );
            adopt_with_provider(request.state_root, root_key, &provider)
        }
        ProviderAdoptionTarget::Keyring { service, account } => {
            if service.trim().is_empty() || account.trim().is_empty() {
                return Err(IdentityError::InvalidRequest);
            }
            let provider = KeyringRootKeyProvider::new(service, account);
            adopt_with_provider(request.state_root, root_key, &provider)
        }
    }
}

fn adopt_with_provider(
    state_root: PathBuf,
    root_key: RootKey,
    provider: &dyn RootKeyProvider,
) -> IdentityResult<ProviderAdoptionReport> {
    let runtime = StoreRuntime::adopt_root_key_provider(state_root, root_key, provider)?;
    let store = DidStore::from_runtime(runtime)?;
    verify_all_managed_secrets(&store)?;
    store
        .runtime
        .complete_root_key_provider_adoption()
        .map_err(IdentityError::from)?;
    let manifest = store.manifest();
    Ok(ProviderAdoptionReport {
        store_id: manifest.store_id.clone(),
        provider: manifest.provider.clone(),
        root_key_fingerprint: manifest.root_key_fingerprint.clone(),
        generation: manifest.generation,
    })
}

fn verify_all_managed_secrets(store: &DidStore) -> IdentityResult<()> {
    for summary in store.list_identities()? {
        let identity = store.open_identity(&summary.did)?;
        for metadata in &identity.record().keys {
            if metadata.origin != KeyOrigin::Managed || metadata.material_erased {
                continue;
            }
            let secret_ref = SecretRef {
                identity_id: identity.identity_id().to_owned(),
                key_id: metadata.kid.clone(),
                role: metadata.role,
                version: metadata.version,
            };
            let _secret = identity
                .runtime()
                .key_store()
                .open(identity.runtime().root_key(), &secret_ref)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Capabilities, DidProfile, KeyRole, ManagedKeySpec};

    fn create_spec() -> crate::CreateIdentityRequest {
        crate::CreateIdentityRequest {
            profile: DidProfile::E1,
            domain: "example.com".to_owned(),
            port: None,
            path_segments: vec!["provider-adoption".to_owned()],
            capabilities: Capabilities { did_wba: true },
            managed_keys: vec![
                ManagedKeySpec {
                    fragment: "root".to_owned(),
                    role: KeyRole::RootControl,
                },
                ManagedKeySpec {
                    fragment: "request".to_owned(),
                    role: KeyRole::RequestSigning,
                },
                ManagedKeySpec {
                    fragment: "agreement".to_owned(),
                    role: KeyRole::E2eeAgreement,
                },
            ],
            external_keys: Vec::new(),
            services: Vec::new(),
            agent_description_url: None,
            extensions: Vec::new(),
        }
    }

    fn record_bytes(root: &std::path::Path) -> Vec<Vec<u8>> {
        let mut paths = std::fs::read_dir(root.join("records"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        paths.sort();
        paths
            .into_iter()
            .map(|path| std::fs::read(path).unwrap())
            .collect()
    }

    #[test]
    fn same_key_adoption_preserves_ciphertexts_fingerprint_and_identity() {
        let root = tempfile::tempdir().unwrap();
        let root_key = [0x63; 32];
        let mut manager = crate::IdentityManager::initialize(crate::IdentityManagerConfig {
            state_root: root.path().to_path_buf(),
            root_key: crate::RootKeySource::Injected(crate::InjectedStoreKey::new(
                "awiki-vault",
                root_key,
            )),
        })
        .unwrap();
        let identity = manager.create(create_spec()).unwrap();
        let reference = identity.reference();
        let before_records = record_bytes(root.path());
        let before_manifest = serde_json::from_slice::<crate::StoreManifest>(
            &std::fs::read(root.path().join("manifest.json")).unwrap(),
        )
        .unwrap();

        let report = adopt_store_root_key_provider(AdoptStoreRootKeyRequest {
            state_root: root.path().to_path_buf(),
            existing_root_key: Zeroizing::new(root_key),
            target: ProviderAdoptionTarget::LocalPrivateFile,
        })
        .unwrap();
        assert_eq!(report.store_id, reference.store_id);
        assert_eq!(
            report.provider.kind,
            crate::RootKeyProviderKind::LocalPrivateFile
        );
        assert_eq!(
            report.root_key_fingerprint,
            before_manifest.root_key_fingerprint
        );
        assert_eq!(record_bytes(root.path()), before_records);
        assert!(!root.path().join("provider-adoption-v1.json").exists());
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

        let repeated = adopt_store_root_key_provider(AdoptStoreRootKeyRequest {
            state_root: root.path().to_path_buf(),
            existing_root_key: Zeroizing::new(root_key),
            target: ProviderAdoptionTarget::LocalPrivateFile,
        })
        .unwrap();
        assert_eq!(repeated.generation, report.generation);
        assert_eq!(record_bytes(root.path()), before_records);
    }

    #[test]
    fn adoption_rejects_wrong_root_key_before_mutating_manifest() {
        let root = tempfile::tempdir().unwrap();
        let mut manager = crate::IdentityManager::initialize(crate::IdentityManagerConfig {
            state_root: root.path().to_path_buf(),
            root_key: crate::RootKeySource::Injected(crate::InjectedStoreKey::new(
                "awiki-vault",
                [0x64; 32],
            )),
        })
        .unwrap();
        manager.create(create_spec()).unwrap();
        let before = std::fs::read(root.path().join("manifest.json")).unwrap();
        let error = adopt_store_root_key_provider(AdoptStoreRootKeyRequest {
            state_root: root.path().to_path_buf(),
            existing_root_key: Zeroizing::new([0x65; 32]),
            target: ProviderAdoptionTarget::LocalPrivateFile,
        })
        .unwrap_err();
        assert_eq!(error, IdentityError::RootKeyMismatch);
        assert_eq!(
            std::fs::read(root.path().join("manifest.json")).unwrap(),
            before
        );
        assert!(!root.path().join("root-key.b64u").exists());
    }

    #[test]
    fn adoption_recovers_after_every_persisted_phase() {
        use crate::store::ProviderAdoptionPersistPoint;

        for fail_after in [
            ProviderAdoptionPersistPoint::TargetKeyImported,
            ProviderAdoptionPersistPoint::InitialJournalWritten,
            ProviderAdoptionPersistPoint::ManifestSwitched,
            ProviderAdoptionPersistPoint::SwitchedJournalWritten,
        ] {
            let root = tempfile::tempdir().unwrap();
            let root_key = [0x66; 32];
            let mut manager = crate::IdentityManager::initialize(crate::IdentityManagerConfig {
                state_root: root.path().to_path_buf(),
                root_key: crate::RootKeySource::Injected(crate::InjectedStoreKey::new(
                    "awiki-vault",
                    root_key,
                )),
            })
            .unwrap();
            let reference = manager.create(create_spec()).unwrap().reference();
            let before_records = record_bytes(root.path());
            let before_fingerprint = serde_json::from_slice::<crate::StoreManifest>(
                &std::fs::read(root.path().join("manifest.json")).unwrap(),
            )
            .unwrap()
            .root_key_fingerprint;
            let target = FileRootKeyProvider::new(
                "local-private-file",
                default_file_root_key_path(root.path()),
            );

            assert!(StoreRuntime::adopt_root_key_provider_injected(
                root.path(),
                RootKey::from_bytes(root_key),
                &target,
                fail_after,
            )
            .is_err());
            let report = adopt_store_root_key_provider(AdoptStoreRootKeyRequest {
                state_root: root.path().to_path_buf(),
                existing_root_key: Zeroizing::new(root_key),
                target: ProviderAdoptionTarget::LocalPrivateFile,
            })
            .unwrap();
            assert_eq!(report.store_id, reference.store_id);
            assert_eq!(report.root_key_fingerprint, before_fingerprint);
            assert_eq!(record_bytes(root.path()), before_records);
            assert!(!root.path().join("provider-adoption-v1.json").exists());
        }

        let root = tempfile::tempdir().unwrap();
        let root_key = [0x67; 32];
        let mut manager = crate::IdentityManager::initialize(crate::IdentityManagerConfig {
            state_root: root.path().to_path_buf(),
            root_key: crate::RootKeySource::Injected(crate::InjectedStoreKey::new(
                "awiki-vault",
                root_key,
            )),
        })
        .unwrap();
        let reference = manager.create(create_spec()).unwrap().reference();
        let target = FileRootKeyProvider::new(
            "local-private-file",
            default_file_root_key_path(root.path()),
        );
        let runtime = StoreRuntime::adopt_root_key_provider(
            root.path(),
            RootKey::from_bytes(root_key),
            &target,
        )
        .unwrap();
        assert!(runtime
            .complete_root_key_provider_adoption_injected(
                ProviderAdoptionPersistPoint::JournalRemoved,
            )
            .is_err());
        let report = adopt_store_root_key_provider(AdoptStoreRootKeyRequest {
            state_root: root.path().to_path_buf(),
            existing_root_key: Zeroizing::new(root_key),
            target: ProviderAdoptionTarget::LocalPrivateFile,
        })
        .unwrap();
        assert_eq!(report.store_id, reference.store_id);
        assert!(!root.path().join("provider-adoption-v1.json").exists());
    }
}
