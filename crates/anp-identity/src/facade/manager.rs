use crate::facade::{
    CreateIdentityRequest, DeleteIdentityRequest, IdentityDescriptor, IdentityError,
    IdentityManagerConfig, IdentityRef, IdentityResult, ManagedIdentity, PublicIdentityState,
    RecoveryReport, RootKeySource, StoreHealth, StoreInfo,
};
use crate::platform::{default_file_root_key_path, FileRootKeyProvider, KeyringRootKeyProvider};
use crate::store::StoreRuntime;
use crate::DidStore;
use std::sync::{Arc, Mutex};

pub struct IdentityManager {
    engine: DidStore,
}

impl IdentityManager {
    pub fn initialize(config: IdentityManagerConfig) -> IdentityResult<Self> {
        let engine = match config.root_key {
            RootKeySource::Injected(key) => {
                let (key_id, bytes) = key.into_parts();
                DidStore::initialize_injected(config.state_root, key_id, bytes)
            }
            RootKeySource::Environment { key_id, variable } => {
                DidStore::initialize_env(config.state_root, key_id, &variable)
            }
            RootKeySource::LocalPrivateFile => DidStore::initialize_local_file(config.state_root),
            RootKeySource::Keyring {
                service,
                account,
                fallback_to_local_file,
            } => DidStore::initialize_keyring(
                config.state_root,
                service,
                account,
                fallback_to_local_file,
            ),
        }?;
        Ok(Self { engine })
    }

    pub fn open(config: IdentityManagerConfig) -> IdentityResult<Self> {
        let engine = match config.root_key {
            RootKeySource::Injected(key) => {
                let (key_id, bytes) = key.into_parts();
                DidStore::open_injected(config.state_root, key_id, bytes)
            }
            RootKeySource::Environment { key_id, variable } => {
                DidStore::open_env(config.state_root, key_id, &variable)
            }
            RootKeySource::LocalPrivateFile => DidStore::open_local_file(config.state_root),
            RootKeySource::Keyring {
                service,
                account,
                fallback_to_local_file,
            } => open_keyring(config.state_root, service, account, fallback_to_local_file),
        }?;
        Ok(Self { engine })
    }

    pub fn info(&self) -> IdentityResult<StoreInfo> {
        Ok(StoreInfo {
            store_id: self.store_id().to_owned(),
            schema_compatible: true,
            identity_count: self.engine.list_identities()?.len(),
            health: StoreHealth::Ready,
        })
    }

    pub fn list(&self) -> IdentityResult<Vec<IdentityDescriptor>> {
        let store_id = self.store_id().to_owned();
        self.engine
            .list_identities()?
            .into_iter()
            .map(|summary| {
                Ok(IdentityDescriptor {
                    reference: IdentityRef {
                        store_id: store_id.clone(),
                        identity_id: summary.identity_id,
                        did: summary.did,
                    },
                    state: PublicIdentityState::try_from(summary.state)?,
                })
            })
            .collect()
    }

    pub fn create(&mut self, request: CreateIdentityRequest) -> IdentityResult<ManagedIdentity> {
        let engine = self.engine.create_identity(request)?;
        Ok(self.wrap(engine))
    }

    pub fn get(&self, reference: &IdentityRef) -> IdentityResult<ManagedIdentity> {
        self.validate_store(reference)?;
        let engine = self.engine.open_identity(&reference.did)?;
        if engine.identity_id() != reference.identity_id {
            return Err(IdentityError::IdentityNotFound);
        }
        Ok(self.wrap(engine))
    }

    pub fn delete(
        &mut self,
        reference: &IdentityRef,
        _request: DeleteIdentityRequest,
    ) -> IdentityResult<()> {
        self.validate_store(reference)?;
        let engine = self.engine.open_identity(&reference.did)?;
        if engine.identity_id() != reference.identity_id {
            return Err(IdentityError::IdentityNotFound);
        }
        self.engine
            .delete_identity_namespace(&reference.did, self.engine.generation())?;
        Ok(())
    }

    pub fn recover(&mut self) -> IdentityResult<RecoveryReport> {
        self.engine.reload()?;
        Ok(RecoveryReport {
            identity_count: self.engine.list_identities()?.len(),
        })
    }

    fn store_id(&self) -> &str {
        &self.engine.manifest().store_id
    }

    fn validate_store(&self, reference: &IdentityRef) -> IdentityResult<()> {
        if reference.store_id != self.store_id() {
            return Err(IdentityError::IdentityNotFound);
        }
        Ok(())
    }

    fn wrap(&self, engine: crate::DidIdentity) -> ManagedIdentity {
        let reference = IdentityRef {
            store_id: self.store_id().to_owned(),
            identity_id: engine.identity_id().to_owned(),
            did: engine.did().to_owned(),
        };
        ManagedIdentity {
            store_id: self.store_id().to_owned(),
            reference,
            engine: Arc::new(Mutex::new(engine)),
        }
    }
}

fn open_keyring(
    state_root: std::path::PathBuf,
    service: String,
    account: String,
    fallback_to_local_file: bool,
) -> crate::DidResult<DidStore> {
    let keyring = KeyringRootKeyProvider::new(service, account);
    let file = FileRootKeyProvider::new(
        "local-private-file",
        default_file_root_key_path(&state_root),
    );
    let runtime = if fallback_to_local_file {
        StoreRuntime::open(state_root, &[&keyring, &file])
    } else {
        StoreRuntime::open(state_root, &[&keyring])
    }?;
    DidStore::from_runtime(runtime)
}

#[cfg(test)]
mod tests;
