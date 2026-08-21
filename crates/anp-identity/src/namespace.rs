use chrono::Utc;

use crate::keystore::SecretRef;
use crate::registry::{
    read_identity, read_registry, remove_identity, remove_journal, write_journal, write_registry,
    CreationJournal, IdentityState, KeyOrigin,
};
use crate::{DidError, DidResult, DidStore};

impl DidStore {
    pub fn delete_identity_namespace(
        &mut self,
        did: &str,
        expected_generation: u64,
    ) -> DidResult<()> {
        self.delete_identity_namespace_inner(did, expected_generation, None)
    }

    fn delete_identity_namespace_inner(
        &mut self,
        did: &str,
        expected_generation: u64,
        failure: Option<NamespaceDeleteFailurePoint>,
    ) -> DidResult<()> {
        let guard = self.runtime.acquire_write()?;
        let mut registry = read_registry(self.runtime.root())?;
        if expected_generation != self.registry_generation
            || registry.generation != expected_generation
        {
            let already_deleted = !registry.identities.contains_key(did)
                && registry.generation == expected_generation.saturating_add(1);
            if already_deleted {
                self.registry_generation = registry.generation;
                return Ok(());
            }
            return Err(DidError::Conflict);
        }
        let summary = registry
            .identities
            .get(did)
            .cloned()
            .ok_or(DidError::IdentityNotFound)?;
        let record = read_identity(self.runtime.root(), &summary.identity_id)?;
        if record.did != did
            || record.state == IdentityState::Creating
            || record.pending_revision.is_some()
            || record.pending_enrollment.is_some()
            || record.pending_root_transfer.is_some()
            || record.root_capability == crate::RootCapabilityState::Pending
        {
            return Err(DidError::InvalidPublicationState);
        }
        let secret_refs = record
            .keys
            .iter()
            .filter(|key| key.origin == KeyOrigin::Managed && !key.material_erased)
            .map(|key| SecretRef {
                identity_id: record.identity_id.clone(),
                key_id: key.kid.clone(),
                role: key.role,
                version: key.version,
            })
            .collect::<Vec<_>>();
        let transaction_id = crate::identity::random_id();
        let journal = CreationJournal::new_namespace_delete(
            transaction_id.clone(),
            record.identity_id.clone(),
            record.did.clone(),
            secret_refs.clone(),
            Utc::now().to_rfc3339(),
        );
        write_journal(self.runtime.root(), &guard, &journal)?;
        maybe_fail(failure, NamespaceDeleteFailurePoint::JournalPersisted)?;
        for secret_ref in &secret_refs {
            self.runtime.key_store().delete(&guard, secret_ref)?;
        }
        maybe_fail(failure, NamespaceDeleteFailurePoint::SecretsDeleted)?;
        remove_identity(self.runtime.root(), &guard, &record.identity_id)?;
        maybe_fail(failure, NamespaceDeleteFailurePoint::IdentityDeleted)?;
        registry.identities.remove(did);
        registry.generation = registry
            .generation
            .checked_add(1)
            .ok_or(DidError::Conflict)?;
        write_registry(self.runtime.root(), &guard, &registry)?;
        maybe_fail(failure, NamespaceDeleteFailurePoint::RegistryCommitted)?;
        remove_journal(self.runtime.root(), &guard, &transaction_id)?;
        drop(guard);
        self.registry_generation = registry.generation;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NamespaceDeleteFailurePoint {
    JournalPersisted,
    SecretsDeleted,
    IdentityDeleted,
    RegistryCommitted,
}

fn maybe_fail(
    configured: Option<NamespaceDeleteFailurePoint>,
    current: NamespaceDeleteFailurePoint,
) -> DidResult<()> {
    if configured == Some(current) {
        return Err(DidError::Io(
            "injected namespace delete failure".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
