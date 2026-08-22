use std::sync::{Arc, Mutex, MutexGuard};

use crate::facade::{
    DidDocument, IdentityError, IdentityRef, IdentityResult, PublicCapabilities, PublicIdentity,
    PublicIdentityState, PublicKeyDescriptor,
};
use crate::DidIdentity;

pub struct ManagedIdentity {
    pub(crate) store_id: String,
    pub(crate) reference: IdentityRef,
    pub(crate) engine: Arc<Mutex<DidIdentity>>,
}

impl ManagedIdentity {
    pub fn reference(&self) -> IdentityRef {
        self.reference.clone()
    }

    pub fn public_identity(&self) -> IdentityResult<PublicIdentity> {
        let engine = self.lock_engine()?;
        project_public_identity(&self.store_id, &engine)
    }

    pub(crate) fn lock_engine(&self) -> IdentityResult<MutexGuard<'_, DidIdentity>> {
        self.engine.lock().map_err(|_| IdentityError::Internal)
    }
}

pub(crate) fn project_public_identity(
    store_id: &str,
    engine: &DidIdentity,
) -> IdentityResult<PublicIdentity> {
    let state = PublicIdentityState::try_from(engine.state())?;
    let active_keys = engine
        .keys()
        .iter()
        .filter_map(PublicKeyDescriptor::from_metadata)
        .collect();
    Ok(PublicIdentity {
        reference: IdentityRef {
            store_id: store_id.to_owned(),
            identity_id: engine.identity_id().to_owned(),
            did: engine.did().to_owned(),
        },
        state,
        revision: engine.revision(),
        document: DidDocument::from_verified(engine.document().clone()),
        active_keys,
        capabilities: PublicCapabilities::from(engine.capabilities()),
    })
}
