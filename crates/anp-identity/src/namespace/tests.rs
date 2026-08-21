use super::*;
use crate::{
    Capabilities, DidCreateSpec, DidProfile, KeyRole, ManagedKeySpec, RootCapabilityState,
};

#[test]
fn namespace_delete_is_generation_checked_isolated_and_idempotent() {
    let root = tempfile::tempdir().unwrap();
    let mut store = DidStore::initialize_injected(root.path(), "host", [101_u8; 32]).unwrap();
    let alice = store.create_identity(spec("alice")).unwrap();
    let alice_did = alice.did().to_string();
    let alice_identity_id = alice.identity_id().to_string();
    let bob = store.create_identity(spec("bob")).unwrap();
    let bob_did = bob.did().to_string();
    let generation = store.generation();

    assert_eq!(
        store.delete_identity_namespace(&alice_did, generation - 1),
        Err(DidError::Conflict)
    );
    store
        .delete_identity_namespace(&alice_did, generation)
        .unwrap();
    assert_eq!(
        alice.sign("#request", b"stale handle"),
        Err(DidError::IdentityNotFound)
    );
    assert_eq!(
        store.open_identity(&alice_did).err(),
        Some(DidError::IdentityNotFound)
    );
    assert!(store.open_identity(&bob_did).is_ok());
    assert!(crate::registry::read_identity(store.runtime.root(), &alice_identity_id).is_err());
    store
        .delete_identity_namespace(&alice_did, generation)
        .unwrap();
    assert_eq!(store.generation(), generation + 1);
}

#[test]
fn namespace_delete_recovery_finishes_every_crash_point_without_touching_other_dids() {
    for (index, failure) in [
        NamespaceDeleteFailurePoint::JournalPersisted,
        NamespaceDeleteFailurePoint::SecretsDeleted,
        NamespaceDeleteFailurePoint::IdentityDeleted,
        NamespaceDeleteFailurePoint::RegistryCommitted,
    ]
    .into_iter()
    .enumerate()
    {
        let root = tempfile::tempdir().unwrap();
        let key = [110_u8.saturating_add(index as u8); 32];
        let mut store = DidStore::initialize_injected(root.path(), "host", key).unwrap();
        let alice = store
            .create_identity(spec(&format!("alice-{index}")))
            .unwrap();
        let alice_did = alice.did().to_string();
        let bob = store
            .create_identity(spec(&format!("bob-{index}")))
            .unwrap();
        let bob_did = bob.did().to_string();
        let generation = store.generation();
        assert!(store
            .delete_identity_namespace_inner(&alice_did, generation, Some(failure))
            .is_err());
        if failure != NamespaceDeleteFailurePoint::RegistryCommitted {
            assert!(crate::registry::read_registry(store.runtime.root())
                .unwrap()
                .identities
                .contains_key(&alice_did));
        }
        drop(store);

        let reopened = DidStore::open_injected(root.path(), "host", key).unwrap();
        assert_eq!(
            reopened.open_identity(&alice_did).err(),
            Some(DidError::IdentityNotFound)
        );
        assert!(reopened.open_identity(&bob_did).is_ok());
        assert_eq!(
            reopened
                .list_identities()
                .unwrap()
                .iter()
                .filter(|identity| identity.did == bob_did)
                .count(),
            1
        );
    }
}

#[test]
fn namespace_delete_rejects_pending_document_and_root_state() {
    let root = tempfile::tempdir().unwrap();
    let mut store = DidStore::initialize_injected(root.path(), "host", [120_u8; 32]).unwrap();
    let mut identity = store.create_identity(spec("pending")).unwrap();
    let did = identity.did().to_string();
    identity
        .prepare_update(crate::DocumentUpdateSpec {
            request_signing_rotation: Some(crate::RequestSigningRotation {
                old_kid: "#request".to_string(),
                new_fragment: "request-next".to_string(),
            }),
            request_signing_mutations: Vec::new(),
            device_mutations: Vec::new(),
            services: None,
        })
        .unwrap();
    store.reload().unwrap();
    assert_eq!(
        store.delete_identity_namespace(&did, store.generation()),
        Err(DidError::InvalidPublicationState)
    );
    assert_eq!(identity.root_capability(), RootCapabilityState::Active);
}

fn spec(name: &str) -> DidCreateSpec {
    DidCreateSpec {
        profile: DidProfile::E1,
        domain: "example.com".to_string(),
        port: None,
        path_segments: vec!["namespace".to_string(), name.to_string()],
        capabilities: Capabilities { did_wba: true },
        managed_keys: vec![
            ManagedKeySpec {
                fragment: "root".to_string(),
                role: KeyRole::RootControl,
            },
            ManagedKeySpec {
                fragment: "request".to_string(),
                role: KeyRole::RequestSigning,
            },
        ],
        external_keys: Vec::new(),
        services: Vec::new(),
        agent_description_url: None,
        extensions: Vec::new(),
    }
}
