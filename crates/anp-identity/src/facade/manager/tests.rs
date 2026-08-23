use crate::facade::{
    DeleteIdentityRequest, DidDocument, IdentityError, IdentityManager, IdentityManagerConfig,
    InjectedStoreKey, RootKeySource,
};
use crate::{Capabilities, DidCreateSpec, DidProfile, KeyRole, ManagedKeySpec};

#[test]
fn manager_preserves_multi_did_engine_behavior_and_checks_full_references() {
    let root = tempfile::tempdir().unwrap();
    let mut manager = IdentityManager::initialize(config(root.path(), [0x51; 32])).unwrap();
    let first = manager.create_engine_for_test(spec("first")).unwrap();
    let second = manager.create_engine_for_test(spec("second")).unwrap();
    let first_public = first.public_identity().unwrap();

    assert_eq!(manager.info().unwrap().identity_count, 2);
    assert_eq!(manager.list().unwrap().len(), 2);
    assert_eq!(first_public.reference, first.reference());
    assert_eq!(
        first_public.document.as_value()["id"],
        first.reference().did
    );
    assert_eq!(first_public.active_keys.len(), 2);

    let mut wrong_store = first.reference();
    wrong_store.store_id = "other-store".to_owned();
    assert_eq!(
        manager.get(&wrong_store).err(),
        Some(IdentityError::IdentityNotFound)
    );
    let mut wrong_identity = first.reference();
    wrong_identity.identity_id = second.reference().identity_id;
    assert_eq!(
        manager.get(&wrong_identity).err(),
        Some(IdentityError::IdentityNotFound)
    );

    drop(manager);
    let reopened = IdentityManager::open(config(root.path(), [0x51; 32])).unwrap();
    assert_eq!(
        reopened
            .get(&first.reference())
            .unwrap()
            .public_identity()
            .unwrap(),
        first_public
    );
}

#[test]
fn manager_and_engine_open_each_others_store_without_schema_changes() {
    let root = tempfile::tempdir().unwrap();
    let mut manager = IdentityManager::initialize(config(root.path(), [0x61; 32])).unwrap();
    let identity = manager
        .create_engine_for_test(spec("schema-parity"))
        .unwrap();
    let reference = identity.reference();
    drop(manager);

    let mut engine =
        crate::DidStore::open_injected(root.path(), "facade-test", [0x61; 32]).unwrap();
    assert_eq!(
        engine.open_identity(&reference.did).unwrap().identity_id(),
        reference.identity_id
    );
    engine.reload().unwrap();
    drop(engine);

    let mut reopened = IdentityManager::open(config(root.path(), [0x61; 32])).unwrap();
    let managed = reopened.get(&reference).unwrap();
    assert_eq!(managed.reference(), reference);
    drop(managed);
    reopened
        .delete(&reference, DeleteIdentityRequest::default())
        .unwrap();
    assert!(reopened.list().unwrap().is_empty());
}

#[test]
fn manager_maps_engine_failures_to_stable_categories() {
    let missing = tempfile::tempdir().unwrap();
    assert_eq!(
        IdentityManager::open(config(missing.path(), [0x71; 32])).err(),
        Some(IdentityError::StoreNotFound)
    );

    let root = tempfile::tempdir().unwrap();
    IdentityManager::initialize(config(root.path(), [0x72; 32])).unwrap();
    assert_eq!(
        IdentityManager::open(config(root.path(), [0x73; 32])).err(),
        Some(IdentityError::RootKeyMismatch)
    );
}

#[test]
fn did_document_can_cross_the_facade_boundary() {
    let value = serde_json::json!({
        "id": "did:wba:example.com:user:alice",
        "verificationMethod": []
    });
    let document = DidDocument::from_value(value.clone());

    assert_eq!(document.as_value(), &value);
    assert_eq!(document.into_value(), value);
}

fn config(root: &std::path::Path, bytes: [u8; 32]) -> IdentityManagerConfig {
    IdentityManagerConfig {
        state_root: root.to_owned(),
        root_key: RootKeySource::Injected(InjectedStoreKey::new("facade-test", bytes)),
    }
}

fn spec(name: &str) -> DidCreateSpec {
    DidCreateSpec {
        profile: DidProfile::E1,
        domain: "example.com".to_owned(),
        port: None,
        path_segments: vec!["facade".to_owned(), name.to_owned()],
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
        ],
        external_keys: Vec::new(),
        services: Vec::new(),
        agent_description_url: None,
        extensions: Vec::new(),
    }
}
