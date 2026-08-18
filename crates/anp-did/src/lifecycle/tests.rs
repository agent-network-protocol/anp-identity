use anp::authentication::{validate_did_document_binding, verify_auth_header_signature};

use super::*;
use crate::registry::list_update_journals;
use crate::{Capabilities, DidCreateSpec, DidProfile, DidStore, ManagedKeySpec};

#[test]
fn lifecycle_candidate_reconcile_commit_retire_revoke_and_delete() {
    let root = tempfile::tempdir().unwrap();
    let mut store = DidStore::initialize_injected(root.path(), "host", [31_u8; 32]).unwrap();
    let mut identity = store.create_identity(spec("commit")).unwrap();
    let old_signature = identity.sign("#request", b"before rotation").unwrap();
    let prepared = identity.prepare_update(update("request-v2")).unwrap();
    assert_eq!(
        identity.pending_revision().unwrap().state,
        PublicationState::Prepared
    );
    assert!(validate_did_document_binding(
        &prepared.candidate_document,
        true
    ));
    assert!(prepared.candidate_document["authentication"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry
            .as_str()
            .is_some_and(|kid| kid.ends_with("#request-v2"))));
    assert!(!prepared.candidate_document["authentication"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry.as_str().is_some_and(|kid| kid.ends_with("#request"))));

    identity.begin_publication(&prepared.revision_id).unwrap();
    identity
        .mark_publication_uncertain(&prepared.revision_id)
        .unwrap();
    assert_eq!(
        identity.abort_update(&prepared.revision_id),
        Err(DidError::InvalidPublicationState)
    );
    assert_eq!(
        identity.mark_published(&prepared.revision_id),
        Err(DidError::InvalidPublicationState)
    );
    assert_eq!(
        identity.commit_update(&prepared.revision_id),
        Err(DidError::InvalidPublicationState)
    );
    assert_eq!(
        identity.end_retirement("#request"),
        Err(DidError::InvalidPublicationState)
    );
    assert_eq!(
        identity.prepare_update(update("request-v3")).err(),
        Some(DidError::InvalidPublicationState)
    );
    assert_eq!(
        identity
            .reconcile_update(&prepared.revision_id, &prepared.candidate_document)
            .unwrap(),
        ReconcileOutcome::Committed
    );

    assert_eq!(identity.revision(), 2);
    assert!(identity.pending_revision().is_none());
    assert_eq!(
        identity.sign("#request", b"retired").err(),
        Some(DidError::KeyNotUsable)
    );
    identity
        .verify("#request", b"before rotation", &old_signature)
        .unwrap();
    let new_signature = identity.sign("#request-v2", b"active").unwrap();
    identity
        .verify("#request-v2", b"active", &new_signature)
        .unwrap();
    let auth_header = identity
        .legacy_did_wba_header("#request-v2", "api.example.com", "1.1")
        .unwrap();
    verify_auth_header_signature(&auth_header, identity.document(), "api.example.com").unwrap();
    identity.end_retirement("#request").unwrap();
    assert_eq!(
        identity.verify("#request", b"before rotation", &old_signature),
        Err(DidError::KeyNotUsable)
    );
    identity.delete_revoked_key("#request").unwrap();
    assert_eq!(
        identity.delete_revoked_key("#root"),
        Err(DidError::UnsupportedOperation)
    );
}

#[test]
fn lifecycle_uncertain_old_allows_abort_and_unknown_conflicts() {
    let root = tempfile::tempdir().unwrap();
    let mut store = DidStore::initialize_injected(root.path(), "host", [32_u8; 32]).unwrap();
    let mut identity = store.create_identity(spec("reconcile")).unwrap();
    let old_document = identity.document().clone();
    let prepared = identity.prepare_update(update("request-v2")).unwrap();
    assert_eq!(
        identity.prepare_update(update("request-v3")).err(),
        Some(DidError::PendingRevisionExists)
    );
    identity.begin_publication(&prepared.revision_id).unwrap();
    identity
        .mark_publication_uncertain(&prepared.revision_id)
        .unwrap();

    let unknown = valid_unknown_document(&identity);
    assert!(validate_did_document_binding(&unknown, true));
    assert_eq!(
        identity.reconcile_update(&prepared.revision_id, &unknown),
        Err(DidError::Conflict)
    );
    assert_eq!(
        identity
            .reconcile_update(&prepared.revision_id, &old_document)
            .unwrap(),
        ReconcileOutcome::RemoteOld
    );
    assert_eq!(
        identity.pending_revision().unwrap().state,
        PublicationState::Prepared
    );
    identity.abort_update(&prepared.revision_id).unwrap();
    assert!(identity.pending_revision().is_none());
    assert_eq!(identity.runtime().key_store().list().unwrap().len(), 4);
}

#[test]
fn lifecycle_direct_published_commit_and_invalid_role_paths() {
    let root = tempfile::tempdir().unwrap();
    let mut store = DidStore::initialize_injected(root.path(), "host", [33_u8; 32]).unwrap();
    let mut identity = store.create_identity(spec("published")).unwrap();
    assert_eq!(
        identity
            .prepare_update(DocumentUpdateSpec {
                request_signing_rotation: RequestSigningRotation {
                    old_kid: "#root".to_string(),
                    new_fragment: "new-root".to_string(),
                },
                services: None,
            })
            .err(),
        Some(DidError::UnsupportedOperation)
    );
    assert_eq!(
        identity
            .prepare_update(DocumentUpdateSpec {
                request_signing_rotation: RequestSigningRotation {
                    old_kid: "#e2ee-signing".to_string(),
                    new_fragment: "wrong-role".to_string(),
                },
                services: None,
            })
            .err(),
        Some(DidError::KeyRoleViolation)
    );
    let prepared = identity.prepare_update(update("request-v2")).unwrap();
    identity.begin_publication(&prepared.revision_id).unwrap();
    identity.mark_published(&prepared.revision_id).unwrap();
    assert_eq!(
        identity.abort_update(&prepared.revision_id),
        Err(DidError::InvalidPublicationState)
    );
    identity.commit_update(&prepared.revision_id).unwrap();
    assert_eq!(identity.revision(), 2);
}

#[test]
fn lifecycle_prepare_and_abort_failure_points_recover_without_orphans() {
    for point in [
        LifecycleFailurePoint::PrepareJournalPersisted,
        LifecycleFailurePoint::PendingSecretPersisted,
        LifecycleFailurePoint::PendingIdentityPersisted,
    ] {
        let root = tempfile::tempdir().unwrap();
        let mut store = DidStore::initialize_injected(root.path(), "host", [34_u8; 32]).unwrap();
        let mut identity = store.create_identity(spec("prepare-failure")).unwrap();
        assert!(identity
            .prepare_update_inner(update("request-v2"), Some(point))
            .is_err());
        drop(identity);
        drop(store);

        let reopened = DidStore::open_injected(root.path(), "host", [34_u8; 32]).unwrap();
        let summary = reopened.list_identities().unwrap().pop().unwrap();
        let mut identity = reopened.open_identity(&summary.did).unwrap();
        if point == LifecycleFailurePoint::PendingIdentityPersisted {
            let pending = identity.pending_revision().unwrap();
            identity.abort_update(&pending.revision_id).unwrap();
        } else {
            assert!(identity.pending_revision().is_none());
        }
        assert_eq!(identity.runtime().key_store().list().unwrap().len(), 4);
        assert!(list_update_journals(root.path()).unwrap().is_empty());
    }

    for point in [
        LifecycleFailurePoint::CleanupJournalPersisted,
        LifecycleFailurePoint::PendingIdentityCleared,
        LifecycleFailurePoint::PendingSecretsDeleted,
    ] {
        let root = tempfile::tempdir().unwrap();
        let mut store = DidStore::initialize_injected(root.path(), "host", [35_u8; 32]).unwrap();
        let mut identity = store.create_identity(spec("abort-failure")).unwrap();
        let prepared = identity.prepare_update(update("request-v2")).unwrap();
        assert!(identity
            .abort_update_inner(&prepared.revision_id, Some(point))
            .is_err());
        drop(identity);
        drop(store);

        let reopened = DidStore::open_injected(root.path(), "host", [35_u8; 32]).unwrap();
        let summary = reopened.list_identities().unwrap().pop().unwrap();
        let identity = reopened.open_identity(&summary.did).unwrap();
        assert!(identity.pending_revision().is_none());
        assert_eq!(identity.runtime().key_store().list().unwrap().len(), 4);
        assert!(list_update_journals(root.path()).unwrap().is_empty());
    }
}

#[test]
fn lifecycle_concurrent_handles_reject_stale_prepare() {
    let root = tempfile::tempdir().unwrap();
    let mut store = DidStore::initialize_injected(root.path(), "host", [36_u8; 32]).unwrap();
    let mut first = store.create_identity(spec("concurrent")).unwrap();
    let mut stale = first.clone();
    first.prepare_update(update("request-v2")).unwrap();
    assert_eq!(
        stale.prepare_update(update("request-v3")).err(),
        Some(DidError::Conflict)
    );
}

fn valid_unknown_document(identity: &DidIdentity) -> Value {
    let mut document = identity.document().clone();
    let domain = document["proof"]["domain"].as_str().map(ToOwned::to_owned);
    document.as_object_mut().unwrap().remove("proof");
    document["unknownRevisionMarker"] = json!("third-version");
    let root = identity
        .keys()
        .iter()
        .find(|key| key.role == KeyRole::RootControl)
        .unwrap();
    let secret = identity.load_managed_secret(root).unwrap();
    crate::document::sign_root_document(&document, &root.kid, &secret, domain).unwrap()
}

fn update(new_fragment: &str) -> DocumentUpdateSpec {
    DocumentUpdateSpec {
        request_signing_rotation: RequestSigningRotation {
            old_kid: "#request".to_string(),
            new_fragment: new_fragment.to_string(),
        },
        services: Some(vec![ServiceSpec {
            id: "message-v2".to_string(),
            service_type: "ANPMessageService".to_string(),
            service_endpoint: "https://example.com/im/v2".to_string(),
            profiles: vec!["anp.core.binding.v1".to_string()],
            security_profiles: vec!["transport-protected".to_string()],
        }]),
    }
}

fn spec(name: &str) -> DidCreateSpec {
    DidCreateSpec {
        profile: DidProfile::E1,
        domain: "example.com".to_string(),
        port: None,
        path_segments: vec!["agents".to_string(), name.to_string()],
        capabilities: Capabilities { did_wba: true },
        managed_keys: vec![
            managed("root", KeyRole::RootControl),
            managed("request", KeyRole::RequestSigning),
            managed("e2ee-signing", KeyRole::E2eeSigning),
            managed("agreement", KeyRole::E2eeAgreement),
        ],
        external_keys: Vec::new(),
        services: vec![ServiceSpec {
            id: "message".to_string(),
            service_type: "ANPMessageService".to_string(),
            service_endpoint: "https://example.com/im".to_string(),
            profiles: Vec::new(),
            security_profiles: Vec::new(),
        }],
        agent_description_url: Some("https://example.com/agent.json".to_string()),
        extensions: Vec::new(),
    }
}

fn managed(fragment: &str, role: KeyRole) -> ManagedKeySpec {
    ManagedKeySpec {
        fragment: fragment.to_string(),
        role,
    }
}
