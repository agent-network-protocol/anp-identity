use anp::authentication::{validate_did_document_binding, verify_auth_header_signature};

use super::*;
use crate::keystore::SecretRef;
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
    assert!(identity.key_metadata("#request").unwrap().material_erased);
    assert_eq!(
        identity.delete_revoked_key("#request"),
        Err(DidError::KeyMaterialErased)
    );
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
fn lifecycle_reconcile_state_and_remote_observation_matrix_is_fail_closed() {
    #[derive(Clone, Copy)]
    enum RemoteObservation {
        Old,
        Candidate,
        Unknown,
    }

    for state in [
        PublicationState::Prepared,
        PublicationState::PublicationInFlight,
        PublicationState::PublicationUncertain,
        PublicationState::Published,
    ] {
        for observation in [
            RemoteObservation::Old,
            RemoteObservation::Candidate,
            RemoteObservation::Unknown,
        ] {
            let root = tempfile::tempdir().unwrap();
            let mut store =
                DidStore::initialize_injected(root.path(), "host", [37_u8; 32]).unwrap();
            let mut identity = store.create_identity(spec("matrix")).unwrap();
            let old_document = identity.document().clone();
            let prepared = identity.prepare_update(update("request-v2")).unwrap();
            let unknown_document = valid_unknown_document(&identity);

            if state != PublicationState::Prepared {
                identity.begin_publication(&prepared.revision_id).unwrap();
            }
            match state {
                PublicationState::Prepared | PublicationState::PublicationInFlight => {}
                PublicationState::PublicationUncertain => identity
                    .mark_publication_uncertain(&prepared.revision_id)
                    .unwrap(),
                PublicationState::Published => {
                    identity.mark_published(&prepared.revision_id).unwrap()
                }
            }

            let observed = match observation {
                RemoteObservation::Old => &old_document,
                RemoteObservation::Candidate => &prepared.candidate_document,
                RemoteObservation::Unknown => &unknown_document,
            };
            let result = identity.reconcile_update(&prepared.revision_id, observed);
            if state != PublicationState::PublicationUncertain {
                assert_eq!(result, Err(DidError::InvalidPublicationState));
                continue;
            }
            match observation {
                RemoteObservation::Old => {
                    assert_eq!(result, Ok(ReconcileOutcome::RemoteOld));
                }
                RemoteObservation::Candidate => {
                    assert_eq!(result, Ok(ReconcileOutcome::Committed));
                }
                RemoteObservation::Unknown => {
                    assert_eq!(result, Err(DidError::Conflict));
                }
            }
        }
    }
}

#[test]
fn lifecycle_direct_published_commit_and_invalid_role_paths() {
    let root = tempfile::tempdir().unwrap();
    let mut store = DidStore::initialize_injected(root.path(), "host", [33_u8; 32]).unwrap();
    let mut identity = store.create_identity(spec("published")).unwrap();
    assert_eq!(
        identity
            .prepare_update(DocumentUpdateSpec {
                request_signing_rotation: Some(RequestSigningRotation {
                    old_kid: "#root".to_string(),
                    new_fragment: "new-root".to_string(),
                }),
                device_mutations: Vec::new(),
                services: None,
            })
            .err(),
        Some(DidError::UnsupportedOperation)
    );
    assert_eq!(
        identity
            .prepare_update(DocumentUpdateSpec {
                request_signing_rotation: Some(RequestSigningRotation {
                    old_kid: "#e2ee-signing".to_string(),
                    new_fragment: "wrong-role".to_string(),
                }),
                device_mutations: Vec::new(),
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
fn lifecycle_adds_and_removes_an_external_device_as_one_published_revision() {
    let root = tempfile::tempdir().unwrap();
    let mut store = DidStore::initialize_injected(root.path(), "host", [35_u8; 32]).unwrap();
    let mut identity = store.create_identity(spec("device-mutation")).unwrap();
    let signing = ManagedPrivateKey::generate("peer-sign".to_string(), KeyRole::DeviceSigning);
    let agreement = ManagedPrivateKey::generate("peer-e2ee".to_string(), KeyRole::E2eeAgreement);
    let signing_kid = format!("{}#peer-sign", identity.did());
    let e2ee_kid = format!("{}#peer-e2ee", identity.did());

    let added = identity
        .prepare_update(DocumentUpdateSpec {
            request_signing_rotation: None,
            device_mutations: vec![DeviceMutationSpec::Add {
                device: DeviceAddSpec {
                    device_id: "peer-device".to_string(),
                    signing_key: DevicePublicKeySpec {
                        kid: signing_kid.clone(),
                        public_key_multibase: crate::document::public_key_multibase(
                            &signing.public_key(),
                        )
                        .unwrap(),
                    },
                    e2ee_key: DevicePublicKeySpec {
                        kid: e2ee_kid.clone(),
                        public_key_multibase: crate::document::public_key_multibase(
                            &agreement.public_key(),
                        )
                        .unwrap(),
                    },
                    profiles: vec!["anp.core.binding.v1".to_string()],
                },
            }],
            services: None,
        })
        .unwrap();
    assert!(
        anp::authentication::validate_device_manifest(&added.candidate_document)
            .unwrap()
            .is_some()
    );
    assert!(anp::authentication::is_authentication_authorized(
        &added.candidate_document,
        &signing_kid,
    ));
    assert!(anp::authentication::is_assertion_method_authorized(
        &added.candidate_document,
        &signing_kid,
    ));
    identity.begin_publication(&added.revision_id).unwrap();
    identity.mark_published(&added.revision_id).unwrap();
    identity.commit_update(&added.revision_id).unwrap();
    assert_eq!(
        identity.key_metadata(&signing_kid).unwrap().origin,
        KeyOrigin::External
    );
    assert_eq!(
        identity.sign_device_assertion(&signing_kid, b"external"),
        Err(DidError::ExternalKeyOperation)
    );

    let removed = identity
        .prepare_update(DocumentUpdateSpec {
            request_signing_rotation: None,
            device_mutations: vec![DeviceMutationSpec::Remove {
                device_id: "peer-device".to_string(),
            }],
            services: None,
        })
        .unwrap();
    assert!(
        anp::authentication::validate_device_manifest(&removed.candidate_document)
            .unwrap()
            .is_none()
    );
    identity.begin_publication(&removed.revision_id).unwrap();
    identity.mark_published(&removed.revision_id).unwrap();
    identity.commit_update(&removed.revision_id).unwrap();
    assert_eq!(
        identity.key_metadata(&signing_kid).unwrap().state,
        KeyState::Retired
    );
    assert_eq!(
        identity.key_metadata(&e2ee_kid).unwrap().state,
        KeyState::Retired
    );
}

#[test]
fn lifecycle_crypto_erasure_converges_when_the_secret_is_already_absent() {
    let root = tempfile::tempdir().unwrap();
    let mut store = DidStore::initialize_injected(root.path(), "host", [38_u8; 32]).unwrap();
    let mut identity = store.create_identity(spec("erasure-retry")).unwrap();
    let prepared = identity.prepare_update(update("request-v2")).unwrap();
    identity.begin_publication(&prepared.revision_id).unwrap();
    identity.mark_published(&prepared.revision_id).unwrap();
    identity.commit_update(&prepared.revision_id).unwrap();
    identity.end_retirement("#request").unwrap();

    let metadata = identity.key_metadata("#request").unwrap();
    let secret_ref = SecretRef {
        identity_id: identity.identity_id().to_string(),
        key_id: metadata.kid.clone(),
        role: metadata.role,
        version: metadata.version,
    };
    let guard = identity.runtime().acquire_write().unwrap();
    identity
        .runtime()
        .key_store()
        .delete(&guard, &secret_ref)
        .unwrap();
    drop(guard);

    identity.delete_revoked_key("#request").unwrap();
    assert!(identity.key_metadata("#request").unwrap().material_erased);
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
        request_signing_rotation: Some(RequestSigningRotation {
            old_kid: "#request".to_string(),
            new_fragment: new_fragment.to_string(),
        }),
        device_mutations: Vec::new(),
        services: Some(vec![ServiceSpec {
            id: "message-v2".to_string(),
            service_type: "ANPMessageService".to_string(),
            service_endpoint: "https://example.com/im/v2".to_string(),
            service_did: None,
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
            service_did: None,
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
