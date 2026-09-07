use super::*;

fn fixture() -> (tempfile::TempDir, DidStore, DidIdentity) {
    let root = tempfile::tempdir().unwrap();
    let mut store = DidStore::initialize_injected(root.path(), "initial", [81; 32]).unwrap();
    let identity = store
        .create_identity(crate::DidCreateSpec {
            profile: crate::DidProfile::E1,
            domain: "example.com".into(),
            port: None,
            path_segments: vec!["users".into(), "initial".into()],
            capabilities: Capabilities { did_wba: true },
            managed_keys: vec![
                crate::ManagedKeySpec {
                    fragment: "root".into(),
                    role: KeyRole::RootControl,
                },
                crate::ManagedKeySpec {
                    fragment: "request".into(),
                    role: KeyRole::RequestSigning,
                },
            ],
            external_keys: vec![],
            services: vec![],
            agent_description_url: None,
            extensions: vec![],
        })
        .unwrap();
    (root, store, identity)
}

fn reproof(identity: &DidIdentity, mut document: Value, challenge: &str) -> Value {
    document.as_object_mut().unwrap().remove("proof");
    identity
        .sign_document_proof(
            &document,
            &format!("{}#root", identity.did()),
            ProofGenerationOptions {
                proof_purpose: Some("assertionMethod".into()),
                proof_type: Some(PROOF_TYPE_DATA_INTEGRITY.into()),
                cryptosuite: Some(CRYPTOSUITE_EDDSA_JCS_2022.into()),
                domain: Some("example.com".into()),
                challenge: Some(challenge.into()),
                ..ProofGenerationOptions::default()
            },
        )
        .unwrap()
}

fn confirmation(document: Value) -> AdoptVerifiedDocumentSpec {
    AdoptVerifiedDocumentSpec {
        evidence: evidence(&document, 1, 1),
        document,
    }
}

#[test]
fn initial_confirmation_survives_reopen_and_consumes_proof_refresh_authority() {
    let (_root, store, identity) = fixture();
    let before = identity.document().clone();
    let refreshed = reproof(&identity, before.clone(), "first-publication");
    assert_ne!(
        canonical_document_digest(&before),
        canonical_document_digest(&refreshed)
    );
    let mut reopened = store.open_identity(identity.did()).unwrap();
    assert_eq!(
        reopened
            .adopt_verified_document(confirmation(refreshed.clone()))
            .unwrap(),
        AdoptDocumentOutcome::Updated
    );
    let mut reopened = store.open_identity(identity.did()).unwrap();
    assert!(!reopened.record().initial_publication_pending);
    assert_eq!(reopened.document(), &refreshed);
    assert_eq!(
        reopened
            .adopt_verified_document(confirmation(refreshed.clone()))
            .unwrap(),
        AdoptDocumentOutcome::Unchanged
    );
    let another = reproof(&reopened, refreshed.clone(), "second-publication");
    assert_eq!(
        reopened.adopt_verified_document(confirmation(another)),
        Err(DidError::Conflict)
    );
    assert_eq!(
        reopened.adopt_verified_document(confirmation(before)),
        Err(DidError::Conflict)
    );
    assert_eq!(reopened.document(), &refreshed);
}

#[test]
fn identical_first_confirmation_also_consumes_authority_and_rejects_stale_writer() {
    let (_root, store, mut identity) = fixture();
    let mut stale = store.open_identity(identity.did()).unwrap();
    let original = identity.document().clone();
    assert_eq!(
        identity
            .adopt_verified_document(confirmation(original.clone()))
            .unwrap(),
        AdoptDocumentOutcome::Unchanged
    );
    let next = reproof(&identity, original, "late-refresh");
    assert_eq!(
        stale.adopt_verified_document(confirmation(next.clone())),
        Err(DidError::Conflict)
    );
    let mut reopened = store.open_identity(identity.did()).unwrap();
    assert_eq!(
        reopened.adopt_verified_document(confirmation(next)),
        Err(DidError::Conflict)
    );
}

#[test]
fn initial_confirmation_rejects_intent_changes_invalid_proofs_and_noninitial_versions() {
    let (_root, _store, mut identity) = fixture();
    let original = identity.document().clone();
    let mut changed = original.clone();
    changed["service"] = json!([{"id": "#unexpected", "type": "Example", "serviceEndpoint": "https://example.com/new"}]);
    let changed = reproof(&identity, changed, "changed-intent");
    assert!(identity
        .adopt_verified_document(confirmation(changed))
        .is_err());
    let refreshed = reproof(&identity, original.clone(), "valid-first");
    let mut invalid = refreshed.clone();
    invalid["proof"]["proofValue"] = json!("invalid");
    assert!(identity
        .adopt_verified_document(confirmation(invalid))
        .is_err());
    let mut wrong = confirmation(refreshed.clone());
    wrong.evidence.registry_version = 2;
    assert_eq!(
        identity.adopt_verified_document(wrong),
        Err(DidError::Conflict)
    );
    let mut wrong = confirmation(refreshed.clone());
    wrong.evidence.document_version = 0;
    assert!(identity.adopt_verified_document(wrong).is_err());
    assert_eq!(identity.document(), &original);
    assert!(identity.record().initial_publication_pending);
    identity
        .adopt_verified_document(confirmation(refreshed))
        .unwrap();
}

#[test]
fn legacy_missing_publication_marker_remains_strict() {
    let (_root, store, identity) = fixture();
    let mut serialized = serde_json::to_value(identity.record()).unwrap();
    serialized
        .as_object_mut()
        .unwrap()
        .remove("initial_publication_pending");
    let legacy: IdentityRecord = serde_json::from_value(serialized).unwrap();
    assert!(!legacy.initial_publication_pending);
    let guard = identity.runtime().acquire_write().unwrap();
    write_identity(identity.runtime().root(), &guard, &legacy).unwrap();
    drop(guard);
    let mut reopened = store.open_identity(identity.did()).unwrap();
    let refreshed = reproof(&reopened, reopened.document().clone(), "legacy-refresh");
    assert_eq!(
        reopened.adopt_verified_document(confirmation(refreshed)),
        Err(DidError::Conflict)
    );
}
