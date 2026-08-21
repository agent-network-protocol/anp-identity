use anp::authentication::{create_did_wba_document, DidDocumentOptions, DEVICE_MANIFEST_TYPE};
use anp::proof::{
    generate_w3c_proof, ProofGenerationOptions, CRYPTOSUITE_EDDSA_JCS_2022,
    PROOF_TYPE_DATA_INTEGRITY,
};
use serde_json::{json, Value};

use super::*;

#[test]
fn enrollment_adopts_verified_device_then_revokes_when_remote_document_removes_it() {
    let bundle = create_did_wba_document(
        "example.com",
        DidDocumentOptions {
            path_segments: vec!["users".to_string(), "alice".to_string()],
            ..DidDocumentOptions::default()
        },
    )
    .unwrap();
    let current = bundle.did_document.clone();
    let current_evidence = evidence(&current, 1, 1);
    let root = tempfile::tempdir().unwrap();
    let mut store = DidStore::initialize_injected(root.path(), "host", [71_u8; 32]).unwrap();

    let (mut identity, prepared) = store
        .prepare_enrollment(EnrollmentSpec {
            verified_document: current,
            evidence: current_evidence,
            device_id: "device-new".to_string(),
            device_signing_fragment: "device-new-sign".to_string(),
            device_e2ee_fragment: "device-new-e2ee".to_string(),
            profiles: vec!["anp.core.binding.v1".to_string()],
            capabilities: Capabilities { did_wba: true },
        })
        .unwrap();

    assert_eq!(identity.state(), IdentityState::Enrolling);
    assert_eq!(identity.root_capability(), RootCapabilityState::Absent);
    assert_eq!(
        prepared.root_key_fingerprint,
        identity.root_key_fingerprint()
    );
    assert_eq!(prepared.checkpoint, *identity.checkpoint().unwrap());
    let public_json = serde_json::to_string(&prepared).unwrap();
    for forbidden in ["private", "secret", "-----BEGIN", "\"d\""] {
        assert!(!public_json.contains(forbidden));
    }
    assert_eq!(
        identity.sign_device_assertion(&prepared.device_signing_key.kid, b"pending"),
        Err(DidError::KeyNotUsable)
    );

    let accepted = signed_device_document(&bundle, &prepared, true);
    assert!(anp::authentication::validate_did_document_binding(
        &accepted, true
    ));
    assert!(anp::authentication::validate_device_manifest(&accepted).is_ok());
    let accepted_evidence = evidence(&accepted, 2, 2);
    assert_eq!(
        identity
            .adopt_verified_document(AdoptVerifiedDocumentSpec {
                document: accepted.clone(),
                evidence: accepted_evidence.clone(),
            })
            .unwrap(),
        AdoptDocumentOutcome::Activated
    );
    assert_eq!(identity.state(), IdentityState::Active);
    identity
        .sign_device_assertion(&prepared.device_signing_key.kid, b"active")
        .unwrap();
    identity
        .http_signature_headers_with_options(
            &prepared.device_signing_key.kid,
            "https://example.com/im",
            "POST",
            None,
            None,
            crate::HttpSignatureOptions::default(),
        )
        .unwrap();
    let peer = x25519_dalek::StaticSecret::from([19_u8; 32]);
    identity
        .ecdh(
            &prepared.device_e2ee_key.kid,
            &x25519_dalek::PublicKey::from(&peer).to_bytes(),
        )
        .unwrap();
    assert_eq!(
        identity
            .adopt_verified_document(AdoptVerifiedDocumentSpec {
                document: accepted.clone(),
                evidence: accepted_evidence,
            })
            .unwrap(),
        AdoptDocumentOutcome::Unchanged
    );
    assert_eq!(
        identity
            .adopt_verified_document(AdoptVerifiedDocumentSpec {
                document: accepted.clone(),
                evidence: evidence(&accepted, 2, 3),
            })
            .unwrap(),
        AdoptDocumentOutcome::Unchanged
    );
    assert_eq!(identity.checkpoint().unwrap().registry_version, 3);

    let removed = signed_device_document(&bundle, &prepared, false);
    assert_eq!(
        identity
            .adopt_verified_document(AdoptVerifiedDocumentSpec {
                document: removed.clone(),
                evidence: evidence(&removed, 3, 4),
            })
            .unwrap(),
        AdoptDocumentOutcome::Revoked
    );
    assert_eq!(identity.state(), IdentityState::Revoked);
    assert_eq!(
        identity.sign(&prepared.device_signing_key.kid, b"revoked"),
        Err(DidError::KeyNotUsable)
    );
    assert_eq!(
        identity
            .ecdh(
                &prepared.device_e2ee_key.kid,
                &x25519_dalek::PublicKey::from(&peer).to_bytes(),
            )
            .err(),
        Some(DidError::KeyNotUsable)
    );

    store.reload().unwrap();
    let reopened = store.open_identity(&prepared.did).unwrap();
    assert_eq!(reopened.state(), IdentityState::Revoked);
    assert_eq!(reopened.root_capability(), RootCapabilityState::Absent);
}

#[test]
fn adoption_rejects_stale_checkpoint_and_wrong_digest() {
    let bundle = create_did_wba_document(
        "example.com",
        DidDocumentOptions {
            path_segments: vec!["users".to_string(), "bob".to_string()],
            ..DidDocumentOptions::default()
        },
    )
    .unwrap();
    let current = bundle.did_document.clone();
    let root = tempfile::tempdir().unwrap();
    let mut store = DidStore::initialize_injected(root.path(), "host", [72_u8; 32]).unwrap();
    let (mut identity, prepared) = store
        .prepare_enrollment(EnrollmentSpec {
            verified_document: current.clone(),
            evidence: evidence(&current, 5, 7),
            device_id: "device-bob".to_string(),
            device_signing_fragment: "device-bob-sign".to_string(),
            device_e2ee_fragment: "device-bob-e2ee".to_string(),
            profiles: vec!["anp.core.binding.v1".to_string()],
            capabilities: Capabilities { did_wba: true },
        })
        .unwrap();
    let accepted = signed_device_document(&bundle, &prepared, true);

    let mut wrong_digest = evidence(&accepted, 6, 8);
    wrong_digest.document_digest = "sha256:wrong".to_string();
    assert_eq!(
        identity.adopt_verified_document(AdoptVerifiedDocumentSpec {
            document: accepted.clone(),
            evidence: wrong_digest,
        }),
        Err(DidError::InvalidIdentity)
    );
    assert_eq!(
        identity.adopt_verified_document(AdoptVerifiedDocumentSpec {
            document: accepted.clone(),
            evidence: evidence(&accepted, 4, 8),
        }),
        Err(DidError::Conflict)
    );
}

#[test]
fn adoption_rejects_a_local_pending_revision() {
    let root = tempfile::tempdir().unwrap();
    let mut store = DidStore::initialize_injected(root.path(), "host", [73_u8; 32]).unwrap();
    let mut identity = store
        .create_identity(crate::DidCreateSpec {
            profile: crate::DidProfile::E1,
            domain: "example.com".to_string(),
            port: None,
            path_segments: vec!["users".to_string(), "carol".to_string()],
            capabilities: Capabilities { did_wba: true },
            managed_keys: vec![
                crate::ManagedKeySpec {
                    fragment: "root".to_string(),
                    role: KeyRole::RootControl,
                },
                crate::ManagedKeySpec {
                    fragment: "request".to_string(),
                    role: KeyRole::RequestSigning,
                },
            ],
            external_keys: Vec::new(),
            services: Vec::new(),
            agent_description_url: None,
            extensions: Vec::new(),
        })
        .unwrap();
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
    let document = identity.document().clone();

    assert_eq!(
        identity.adopt_verified_document(AdoptVerifiedDocumentSpec {
            document: document.clone(),
            evidence: evidence(&document, 2, 2),
        }),
        Err(DidError::PendingRevisionExists)
    );
}

#[test]
fn request_signing_enrollment_is_authentication_only_and_revokes_on_relationship_drift() {
    let bundle = create_did_wba_document(
        "example.com",
        DidDocumentOptions {
            path_segments: vec!["daemons".to_string(), "alice".to_string()],
            ..DidDocumentOptions::default()
        },
    )
    .unwrap();
    let current = bundle.did_document.clone();
    let root = tempfile::tempdir().unwrap();
    let mut store = DidStore::initialize_injected(root.path(), "daemon", [75_u8; 32]).unwrap();
    let (mut identity, prepared) = store
        .prepare_request_signing_enrollment(RequestSigningEnrollmentSpec {
            verified_document: current.clone(),
            evidence: evidence(&current, 1, 1),
            fragment: "daemon-key-1".to_string(),
            capabilities: Capabilities { did_wba: true },
        })
        .unwrap();
    assert_eq!(identity.state(), IdentityState::Enrolling);
    assert_eq!(identity.keys().len(), 2);
    let accepted = signed_request_document(&bundle, &prepared, false);
    assert_eq!(
        identity
            .adopt_verified_document(AdoptVerifiedDocumentSpec {
                document: accepted.clone(),
                evidence: evidence(&accepted, 2, 2),
            })
            .unwrap(),
        AdoptDocumentOutcome::Activated
    );
    identity
        .legacy_did_wba_header(&prepared.request_signing_key.kid, "api.example.com", "1.1")
        .unwrap();
    assert_eq!(
        identity.sign_object_proof(
            &prepared.request_signing_key.kid,
            &json!({"operation": "forbidden"}),
            identity.did(),
            None,
        ),
        Err(DidError::KeyRoleViolation)
    );

    let drifted = signed_request_document(&bundle, &prepared, true);
    assert_eq!(
        identity
            .adopt_verified_document(AdoptVerifiedDocumentSpec {
                document: drifted.clone(),
                evidence: evidence(&drifted, 3, 3),
            })
            .unwrap(),
        AdoptDocumentOutcome::Revoked
    );
    assert_eq!(identity.state(), IdentityState::Revoked);
}

#[test]
fn state_transition_journal_repairs_registry_after_identity_commit_crash() {
    let bundle = create_did_wba_document(
        "example.com",
        DidDocumentOptions {
            path_segments: vec!["users".to_string(), "journal".to_string()],
            ..DidDocumentOptions::default()
        },
    )
    .unwrap();
    let current = bundle.did_document.clone();
    let root = tempfile::tempdir().unwrap();
    let mut store = DidStore::initialize_injected(root.path(), "host", [74_u8; 32]).unwrap();
    let (identity, prepared) = store
        .prepare_enrollment(EnrollmentSpec {
            verified_document: current.clone(),
            evidence: evidence(&current, 1, 1),
            device_id: "device-journal".to_string(),
            device_signing_fragment: "device-journal-sign".to_string(),
            device_e2ee_fragment: "device-journal-e2ee".to_string(),
            profiles: vec!["anp.core.binding.v1".to_string()],
            capabilities: Capabilities { did_wba: true },
        })
        .unwrap();

    let guard = identity.runtime().acquire_write().unwrap();
    let mut record =
        crate::registry::read_identity(identity.runtime().root(), identity.identity_id()).unwrap();
    record.state = IdentityState::Revoked;
    record.generation += 1;
    let journal = crate::registry::CreationJournal::new_state_transition(
        crate::identity::random_id(),
        record.identity_id.clone(),
        record.did.clone(),
        chrono::Utc::now().to_rfc3339(),
    );
    crate::registry::write_journal(identity.runtime().root(), &guard, &journal).unwrap();
    crate::registry::write_identity(identity.runtime().root(), &guard, &record).unwrap();
    drop(guard);
    drop(identity);
    drop(store);

    let reopened = DidStore::open_injected(root.path(), "host", [74_u8; 32]).unwrap();
    assert_eq!(
        reopened.open_identity(&prepared.did).unwrap().state(),
        IdentityState::Revoked
    );
}

fn signed_device_document(
    bundle: &anp::authentication::DidDocumentBundle,
    prepared: &PreparedEnrollment,
    include_device: bool,
) -> Value {
    let mut document = bundle.did_document.clone();
    document.as_object_mut().unwrap().remove("proof");
    if include_device {
        document["verificationMethod"]
            .as_array_mut()
            .unwrap()
            .extend([
                json!({
                    "id": prepared.device_signing_key.kid,
                    "type": "Multikey",
                    "controller": prepared.did,
                    "publicKeyMultibase": prepared.device_signing_key.public_key_multibase,
                }),
                json!({
                    "id": prepared.device_e2ee_key.kid,
                    "type": "X25519KeyAgreementKey2019",
                    "controller": prepared.did,
                    "publicKeyMultibase": prepared.device_e2ee_key.public_key_multibase,
                }),
            ]);
        document["authentication"]
            .as_array_mut()
            .unwrap()
            .push(Value::String(prepared.device_signing_key.kid.clone()));
        document["assertionMethod"]
            .as_array_mut()
            .unwrap()
            .push(Value::String(prepared.device_signing_key.kid.clone()));
        document["keyAgreement"]
            .as_array_mut()
            .unwrap()
            .push(Value::String(prepared.device_e2ee_key.kid.clone()));
        document["deviceManifest"] = json!({
            "type": DEVICE_MANIFEST_TYPE,
            "devices": [{
                "device_id": prepared.device_id,
                "signing_key_id": prepared.device_signing_key.kid,
                "e2ee_key_id": prepared.device_e2ee_key.kid,
                "profiles": prepared.profiles,
            }],
        });
    }
    let root_kid = bundle.did_document["proof"]["verificationMethod"]
        .as_str()
        .unwrap();
    generate_w3c_proof(
        &document,
        &bundle.load_private_key("key-1").unwrap(),
        root_kid,
        ProofGenerationOptions {
            proof_purpose: Some("assertionMethod".to_string()),
            proof_type: Some(PROOF_TYPE_DATA_INTEGRITY.to_string()),
            cryptosuite: Some(CRYPTOSUITE_EDDSA_JCS_2022.to_string()),
            domain: Some("example.com".to_string()),
            challenge: Some("adoption-test".to_string()),
            ..ProofGenerationOptions::default()
        },
    )
    .unwrap()
}

fn signed_request_document(
    bundle: &anp::authentication::DidDocumentBundle,
    prepared: &PreparedRequestSigningEnrollment,
    include_assertion: bool,
) -> Value {
    let mut document = bundle.did_document.clone();
    document.as_object_mut().unwrap().remove("proof");
    document["verificationMethod"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id": prepared.request_signing_key.kid,
            "type": "Multikey",
            "controller": prepared.did,
            "publicKeyMultibase": prepared.request_signing_key.public_key_multibase,
        }));
    document["authentication"]
        .as_array_mut()
        .unwrap()
        .push(Value::String(prepared.request_signing_key.kid.clone()));
    if include_assertion {
        document["assertionMethod"]
            .as_array_mut()
            .unwrap()
            .push(Value::String(prepared.request_signing_key.kid.clone()));
    }
    let root_kid = bundle.did_document["proof"]["verificationMethod"]
        .as_str()
        .unwrap();
    generate_w3c_proof(
        &document,
        &bundle.load_private_key("key-1").unwrap(),
        root_kid,
        ProofGenerationOptions {
            proof_purpose: Some("assertionMethod".to_string()),
            proof_type: Some(PROOF_TYPE_DATA_INTEGRITY.to_string()),
            cryptosuite: Some(CRYPTOSUITE_EDDSA_JCS_2022.to_string()),
            domain: Some("example.com".to_string()),
            challenge: Some("request-enrollment-test".to_string()),
            ..ProofGenerationOptions::default()
        },
    )
    .unwrap()
}

fn evidence(
    document: &Value,
    document_version: u64,
    registry_version: u64,
) -> VerifiedDocumentEvidence {
    VerifiedDocumentEvidence {
        document_version,
        registry_version,
        document_digest: canonical_document_digest(document).unwrap(),
    }
}
