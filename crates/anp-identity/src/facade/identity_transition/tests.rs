use super::*;
use crate::facade::{IdentityManagerConfig, InjectedStoreKey, RootKeySource};
use crate::{
    Capabilities, DidCreateSpec, DidProfile, ExternalPublicKeyMaterial, ExternalPublicKeySpec,
    KeyRole, ManagedKeySpec,
};
use anp::authentication::{resolve_current_did, InMemoryTransitionCache, TransitionStatus};
use ed25519_dalek::{Signer, SigningKey};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn identity_transition_shared_resolver_contract_precedes_local_session() {
    let fixture_root =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../anp/anp/testdata/did_transition");
    let suite: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture_root.join("transition_vectors.json")).unwrap())
            .unwrap();
    let case = suite["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["id"] == "old-binding-verified")
        .unwrap();
    let resolved = load_fixture_map(&fixture_root, &case["resolvedDocuments"]);
    let trusted = load_fixture_map(&fixture_root, &case["trustedDocuments"]);
    let fetch = |did: &str| {
        resolved
            .get(did)
            .cloned()
            .ok_or_else(|| format!("missing resolved document {did}"))
    };
    let mut cache = InMemoryTransitionCache::new(HashMap::new());
    let result = resolve_current_did(
        case["requestedDid"].as_str().unwrap(),
        &fetch,
        &trusted,
        None,
        &mut cache,
        case["maxHops"].as_u64().unwrap() as usize,
    )
    .unwrap();
    assert_eq!(result.status, TransitionStatus::Superseded);
    assert_eq!(result.hops.len(), 1);
    assert_eq!(result.hops[0].assurance, TransitionAssurance::Verified);

    let root = tempfile::tempdir().unwrap();
    let (mut manager, predecessor, successor) = identities(root.path(), [0x90; 32]);
    let session = manager
        .prepare_identity_transition(request(
            &predecessor,
            &successor,
            "transition-shared-vector-handoff",
        ))
        .unwrap();
    assert_eq!(session.candidate().assurance, "verified");
}

fn load_fixture_map(
    root: &Path,
    entries: &serde_json::Value,
) -> HashMap<String, serde_json::Value> {
    entries
        .as_object()
        .unwrap()
        .iter()
        .map(|(did, relative)| {
            let path = PathBuf::from(relative.as_str().unwrap());
            let document = serde_json::from_slice(&fs::read(root.join(path)).unwrap()).unwrap();
            (did.clone(), document)
        })
        .collect()
}

#[test]
fn identity_transition_confirmed_path_and_operation_replay_are_stable() {
    let root = tempfile::tempdir().unwrap();
    let (mut manager, predecessor, successor) = identities(root.path(), [0x91; 32]);
    let transition_request = request(&predecessor, &successor, "transition-confirmed");
    let mut session = manager
        .prepare_identity_transition(transition_request.clone())
        .unwrap();
    let candidate = session.candidate().clone();
    assert_eq!(candidate.assurance, "verified");
    assert_eq!(candidate.expected_current_did, predecessor.did);
    assert_eq!(candidate.successor_did, successor.did);
    assert_eq!(
        candidate.predecessor_document.as_value()["successorDid"],
        successor.did
    );
    assert_eq!(
        candidate.predecessor_document.as_value()["deactivated"],
        true
    );

    let attempt = session.begin_publication().unwrap();
    assert_eq!(attempt.operation_id(), "transition-confirmed");
    assert_eq!(
        session
            .complete(
                attempt,
                IdentityTransitionPublicationResult::Confirmed {
                    evidence: evidence(&candidate),
                },
            )
            .unwrap(),
        IdentityTransitionOutcome::Committed {
            current_did: successor.did.clone(),
        }
    );
    assert!(manager
        .resume_identity_transition(&predecessor.did)
        .unwrap()
        .is_none());

    let replay = manager
        .prepare_identity_transition(transition_request)
        .unwrap();
    assert_eq!(replay.candidate(), &candidate);
    let alternative = manager
        .create_engine_for_test(spec("alice"))
        .unwrap()
        .reference();
    assert_eq!(
        manager
            .prepare_identity_transition(request(
                &predecessor,
                &alternative,
                "transition-after-commit-fork",
            ))
            .err(),
        Some(IdentityError::Conflict)
    );
}

#[test]
fn identity_transition_rejects_forks_stale_sessions_and_path_mismatch() {
    let root = tempfile::tempdir().unwrap();
    let (mut manager, predecessor, successor) = identities(root.path(), [0x92; 32]);
    let second_successor = manager
        .create_engine_for_test(spec("alice"))
        .unwrap()
        .reference();
    let mut first = manager
        .prepare_identity_transition(request(&predecessor, &successor, "transition-cas"))
        .unwrap();
    let mut stale = manager
        .prepare_identity_transition(request(&predecessor, &successor, "transition-cas"))
        .unwrap();
    assert_eq!(
        manager
            .prepare_identity_transition(request(
                &predecessor,
                &second_successor,
                "transition-fork",
            ))
            .err(),
        Some(IdentityError::Conflict)
    );
    first.begin_publication().unwrap();
    assert_eq!(
        stale.begin_publication().err(),
        Some(IdentityError::Conflict)
    );

    let isolated_root = tempfile::tempdir().unwrap();
    let mut isolated =
        IdentityManager::initialize(config(isolated_root.path(), [0x93; 32])).unwrap();
    let isolated_predecessor = isolated
        .create_engine_for_test(spec("alice"))
        .unwrap()
        .reference();
    let different_path = isolated
        .create_engine_for_test(spec("bob"))
        .unwrap()
        .reference();
    assert_eq!(
        isolated
            .prepare_identity_transition(IdentityTransitionRequest {
                expected_current_did: isolated_predecessor.did,
                operation_id: "transition-path-mismatch".to_string(),
                successor: different_path,
                transition_document: None,
            })
            .err(),
        Some(IdentityError::InvalidRequest)
    );
}

#[test]
fn identity_transition_resumes_each_publication_boundary_and_reconciles_response_loss() {
    let root = tempfile::tempdir().unwrap();
    let (mut manager, predecessor, successor) = identities(root.path(), [0x94; 32]);
    let request = request(&predecessor, &successor, "transition-resume");
    let prepared = manager.prepare_identity_transition(request).unwrap();
    let candidate = prepared.candidate().clone();
    drop(prepared);
    drop(manager);

    let mut manager = IdentityManager::open(config(root.path(), [0x94; 32])).unwrap();
    let mut in_flight = manager
        .resume_identity_transition(&predecessor.did)
        .unwrap()
        .unwrap();
    assert_eq!(in_flight.candidate(), &candidate);
    let attempt = in_flight.begin_publication().unwrap();
    drop(in_flight);
    drop(manager);

    let mut manager = IdentityManager::open(config(root.path(), [0x94; 32])).unwrap();
    let mut uncertain = manager
        .resume_identity_transition(&predecessor.did)
        .unwrap()
        .unwrap();
    let resumed_attempt = uncertain.begin_publication().unwrap();
    assert_eq!(attempt.operation_id(), resumed_attempt.operation_id());
    assert_eq!(
        uncertain
            .complete(
                resumed_attempt.clone(),
                IdentityTransitionPublicationResult::Unknown,
            )
            .unwrap(),
        IdentityTransitionOutcome::PublicationUncertain
    );
    assert_eq!(
        uncertain
            .complete(
                resumed_attempt,
                IdentityTransitionPublicationResult::RejectedBeforeAcceptance,
            )
            .err(),
        Some(IdentityError::Conflict)
    );
    assert_eq!(
        uncertain
            .reconcile(IdentityTransitionRemoteObservation::RemoteOld {
                current_document: DidDocument::from_value(
                    manager
                        .get(&predecessor)
                        .unwrap()
                        .public_identity()
                        .unwrap()
                        .document
                        .into_value(),
                ),
            })
            .unwrap(),
        IdentityTransitionOutcome::ReadyForPublication
    );
    let retry = uncertain.begin_publication().unwrap();
    uncertain
        .complete(retry, IdentityTransitionPublicationResult::Unknown)
        .unwrap();
    drop(uncertain);
    drop(manager);

    let mut manager = IdentityManager::open(config(root.path(), [0x94; 32])).unwrap();
    let mut recovered = manager
        .resume_identity_transition(&predecessor.did)
        .unwrap()
        .unwrap();
    assert_eq!(
        recovered
            .reconcile(IdentityTransitionRemoteObservation::Published {
                predecessor_document: candidate.predecessor_document.clone(),
                successor_document: candidate.successor_document.clone(),
            })
            .unwrap(),
        IdentityTransitionOutcome::Committed {
            current_did: successor.did,
        }
    );
}

#[test]
fn transition_public_values_serialize_without_private_material() {
    let root = tempfile::tempdir().unwrap();
    let (mut manager, predecessor, successor) = identities(root.path(), [0x95; 32]);
    let session = manager
        .prepare_identity_transition(request(
            &predecessor,
            &successor,
            "transition-public-boundary",
        ))
        .unwrap();
    let serialized = serde_json::to_string(session.candidate()).unwrap();
    let debugged = format!("{:?}", session.candidate());
    for output in [serialized, debugged] {
        let lower = output.to_ascii_lowercase();
        assert!(!lower.contains("private"));
        assert!(!lower.contains("secret"));
        assert!(!lower.contains("begin private key"));
    }
}

#[test]
fn identity_transition_preserves_recovery_and_unverified_assurance() {
    let recovery_key = SigningKey::from_bytes(&[0x31; 32]);
    let recovery_root = tempfile::tempdir().unwrap();
    let mut recovery_manager =
        IdentityManager::initialize(config(recovery_root.path(), [0x96; 32])).unwrap();
    let recovery_public = multibase(&recovery_key);
    let predecessor = recovery_manager
        .create_engine_for_test(spec_with_assertion_method_external_key(
            "alice",
            "recovery",
            &recovery_public,
        ))
        .unwrap()
        .reference();
    let successor = recovery_manager
        .create_engine_for_test(spec_with_assertion_method_external_key(
            "alice",
            "recovery",
            &recovery_public,
        ))
        .unwrap()
        .reference();
    let trusted = recovery_manager
        .get(&predecessor)
        .unwrap()
        .public_identity()
        .unwrap()
        .document;
    let recovery_document = signed_transition(
        trusted.as_value(),
        &successor.did,
        &format!("{}#recovery", predecessor.did),
        &recovery_key,
    );
    let mut recovery_request = request(&predecessor, &successor, "transition-recovery");
    recovery_request.transition_document = Some(DidDocument::from_value(recovery_document));
    assert_assurance_survives_response_loss(
        recovery_manager
            .prepare_identity_transition(recovery_request)
            .unwrap(),
        "recovery_verified",
    );

    let unverified_root = tempfile::tempdir().unwrap();
    let (mut unverified_manager, predecessor, successor) =
        identities(unverified_root.path(), [0x98; 32]);
    let trusted = unverified_manager
        .get(&predecessor)
        .unwrap()
        .public_identity()
        .unwrap()
        .document;
    let mut unverified_request = request(&predecessor, &successor, "transition-unverified");
    unverified_request.transition_document = Some(DidDocument::from_value(unsigned_transition(
        trusted.as_value(),
        &successor.did,
    )));
    assert_assurance_survives_response_loss(
        unverified_manager
            .prepare_identity_transition(unverified_request)
            .unwrap(),
        "unverified",
    );
}

fn assert_assurance_survives_response_loss(
    mut session: IdentityTransitionSession,
    expected_assurance: &str,
) {
    let candidate = session.candidate().clone();
    assert_eq!(candidate.assurance, expected_assurance);
    let attempt = session.begin_publication().unwrap();
    assert_eq!(
        session
            .complete(attempt, IdentityTransitionPublicationResult::Unknown)
            .unwrap(),
        IdentityTransitionOutcome::PublicationUncertain
    );
    assert_eq!(
        session
            .reconcile(IdentityTransitionRemoteObservation::Published {
                predecessor_document: candidate.predecessor_document,
                successor_document: candidate.successor_document,
            })
            .unwrap(),
        IdentityTransitionOutcome::Committed {
            current_did: candidate.successor_did,
        }
    );
}

fn identities(
    root: &std::path::Path,
    key: [u8; 32],
) -> (IdentityManager, IdentityRef, IdentityRef) {
    let mut manager = IdentityManager::initialize(config(root, key)).unwrap();
    let predecessor = manager
        .create_engine_for_test(spec("alice"))
        .unwrap()
        .reference();
    let successor = manager
        .create_engine_for_test(spec("alice"))
        .unwrap()
        .reference();
    (manager, predecessor, successor)
}

fn config(root: &std::path::Path, bytes: [u8; 32]) -> IdentityManagerConfig {
    IdentityManagerConfig {
        state_root: root.to_owned(),
        root_key: RootKeySource::Injected(InjectedStoreKey::new("transition-test", bytes)),
    }
}

fn spec(subject: &str) -> DidCreateSpec {
    DidCreateSpec {
        profile: DidProfile::E1,
        domain: "example.com".to_string(),
        port: None,
        path_segments: vec!["transition".to_string(), subject.to_string()],
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

fn spec_with_assertion_method_external_key(
    subject: &str,
    fragment: &str,
    public_key_multibase: &str,
) -> DidCreateSpec {
    let mut value = spec(subject);
    // E2eeSigning is used only to place this test key in assertionMethod. It does
    // not model a production recovery-key role or authorize E2EE key reuse.
    value.external_keys.push(ExternalPublicKeySpec {
        kid: format!("#{fragment}"),
        role: KeyRole::E2eeSigning,
        material: ExternalPublicKeyMaterial::Multibase {
            value: public_key_multibase.to_string(),
        },
    });
    value
}

fn request(
    predecessor: &IdentityRef,
    successor: &IdentityRef,
    operation_id: &str,
) -> IdentityTransitionRequest {
    IdentityTransitionRequest {
        expected_current_did: predecessor.did.clone(),
        operation_id: operation_id.to_string(),
        successor: successor.clone(),
        transition_document: None,
    }
}

fn evidence(candidate: &PreparedIdentityTransition) -> IdentityTransitionPublicationEvidence {
    IdentityTransitionPublicationEvidence {
        predecessor_digest: candidate.predecessor_digest.clone(),
        successor_digest: candidate.successor_digest.clone(),
    }
}

fn unsigned_transition(document: &serde_json::Value, successor_did: &str) -> serde_json::Value {
    let mut transition = document.clone();
    let object = transition.as_object_mut().unwrap();
    object.remove("proof");
    object.insert("deactivated".to_string(), serde_json::Value::Bool(true));
    object.insert(
        "successorDid".to_string(),
        serde_json::Value::String(successor_did.to_string()),
    );
    transition
}

fn signed_transition(
    document: &serde_json::Value,
    successor_did: &str,
    verification_method: &str,
    key: &SigningKey,
) -> serde_json::Value {
    sign_value(
        unsigned_transition(document, successor_did),
        verification_method,
        key,
    )
}

fn sign_value(
    document: serde_json::Value,
    verification_method: &str,
    key: &SigningKey,
) -> serde_json::Value {
    let public = anp::PublicKeyMaterial::Ed25519(key.verifying_key());
    let prepared = anp::proof::prepare_w3c_proof(
        &document,
        &public,
        verification_method,
        anp::proof::ProofGenerationOptions {
            proof_purpose: Some("assertionMethod".to_string()),
            proof_type: Some(anp::proof::PROOF_TYPE_DATA_INTEGRITY.to_string()),
            cryptosuite: Some(anp::proof::CRYPTOSUITE_EDDSA_JCS_2022.to_string()),
            created: Some("2026-08-25T00:00:00Z".to_string()),
            domain: None,
            challenge: None,
        },
    )
    .unwrap();
    let signature = key.sign(prepared.signing_input()).to_bytes();
    anp::proof::complete_w3c_proof(prepared, &signature).unwrap()
}

fn multibase(key: &SigningKey) -> String {
    let mut bytes = vec![0xed, 0x01];
    bytes.extend_from_slice(key.verifying_key().as_bytes());
    format!("z{}", bs58::encode(bytes).into_string())
}
