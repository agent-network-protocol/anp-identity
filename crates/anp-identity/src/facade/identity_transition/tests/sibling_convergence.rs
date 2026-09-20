use super::*;
use crate::host::{ConvergenceOutcome, ConvergenceWorkflow, IdentityStatusPort};
use crate::{VerifiedPublicationEvidence, VerifiedRemoteDocument};

fn remote(identity: &crate::ManagedIdentity) -> VerifiedRemoteDocument {
    let checkpoint = identity.host_status().unwrap().checkpoint.unwrap();
    VerifiedRemoteDocument {
        document: identity.public_identity().unwrap().document,
        evidence: VerifiedPublicationEvidence {
            document_version: checkpoint.document_version,
            registry_version: checkpoint.registry_version,
            document_digest: checkpoint.document_digest,
        },
    }
}

#[test]
fn sibling_adoption_rejects_transition_prepared_after_identity_open_without_mutation() {
    for phase in ["prepared", "in_flight", "uncertain"] {
        let root = tempfile::tempdir().unwrap();
        let (mut manager, predecessor, successor) = identities(root.path(), [0x93; 32]);
        // Open both handles before preparing the transition. Its journal does
        // not advance their identity generations, so generation CAS alone is
        // insufficient to reject this operation.
        let mut before_identity = manager.get(&predecessor).unwrap();
        let mut after_identity = manager.get(&successor).unwrap();
        let mut transition = manager
            .prepare_identity_transition(request(&predecessor, &successor, "sibling-race"))
            .unwrap();
        if phase != "prepared" {
            let attempt = transition.begin_publication().unwrap();
            if phase == "uncertain" {
                transition
                    .complete(attempt, IdentityTransitionPublicationResult::Unknown)
                    .unwrap();
            }
        }
        let journal_before = list_identity_transition_journals(root.path()).unwrap();
        for identity in [&mut before_identity, &mut after_identity] {
            let document_before = identity.public_identity().unwrap();
            let status_before = identity.host_status().unwrap();
            let mut requested = remote(identity);
            requested.evidence.registry_version += 1;
            assert_eq!(
                identity
                    .adopt_verified_sibling_document(requested)
                    .unwrap_err(),
                IdentityError::Conflict,
                "{phase}",
            );
            assert_eq!(identity.public_identity().unwrap(), document_before);
            assert_eq!(identity.host_status().unwrap(), status_before);
        }
        assert_eq!(
            list_identity_transition_journals(root.path()).unwrap(),
            journal_before
        );
    }
}

#[test]
fn sibling_adoption_allows_aborted_transition_and_preserves_ordinary_convergence() {
    let root = tempfile::tempdir().unwrap();
    let (mut manager, predecessor, successor) = identities(root.path(), [0x94; 32]);
    let mut identity = manager.get(&predecessor).unwrap();
    let mut transition = manager
        .prepare_identity_transition(request(&predecessor, &successor, "sibling-aborted"))
        .unwrap();
    let attempt = transition.begin_publication().unwrap();
    transition
        .complete(
            attempt,
            IdentityTransitionPublicationResult::RejectedBeforeAcceptance,
        )
        .unwrap();
    let mut requested = remote(&identity);
    requested.evidence.registry_version += 1;
    assert_eq!(
        identity
            .adopt_verified_sibling_document(requested.clone())
            .unwrap(),
        ConvergenceOutcome::Unchanged
    );
    assert_eq!(
        identity
            .host_status()
            .unwrap()
            .checkpoint
            .unwrap()
            .registry_version,
        requested.evidence.registry_version
    );

    // A pending transition remains compatible with the pre-existing adoption
    // entrypoint; sibling-only restrictions must not change Recovery semantics.
    let mut manager = IdentityManager::open(config(root.path(), [0x94; 32])).unwrap();
    manager
        .prepare_identity_transition(request(&predecessor, &successor, "ordinary-preserved"))
        .unwrap();
    let ordinary = remote(&identity);
    assert_eq!(
        identity.adopt_verified_document(ordinary).unwrap(),
        ConvergenceOutcome::Unchanged
    );
}

#[test]
fn sibling_updated_keeps_long_lived_manager_writable_and_stale_identity_fenced() {
    let root = tempfile::tempdir().unwrap();
    let (mut manager, predecessor, successor) = identities(root.path(), [0x95; 32]);
    let mut identity = manager.get(&predecessor).unwrap();
    let mut stale = manager.get(&predecessor).unwrap();
    let mut requested = remote(&identity);
    let mut document = requested.document.as_value().clone();
    document.as_object_mut().unwrap().remove("proof");
    document["service"] = serde_json::json!([{
        "id": format!("{}#sibling-service", predecessor.did),
        "type": "ANPMessageService",
        "serviceEndpoint": "https://example.com/messages"
    }]);
    let signed = identity
        .lock_engine()
        .unwrap()
        .sign_document_proof(
            &document,
            "#root",
            anp::proof::ProofGenerationOptions {
                proof_purpose: Some("assertionMethod".into()),
                proof_type: Some(anp::proof::PROOF_TYPE_DATA_INTEGRITY.into()),
                cryptosuite: Some(anp::proof::CRYPTOSUITE_EDDSA_JCS_2022.into()),
                created: Some("2026-09-17T00:00:00Z".into()),
                domain: None,
                challenge: None,
            },
        )
        .unwrap();
    requested.document = crate::DidDocument::from_value(signed);
    requested.evidence.document_version += 1;
    requested.evidence.registry_version += 1;
    requested.evidence.document_digest =
        crate::canonical_document_digest(requested.document.as_value()).unwrap();
    assert_eq!(
        identity
            .adopt_verified_sibling_document(requested.clone())
            .unwrap(),
        ConvergenceOutcome::Updated
    );
    assert_eq!(
        stale
            .adopt_verified_sibling_document(requested)
            .unwrap_err(),
        IdentityError::Conflict
    );
    // Neither manager nor identity is reopened/recovered between these writes.
    manager.create_engine_for_test(spec("another")).unwrap();
    manager
        .prepare_identity_transition(request(&predecessor, &successor, "after-sibling-update"))
        .unwrap();
}
