use super::*;
use crate::facade::{IdentityManager, IdentityManagerConfig, InjectedStoreKey, RootKeySource};
use crate::{Capabilities, DidCreateSpec, DidProfile, KeyRole, ManagedKeySpec};

#[test]
fn confirmed_change_commits_and_rejected_change_aborts() {
    let (_root, mut identity) = identity();
    let mut confirmed = identity
        .prepare_document_change(rotation("request-v2"))
        .unwrap();
    let candidate = confirmed.candidate().clone();
    let attempt = confirmed.begin_publication().unwrap();
    let outcome = confirmed
        .complete(
            attempt,
            PublicationResult::Confirmed {
                evidence: evidence(&candidate),
            },
        )
        .unwrap();
    let DocumentChangeOutcome::Committed { identity: public } = outcome else {
        panic!("confirmed publication must commit");
    };
    assert_eq!(public.revision, 2);
    assert!(public
        .active_keys
        .iter()
        .any(|key| key.kid.ends_with("#request-v2")));

    let mut rejected = identity
        .prepare_document_change(rotation_from("#request-v2", "request-v3"))
        .unwrap();
    let attempt = rejected.begin_publication().unwrap();
    assert_eq!(
        rejected
            .complete(attempt, PublicationResult::RejectedBeforeAcceptance)
            .unwrap(),
        DocumentChangeOutcome::Aborted
    );
    assert!(identity.resume_document_change().unwrap().is_none());
    assert_eq!(identity.public_identity().unwrap().revision, 2);
}

#[test]
fn uncertain_change_can_only_reconcile_remote_old_or_candidate() {
    let (_root, mut identity) = identity();
    let old = identity.public_identity().unwrap().document;
    let mut session = identity
        .prepare_document_change(rotation("request-v2"))
        .unwrap();
    let candidate = session.candidate().clone();
    let attempt = session.begin_publication().unwrap();
    assert_eq!(
        session
            .complete(attempt.clone(), PublicationResult::Unknown)
            .unwrap(),
        DocumentChangeOutcome::PublicationUncertain
    );
    assert_eq!(
        session.begin_publication().err(),
        Some(IdentityError::InvalidDocumentChangeState)
    );
    assert_eq!(
        session
            .complete(attempt, PublicationResult::RejectedBeforeAcceptance)
            .err(),
        Some(IdentityError::Conflict)
    );

    assert_eq!(
        session.reconcile(remote(old.clone())).unwrap(),
        DocumentChangeOutcome::ReadyForPublication
    );
    let retry = session.begin_publication().unwrap();
    assert_eq!(
        session.complete(retry, PublicationResult::Unknown).unwrap(),
        DocumentChangeOutcome::PublicationUncertain
    );
    let DocumentChangeOutcome::Committed { identity: public } = session
        .reconcile(remote(candidate.candidate_document))
        .unwrap()
    else {
        panic!("candidate observation must commit");
    };
    assert_eq!(public.revision, 2);
}

#[test]
fn session_resumes_in_flight_and_published_crash_windows() {
    let (_root, mut identity) = identity();
    let mut first = identity
        .prepare_document_change(rotation("request-v2"))
        .unwrap();
    first.begin_publication().unwrap();
    drop(first);

    let mut resumed = identity.resume_document_change().unwrap().unwrap();
    let candidate = resumed.candidate().clone();
    let attempt = resumed.begin_publication().unwrap();
    identity
        .lock_engine()
        .unwrap()
        .mark_published(&candidate.operation_id)
        .unwrap();
    drop(resumed);

    let mut published = identity.resume_document_change().unwrap().unwrap();
    let resumed_attempt = published.begin_publication().unwrap();
    assert_ne!(attempt.publication_generation, 0);
    let DocumentChangeOutcome::Committed { identity: public } = published
        .complete(
            resumed_attempt,
            PublicationResult::Confirmed {
                evidence: evidence(&candidate),
            },
        )
        .unwrap()
    else {
        panic!("published crash window must remain committable");
    };
    assert_eq!(public.revision, 2);
}

#[test]
fn attempts_and_verified_evidence_are_bound_to_the_candidate() {
    let (_root, mut identity) = identity();
    let mut session = identity
        .prepare_document_change(rotation("request-v2"))
        .unwrap();
    let candidate = session.candidate().clone();
    let attempt = session.begin_publication().unwrap();
    let mut wrong = evidence(&candidate);
    wrong.document_digest = "sha256:wrong".to_owned();
    assert_eq!(
        session
            .complete(attempt, PublicationResult::Confirmed { evidence: wrong })
            .err(),
        Some(IdentityError::InvalidRequest)
    );

    let mut observation = remote(candidate.candidate_document);
    observation.evidence.document_digest = "sha256:wrong".to_owned();
    assert_eq!(
        session.reconcile(observation).err(),
        Some(IdentityError::InvalidRequest)
    );
}

fn rotation(new_fragment: &str) -> DocumentChangeRequest {
    rotation_from("#request", new_fragment)
}

fn rotation_from(old_kid: &str, new_fragment: &str) -> DocumentChangeRequest {
    DocumentChangeRequest {
        changes: vec![DocumentChange::RotateSigningKey {
            old_kid: old_kid.to_owned(),
            new_fragment: new_fragment.to_owned(),
        }],
    }
}

fn evidence(candidate: &PreparedDocumentChange) -> VerifiedPublicationEvidence {
    VerifiedPublicationEvidence {
        document_version: 2,
        registry_version: 2,
        document_digest: candidate.candidate_digest.clone(),
    }
}

fn remote(document: DidDocument) -> VerifiedRemoteDocument {
    let digest = crate::canonical_document_digest(document.as_value()).unwrap();
    VerifiedRemoteDocument {
        document,
        evidence: VerifiedPublicationEvidence {
            document_version: 2,
            registry_version: 2,
            document_digest: digest,
        },
    }
}

fn identity() -> (tempfile::TempDir, ManagedIdentity) {
    let root = tempfile::tempdir().unwrap();
    let mut manager = IdentityManager::initialize(IdentityManagerConfig {
        state_root: root.path().to_owned(),
        root_key: RootKeySource::Injected(InjectedStoreKey::new("document-change", [0x91; 32])),
    })
    .unwrap();
    let identity = manager
        .create(DidCreateSpec {
            profile: DidProfile::E1,
            domain: "example.com".to_owned(),
            port: None,
            path_segments: vec!["facade".to_owned(), "document-change".to_owned()],
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
        })
        .unwrap();
    (root, identity)
}
