use super::*;
use crate::facade::{IdentityManager, IdentityManagerConfig, InjectedStoreKey, RootKeySource};
use crate::host::{DocumentChangeRecoveryPort, HostDocumentChangePhase};
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
    assert_eq!(
        session.host_phase().unwrap(),
        HostDocumentChangePhase::Prepared
    );
    let candidate = session.candidate().clone();
    let attempt = session.begin_publication().unwrap();
    assert_eq!(
        session.host_phase().unwrap(),
        HostDocumentChangePhase::PublicationInFlight
    );
    assert_eq!(
        session
            .complete(attempt.clone(), PublicationResult::Unknown)
            .unwrap(),
        DocumentChangeOutcome::PublicationUncertain
    );
    assert_eq!(
        session.host_phase().unwrap(),
        HostDocumentChangePhase::PublicationUncertain
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

#[test]
fn confirmed_and_reconciled_changes_persist_independent_remote_versions() {
    for reconcile in [false, true] {
        let (_root, mut identity) = identity();
        let mut session = identity
            .prepare_document_change(rotation("request-v2"))
            .unwrap();
        let candidate = session.candidate().clone();
        let verified = VerifiedPublicationEvidence {
            document_version: 4,
            registry_version: 7,
            ..evidence(&candidate)
        };
        let attempt = session.begin_publication().unwrap();
        let outcome = if reconcile {
            session
                .complete(attempt, PublicationResult::Unknown)
                .unwrap();
            session
                .reconcile(VerifiedRemoteDocument {
                    document: candidate.candidate_document,
                    evidence: VerifiedPublicationEvidence {
                        document_digest: format!("sha256:{}", verified.document_digest),
                        ..verified.clone()
                    },
                })
                .unwrap()
        } else {
            session
                .complete(
                    attempt,
                    PublicationResult::Confirmed {
                        evidence: verified.clone(),
                    },
                )
                .unwrap()
        };
        let DocumentChangeOutcome::Committed { identity: public } = outcome else {
            panic!("verified publication must commit");
        };
        assert_eq!(public.revision, 4);
        let engine = identity.lock_engine().unwrap();
        let checkpoint = engine.checkpoint().unwrap();
        assert_eq!(checkpoint.document_version, verified.document_version);
        assert_eq!(checkpoint.registry_version, verified.registry_version);
        assert_eq!(
            checkpoint.document_digest,
            format!("sha256:{}", verified.document_digest)
        );
        assert!(engine.pending_revision().is_none());
        let persisted =
            crate::registry::read_identity(engine.runtime().root(), engine.identity_id()).unwrap();
        assert_eq!(persisted.checkpoint.as_ref(), Some(checkpoint));
        assert!(persisted.pending_revision.is_none());
    }
}

#[test]
fn publication_checkpoint_rollback_preserves_pending_transaction() {
    for reconcile in [false, true] {
        let (_root, mut identity) = identity();
        let mut first = identity
            .prepare_document_change(rotation("request-v2"))
            .unwrap();
        let candidate = first.candidate().clone();
        let attempt = first.begin_publication().unwrap();
        first
            .complete(
                attempt,
                PublicationResult::Confirmed {
                    evidence: VerifiedPublicationEvidence {
                        document_version: 2,
                        registry_version: 7,
                        ..evidence(&candidate)
                    },
                },
            )
            .unwrap();
        let mut next = identity
            .prepare_document_change(rotation_from("#request-v2", "request-v3"))
            .unwrap();
        let candidate = next.candidate().clone();
        let attempt = next.begin_publication().unwrap();
        if reconcile {
            next.complete(attempt.clone(), PublicationResult::Unknown)
                .unwrap();
        }
        let before = identity.lock_engine().unwrap().record().clone();
        for (document_version, registry_version) in [(3, 6), (1, 8), (2, 8)] {
            let verified = VerifiedPublicationEvidence {
                document_version,
                registry_version,
                document_digest: candidate.candidate_digest.clone(),
            };
            let result = if reconcile {
                next.reconcile(VerifiedRemoteDocument {
                    document: candidate.candidate_document.clone(),
                    evidence: VerifiedPublicationEvidence {
                        document_digest: format!("sha256:{}", verified.document_digest),
                        ..verified
                    },
                })
            } else {
                next.complete(
                    attempt.clone(),
                    PublicationResult::Confirmed { evidence: verified },
                )
            };
            assert_eq!(result.err(), Some(IdentityError::Conflict));
            let engine = identity.lock_engine().unwrap();
            let persisted =
                crate::registry::read_identity(engine.runtime().root(), engine.identity_id())
                    .unwrap();
            assert_eq!(persisted.generation, before.generation);
            assert_eq!(persisted.checkpoint, before.checkpoint);
            assert_eq!(persisted.pending_revision, before.pending_revision);
        }
    }
}

#[test]
fn initial_proof_refresh_keeps_first_remote_checkpoint_and_consumes_initial_authority() {
    for reconcile in [false, true] {
        let service = IdentityService {
            id: "messages".to_owned(),
            service_type: "ANPMessageService".to_owned(),
            service_endpoint: "https://example.com/messages".to_owned(),
            service_did: None,
            profiles: Vec::new(),
            security_profiles: Vec::new(),
        };
        let (_root, mut identity) = identity_with_services(vec![service.clone().into()]);
        let mut session = identity
            .prepare_document_change(DocumentChangeRequest {
                changes: vec![DocumentChange::ReplaceServices {
                    services: vec![service],
                }],
            })
            .unwrap();
        let candidate = session.candidate().clone();
        let attempt = session.begin_publication().unwrap();
        let verified = VerifiedPublicationEvidence {
            document_version: 1,
            registry_version: 1,
            ..evidence(&candidate)
        };
        if reconcile {
            session
                .complete(attempt, PublicationResult::Unknown)
                .unwrap();
            session
                .reconcile(VerifiedRemoteDocument {
                    document: candidate.candidate_document,
                    evidence: VerifiedPublicationEvidence {
                        document_digest: format!("sha256:{}", verified.document_digest),
                        ..verified
                    },
                })
                .unwrap();
        } else {
            session
                .complete(attempt, PublicationResult::Confirmed { evidence: verified })
                .unwrap();
        }
        {
            let engine = identity.lock_engine().unwrap();
            assert_eq!(engine.checkpoint().unwrap().document_version, 1);
            assert_eq!(engine.checkpoint().unwrap().registry_version, 1);
            assert!(!engine.record().initial_publication_pending);
            assert!(engine.pending_revision().is_none());
        }
        let mut next = identity
            .prepare_document_change(rotation("request-v2"))
            .unwrap();
        let candidate = next.candidate().clone();
        let attempt = next.begin_publication().unwrap();
        assert_eq!(
            next.complete(
                attempt,
                PublicationResult::Confirmed {
                    evidence: VerifiedPublicationEvidence {
                        document_version: 1,
                        registry_version: 1,
                        ..evidence(&candidate)
                    },
                }
            )
            .err(),
            Some(IdentityError::Conflict)
        );
    }
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
    identity_with_services(Vec::new())
}

fn identity_with_services(services: Vec<ServiceSpec>) -> (tempfile::TempDir, ManagedIdentity) {
    let root = tempfile::tempdir().unwrap();
    let mut manager = IdentityManager::initialize(IdentityManagerConfig {
        state_root: root.path().to_owned(),
        root_key: RootKeySource::Injected(InjectedStoreKey::new("document-change", [0x91; 32])),
    })
    .unwrap();
    let identity = manager
        .create_engine_for_test(DidCreateSpec {
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
            services,
            agent_description_url: None,
            extensions: Vec::new(),
        })
        .unwrap();
    (root, identity)
}
