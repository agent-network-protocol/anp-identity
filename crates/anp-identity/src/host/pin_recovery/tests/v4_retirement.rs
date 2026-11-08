use super::*;

fn request(fixture: &Fixture, session: &PinRootRecoverySession) -> PinRecoveryV4RetirementRequest {
    let successor = Fixture::new();
    let successor_did = successor.binding.did.clone();
    let next_generation = "123456789012345678901234567891".to_owned();
    PinRecoveryV4RetirementRequest {
        identity: session.proposal.identity.clone(),
        expected_generation: session.proposal.generation,
        binding: fixture.binding.clone(),
        scope: PinRecoveryV4RetirementScope::UnprojectedPinRecovery {
            never_projected: true,
            absent_from_previous_custody: true,
        },
        evidence: VerifiedPinRecoveryV4Supersession {
            v4_operation_id: format!("recover_v4_{}", URL_SAFE_NO_PAD.encode([17; 24])),
            v4_intent_hash: format!("sha256:{}", URL_SAFE_NO_PAD.encode([17; 32])),
            account_user_id: fixture.binding.account_user_id.clone(),
            full_handle: fixture.binding.handle.clone(),
            previous_did: fixture.binding.did.clone(),
            previous_binding_generation: fixture.binding.binding_generation.clone(),
            successor_did: successor_did.clone(),
            successor_binding_generation: next_generation.clone(),
            committed_checkpoint: HostDocumentCheckpoint {
                document_version: successor.remote.evidence.document_version,
                registry_version: successor.remote.evidence.registry_version,
                document_digest: successor.remote.evidence.document_digest.clone(),
            },
            current_binding: PinRecoveryCurrentBinding {
                full_handle: fixture.binding.handle.clone(),
                did: successor_did,
                binding_generation: next_generation,
            },
            current_document: successor.remote.clone(),
        },
    }
}

fn assert_isolated(manager: &IdentityManager, reference: &IdentityRef) {
    let identity = manager.get(reference).unwrap();
    let engine = identity.lock_engine().unwrap();
    assert_eq!(engine.state(), IdentityState::Revoked);
    assert_eq!(engine.root_capability(), RootCapabilityState::Absent);
    assert!(engine
        .keys()
        .iter()
        .all(|key| key.state == KeyState::Revoked));
    assert!(engine.record().pending_enrollment.is_none());
    assert_eq!(
        engine.record().pin_recovery.as_ref().unwrap().phase,
        PinRecoveryPhase::SupersededByV4
    );
}

#[test]
fn v4_isolates_only_attested_unprojected_pin_origin_in_all_three_phases_then_exact_delete() {
    for phase in [
        PinRecoveryPhase::Prepared,
        PinRecoveryPhase::PublicationUncertain,
        PinRecoveryPhase::Active,
    ] {
        let mut fixture = Fixture::new();
        let mut session = fixture.begin();
        if phase != PinRecoveryPhase::Prepared {
            let sign = fixture.signing_request(&session);
            let signed = session.sign_pin_recovery_intent(sign).unwrap();
            if phase == PinRecoveryPhase::Active {
                let completion = fixture.complete_request(&session, &signed);
                session.complete_pin_root_recovery(completion).unwrap();
            }
            // In the uncertain case the server may already have accepted this
            // device. Later V4 is authoritative regardless of that old outcome.
        }
        let retirement = request(&fixture, &session);
        for (never_projected, absent_from_previous_custody) in [(false, true), (true, false)] {
            let mut denied = retirement.clone();
            denied.scope = PinRecoveryV4RetirementScope::UnprojectedPinRecovery {
                never_projected,
                absent_from_previous_custody,
            };
            assert_eq!(
                fixture
                    .manager
                    .retire_pin_root_recovery_after_v4(denied)
                    .err(),
                Some(IdentityError::InvalidRequest)
            );
            let actual = fixture.manager.get(&retirement.identity).unwrap();
            assert_eq!(
                actual
                    .lock_engine()
                    .unwrap()
                    .record()
                    .pin_recovery
                    .as_ref()
                    .unwrap()
                    .phase,
                phase
            );
        }
        let reference = retirement.identity.clone();
        let outcome = fixture
            .manager
            .retire_pin_root_recovery_after_v4(retirement)
            .unwrap();
        assert_eq!(outcome.identity, reference);
        assert_isolated(&fixture.manager, &reference);
        let identity = fixture.manager.get(&reference).unwrap();
        assert_eq!(
            identity
                .export_root_for_pin_backup(PinRootBackupRequest {
                    expected_generation: outcome.generation,
                    root_kid: fixture.binding.root_kid.clone(),
                    user_presence_confirmed: true,
                })
                .err(),
            Some(IdentityError::CapabilityUnavailable)
        );
        let mut resumed = fixture
            .manager
            .begin_pin_root_recovery(fixture.begin_request(None))
            .unwrap();
        assert_eq!(resumed.proposal.phase, PinRecoveryPhase::SupersededByV4);
        let sign_request = fixture.signing_request(&resumed);
        assert_eq!(
            resumed.sign_pin_recovery_intent(sign_request).err(),
            Some(IdentityError::InvalidDocumentChangeState)
        );
        let mut isolated_identity = fixture.manager.get(&reference).unwrap();
        assert_eq!(
            isolated_identity
                .adopt_verified_document(fixture.remote.clone())
                .err(),
            Some(IdentityError::InvalidDocumentChangeState)
        );
        fixture
            .manager
            .delete(
                &reference,
                crate::DeleteIdentityRequest {
                    discard_pending_changes: false,
                },
            )
            .unwrap();
        assert!(fixture.manager.list().unwrap().is_empty());
    }
}

#[test]
fn v4_retirement_rejects_projected_or_retained_scope_and_wrong_exact_binding() {
    let mut fixture = Fixture::new();
    let session = fixture.begin();
    let valid = request(&fixture, &session);
    let before = session.proposal.clone();
    let mut cases = Vec::new();
    for (never_projected, absent_from_previous_custody) in
        [(false, true), (true, false), (false, false)]
    {
        let mut r = valid.clone();
        r.scope = PinRecoveryV4RetirementScope::UnprojectedPinRecovery {
            never_projected,
            absent_from_previous_custody,
        };
        cases.push(r);
    }
    let mut r = valid.clone();
    r.evidence.account_user_id = "other-account".into();
    cases.push(r);
    let mut r = valid.clone();
    r.evidence.full_handle = "other.example.com".into();
    cases.push(r);
    let mut r = valid.clone();
    r.evidence.previous_did = r.evidence.successor_did.clone();
    cases.push(r);
    let mut r = valid.clone();
    r.evidence.previous_binding_generation = "1".into();
    cases.push(r);
    let mut r = valid.clone();
    r.evidence.successor_binding_generation = fixture.binding.binding_generation.clone();
    cases.push(r);
    let mut r = valid.clone();
    r.evidence.current_binding.did = fixture.binding.did.clone();
    cases.push(r);
    let mut r = valid.clone();
    r.evidence.current_binding.binding_generation = "1".into();
    cases.push(r);
    let mut r = valid.clone();
    r.evidence.committed_checkpoint.document_digest =
        format!("sha256:{}", URL_SAFE_NO_PAD.encode([22; 32]));
    cases.push(r);
    let mut r = valid.clone();
    r.evidence.committed_checkpoint.document_version = 2;
    cases.push(r);
    let mut r = valid.clone();
    r.binding.operation_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into();
    cases.push(r);
    let mut r = valid.clone();
    r.identity.identity_id = "wrong-namespace".into();
    cases.push(r);
    let mut r = valid.clone();
    r.identity.store_id = "wrong-store".into();
    cases.push(r);
    let mut r = valid.clone();
    r.expected_generation += 1;
    cases.push(r);
    let mut r = valid.clone();
    r.evidence.current_document = fixture.remote.clone();
    cases.push(r);
    let mut r = valid.clone();
    r.evidence.v4_operation_id = "invalid operation".into();
    cases.push(r);
    for r in cases {
        assert!(fixture
            .manager
            .retire_pin_root_recovery_after_v4(r)
            .is_err());
        let resumed = fixture
            .manager
            .begin_pin_root_recovery(fixture.begin_request(None))
            .unwrap();
        assert_eq!(resumed.proposal, before);
    }
}

#[test]
fn v4_retirement_cannot_revoke_ordinary_active_identity_without_pin_origin() {
    let fixture = Fixture::new();
    let mut source_manager = IdentityManager::open(config(fixture._source_dir.path(), 1)).unwrap();
    let mut target = Fixture::new();
    let session = target.begin();
    let mut r = request(&target, &session);
    r.identity = fixture.source.reference();
    r.binding = fixture.binding.clone();
    r.expected_generation = fixture.source.pin_root_generation().unwrap();
    assert_eq!(
        source_manager.retire_pin_root_recovery_after_v4(r).err(),
        Some(IdentityError::CapabilityUnavailable)
    );
    assert_eq!(
        fixture.source.host_status().unwrap().root_capability,
        crate::host::HostRootCapability::Active
    );
}

#[test]
fn v4_isolation_is_idempotent_for_same_transition_and_rejects_changed_v4_claim() {
    let mut fixture = Fixture::new();
    let session = fixture.begin();
    let r = request(&fixture, &session);
    let first = fixture
        .manager
        .retire_pin_root_recovery_after_v4(r.clone())
        .unwrap();
    let replay = fixture
        .manager
        .retire_pin_root_recovery_after_v4(r.clone())
        .unwrap();
    assert_eq!(replay, first);
    let mut current = r.clone();
    current.expected_generation = first.generation;
    assert_eq!(
        fixture
            .manager
            .retire_pin_root_recovery_after_v4(current)
            .unwrap(),
        first
    );
    let mut different = r.clone();
    different.evidence.v4_operation_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into();
    assert_eq!(
        fixture
            .manager
            .retire_pin_root_recovery_after_v4(different)
            .err(),
        Some(IdentityError::Conflict)
    );
    assert_isolated(&fixture.manager, &r.identity);
}

#[test]
fn v4_isolation_and_late_pin_activation_race_is_fenced_by_store_lock_and_generation() {
    let mut fixture = Fixture::new();
    let mut session = fixture.begin();
    let sign = fixture.signing_request(&session);
    let signed = session.sign_pin_recovery_intent(sign).unwrap();
    let retirement = request(&fixture, &session);
    let completion = fixture.complete_request(&session, &signed);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let mut manager = fixture.manager;
    let first_barrier = barrier.clone();
    let first_request = retirement.clone();
    let retiring = std::thread::spawn(move || {
        first_barrier.wait();
        manager.retire_pin_root_recovery_after_v4(first_request)
    });
    let completing = std::thread::spawn(move || {
        barrier.wait();
        session.complete_pin_root_recovery(completion)
    });
    let retired = retiring.join().unwrap();
    let completed = completing.join().unwrap();
    assert!(retired.is_ok() ^ completed.is_ok());
    let mut manager = IdentityManager::open(config(fixture.target_dir.path(), 2)).unwrap();
    if retired.is_err() {
        assert_eq!(retired.err(), Some(IdentityError::Conflict));
        let mut retry = retirement.clone();
        retry.expected_generation = manager
            .get(&retry.identity)
            .unwrap()
            .pin_root_generation()
            .unwrap();
        manager.retire_pin_root_recovery_after_v4(retry).unwrap();
    } else {
        assert_eq!(completed.err(), Some(IdentityError::Conflict));
    }
    assert_isolated(&manager, &retirement.identity);
}

#[test]
fn v4_isolation_crash_repairs_registry_and_keeps_old_root_unavailable_before_delete_retry() {
    let mut fixture = Fixture::new();
    let session = fixture.begin();
    let r = request(&fixture, &session);
    let before = {
        let engine = session.identity.lock_engine().unwrap();
        engine.record().summary()
    };
    let outcome = fixture
        .manager
        .retire_pin_root_recovery_after_v4(r.clone())
        .unwrap();
    let identity = fixture.manager.get(&outcome.identity).unwrap();
    let engine = identity.lock_engine().unwrap();
    let runtime = std::sync::Arc::clone(engine.runtime());
    let guard = runtime.acquire_write().unwrap();
    let journal = crate::registry::CreationJournal::new_state_transition(
        crate::identity::random_id(),
        engine.identity_id().into(),
        engine.did().into(),
        chrono::Utc::now().to_rfc3339(),
    );
    crate::registry::write_journal(runtime.root(), &guard, &journal).unwrap();
    let mut registry = crate::registry::read_registry(runtime.root()).unwrap();
    registry.identities.insert(engine.did().into(), before);
    crate::registry::write_registry(runtime.root(), &guard, &registry).unwrap();
    drop(guard);
    drop(engine);
    drop(identity);
    fixture.manager = IdentityManager::open(config(fixture.target_dir.path(), 2)).unwrap();
    assert_isolated(&fixture.manager, &r.identity);
    assert_eq!(
        fixture
            .manager
            .retire_pin_root_recovery_after_v4(r.clone())
            .unwrap(),
        outcome
    );
    assert_eq!(
        session
            .identity
            .export_root_for_pin_backup(PinRootBackupRequest {
                expected_generation: session.proposal.generation,
                root_kid: fixture.binding.root_kid.clone(),
                user_presence_confirmed: true,
            })
            .err(),
        Some(IdentityError::Conflict)
    );
    fixture
        .manager
        .delete(
            &r.identity,
            crate::DeleteIdentityRequest {
                discard_pending_changes: false,
            },
        )
        .unwrap();
    assert!(fixture.manager.list().unwrap().is_empty());
    assert!(crate::registry::list_journals(runtime.root())
        .unwrap()
        .is_empty());
}

#[test]
fn v4_delete_failure_keeps_root_fenced_and_journal_recovery_preserves_other_identity() {
    let mut fixture = Fixture::new();
    let session = fixture.begin();
    let retirement = request(&fixture, &session);
    fixture
        .manager
        .retire_pin_root_recovery_after_v4(retirement.clone())
        .unwrap();
    let unrelated = fixture
        .manager
        .create_engine_for_test(crate::DidCreateSpec {
            profile: crate::DidProfile::E1,
            domain: "example.com".into(),
            port: None,
            path_segments: vec!["unrelated".into()],
            capabilities: crate::Capabilities { did_wba: true },
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
    let isolated = fixture.manager.get(&retirement.identity).unwrap();
    let engine = isolated.lock_engine().unwrap();
    let runtime = std::sync::Arc::clone(engine.runtime());
    let secrets = engine
        .keys()
        .iter()
        .map(|key| crate::keystore::SecretRef {
            identity_id: engine.identity_id().into(),
            key_id: key.kid.clone(),
            role: key.role,
            version: key.version,
        })
        .collect::<Vec<_>>();
    let root_path = runtime.key_store().record_path(&secrets[0]);
    drop(engine);
    let saved_ciphertext = root_path.with_extension("preserved-ciphertext");
    std::fs::rename(&root_path, &saved_ciphertext).unwrap();
    std::fs::create_dir(&root_path).unwrap();
    assert_eq!(
        fixture
            .manager
            .delete(
                &retirement.identity,
                crate::DeleteIdentityRequest {
                    discard_pending_changes: false
                }
            )
            .err(),
        Some(IdentityError::Storage)
    );
    assert_isolated(&fixture.manager, &retirement.identity);
    assert_eq!(
        isolated
            .export_root_for_pin_backup(PinRootBackupRequest {
                expected_generation: isolated.pin_root_generation().unwrap(),
                root_kid: fixture.binding.root_kid.clone(),
                user_presence_confirmed: true,
            })
            .err(),
        Some(IdentityError::CapabilityUnavailable)
    );
    assert_eq!(
        crate::registry::list_journals(runtime.root())
            .unwrap()
            .len(),
        1
    );
    std::fs::remove_dir(&root_path).unwrap();
    std::fs::rename(&saved_ciphertext, &root_path).unwrap();
    fixture.manager.recover().unwrap();
    assert!(fixture.manager.get(&retirement.identity).is_err());
    assert_eq!(
        fixture
            .manager
            .get(&unrelated.reference())
            .unwrap()
            .host_status()
            .unwrap()
            .root_capability,
        crate::host::HostRootCapability::Active
    );
    for secret in secrets {
        assert!(runtime
            .key_store()
            .open(runtime.root_key(), &secret)
            .is_err());
    }
    assert!(crate::registry::list_journals(runtime.root())
        .unwrap()
        .is_empty());
}
