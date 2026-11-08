use super::*;
use crate::host::{ConvergenceWorkflow, EnrollmentWorkflow, IdentityStatusPort};
use crate::{
    DidDocument, IdentityManagerConfig, InjectedStoreKey, RootKeySource,
    VerifiedPublicationEvidence,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::Verifier;

struct Fixture {
    _source_dir: tempfile::TempDir,
    target_dir: tempfile::TempDir,
    source: ManagedIdentity,
    manager: IdentityManager,
    binding: PinRecoveryBinding,
    remote: VerifiedRemoteDocument,
}
impl Fixture {
    fn new() -> Self {
        let source_dir = tempfile::tempdir().unwrap();
        let target_dir = tempfile::tempdir().unwrap();
        let mut source_manager = IdentityManager::initialize(config(source_dir.path(), 1)).unwrap();
        let source = source_manager
            .create_engine_for_test(crate::DidCreateSpec {
                profile: crate::DidProfile::E1,
                domain: "example.com".into(),
                port: None,
                path_segments: vec!["pin".into()],
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
        let doc = source.public_identity().unwrap().document.into_value();
        let root_kid = doc["proof"]["verificationMethod"]
            .as_str()
            .unwrap()
            .to_owned();
        let root = source
            .lock_engine()
            .unwrap()
            .key_metadata(&root_kid)
            .unwrap()
            .clone();
        let remote = remote(doc, 1, 1);
        let binding = PinRecoveryBinding {
            operation_id: "11111111-1111-4111-8111-111111111111".into(),
            account_user_id: "account-1".into(),
            target_id: "target-1".into(),
            handle: "alice.example.com".into(),
            did: source.reference().did.clone(),
            domain: "example.com".into(),
            binding_generation: "123456789012345678901234567890".into(),
            recovery_id: "22222222-2222-4222-8222-222222222222".into(),
            backup_epoch: 1,
            slot_id: format!("rs_{}", URL_SAFE_NO_PAD.encode([9; 32])),
            op_jkt: URL_SAFE_NO_PAD.encode([8; 32]),
            root_kid,
            root_public_key_multibase: root.public_key_multibase,
            encrypted_package_hash: Some(URL_SAFE_NO_PAD.encode([7; 32])),
            config_hash: URL_SAFE_NO_PAD.encode([6; 32]),
            audience: "https://example.com/user-service/v1/key-recovery".into(),
        };
        let manager = IdentityManager::initialize(config(target_dir.path(), 2)).unwrap();
        Self {
            _source_dir: source_dir,
            target_dir,
            source,
            manager,
            binding,
            remote,
        }
    }
    fn export(&self) -> PinRootBackup {
        self.source
            .export_root_for_pin_backup(PinRootBackupRequest {
                expected_generation: self.source.pin_root_generation().unwrap(),
                root_kid: self.binding.root_kid.clone(),
                user_presence_confirmed: true,
            })
            .unwrap()
    }
    fn begin(&mut self) -> PinRootRecoverySession {
        let root = Zeroizing::new(self.export().as_pkcs8_der().to_vec());
        self.manager
            .begin_pin_root_recovery(self.begin_request(Some(root)))
            .unwrap()
    }
    fn begin_request(&self, root_key: Option<Zeroizing<Vec<u8>>>) -> BeginPinRootRecoveryRequest {
        BeginPinRootRecoveryRequest {
            binding: self.binding.clone(),
            remote: self.remote.clone(),
            root_key,
            profiles: vec!["anp.core.v1".into()],
            device_label: "Linux B".into(),
            user_presence_confirmed: true,
        }
    }
    fn signing_request(&self, session: &PinRootRecoverySession) -> PinRecoverySignRequest {
        let engine = session.identity.lock_engine().unwrap();
        let candidate =
            candidate_document(engine.record(), self.remote.document.as_value()).unwrap();
        let intent = intent(
            &self.binding,
            "recover",
            Some(&session.proposal.device_proposal),
            Some(&candidate),
        );
        PinRecoverySignRequest {
            expected_generation: session.proposal.generation,
            challenge: challenge(
                &self.binding,
                &self.remote,
                intent,
                "awiki.pin-recovery.device-commit.v1",
            ),
            remote: self.remote.clone(),
            candidate_document: candidate,
            user_presence_confirmed: true,
        }
    }
    fn complete_request(
        &self,
        session: &PinRootRecoverySession,
        signed: &PinRecoverySignedIntent,
    ) -> PinRecoveryCompletion {
        PinRecoveryCompletion {
            expected_generation: session.proposal.generation,
            binding: self.binding.clone(),
            challenge_id: "33333333-3333-4333-8333-333333333333".into(),
            remote: remote(signed.signed_document.clone(), 2, 2),
            outcome: PinRecoveryRemoteOutcome::Committed,
        }
    }
}
fn config(path: &std::path::Path, byte: u8) -> IdentityManagerConfig {
    IdentityManagerConfig {
        state_root: path.to_owned(),
        root_key: RootKeySource::Injected(InjectedStoreKey::new("pin", [byte; 32])),
    }
}
fn remote(document: Value, document_version: u64, registry_version: u64) -> VerifiedRemoteDocument {
    let digest = crate::document::document_digest(&document).unwrap();
    VerifiedRemoteDocument {
        document: DidDocument::from_verified(document),
        evidence: VerifiedPublicationEvidence {
            document_version,
            registry_version,
            document_digest: digest,
        },
    }
}
fn intent(
    binding: &PinRecoveryBinding,
    kind: &str,
    proposal: Option<&Value>,
    candidate: Option<&Value>,
) -> Value {
    json!({"kind":kind,"operation_id":binding.operation_id,"recovery_id":binding.recovery_id,
        "backup_epoch":binding.backup_epoch,"slot_id":binding.slot_id,"expected_active_epoch":if kind == "recover" { Some(binding.backup_epoch) } else { None },
        "backup_hash":binding.encrypted_package_hash,"config_hash":binding.config_hash,"registration_version":"0123456789abcdef0123456789abcdef",
        "registered_receipt_ids":[],"verified_receipt_ids":["44444444-4444-4444-8444-444444444444","55555555-5555-4555-8555-555555555555"],
        "new_device_proposal_hash":proposal.map(|v| hash_json(v).unwrap()),"candidate_document_digest":candidate.map(|v| hash_json(v).unwrap()),"binding_generation":binding.binding_generation})
}
fn challenge(
    binding: &PinRecoveryBinding,
    remote: &VerifiedRemoteDocument,
    intent: Value,
    purpose: &str,
) -> PinRecoveryChallenge {
    let now = chrono::Utc::now().timestamp();
    PinRecoveryChallenge {
        payload: json!({"protocol":"awiki.pin-recovery.v1","purpose":purpose,"aud":binding.audience,
        "operation_id":binding.operation_id,"challenge_id":"33333333-3333-4333-8333-333333333333","nonce":URL_SAFE_NO_PAD.encode([5;32]),"iat":now,"exp":now+120,
        "account_user_id":binding.account_user_id,"recovery_id":binding.recovery_id,"backup_epoch":binding.backup_epoch,"slot_id":binding.slot_id,
        "did":binding.did,"root_kid":binding.root_kid,"root_jkt":hash_json(&public_jwk(&binding.root_public_key_multibase).unwrap()).unwrap(),"op_jkt":binding.op_jkt,
        "binding_generation":binding.binding_generation,"document_version":remote.evidence.document_version,"registry_version":remote.evidence.registry_version,
        "document_digest":remote.evidence.document_digest.strip_prefix("sha256:").unwrap(),"intent_hash":hash_json(&intent).unwrap()}),
        intent,
    }
}
fn verify_jws(jws: &str, public_jwk: &Value, payload: &Value, typ: &str) {
    let parts = jws.split('.').collect::<Vec<_>>();
    assert_eq!(parts.len(), 3);
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
    assert_eq!(header["typ"], typ);
    assert_eq!(header["alg"], "EdDSA");
    assert_eq!(
        URL_SAFE_NO_PAD.decode(parts[1]).unwrap(),
        serde_json_canonicalizer::to_vec(payload).unwrap()
    );
    let key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(public_jwk["x"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let signature =
        ed25519_dalek::Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
    ed25519_dalek::VerifyingKey::from_bytes(&key)
        .unwrap()
        .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
        .unwrap();
}

#[test]
fn pin_export_requires_presence_current_generation_and_root_role() {
    let fixture = Fixture::new();
    let generation = fixture.source.pin_root_generation().unwrap();
    for (expected_generation, user_presence_confirmed, root_kid, error) in [
        (
            generation,
            false,
            fixture.binding.root_kid.clone(),
            IdentityError::CapabilityUnavailable,
        ),
        (
            generation + 1,
            true,
            fixture.binding.root_kid.clone(),
            IdentityError::Conflict,
        ),
        (
            generation,
            true,
            format!("{}#request", fixture.binding.did),
            IdentityError::CapabilityUnavailable,
        ),
    ] {
        assert_eq!(
            fixture
                .source
                .export_root_for_pin_backup(PinRootBackupRequest {
                    expected_generation,
                    user_presence_confirmed,
                    root_kid
                })
                .err(),
            Some(error)
        );
    }
    assert_eq!(fixture.export().as_pkcs8_der().len(), 48);
}

#[test]
fn pin_wrong_root_creates_no_identity_and_valid_pending_is_sealed() {
    let mut fixture = Fixture::new();
    let mut wrong = Zeroizing::new(fixture.export().as_pkcs8_der().to_vec());
    wrong[20] ^= 1;
    let request = fixture.begin_request(Some(wrong));
    assert_eq!(
        fixture.manager.begin_pin_root_recovery(request).err(),
        Some(IdentityError::RootKeyMismatch)
    );
    assert!(fixture.manager.list().unwrap().is_empty());
    let raw = fixture.export().as_pkcs8_der()[16..].to_vec();
    let session = fixture.begin();
    assert_eq!(session.proposal.phase, PinRecoveryPhase::Prepared);
    let engine = session.identity.lock_engine().unwrap();
    assert_eq!(engine.root_capability(), RootCapabilityState::Pending);
    assert_eq!(engine.state(), IdentityState::Enrolling);
    drop(engine);
    fn inspect(path: &std::path::Path, secret: &[u8]) {
        for entry in std::fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                inspect(&entry.path(), secret);
            } else {
                let bytes = std::fs::read(entry.path()).unwrap();
                assert!(!bytes.windows(secret.len()).any(|window| window == secret));
            }
        }
    }
    inspect(fixture.target_dir.path(), &raw);
}

#[test]
fn pin_resume_preserves_device_and_rejects_binding_substitution() {
    let mut fixture = Fixture::new();
    let session = fixture.begin();
    let proposal = session.proposal.clone();
    drop(session);
    fixture.manager = IdentityManager::open(config(fixture.target_dir.path(), 2)).unwrap();
    let request = fixture.begin_request(None);
    let resumed = fixture.manager.begin_pin_root_recovery(request).unwrap();
    assert_eq!(resumed.proposal, proposal);
    let mut request = fixture.begin_request(None);
    request.binding.op_jkt = URL_SAFE_NO_PAD.encode([99; 32]);
    assert_eq!(
        fixture.manager.begin_pin_root_recovery(request).err(),
        Some(IdentityError::InvalidRequest)
    );
    assert_eq!(fixture.manager.list().unwrap().len(), 1);
}

#[test]
fn pin_pending_cannot_use_generic_enrollment_signing_or_adoption() {
    let mut fixture = Fixture::new();
    let session = fixture.begin();
    let reference = session.proposal.identity.clone();
    let enrollment = fixture
        .manager
        .resume_enrollment(&reference)
        .unwrap()
        .unwrap();
    assert_eq!(
        enrollment.sign_device_assertion(b"arbitrary").err(),
        Some(IdentityError::KeyUnavailable)
    );
    let mut identity = fixture.manager.get(&reference).unwrap();
    assert_eq!(
        identity
            .adopt_verified_document(fixture.remote.clone())
            .err(),
        Some(IdentityError::InvalidDocumentChangeState)
    );
    assert!(identity
        .export_root_for_pin_backup(PinRootBackupRequest {
            expected_generation: session.proposal.generation,
            root_kid: fixture.binding.root_kid.clone(),
            user_presence_confirmed: true
        })
        .is_err());
}

#[test]
fn pin_signed_jws_is_exact_and_uncertain_has_no_delete_or_resign_path() {
    let mut fixture = Fixture::new();
    let mut session = fixture.begin();
    let request = fixture.signing_request(&session);
    let signed = session.sign_pin_recovery_intent(request).unwrap();
    verify_jws(
        &signed.root_proof,
        &public_jwk(&fixture.binding.root_public_key_multibase).unwrap(),
        &signed.challenge.payload,
        "awiki-root-authorization+jwt",
    );
    verify_jws(
        &signed.device_proof,
        &session.proposal.device_proposal["signing_public_jwk"],
        &signed.challenge.payload,
        "awiki-device-possession+jwt",
    );
    assert_eq!(
        session.proposal.phase,
        PinRecoveryPhase::PublicationUncertain
    );
    let request = fixture.signing_request(&session);
    assert_eq!(
        session.sign_pin_recovery_intent(request).err(),
        Some(IdentityError::InvalidDocumentChangeState)
    );
    assert_eq!(
        fixture
            .manager
            .delete(
                &session.proposal.identity,
                crate::DeleteIdentityRequest {
                    discard_pending_changes: true
                }
            )
            .err(),
        Some(IdentityError::InvalidDocumentChangeState)
    );
}

#[test]
fn pin_candidate_tampering_and_wrong_operation_are_rejected_before_signing() {
    let mut fixture = Fixture::new();
    let mut session = fixture.begin();
    let mut request = fixture.signing_request(&session);
    request.candidate_document["service"] = json!([{"id":"evil"}]);
    assert_eq!(
        session.sign_pin_recovery_intent(request).err(),
        Some(IdentityError::InvalidRequest)
    );
    let mut request = fixture.signing_request(&session);
    request.challenge.payload["operation_id"] = json!("99999999-9999-4999-8999-999999999999");
    assert_eq!(
        session.sign_pin_recovery_intent(request).err(),
        Some(IdentityError::InvalidRequest)
    );
    let mut request = fixture.signing_request(&session);
    request.challenge.payload["purpose"] = json!("awiki.pin-recovery.authorize.v1");
    assert_eq!(
        session.sign_pin_recovery_intent(request).err(),
        Some(IdentityError::InvalidRequest)
    );
    assert_eq!(session.proposal.phase, PinRecoveryPhase::Prepared);
}

#[test]
fn pin_exact_committed_document_activates_same_root_and_new_keys_after_restart() {
    let mut fixture = Fixture::new();
    let mut session = fixture.begin();
    let request = fixture.signing_request(&session);
    let signed = session.sign_pin_recovery_intent(request).unwrap();
    let reference = session.proposal.identity.clone();
    drop(session);
    fixture.manager = IdentityManager::open(config(fixture.target_dir.path(), 2)).unwrap();
    let request = fixture.begin_request(None);
    let mut session = fixture.manager.begin_pin_root_recovery(request).unwrap();
    let mut wrong = fixture.complete_request(&session, &signed);
    wrong.remote = fixture.remote.clone();
    assert!(session.complete_pin_root_recovery(wrong).is_err());
    let request = fixture.complete_request(&session, &signed);
    let active = session
        .complete_pin_root_recovery(request)
        .unwrap()
        .unwrap();
    assert_eq!(active.reference(), reference);
    assert_eq!(
        active.host_status().unwrap().root_capability,
        crate::host::HostRootCapability::Active
    );
    assert_eq!(
        fixture.export().as_pkcs8_der(),
        active
            .export_root_for_pin_backup(PinRootBackupRequest {
                expected_generation: active.pin_root_generation().unwrap(),
                root_kid: fixture.binding.root_kid.clone(),
                user_presence_confirmed: true
            })
            .unwrap()
            .as_pkcs8_der()
    );
    let request = fixture.complete_request(&session, &signed);
    assert!(session
        .complete_pin_root_recovery(request)
        .unwrap()
        .is_some());
}

#[test]
fn pin_conflicting_snapshot_cannot_sign_or_complete() {
    let mut fixture = Fixture::new();
    let mut first = fixture.begin();
    let request = fixture.begin_request(None);
    let mut stale = fixture.manager.begin_pin_root_recovery(request).unwrap();
    let request = fixture.signing_request(&first);
    let signed = first.sign_pin_recovery_intent(request).unwrap();
    let request = fixture.signing_request(&stale);
    assert_eq!(
        stale.sign_pin_recovery_intent(request).err(),
        Some(IdentityError::Conflict)
    );
    let request = fixture.complete_request(&stale, &signed);
    assert_eq!(
        stale.complete_pin_root_recovery(request).err(),
        Some(IdentityError::Conflict)
    );
}

#[test]
fn pin_not_committed_reconcile_keeps_device_and_requires_exact_base() {
    let mut fixture = Fixture::new();
    let mut session = fixture.begin();
    let device = session.proposal.device_proposal.clone();
    let request = fixture.signing_request(&session);
    let signed = session.sign_pin_recovery_intent(request).unwrap();
    let mut request = fixture.complete_request(&session, &signed);
    request.outcome = PinRecoveryRemoteOutcome::NotCommitted;
    assert!(session.complete_pin_root_recovery(request).is_err());
    let mut request = fixture.complete_request(&session, &signed);
    request.outcome = PinRecoveryRemoteOutcome::NotCommitted;
    request.remote = fixture.remote.clone();
    assert!(session
        .complete_pin_root_recovery(request)
        .unwrap()
        .is_none());
    assert_eq!(session.proposal.phase, PinRecoveryPhase::Prepared);
    assert_eq!(session.proposal.device_proposal, device);
    let request = fixture.signing_request(&session);
    assert!(session.sign_pin_recovery_intent(request).is_ok());
}

#[test]
fn pin_backup_signer_allows_only_fixed_enable_authorize_and_three_receipt_commit() {
    let fixture = Fixture::new();
    let mut binding = fixture.binding.clone();
    binding.encrypted_package_hash = None;
    let mut expected = intent(&binding, "enable", None, None);
    expected["registration_version"] = Value::Null;
    expected["registered_receipt_ids"] = json!([]);
    expected["verified_receipt_ids"] = json!([]);
    let ch = challenge(
        &binding,
        &fixture.remote,
        expected.clone(),
        "awiki.pin-recovery.authorize.v1",
    );
    let proof = fixture
        .source
        .sign_pin_recovery_intent(PinBackupIntentRequest {
            expected_generation: fixture.source.pin_root_generation().unwrap(),
            binding: binding.clone(),
            purpose: PinBackupPurpose::Authorize,
            expected_intent: expected.clone(),
            challenge: ch.clone(),
            user_presence_confirmed: true,
        })
        .unwrap();
    verify_jws(
        &proof,
        &public_jwk(&binding.root_public_key_multibase).unwrap(),
        &ch.payload,
        "awiki-root-authorization+jwt",
    );
    binding.encrypted_package_hash = fixture.binding.encrypted_package_hash.clone();
    let mut expected = intent(&binding, "enable", None, None);
    expected["registered_receipt_ids"] = json!([
        "66666666-6666-4666-8666-666666666666",
        "77777777-7777-4777-8777-777777777777"
    ]);
    let ch = challenge(
        &binding,
        &fixture.remote,
        expected.clone(),
        "awiki.pin-recovery.backup-commit.v1",
    );
    assert_eq!(
        fixture
            .source
            .sign_pin_recovery_intent(PinBackupIntentRequest {
                expected_generation: fixture.source.pin_root_generation().unwrap(),
                binding: binding.clone(),
                purpose: PinBackupPurpose::BackupCommit,
                expected_intent: expected,
                challenge: ch,
                user_presence_confirmed: true
            })
            .err(),
        Some(IdentityError::InvalidRequest)
    );
    let mut expected = intent(&binding, "enable", None, None);
    expected["registered_receipt_ids"] = json!([
        "66666666-6666-4666-8666-666666666666",
        "77777777-7777-4777-8777-777777777777",
        "88888888-8888-4888-8888-888888888888"
    ]);
    let ch = challenge(
        &binding,
        &fixture.remote,
        expected.clone(),
        "awiki.pin-recovery.backup-commit.v1",
    );
    assert!(fixture
        .source
        .sign_pin_recovery_intent(PinBackupIntentRequest {
            expected_generation: fixture.source.pin_root_generation().unwrap(),
            binding,
            purpose: PinBackupPurpose::BackupCommit,
            expected_intent: expected,
            challenge: ch,
            user_presence_confirmed: true
        })
        .is_ok());
}

#[test]
fn pin_not_committed_reconcile_accepts_forward_sibling_document_without_regenerating_keys() {
    let mut fixture = Fixture::new();
    let mut session = fixture.begin();
    let device = session.proposal.device_proposal.clone();
    let request = fixture.signing_request(&session);
    let signed = session.sign_pin_recovery_intent(request).unwrap();
    // The host has independently verified this newer document. Its service
    // change belongs to another publication; the PIN candidate must preserve it.
    let mut next = fixture.remote.document.as_value().clone();
    next["service"] = json!([{"id":format!("{}#new-service",fixture.binding.did),"type":"Messaging","serviceEndpoint":"https://example.com/new"}]);
    let next = crate::host::TypedProofPort::sign_document_proof(
        &fixture.source,
        crate::host::DocumentProofRequest {
            key: crate::KeySelector::Kid(fixture.binding.root_kid.clone()),
            document: next,
            options: crate::host::DocumentProofOptions {
                proof_purpose: Some("assertionMethod".into()),
                proof_type: Some(anp::proof::PROOF_TYPE_DATA_INTEGRITY.into()),
                cryptosuite: Some(anp::proof::CRYPTOSUITE_EDDSA_JCS_2022.into()),
                domain: Some("example.com".into()),
                challenge: Some("sibling-update".into()),
                ..Default::default()
            },
        },
    )
    .unwrap();
    let next = remote(next, 2, 2);
    let mut completion = fixture.complete_request(&session, &signed);
    completion.remote = next.clone();
    completion.outcome = PinRecoveryRemoteOutcome::NotCommitted;
    assert!(session
        .complete_pin_root_recovery(completion)
        .unwrap()
        .is_none());
    assert_eq!(session.proposal.device_proposal, device);
    fixture.remote = next;
    let request = fixture.signing_request(&session);
    let signed = session.sign_pin_recovery_intent(request).unwrap();
    assert_eq!(
        signed.signed_document["service"],
        fixture.remote.document.as_value()["service"]
    );
}

#[test]
fn pin_crash_before_registry_commit_removes_all_three_orphaned_keys() {
    let mut fixture = Fixture::new();
    let session = fixture.begin();
    let engine = session.identity.lock_engine().unwrap();
    let guard = engine.runtime().acquire_write().unwrap();
    let record = engine.record();
    let secrets = record
        .keys
        .iter()
        .filter(|key| key.origin == KeyOrigin::Managed)
        .map(|key| crate::keystore::SecretRef {
            identity_id: record.identity_id.clone(),
            key_id: key.kid.clone(),
            role: key.role,
            version: key.version,
        })
        .collect::<Vec<_>>();
    assert_eq!(secrets.len(), 3);
    let journal = crate::registry::CreationJournal::new(
        crate::identity::random_id(),
        record.identity_id.clone(),
        record.did.clone(),
        secrets.clone(),
        chrono::Utc::now().to_rfc3339(),
    );
    crate::registry::write_journal(engine.runtime().root(), &guard, &journal).unwrap();
    let mut registry = crate::registry::read_registry(engine.runtime().root()).unwrap();
    registry.identities.remove(&record.did);
    registry.generation += 1;
    crate::registry::write_registry(engine.runtime().root(), &guard, &registry).unwrap();
    drop(guard);
    let reopened = IdentityManager::open(config(fixture.target_dir.path(), 2)).unwrap();
    assert!(reopened.list().unwrap().is_empty());
    for secret in secrets {
        assert!(engine
            .runtime()
            .key_store()
            .open(engine.runtime().root_key(), &secret)
            .is_err());
    }
    assert!(crate::registry::list_journals(engine.runtime().root())
        .unwrap()
        .is_empty());
}

#[test]
fn pin_crash_after_activation_record_reconciles_registry_and_retries_without_new_keys() {
    let mut fixture = Fixture::new();
    let mut session = fixture.begin();
    let request = fixture.signing_request(&session);
    let signed = session.sign_pin_recovery_intent(request).unwrap();
    let previous_summary = {
        let engine = session.identity.lock_engine().unwrap();
        engine.record().summary()
    };
    let request = fixture.complete_request(&session, &signed);
    let identity = session
        .complete_pin_root_recovery(request)
        .unwrap()
        .unwrap();
    let engine = identity.lock_engine().unwrap();
    let guard = engine.runtime().acquire_write().unwrap();
    let journal = crate::registry::CreationJournal::new_state_transition(
        crate::identity::random_id(),
        engine.identity_id().into(),
        engine.did().into(),
        chrono::Utc::now().to_rfc3339(),
    );
    crate::registry::write_journal(engine.runtime().root(), &guard, &journal).unwrap();
    let mut registry = crate::registry::read_registry(engine.runtime().root()).unwrap();
    registry
        .identities
        .insert(engine.did().into(), previous_summary);
    registry.generation += 1;
    crate::registry::write_registry(engine.runtime().root(), &guard, &registry).unwrap();
    drop(guard);
    drop(engine);
    drop(identity);
    drop(session);
    fixture.manager = IdentityManager::open(config(fixture.target_dir.path(), 2)).unwrap();
    let request = fixture.begin_request(None);
    let mut session = fixture.manager.begin_pin_root_recovery(request).unwrap();
    assert_eq!(session.proposal.phase, PinRecoveryPhase::Active);
    let request = fixture.complete_request(&session, &signed);
    assert!(session
        .complete_pin_root_recovery(request)
        .unwrap()
        .is_some());
    assert_eq!(fixture.manager.list().unwrap().len(), 1);
}

#[test]
fn pin_rejects_rootless_web_and_absent_presence_without_partial_creation() {
    let mut fixture = Fixture::new();
    let web_dir = tempfile::tempdir().unwrap();
    let mut web_manager = IdentityManager::initialize(config(web_dir.path(), 4)).unwrap();
    let web = web_manager
        .create_engine_for_test(crate::DidCreateSpec {
            profile: crate::DidProfile::Web,
            domain: "example.com".into(),
            port: None,
            path_segments: vec!["web".into()],
            capabilities: crate::Capabilities { did_wba: true },
            managed_keys: vec![crate::ManagedKeySpec {
                fragment: "request".into(),
                role: KeyRole::RequestSigning,
            }],
            external_keys: vec![],
            services: vec![],
            agent_description_url: None,
            extensions: vec![],
        })
        .unwrap();
    let web_remote = remote(web.public_identity().unwrap().document.into_value(), 1, 1);
    let mut request = fixture.begin_request(Some(Zeroizing::new(
        fixture.export().as_pkcs8_der().to_vec(),
    )));
    request.binding.did = web.reference().did;
    request.remote = web_remote;
    assert_eq!(
        fixture.manager.begin_pin_root_recovery(request).err(),
        Some(IdentityError::Unsupported)
    );
    assert!(fixture.manager.list().unwrap().is_empty());
    let mut request = fixture.begin_request(Some(Zeroizing::new(
        fixture.export().as_pkcs8_der().to_vec(),
    )));
    request.user_presence_confirmed = false;
    assert_eq!(
        fixture.manager.begin_pin_root_recovery(request).err(),
        Some(IdentityError::CapabilityUnavailable)
    );
    assert!(fixture.manager.list().unwrap().is_empty());
}

#[test]
fn pin_challenge_expiry_receipts_presence_and_decimal_generation_fail_closed() {
    let mut fixture = Fixture::new();
    let mut session = fixture.begin();
    let mut request = fixture.signing_request(&session);
    request.user_presence_confirmed = false;
    assert_eq!(
        session.sign_pin_recovery_intent(request).err(),
        Some(IdentityError::CapabilityUnavailable)
    );
    let mut request = fixture.signing_request(&session);
    request.challenge.payload["exp"] = json!(chrono::Utc::now().timestamp() - 1);
    assert_eq!(
        session.sign_pin_recovery_intent(request).err(),
        Some(IdentityError::InvalidRequest)
    );
    let mut request = fixture.signing_request(&session);
    request.challenge.intent["verified_receipt_ids"] = json!([
        "44444444-4444-4444-8444-444444444444",
        "44444444-4444-4444-8444-444444444444"
    ]);
    request.challenge.payload["intent_hash"] = json!(hash_json(&request.challenge.intent).unwrap());
    assert_eq!(
        session.sign_pin_recovery_intent(request).err(),
        Some(IdentityError::InvalidRequest)
    );
    for generation in ["0", "01", "1.2", "-1"] {
        let mut binding = fixture.binding.clone();
        binding.binding_generation = generation.into();
        assert_eq!(
            validate_binding(&binding, fixture.remote.document.as_value()).err(),
            Some(IdentityError::InvalidRequest)
        );
    }
    assert_eq!(session.proposal.phase, PinRecoveryPhase::Prepared);
}

#[test]
fn pin_malformed_intent_fields_never_change_pending_phase_or_generation() {
    let mut fixture = Fixture::new();
    let mut session = fixture.begin();
    let before = session.proposal.clone();
    let cases = [
        ("registration_version", json!({"arbitrary":"data"})),
        ("registration_version", json!(42)),
        (
            "registration_version",
            json!("ABCDEF0123456789ABCDEF0123456789"),
        ),
        ("registration_version", json!("short")),
        ("expected_active_epoch", json!(0)),
        ("expected_active_epoch", json!(1.5)),
        ("backup_hash", json!({"hash":"data"})),
        ("backup_hash", json!("short")),
        ("new_device_proposal_hash", json!(false)),
        ("candidate_document_digest", json!([])),
        ("registered_receipt_ids", json!(["not-a-uuid"])),
        (
            "verified_receipt_ids",
            json!(["44444444-4444-4444-8444-444444444444", 123]),
        ),
        (
            "registered_receipt_ids",
            json!([
                "11111111-1111-4111-8111-111111111111",
                "22222222-2222-4222-8222-222222222222",
                "33333333-3333-4333-8333-333333333333",
                "44444444-4444-4444-8444-444444444444"
            ]),
        ),
    ];
    for (field, value) in cases {
        let mut request = fixture.signing_request(&session);
        request.challenge.intent[field] = value;
        // A well-formed hash does not make a malformed intent safe to sign.
        request.challenge.payload["intent_hash"] =
            json!(hash_json(&request.challenge.intent).unwrap());
        assert_eq!(
            session.sign_pin_recovery_intent(request).err(),
            Some(IdentityError::InvalidRequest),
            "{field}"
        );
        assert_eq!(session.proposal, before);
    }
    let resumed = fixture
        .manager
        .begin_pin_root_recovery(fixture.begin_request(None))
        .unwrap();
    assert_eq!(resumed.proposal, before);
}

#[test]
fn pin_schema_rejects_bad_uuid_slot_and_hash_even_when_binding_matches() {
    let mut fixture = Fixture::new();
    for (field, value) in [
        ("operation_id", "operation-1"),
        ("recovery_id", "recovery-1"),
        ("slot_id", "rs_short"),
        ("slot_id", "no-prefix"),
        ("op_jkt", "bad-thumbprint"),
        ("config_hash", "bad-config"),
        ("audience", "https://example.com/invalid path"),
    ] {
        let mut request = fixture.begin_request(Some(Zeroizing::new(
            fixture.export().as_pkcs8_der().to_vec(),
        )));
        let mut binding = serde_json::to_value(&request.binding).unwrap();
        binding[field] = json!(value);
        request.binding = serde_json::from_value(binding).unwrap();
        assert_eq!(
            fixture.manager.begin_pin_root_recovery(request).err(),
            Some(IdentityError::InvalidRequest),
            "{field}"
        );
        assert!(fixture.manager.list().unwrap().is_empty());
    }
    let mut session = fixture.begin();
    for (field, value) in [
        ("challenge_id", json!("challenge-1")),
        ("nonce", json!("short")),
        ("iat", json!(1.5)),
        ("document_version", json!("1")),
        ("registry_version", json!(0)),
        ("root_jkt", Value::Null),
    ] {
        let mut request = fixture.signing_request(&session);
        request.challenge.payload[field] = value;
        assert_eq!(
            session.sign_pin_recovery_intent(request).err(),
            Some(IdentityError::InvalidRequest),
            "{field}"
        );
        assert_eq!(session.proposal.phase, PinRecoveryPhase::Prepared);
    }
}

#[test]
fn pin_prepared_cancel_cleans_exact_namespace_and_allows_same_did_new_operation() {
    let mut fixture = Fixture::new();
    let mut session = fixture.begin();
    let old_device = session.proposal.device_proposal.clone();
    let old_binding = fixture.binding.clone();
    let old_generation = session.proposal.generation;
    let engine = session.identity.lock_engine().unwrap();
    let secrets = engine
        .record()
        .keys
        .iter()
        .map(|key| crate::keystore::SecretRef {
            identity_id: engine.identity_id().into(),
            key_id: key.kid.clone(),
            role: key.role,
            version: key.version,
        })
        .collect::<Vec<_>>();
    let runtime = std::sync::Arc::clone(engine.runtime());
    drop(engine);
    assert_eq!(
        session
            .cancel_pin_root_recovery(PinRecoveryCancelRequest {
                expected_generation: old_generation + 1,
                binding: old_binding.clone(),
            })
            .err(),
        Some(IdentityError::Conflict)
    );
    let mut wrong = old_binding.clone();
    wrong.operation_id = "99999999-9999-4999-8999-999999999999".into();
    assert_eq!(
        session
            .cancel_pin_root_recovery(PinRecoveryCancelRequest {
                expected_generation: old_generation,
                binding: wrong,
            })
            .err(),
        Some(IdentityError::InvalidDocumentChangeState)
    );
    session
        .cancel_pin_root_recovery(PinRecoveryCancelRequest {
            expected_generation: old_generation,
            binding: old_binding.clone(),
        })
        .unwrap();
    assert!(fixture.manager.list().unwrap().is_empty());
    for secret in secrets {
        assert!(runtime
            .key_store()
            .open(runtime.root_key(), &secret)
            .is_err());
    }
    assert!(crate::registry::list_journals(runtime.root())
        .unwrap()
        .is_empty());
    session
        .cancel_pin_root_recovery(PinRecoveryCancelRequest {
            expected_generation: old_generation,
            binding: old_binding.clone(),
        })
        .unwrap();
    fixture.binding.operation_id = "99999999-9999-4999-8999-999999999999".into();
    let fresh = fixture.begin();
    assert_ne!(fresh.proposal.device_proposal, old_device);
    assert_eq!(fresh.proposal.identity.did, fixture.binding.did);
    assert_eq!(
        session
            .cancel_pin_root_recovery(PinRecoveryCancelRequest {
                expected_generation: old_generation,
                binding: old_binding,
            })
            .err(),
        Some(IdentityError::Conflict)
    );
    assert_eq!(fixture.manager.list().unwrap().len(), 1);
}

#[test]
fn pin_cancel_never_deletes_uncertain_or_active_custody() {
    let mut fixture = Fixture::new();
    let mut session = fixture.begin();
    let request = fixture.signing_request(&session);
    let signed = session.sign_pin_recovery_intent(request).unwrap();
    assert_eq!(
        session
            .cancel_pin_root_recovery(PinRecoveryCancelRequest {
                expected_generation: session.proposal.generation,
                binding: fixture.binding.clone(),
            })
            .err(),
        Some(IdentityError::InvalidDocumentChangeState)
    );
    let completion = fixture.complete_request(&session, &signed);
    let active = session
        .complete_pin_root_recovery(completion)
        .unwrap()
        .unwrap();
    assert_eq!(
        session
            .cancel_pin_root_recovery(PinRecoveryCancelRequest {
                expected_generation: session.proposal.generation,
                binding: fixture.binding.clone(),
            })
            .err(),
        Some(IdentityError::InvalidDocumentChangeState)
    );
    assert_eq!(
        active.host_status().unwrap().root_capability,
        crate::host::HostRootCapability::Active
    );
    assert_eq!(fixture.manager.list().unwrap().len(), 1);
}

mod v4_retirement;
