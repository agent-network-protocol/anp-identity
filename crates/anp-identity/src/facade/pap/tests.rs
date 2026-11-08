use super::*;
use crate::{
    Capabilities, DidCreateSpec, DidProfile, IdentityManager, IdentityManagerConfig,
    InjectedStoreKey, ManagedKeySpec, RootKeySource,
};
fn config(root: &std::path::Path) -> IdentityManagerConfig {
    IdentityManagerConfig {
        state_root: root.into(),
        root_key: RootKeySource::Injected(InjectedStoreKey::new("pap", [73; 32])),
    }
}
fn setup() -> (tempfile::TempDir, IdentityManager, ManagedIdentity) {
    let root = tempfile::tempdir().unwrap();
    let mut manager = IdentityManager::initialize(config(root.path())).unwrap();
    let identity = manager
        .create_engine_for_test(DidCreateSpec {
            profile: DidProfile::E1,
            domain: "example.test".into(),
            port: None,
            path_segments: vec!["pap".into()],
            capabilities: Capabilities { did_wba: true },
            managed_keys: vec![
                ManagedKeySpec {
                    fragment: "root".into(),
                    role: KeyRole::RootControl,
                },
                ManagedKeySpec {
                    fragment: "request".into(),
                    role: KeyRole::RequestSigning,
                },
                ManagedKeySpec {
                    fragment: "oauth".into(),
                    role: KeyRole::OAuthAuthentication,
                },
            ],
            external_keys: vec![],
            services: vec![],
            agent_description_url: None,
            extensions: vec![],
        })
        .unwrap();
    (root, manager, identity)
}
fn scope() -> TemporaryKeyScope {
    TemporaryKeyScope {
        owner: "host".into(),
        company_id: "https://company.example".into(),
        user_id: "user-private".into(),
        account_slot: Some("account-one".into()),
    }
}
fn create(operation: &str) -> CreateTemporaryKeyRequest {
    CreateTemporaryKeyRequest {
        operation_id: operation.into(),
        scope: scope(),
    }
}
fn decode(token: &str) -> (Value, Value, Vec<u8>, String) {
    let p = token.split('.').collect::<Vec<_>>();
    (
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(p[0]).unwrap()).unwrap(),
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(p[1]).unwrap()).unwrap(),
        URL_SAFE_NO_PAD.decode(p[2]).unwrap(),
        format!("{}.{}", p[0], p[1]),
    )
}
fn verify(token: &str, jwk: &P256PublicJwk) -> (Value, Value) {
    use p256::ecdsa::signature::Verifier;
    let (h, c, s, i) = decode(token);
    assert_eq!(s.len(), 64);
    jwk.verifier()
        .unwrap()
        .verify(
            i.as_bytes(),
            &p256::ecdsa::Signature::from_slice(&s).unwrap(),
        )
        .unwrap();
    (h, c)
}
#[test]
fn pap_chain_dpop_and_persistence_use_separate_local_keys() {
    let (root, _manager, identity) = setup();
    let reference = identity.reference();
    let key = identity
        .create_delegated_key(create("delegated-one"))
        .unwrap();
    assert_eq!(
        identity
            .create_delegated_key(create("delegated-one"))
            .unwrap(),
        key
    );
    let dpop = identity.create_dpop_key(create("dpop-one")).unwrap();
    assert_ne!(key.public_jwk, dpop.public_jwk);
    let delegation = identity
        .issue_pap_delegation(PapDelegationRequest {
            client_id: "https://id.example/client.json".into(),
            key: KeySelector::Kid("#oauth".into()),
            delegated_key: TemporaryKeyReference {
                handle: key.handle.clone(),
                generation: 1,
            },
            scope: scope(),
            ttl_seconds: 300,
        })
        .unwrap();
    let public = identity
        .oauth_public_jwk(KeySelector::Kid("#oauth".into()))
        .unwrap();
    let jwk = P256PublicJwk {
        kty: public.kty,
        crv: public.crv,
        x: public.x,
        y: public.y.unwrap(),
    };
    let (header, claims) = verify(&delegation, &jwk);
    assert_eq!(header["typ"], "poppy-delegation+jwt");
    assert_eq!(claims.as_object().unwrap().len(), 5);
    assert!(claims.get("aud").is_none());
    assert!(claims.get("sub").is_none());
    assert!(!delegation.contains("user-private"));
    let session = identity
        .sign_pap_session_request(PapSessionRequest {
            handle: key.handle.clone(),
            generation: 1,
            scope: scope(),
            delegation: delegation.clone(),
            client_id: "https://id.example/client.json".into(),
            sid: "stable-sid".into(),
            sub: "user-private".into(),
            agent_id: None,
            http_method: "POST".into(),
            http_uri: "https://api.company.example/tools?q=one#fragment".into(),
            access_token: None,
        })
        .unwrap();
    let (h, c) = verify(&session, &key.public_jwk);
    assert_eq!(h["poppy_dlg"], delegation);
    assert_eq!(h["kid"], key.thumbprint);
    assert_eq!(c["htu"], "https://api.company.example/tools");
    assert!(c.get("exp").is_none());
    assert!(c.get("ath").is_none());
    let proof = identity
        .sign_dpop_proof(DpopProofRequest {
            handle: dpop.handle.clone(),
            generation: 1,
            scope: scope(),
            http_method: "GET".into(),
            http_uri: "https://api.company.example/tools?a=1".into(),
            access_token: Some("exact-token".into()),
            nonce: Some("as-nonce".into()),
        })
        .unwrap();
    let (h, c) = verify(&proof, &dpop.public_jwk);
    assert_eq!(h["typ"], "dpop+jwt");
    assert_eq!(
        c["ath"],
        URL_SAFE_NO_PAD.encode(Sha256::digest(b"exact-token"))
    );
    assert_eq!(c["nonce"], "as-nonce");
    let reopened = IdentityManager::open(config(root.path())).unwrap();
    let reloaded = reopened.get(&reference).unwrap();
    assert_eq!(
        reloaded
            .describe_temporary_key(DescribeTemporaryKeyRequest {
                handle: key.handle.clone(),
                generation: 1,
                scope: scope(),
                purpose: TemporaryKeyPurpose::PapSession
            })
            .unwrap(),
        key
    );
    assert_eq!(
        reloaded
            .create_delegated_key(create("delegated-one"))
            .unwrap(),
        key
    );
    for entry in std::fs::read_dir(root.path().join("records")).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["schema_version"], 2);
        assert!(v.get("algorithm").is_some());
        assert!(v.get("d").is_none());
    }
}
#[test]
fn pap_handles_reject_scope_purpose_generation_retirement_and_claim_injection() {
    let (_root, _manager, identity) = setup();
    let key = identity.create_delegated_key(create("one")).unwrap();
    let mut request = DescribeTemporaryKeyRequest {
        handle: key.handle.clone(),
        generation: 1,
        scope: scope(),
        purpose: TemporaryKeyPurpose::PapSession,
    };
    request.purpose = TemporaryKeyPurpose::PapDpop;
    assert_eq!(
        identity
            .describe_temporary_key(request.clone())
            .unwrap_err(),
        IdentityError::KeyPurposeViolation
    );
    request.purpose = TemporaryKeyPurpose::PapSession;
    request.scope.user_id = "other".into();
    assert_eq!(
        identity
            .describe_temporary_key(request.clone())
            .unwrap_err(),
        IdentityError::KeyPurposeViolation
    );
    request.scope = scope();
    request.generation = 2;
    assert_eq!(
        identity.describe_temporary_key(request).unwrap_err(),
        IdentityError::KeyUnavailable
    );
    assert_eq!(
        identity
            .sign_dpop_proof(DpopProofRequest {
                handle: key.handle.clone(),
                generation: 1,
                scope: scope(),
                http_method: "GET".into(),
                http_uri: "https://api.example/resource".into(),
                access_token: None,
                nonce: None
            })
            .unwrap_err(),
        IdentityError::KeyPurposeViolation
    );
    let mut changed = create("one");
    changed.scope.user_id = "other".into();
    assert_eq!(
        identity.create_delegated_key(changed).unwrap_err(),
        IdentityError::Conflict
    );
    identity
        .retire_temporary_key(RetireTemporaryKeyRequest {
            handle: key.handle.clone(),
            generation: 1,
            scope: scope(),
        })
        .unwrap();
    assert_eq!(
        identity.create_delegated_key(create("one")).unwrap_err(),
        IdentityError::Conflict
    );
    assert_eq!(
        identity
            .issue_pap_delegation(PapDelegationRequest {
                client_id: "https://id.example/client".into(),
                key: KeySelector::Kid("#oauth".into()),
                delegated_key: TemporaryKeyReference {
                    handle: key.handle,
                    generation: 1
                },
                scope: scope(),
                ttl_seconds: 300
            })
            .unwrap_err(),
        IdentityError::KeyUnavailable
    );
    assert!(serde_json::from_value::<P256PublicJwk>(
        json!({"kty":"EC","crv":"P-256","x":"bad","y":"bad","d":"secret"})
    )
    .is_err());
    assert!(P256PublicJwk {
        kty: "EC".into(),
        crv: "P-256".into(),
        x: "AA".into(),
        y: "AA".into()
    }
    .thumbprint()
    .is_err());
}
#[test]
fn oauth_key_change_is_pending_until_verified_commit_and_survives_reload() {
    let (root, _manager, mut identity) = setup();
    let reference = identity.reference();
    let request = super::super::oauth::OAuthKeyChangeRequest {
        fragment: "oauth-two".into(),
        operation_id: "oauth-change-one".into(),
        expected_revision: 1,
    };
    let mut change = identity.prepare_oauth_key_change(request.clone()).unwrap();
    let candidate = change.candidate().clone();
    assert_eq!(
        identity
            .prepare_oauth_key_change(request)
            .unwrap()
            .candidate(),
        &candidate
    );
    let jwk = identity
        .export_candidate_oauth_public_jwk("#oauth-two".into())
        .unwrap();
    assert_eq!(jwk.alg, "ES256");
    assert!(identity
        .oauth_public_jwk(KeySelector::Kid("#oauth-two".into()))
        .is_err());
    let attempt = change.begin_publication().unwrap();
    change
        .complete(
            attempt,
            crate::PublicationResult::Confirmed {
                evidence: crate::VerifiedPublicationEvidence {
                    document_version: 2,
                    registry_version: 2,
                    document_digest: format!("sha256:{}", candidate.candidate_digest),
                },
            },
        )
        .unwrap();
    assert_eq!(
        identity
            .oauth_public_jwk(KeySelector::Kid("#oauth-two".into()))
            .unwrap(),
        jwk
    );
    let reopened = IdentityManager::open(config(root.path())).unwrap();
    assert_eq!(
        reopened
            .get(&reference)
            .unwrap()
            .oauth_public_jwk(KeySelector::Kid("#oauth-two".into()))
            .unwrap(),
        jwk
    );
}

#[test]
fn temporary_journal_recovery_keeps_committed_keys_erases_orphans_and_finishes_retirement() {
    let (root, mut manager, identity) = setup();
    let reference = identity.reference();
    let public = identity.create_delegated_key(create("committed")).unwrap();
    {
        let engine = identity.lock_engine().unwrap();
        let guard = engine.runtime().acquire_write().unwrap();
        let stored = &engine.record().temporary_keys[0];
        let journal = UpdateJournal::new(
            "temporary-committed".into(),
            engine.identity_id().into(),
            vec![stored.secret_ref(engine.identity_id())],
            UpdateJournalKind::Prepare,
            chrono::Utc::now().to_rfc3339(),
        );
        write_update_journal(engine.runtime().root(), &guard, &journal).unwrap();
        let orphan = SecretRef {
            identity_id: engine.identity_id().into(),
            key_id: "urn:anp:temporary:orphan".into(),
            role: KeyRole::OAuthAuthentication,
            version: 1,
        };
        engine
            .runtime()
            .key_store()
            .seal_if_absent(
                &guard,
                engine.runtime().root_key(),
                orphan.clone(),
                crate::secret::SecretBytes::new(vec![21; 32]),
            )
            .unwrap();
        write_update_journal(
            engine.runtime().root(),
            &guard,
            &UpdateJournal::new(
                "temporary-orphan".into(),
                engine.identity_id().into(),
                vec![orphan],
                UpdateJournalKind::Prepare,
                chrono::Utc::now().to_rfc3339(),
            ),
        )
        .unwrap();
    }
    manager.recover().unwrap();
    let identity = manager.get(&reference).unwrap();
    assert_eq!(
        identity.create_delegated_key(create("committed")).unwrap(),
        public
    );
    {
        let engine = identity.lock_engine().unwrap();
        let guard = engine.runtime().acquire_write().unwrap();
        assert_eq!(engine.runtime().key_store().list().unwrap().len(), 4);
        write_update_journal(
            engine.runtime().root(),
            &guard,
            &UpdateJournal::new(
                "retire-before-tombstone".into(),
                engine.identity_id().into(),
                vec![engine.record().temporary_keys[0].secret_ref(engine.identity_id())],
                UpdateJournalKind::Cleanup,
                chrono::Utc::now().to_rfc3339(),
            ),
        )
        .unwrap();
    }
    manager.recover().unwrap();
    let identity = manager.get(&reference).unwrap();
    assert!(identity
        .describe_temporary_key(DescribeTemporaryKeyRequest {
            handle: public.handle,
            generation: 1,
            scope: scope(),
            purpose: TemporaryKeyPurpose::PapSession
        })
        .is_err());
    let engine = identity.lock_engine().unwrap();
    assert_eq!(engine.runtime().key_store().list().unwrap().len(), 3);
    assert!(std::fs::read_dir(root.path().join("update-transactions"))
        .map(|mut e| e.next().is_none())
        .unwrap_or(true));
}
#[test]
fn legacy_identity_schema_is_inferred_only_for_original_roles_and_future_schema_is_rejected() {
    let (root, _manager, identity) = setup();
    let reference = identity.reference();
    let path = std::fs::read_dir(root.path().join("identities"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut value: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    value["schema_version"] = json!(1);
    for key in value["keys"].as_array_mut().unwrap() {
        key.as_object_mut().unwrap().remove("algorithm");
    }
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(IdentityManager::open(config(root.path()))
        .and_then(|manager| manager.get(&reference))
        .is_err());
    value["keys"]
        .as_array_mut()
        .unwrap()
        .retain(|key| key["role"] != "oauth_authentication");
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(IdentityManager::open(config(root.path()))
        .and_then(|manager| manager.get(&reference))
        .is_ok());
    value["schema_version"] = json!(99);
    std::fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(IdentityManager::open(config(root.path()))
        .and_then(|manager| manager.get(&reference))
        .is_err());
}

#[test]
fn session_verifies_delegation_signature_type_claim_set_expiry_and_exact_confirmation() {
    let (_root, _manager, identity) = setup();
    let key = identity
        .create_delegated_key(create("delegation-validation"))
        .unwrap();
    let valid = identity
        .issue_pap_delegation(PapDelegationRequest {
            client_id: "https://id.example/client.json".into(),
            key: KeySelector::Kid("#oauth".into()),
            delegated_key: TemporaryKeyReference {
                handle: key.handle.clone(),
                generation: 1,
            },
            scope: scope(),
            ttl_seconds: 300,
        })
        .unwrap();
    let request = PapSessionRequest {
        handle: key.handle,
        generation: 1,
        scope: scope(),
        delegation: valid.clone(),
        client_id: "https://id.example/client.json".into(),
        sid: "one".into(),
        sub: scope().user_id,
        agent_id: None,
        http_method: "POST".into(),
        http_uri: "https://company.example/api".into(),
        access_token: None,
    };
    let (header, claims, _, _) = decode(&valid);
    for mutation in ["typ", "alg", "aud", "expiry", "cnf", "issuer"] {
        let mut h = header.clone();
        let mut c = claims.clone();
        match mutation {
            "typ" => h["typ"] = json!("JWT"),
            "alg" => h["alg"] = json!("EdDSA"),
            "aud" => c["aud"] = json!("https://company.example"),
            "expiry" => c["exp"] = json!(chrono::Utc::now().timestamp() - 1),
            "cnf" => c["cnf"]["jwk"]["x"] = json!("AA"),
            "issuer" => c["iss"] = json!("https://other.example/client.json"),
            _ => unreachable!(),
        }
        let token = {
            let engine = identity.lock_engine().unwrap();
            let metadata = select_oauth_key(&engine, &KeySelector::Kid("#oauth".into())).unwrap();
            sign_identity_jws(&engine, metadata, h, c).unwrap()
        };
        let mut bad = request.clone();
        bad.delegation = token;
        assert!(
            identity.sign_pap_session_request(bad).is_err(),
            "{mutation}"
        );
    }
    let (h, c, signature, input) = decode(&valid);
    assert_eq!(h["alg"], "ES256");
    assert!(c["cnf"].is_object());
    let der = p256::ecdsa::Signature::from_slice(&signature)
        .unwrap()
        .to_der();
    let mut bad = request.clone();
    bad.delegation = format!("{input}.{}", URL_SAFE_NO_PAD.encode(der.as_bytes()));
    assert!(identity.sign_pap_session_request(bad).is_err());
    let mut bad = request;
    bad.delegation.push('x');
    assert!(identity.sign_pap_session_request(bad).is_err());
}
