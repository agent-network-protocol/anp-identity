use super::*;
use crate::facade::{IdentityManager, IdentityManagerConfig, InjectedStoreKey, RootKeySource};
use crate::{Capabilities, DidCreateSpec, DidProfile, ManagedKeySpec};

#[test]
fn purpose_signing_selects_one_role_and_domain_separates_application_bytes() {
    let (_root, identity) = identity(false);
    let auth = identity
        .sign(SignRequest {
            purpose: SigningPurpose::Authentication,
            key: KeySelector::Default,
            payload: b"payload".to_vec(),
        })
        .unwrap();
    assert!(auth.kid.ends_with("#request"));
    assert_eq!(
        identity
            .verify(VerifyRequest {
                purpose: SigningPurpose::Authentication,
                kid: auth.kid.clone(),
                payload: b"payload".to_vec(),
                signature: auth.bytes.clone(),
            })
            .unwrap(),
        VerificationOutcome::Valid
    );
    assert_eq!(
        identity
            .verify(VerifyRequest {
                purpose: SigningPurpose::Authentication,
                kid: auth.kid,
                payload: b"tampered".to_vec(),
                signature: auth.bytes,
            })
            .unwrap(),
        VerificationOutcome::Invalid
    );

    let application = identity
        .sign(SignRequest {
            purpose: SigningPurpose::ApplicationAssertion {
                domain: "awiki.message.v1".to_owned(),
            },
            key: KeySelector::Default,
            payload: b"payload".to_vec(),
        })
        .unwrap();
    assert!(application.kid.ends_with("#application"));
    assert_eq!(
        identity
            .verify(VerifyRequest {
                purpose: SigningPurpose::ApplicationAssertion {
                    domain: "other.domain".to_owned(),
                },
                kid: application.kid,
                payload: b"payload".to_vec(),
                signature: application.bytes,
            })
            .unwrap(),
        VerificationOutcome::Invalid
    );
}

#[test]
fn explicit_key_still_checks_purpose_and_ambiguous_default_fails_closed() {
    let (_root, identity) = identity(true);
    assert_eq!(
        identity
            .sign(SignRequest {
                purpose: SigningPurpose::Authentication,
                key: KeySelector::Default,
                payload: b"payload".to_vec(),
            })
            .err(),
        Some(IdentityError::AmbiguousKey)
    );
    assert_eq!(
        identity
            .sign(SignRequest {
                purpose: SigningPurpose::DeviceAssertion,
                key: KeySelector::Kid("#request".to_owned()),
                payload: b"payload".to_vec(),
            })
            .err(),
        Some(IdentityError::KeyPurposeViolation)
    );
    assert_eq!(
        identity
            .sign(SignRequest {
                purpose: SigningPurpose::ApplicationAssertion {
                    domain: " ".to_owned(),
                },
                key: KeySelector::Kid("#application".to_owned()),
                payload: b"payload".to_vec(),
            })
            .err(),
        Some(IdentityError::InvalidRequest)
    );
}

#[test]
fn facade_origin_proof_matches_the_engine_semantics() {
    let (_root, identity) = identity(false);
    let meta = serde_json::json!({
        "sender_did": identity.reference().did,
        "timestamp": 1_787_403_600_i64,
        "target": {"kind": "agent", "did": "did:wba:example.com:facade:peer"},
        "operation_id": "operation-1",
        "message_id": "message-1",
        "content_type": "application/json"
    });
    let body = serde_json::json!({"message": "facade"});
    let facade = identity
        .sign_origin_proof(OriginProofRequest {
            method: "message.send".to_owned(),
            meta: meta.clone(),
            body: body.clone(),
            key: KeySelector::Kid("#request".to_owned()),
            options: OriginProofOptions {
                created: Some(1_787_403_600),
                expires: Some(1_787_403_900),
                nonce: Some("facade-parity".to_owned()),
            },
        })
        .unwrap();
    let engine = identity
        .lock_engine()
        .unwrap()
        .sign_origin_proof(
            "message.send",
            &meta,
            &body,
            "#request",
            anp::proof::Rfc9421OriginProofGenerationOptions {
                created: Some(1_787_403_600),
                expires: Some(1_787_403_900),
                nonce: Some("facade-parity".to_owned()),
                label: None,
            },
        )
        .unwrap();
    assert_eq!(facade.content_digest, engine.content_digest);
    assert_eq!(facade.signature_input, engine.signature_input);
    assert_eq!(facade.signature, engine.signature);
}

fn identity(duplicate_request: bool) -> (tempfile::TempDir, ManagedIdentity) {
    let root = tempfile::tempdir().unwrap();
    let mut manager = IdentityManager::initialize(IdentityManagerConfig {
        state_root: root.path().to_owned(),
        root_key: RootKeySource::Injected(InjectedStoreKey::new("signing", [0x81; 32])),
    })
    .unwrap();
    let mut keys = vec![
        managed("root", KeyRole::RootControl),
        managed("request", KeyRole::RequestSigning),
        managed("device", KeyRole::DeviceSigning),
        managed("application", KeyRole::E2eeSigning),
    ];
    if duplicate_request {
        keys.push(managed("request-secondary", KeyRole::RequestSigning));
    }
    let identity = manager
        .create(DidCreateSpec {
            profile: DidProfile::E1,
            domain: "example.com".to_owned(),
            port: None,
            path_segments: vec!["facade".to_owned(), "signing".to_owned()],
            capabilities: Capabilities { did_wba: true },
            managed_keys: keys,
            external_keys: Vec::new(),
            services: Vec::new(),
            agent_description_url: None,
            extensions: Vec::new(),
        })
        .unwrap();
    (root, identity)
}

fn managed(fragment: &str, role: KeyRole) -> ManagedKeySpec {
    ManagedKeySpec {
        fragment: fragment.to_owned(),
        role,
    }
}
