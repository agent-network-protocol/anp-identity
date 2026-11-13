use super::*;
use crate::facade::{IdentityManager, IdentityManagerConfig, InjectedStoreKey, RootKeySource};
use crate::{Capabilities, DidCreateSpec, DidProfile, ManagedKeySpec};
use ed25519_dalek::{Signature, VerifyingKey};

fn request() -> OAuthClientAssertionRequest {
    OAuthClientAssertionRequest {
        client_id: "https://id.example:443/agents/one/client.json".into(),
        audience: "https://as.example/token".into(),
        key: KeySelector::Default,
    }
}

#[test]
fn oauth_jwk_and_assertion_verify_with_independent_ed25519_implementation() {
    let (_root, identity) = identity(false);
    let jwk = identity.oauth_public_jwk(KeySelector::Default).unwrap();
    assert_eq!(
        (jwk.kty.as_str(), jwk.crv.as_str(), jwk.alg.as_str()),
        ("OKP", "Ed25519", "EdDSA")
    );
    assert!(!serde_json::to_value(&jwk)
        .unwrap()
        .as_object()
        .unwrap()
        .contains_key("d"));
    let token = identity.sign_oauth_client_assertion(request()).unwrap();
    let parts: Vec<_> = token.split('.').collect();
    assert_eq!(parts.len(), 3);
    let header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
    let claims: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    assert_eq!(header, json!({"alg":"EdDSA","typ":"JWT","kid":jwk.kid}));
    assert_eq!(claims["iss"], request().client_id);
    assert_eq!(claims["sub"], claims["iss"]);
    assert_eq!(claims["aud"], request().audience);
    assert_eq!(
        claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
        60
    );
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(claims["jti"].as_str().unwrap())
            .unwrap()
            .len(),
        32
    );
    let key: [u8; 32] = URL_SAFE_NO_PAD.decode(jwk.x).unwrap().try_into().unwrap();
    let verifier = VerifyingKey::from_bytes(&key).unwrap();
    let signature = Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
    verifier
        .verify_strict(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
        .unwrap();
    assert!(verifier.verify_strict(b"tampered", &signature).is_err());
    assert_ne!(
        token,
        identity.sign_oauth_client_assertion(request()).unwrap()
    );
}

#[test]
fn oauth_rejects_other_key_roles_and_ambiguous_selection() {
    let (_root, identity) = identity(false);
    for fragment in ["#root", "#device", "#application"] {
        let key = KeySelector::Kid(fragment.into());
        assert_eq!(
            identity.oauth_public_jwk(key.clone()).unwrap_err(),
            IdentityError::KeyPurposeViolation
        );
        let mut r = request();
        r.key = key;
        assert_eq!(
            identity.sign_oauth_client_assertion(r).unwrap_err(),
            IdentityError::KeyPurposeViolation
        );
    }
    let (_root2, ambiguous) = self::identity(true);
    assert_eq!(
        ambiguous
            .oauth_public_jwk(KeySelector::Default)
            .unwrap_err(),
        IdentityError::AmbiguousKey
    );
    assert_eq!(
        ambiguous
            .sign_oauth_client_assertion(request())
            .unwrap_err(),
        IdentityError::AmbiguousKey
    );
}

#[test]
fn oauth_url_validation_preserves_exact_identifiers_and_rejects_normalization() {
    for invalid in [
        "http://id.example/client",
        "https:///id.example/client",
        "https://id.example/a%",
        "https://id.example/a%gg",
        "https://id.example",
        "https://@id.example/client",
        "https://u:p@id.example/client",
        "https://id.example/a/../client",
        "https://id.example/%2E/client",
        "https://id.example/a?x=1",
        "https://id.example/a#frag",
        "https://id.example/\\client",
        " https://id.example/client",
        "https://id.example/a\n",
    ] {
        assert_eq!(
            validate_https_identifier(invalid, true),
            Err(IdentityError::InvalidRequest),
            "{invalid}"
        );
    }
    assert!(validate_https_identifier(&request().client_id, true).is_ok());
    assert!(validate_https_identifier("https://issuer.example", false).is_ok());
}

#[test]
fn oauth_rejects_claim_injection_at_dto_boundary() {
    let value = json!({"client_id":request().client_id,"audience":request().audience,"key":"default","exp":9999999999u64});
    assert!(serde_json::from_value::<OAuthClientAssertionRequest>(value).is_err());
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
        .create_engine_for_test(DidCreateSpec {
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
