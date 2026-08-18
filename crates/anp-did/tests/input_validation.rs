use anp_did::{
    Capabilities, DidCreateSpec, DidError, DidProfile, ExternalPublicKeyMaterial,
    ExternalPublicKeySpec, KeyRole, ManagedKeySpec, PublicOkpJwk,
};

fn valid_spec() -> DidCreateSpec {
    DidCreateSpec {
        profile: DidProfile::E1,
        domain: "example.com".to_string(),
        port: None,
        path_segments: vec!["agents".to_string(), "alice".to_string()],
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

#[test]
fn rejects_external_root_empty_path_and_missing_managed_request_key() {
    let mut spec = valid_spec();
    spec.external_keys.push(ExternalPublicKeySpec {
        kid: "#external-root".to_string(),
        role: KeyRole::RootControl,
        material: ExternalPublicKeyMaterial::Jwk {
            public_key_jwk: PublicOkpJwk {
                kty: "OKP".to_string(),
                crv: "Ed25519".to_string(),
                x: "11qYAYLefK3DUy1zSvP1cptC7Zb7e7S9F9ZAR4c7D0k".to_string(),
            },
        },
    });
    assert_eq!(spec.validate(), Err(DidError::ExternalRootControl));

    let mut spec = valid_spec();
    spec.path_segments.clear();
    assert_eq!(spec.validate(), Err(DidError::EmptyPath));

    let mut spec = valid_spec();
    spec.managed_keys
        .retain(|key| key.role != KeyRole::RequestSigning);
    assert_eq!(spec.validate(), Err(DidError::MissingManagedRequestSigning));
}

#[test]
fn rejects_private_jwk_unknown_extension_and_oversized_input() {
    let private_jwk = r##"{
        "kid":"#external",
        "role":"request_signing",
        "material":{
            "format":"jwk",
            "public_key_jwk":{
                "kty":"OKP",
                "crv":"Ed25519",
                "x":"11qYAYLefK3DUy1zSvP1cptC7Zb7e7S9F9ZAR4c7D0k",
                "d":"private"
            }
        }
    }"##;
    assert!(serde_json::from_str::<ExternalPublicKeySpec>(private_jwk).is_err());

    let unknown_extension = r#"{"type":"unknown","value":{}}"#;
    assert!(serde_json::from_str::<anp_did::DidExtensionSpec>(unknown_extension).is_err());

    let mut spec = valid_spec();
    spec.path_segments[0] = "x".repeat(129);
    assert_eq!(spec.validate(), Err(DidError::InvalidPathSegment));
    spec = valid_spec();
    spec.managed_keys[0].fragment = "x".repeat(129);
    assert_eq!(spec.validate(), Err(DidError::InvalidKidFragment));
    spec = valid_spec();
    spec.path_segments[0] = "bad/segment".to_string();
    assert_eq!(spec.validate(), Err(DidError::InvalidPathSegment));

    let unsupported_profile = r#""k1""#;
    assert!(serde_json::from_str::<DidProfile>(unsupported_profile).is_err());
}
