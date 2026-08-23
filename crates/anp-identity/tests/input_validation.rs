use anp_identity::{
    CreateIdentityCapabilities, CreateIdentityExtension, CreateIdentityProfile,
    CreateIdentityRequest, DeviceManifestEntryInput, ExternalPublicKeyInput,
    ExternalPublicKeyInputMaterial, IdentityError, IdentityManager, IdentityManagerConfig,
    InjectedStoreKey, ManagedKeyInput, ManagedKeyRole, OkpPublicJwk, RootKeySource,
};

fn valid_request() -> CreateIdentityRequest {
    CreateIdentityRequest {
        profile: CreateIdentityProfile::E1,
        domain: "example.com".to_string(),
        port: None,
        path_segments: vec!["agents".to_string(), "alice".to_string()],
        capabilities: CreateIdentityCapabilities { did_wba: true },
        managed_keys: vec![
            ManagedKeyInput {
                fragment: "root".to_string(),
                role: ManagedKeyRole::RootControl,
            },
            ManagedKeyInput {
                fragment: "request".to_string(),
                role: ManagedKeyRole::RequestSigning,
            },
        ],
        external_keys: Vec::new(),
        services: Vec::new(),
        agent_description_url: None,
        extensions: Vec::new(),
    }
}

fn assert_invalid(request: CreateIdentityRequest) {
    let root = tempfile::tempdir().unwrap();
    let mut manager = IdentityManager::initialize(IdentityManagerConfig {
        state_root: root.path().to_path_buf(),
        root_key: RootKeySource::Injected(InjectedStoreKey::new("validation", [0x41; 32])),
    })
    .unwrap();
    assert_eq!(
        manager.create(request).err(),
        Some(IdentityError::InvalidRequest)
    );
}

#[test]
fn rejects_external_root_empty_path_and_missing_managed_request_key() {
    let mut request = valid_request();
    request.external_keys.push(ExternalPublicKeyInput {
        kid: "#external-root".to_string(),
        role: ManagedKeyRole::RootControl,
        material: ExternalPublicKeyInputMaterial::Jwk {
            public_key_jwk: OkpPublicJwk {
                kty: "OKP".to_string(),
                crv: "Ed25519".to_string(),
                x: "11qYAYLefK3DUy1zSvP1cptC7Zb7e7S9F9ZAR4c7D0k".to_string(),
            },
        },
    });
    assert_invalid(request);

    let mut request = valid_request();
    request.path_segments.clear();
    assert_invalid(request);

    let mut request = valid_request();
    request
        .managed_keys
        .retain(|key| key.role != ManagedKeyRole::RequestSigning);
    assert_invalid(request);
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
    assert!(serde_json::from_str::<ExternalPublicKeyInput>(private_jwk).is_err());

    let unknown_extension = r#"{"type":"unknown","value":{}}"#;
    assert!(serde_json::from_str::<CreateIdentityExtension>(unknown_extension).is_err());

    let mut request = valid_request();
    request.path_segments[0] = "x".repeat(129);
    assert_invalid(request);
    let mut request = valid_request();
    request.managed_keys[0].fragment = "x".repeat(129);
    assert_invalid(request);
    let mut request = valid_request();
    request.path_segments[0] = "bad/segment".to_string();
    assert_invalid(request);

    let unsupported_profile = r#""k1""#;
    assert!(serde_json::from_str::<CreateIdentityProfile>(unsupported_profile).is_err());

    let mut request = valid_request();
    request.extensions = vec![CreateIdentityExtension::DeviceManifest {
        devices: vec![DeviceManifestEntryInput {
            device_id: "device-1".to_string(),
            signing_key_id: "#request".to_string(),
            e2ee_key_id: "#agreement".to_string(),
            profiles: Vec::new(),
        }],
    }];
    assert_invalid(request);
}
