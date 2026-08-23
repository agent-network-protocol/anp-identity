use anp_identity::host::{
    ExactHttpRequest, HttpRequestSigningOptions, HttpRequestSigningPort, KeyAgreementPort,
    KeyAgreementRequest,
};
use anp_identity::{
    CreateIdentityCapabilities, CreateIdentityProfile, CreateIdentityRequest, IdentityManager,
    IdentityManagerConfig, InjectedStoreKey, KeyPurpose, KeySelector, ManagedIdentity,
    ManagedKeyInput, ManagedKeyRole, OriginProofOptions, OriginProofRequest, RootKeySource,
    SignRequest, SigningPurpose,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn hot_paths(criterion: &mut Criterion) {
    let root = tempfile::tempdir().expect("create benchmark root");
    let root_key = [0x51; 32];
    let config = || IdentityManagerConfig {
        state_root: root.path().to_path_buf(),
        root_key: RootKeySource::Injected(InjectedStoreKey::new("benchmark", root_key)),
    };
    let mut manager = IdentityManager::initialize(config()).expect("initialize benchmark store");
    let identity = manager
        .create(identity_request())
        .expect("create benchmark identity");
    let agreement_public = agreement_public(&identity);
    let meta = serde_json::json!({
        "sender_did": identity.reference().did,
        "timestamp": 1_787_403_600_i64,
        "target": {
            "kind": "agent",
            "did": "did:wba:example.com:agents:recipient"
        },
        "operation_id": "benchmark-operation",
        "message_id": "benchmark-message",
        "content_type": "application/json",
    });
    let body = serde_json::json!({"message": "benchmark"});

    criterion.bench_function("manager_open_injected", |bencher| {
        bencher.iter(|| black_box(IdentityManager::open(config()).expect("open benchmark store")))
    });

    criterion.bench_function("sign_request", |bencher| {
        bencher.iter(|| {
            black_box(
                identity
                    .sign(SignRequest {
                        purpose: SigningPurpose::Authentication,
                        key: KeySelector::Kid("#request".to_owned()),
                        payload: black_box(b"anp-identity benchmark payload".to_vec()),
                    })
                    .expect("sign benchmark payload"),
            )
        })
    });

    criterion.bench_function("sign_origin_proof", |bencher| {
        bencher.iter(|| {
            black_box(
                identity
                    .sign_origin_proof(OriginProofRequest {
                        method: "message.send".to_owned(),
                        meta: black_box(meta.clone()),
                        body: black_box(body.clone()),
                        key: KeySelector::Kid("#request".to_owned()),
                        options: OriginProofOptions::default(),
                    })
                    .expect("sign benchmark Origin Proof"),
            )
        })
    });

    criterion.bench_function("prepare_http_signature", |bencher| {
        bencher.iter(|| {
            black_box(
                identity
                    .prepare_http_signature(ExactHttpRequest {
                        key: KeySelector::Kid("#request".to_owned()),
                        url: "https://api.example.com/messages".to_owned(),
                        method: "POST".to_owned(),
                        headers: Vec::new(),
                        body: Some(black_box(br#"{"message":"benchmark"}"#.to_vec())),
                        options: HttpRequestSigningOptions::default(),
                    })
                    .expect("sign benchmark HTTP request"),
            )
        })
    });

    criterion.bench_function("ecdh", |bencher| {
        bencher.iter(|| {
            black_box(
                identity
                    .derive_shared_secret(KeyAgreementRequest {
                        key: KeySelector::Kid("#agreement".to_owned()),
                        peer_public: black_box(agreement_public),
                    })
                    .expect("derive benchmark shared secret"),
            )
        })
    });
}

fn agreement_public(identity: &ManagedIdentity) -> [u8; 32] {
    let public = identity.public_identity().expect("public identity");
    let key = public
        .active_keys
        .iter()
        .find(|key| key.purposes.contains(&KeyPurpose::KeyAgreement))
        .expect("agreement key");
    let method =
        anp::authentication::find_verification_method(public.document.as_value(), &key.kid)
            .expect("agreement verification method");
    match anp::authentication::extract_public_key(&method).expect("agreement public key") {
        anp::PublicKeyMaterial::X25519(bytes) => bytes,
        _ => panic!("agreement key must be X25519"),
    }
}

fn identity_request() -> CreateIdentityRequest {
    CreateIdentityRequest {
        profile: CreateIdentityProfile::E1,
        domain: "example.com".to_owned(),
        port: None,
        path_segments: vec!["agents".to_owned(), "benchmark".to_owned()],
        capabilities: CreateIdentityCapabilities { did_wba: true },
        managed_keys: vec![
            managed_key("root", ManagedKeyRole::RootControl),
            managed_key("request", ManagedKeyRole::RequestSigning),
            managed_key("agreement", ManagedKeyRole::E2eeAgreement),
        ],
        external_keys: Vec::new(),
        services: Vec::new(),
        agent_description_url: None,
        extensions: Vec::new(),
    }
}

fn managed_key(fragment: &str, role: ManagedKeyRole) -> ManagedKeyInput {
    ManagedKeyInput {
        fragment: fragment.to_owned(),
        role,
    }
}

criterion_group!(benches, hot_paths);
criterion_main!(benches);
