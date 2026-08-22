use anp_identity::{
    Capabilities, DidCreateSpec, DidExtensionSpec, DidProfile, DidStore, KeyRole, ManagedKeySpec,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn hot_paths(criterion: &mut Criterion) {
    let root = tempfile::tempdir().expect("create benchmark root");
    let root_key = [0x51; 32];
    let mut store = DidStore::initialize_injected(root.path(), "benchmark", root_key)
        .expect("initialize benchmark store");
    let identity = store
        .create_identity(identity_spec())
        .expect("create benchmark identity");
    let agreement_public = identity
        .public_key_bytes("#agreement")
        .expect("read agreement public key");
    let meta = serde_json::json!({
        "sender_did": identity.did(),
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

    criterion.bench_function("store_open_injected", |bencher| {
        bencher.iter(|| {
            black_box(
                DidStore::open_injected(root.path(), "benchmark", root_key)
                    .expect("open benchmark store"),
            )
        });
    });

    criterion.bench_function("sign_request", |bencher| {
        bencher.iter(|| {
            black_box(
                identity
                    .sign("#request", black_box(b"anp-identity benchmark payload"))
                    .expect("sign benchmark payload"),
            )
        });
    });

    criterion.bench_function("sign_origin_proof", |bencher| {
        bencher.iter(|| {
            black_box(
                identity
                    .sign_origin_proof(
                        "message.send",
                        black_box(&meta),
                        black_box(&body),
                        "#request",
                        Default::default(),
                    )
                    .expect("sign benchmark Origin Proof"),
            )
        });
    });

    criterion.bench_function("http_signature_headers", |bencher| {
        bencher.iter(|| {
            black_box(
                identity
                    .http_signature_headers(
                        "#request",
                        "https://api.example.com/messages",
                        "POST",
                        None,
                        Some(black_box(br#"{"message":"benchmark"}"#)),
                    )
                    .expect("sign benchmark HTTP request"),
            )
        });
    });

    criterion.bench_function("ecdh", |bencher| {
        bencher.iter(|| {
            black_box(
                identity
                    .ecdh("#agreement", black_box(&agreement_public))
                    .expect("derive benchmark shared secret"),
            )
        });
    });
}

fn identity_spec() -> DidCreateSpec {
    DidCreateSpec {
        profile: DidProfile::E1,
        domain: "example.com".to_owned(),
        port: None,
        path_segments: vec!["agents".to_owned(), "benchmark".to_owned()],
        capabilities: Capabilities { did_wba: true },
        managed_keys: vec![
            managed_key("root", KeyRole::RootControl),
            managed_key("request", KeyRole::RequestSigning),
            managed_key("agreement", KeyRole::E2eeAgreement),
        ],
        external_keys: Vec::new(),
        services: Vec::new(),
        agent_description_url: None,
        extensions: Vec::<DidExtensionSpec>::new(),
    }
}

fn managed_key(fragment: &str, role: KeyRole) -> ManagedKeySpec {
    ManagedKeySpec {
        fragment: fragment.to_owned(),
        role,
    }
}

criterion_group!(benches, hot_paths);
criterion_main!(benches);
