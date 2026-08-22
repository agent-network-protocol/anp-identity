use super::*;
use crate::{
    Capabilities, DidCreateSpec, DidProfile, IdentityManager, IdentityManagerConfig,
    InjectedStoreKey, KeyRole, ManagedKeySpec, RootKeySource,
};

#[test]
fn exact_http_signing_matches_engine_and_binds_the_request() {
    let (_root, identity) = identity();
    let request = ExactHttpRequest {
        key: KeySelector::Default,
        url: "https://api.example.com/messages".to_owned(),
        method: "POST".to_owned(),
        headers: vec![HttpHeader {
            name: "X-Request-ID".to_owned(),
            value: "request-1".to_owned(),
        }],
        body: Some(br#"{"message":"hello"}"#.to_vec()),
        options: HttpRequestSigningOptions {
            nonce: Some("challenge".to_owned()),
            created: Some(1_787_403_600),
            expires: Some(1_787_403_900),
            covered_components: Some(vec![
                "@method".to_owned(),
                "@target-uri".to_owned(),
                "content-digest".to_owned(),
            ]),
        },
    };
    let prepared = identity.prepare_http_signature(request.clone()).unwrap();
    assert!(prepared.kid.ends_with("#request"));
    assert!(prepared.binding_digest.starts_with("sha256:"));
    assert!(prepared
        .header_patch
        .iter()
        .any(|header| header.name.eq_ignore_ascii_case("signature")));

    let repeated = identity.prepare_http_signature(request).unwrap();
    assert_eq!(prepared, repeated);
}

#[test]
fn managed_headers_duplicate_names_and_oversized_bodies_fail_before_signing() {
    let (_root, identity) = identity();
    for headers in [
        vec![HttpHeader {
            name: "Authorization".to_owned(),
            value: "Bearer forbidden".to_owned(),
        }],
        vec![
            HttpHeader {
                name: "X-Test".to_owned(),
                value: "one".to_owned(),
            },
            HttpHeader {
                name: "x-test".to_owned(),
                value: "two".to_owned(),
            },
        ],
    ] {
        assert_eq!(
            identity
                .prepare_http_signature(ExactHttpRequest {
                    key: KeySelector::Default,
                    url: "https://api.example.com/messages".to_owned(),
                    method: "POST".to_owned(),
                    headers,
                    body: None,
                    options: HttpRequestSigningOptions::default(),
                })
                .err(),
            Some(IdentityError::InvalidRequest)
        );
    }

    assert_eq!(
        identity
            .prepare_http_signature(ExactHttpRequest {
                key: KeySelector::Default,
                url: "https://api.example.com/messages".to_owned(),
                method: "POST".to_owned(),
                headers: Vec::new(),
                body: Some(vec![0; MAX_HTTP_SIGNING_BODY_BYTES + 1]),
                options: HttpRequestSigningOptions::default(),
            })
            .err(),
        Some(IdentityError::InvalidRequest)
    );
}

#[test]
fn device_authentication_key_remains_valid_for_http_signing() {
    let root = tempfile::tempdir().unwrap();
    let mut manager = IdentityManager::initialize(IdentityManagerConfig {
        state_root: root.path().to_owned(),
        root_key: RootKeySource::Injected(InjectedStoreKey::new("http-device", [0x92; 32])),
    })
    .unwrap();
    let identity = manager
        .create(DidCreateSpec {
            profile: DidProfile::E1,
            domain: "example.com".to_owned(),
            port: None,
            path_segments: vec!["facade".to_owned(), "http-device".to_owned()],
            capabilities: Capabilities { did_wba: true },
            managed_keys: vec![
                ManagedKeySpec {
                    fragment: "root".to_owned(),
                    role: KeyRole::RootControl,
                },
                ManagedKeySpec {
                    fragment: "device".to_owned(),
                    role: KeyRole::DeviceSigning,
                },
            ],
            external_keys: Vec::new(),
            services: Vec::new(),
            agent_description_url: None,
            extensions: Vec::new(),
        })
        .unwrap();
    let attempt = identity
        .prepare_http_signature(ExactHttpRequest {
            key: KeySelector::Kid("#device".to_owned()),
            url: "https://api.example.com/messages".to_owned(),
            method: "POST".to_owned(),
            headers: Vec::new(),
            body: None,
            options: HttpRequestSigningOptions::default(),
        })
        .unwrap();
    assert!(attempt.kid.ends_with("#device"));
}

fn identity() -> (tempfile::TempDir, crate::ManagedIdentity) {
    let root = tempfile::tempdir().unwrap();
    let mut manager = IdentityManager::initialize(IdentityManagerConfig {
        state_root: root.path().to_owned(),
        root_key: RootKeySource::Injected(InjectedStoreKey::new("http", [0x91; 32])),
    })
    .unwrap();
    let identity = manager
        .create(DidCreateSpec {
            profile: DidProfile::E1,
            domain: "example.com".to_owned(),
            port: None,
            path_segments: vec!["facade".to_owned(), "http".to_owned()],
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
            services: Vec::new(),
            agent_description_url: None,
            extensions: Vec::new(),
        })
        .unwrap();
    (root, identity)
}
