use super::*;
use crate::facade::{IdentityManager, IdentityManagerConfig, InjectedStoreKey, RootKeySource};
use crate::{Capabilities, DidCreateSpec, DidProfile, ManagedKeySpec};

#[test]
fn key_agreement_is_role_scoped_and_matches_x25519() {
    let root = tempfile::tempdir().unwrap();
    let mut manager = IdentityManager::initialize(IdentityManagerConfig {
        state_root: root.path().to_owned(),
        root_key: RootKeySource::Injected(InjectedStoreKey::new("agreement", [0xa1; 32])),
    })
    .unwrap();
    let identity = manager
        .create(DidCreateSpec {
            profile: DidProfile::E1,
            domain: "example.com".to_owned(),
            port: None,
            path_segments: vec!["facade".to_owned(), "agreement".to_owned()],
            capabilities: Capabilities { did_wba: true },
            managed_keys: vec![
                managed("root", KeyRole::RootControl),
                managed("request", KeyRole::RequestSigning),
                managed("agreement", KeyRole::E2eeAgreement),
            ],
            external_keys: Vec::new(),
            services: Vec::new(),
            agent_description_url: None,
            extensions: Vec::new(),
        })
        .unwrap();
    let peer_private = x25519_dalek::StaticSecret::from([0x19; 32]);
    let peer_public = x25519_dalek::PublicKey::from(&peer_private).to_bytes();
    let shared = identity
        .derive_shared_secret(KeyAgreementRequest {
            key: KeySelector::Default,
            peer_public,
        })
        .unwrap();
    assert!(shared.as_bytes().iter().any(|byte| *byte != 0));
    assert_eq!(
        identity
            .derive_shared_secret(KeyAgreementRequest {
                key: KeySelector::Kid("#request".to_owned()),
                peer_public,
            })
            .err(),
        Some(IdentityError::KeyPurposeViolation)
    );
    assert_eq!(
        identity
            .derive_shared_secret(KeyAgreementRequest {
                key: KeySelector::Default,
                peer_public: [0; 32],
            })
            .err(),
        Some(IdentityError::InvalidRequest)
    );
}

fn managed(fragment: &str, role: KeyRole) -> ManagedKeySpec {
    ManagedKeySpec {
        fragment: fragment.to_owned(),
        role,
    }
}
