use super::*;
use crate::facade::{IdentityManager, IdentityManagerConfig, InjectedStoreKey, RootKeySource};
use crate::{Capabilities, DidCreateSpec, DidProfile, ManagedKeySpec};

#[test]
fn legacy_root_export_requires_explicit_user_presence_and_matches_engine() {
    let root = tempfile::tempdir().unwrap();
    let mut manager = IdentityManager::initialize(IdentityManagerConfig {
        state_root: root.path().to_owned(),
        root_key: RootKeySource::Injected(InjectedStoreKey::new("root-export", [0xd1; 32])),
    })
    .unwrap();
    let identity = manager.create(spec()).unwrap();
    assert_eq!(
        identity
            .export_root_for_legacy_envelope(UserConfirmedRootExportRequest {
                key: KeySelector::Default,
                user_presence_confirmed: false,
            })
            .err(),
        Some(IdentityError::CapabilityUnavailable)
    );
    let facade = identity
        .export_root_for_legacy_envelope(UserConfirmedRootExportRequest {
            key: KeySelector::Default,
            user_presence_confirmed: true,
        })
        .unwrap();
    let engine = identity
        .lock_engine()
        .unwrap()
        .export_root_private_key("#root")
        .unwrap();
    assert_eq!(facade.as_pkcs8_der(), engine.as_pkcs8_der());
}

fn spec() -> DidCreateSpec {
    DidCreateSpec {
        profile: DidProfile::E1,
        domain: "example.com".to_owned(),
        port: None,
        path_segments: vec!["facade".to_owned(), "root-export".to_owned()],
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
    }
}
