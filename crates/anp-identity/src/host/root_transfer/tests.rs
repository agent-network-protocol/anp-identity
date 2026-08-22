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

#[test]
fn wrapped_root_import_is_available_only_through_the_host_port() {
    let root = tempfile::tempdir().unwrap();
    let mut manager = IdentityManager::initialize(IdentityManagerConfig {
        state_root: root.path().to_owned(),
        root_key: RootKeySource::Injected(InjectedStoreKey::new("wrapped-import", [0xd2; 32])),
    })
    .unwrap();
    let mut identity = manager.create(spec()).unwrap();
    let envelope = crate::WrappedRootEnvelope {
        envelope_type: crate::WRAPPED_ROOT_ENVELOPE_TYPE.to_owned(),
        version: crate::WRAPPED_ROOT_ENVELOPE_VERSION,
        context: crate::RootTransferContext {
            source_did: identity.reference().did.clone(),
            target_did: identity.reference().did.clone(),
            sender_device_id: "sender".to_owned(),
            recipient_device_id: "recipient".to_owned(),
            recipient_agreement_kid: format!("{}#missing", identity.reference().did),
            root_kid: format!("{}#root", identity.reference().did),
            checkpoint: crate::DocumentCheckpoint {
                document_version: 1,
                registry_version: 1,
                document_digest: "sha256:invalid".to_owned(),
            },
            created_at: "2026-08-22T00:00:00Z".to_owned(),
            expires_at: "2026-08-22T00:05:00Z".to_owned(),
        },
        ephemeral_public_b64u: "invalid".to_owned(),
        nonce_b64u: "invalid".to_owned(),
        ciphertext_b64u: "invalid".to_owned(),
        signature_b64u: "invalid".to_owned(),
    };

    assert_eq!(
        identity.import_wrapped_root_envelope(&envelope).err(),
        Some(IdentityError::InvalidRequest)
    );
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
