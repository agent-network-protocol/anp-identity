use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;

use anp::authentication::validate_did_document_binding;

use super::*;
use crate::keystore::SecretRef;
use crate::platform::InjectedRootKeyProvider;
use crate::secret::SecretBytes;
use crate::store::ProviderInitialization;
use crate::{
    Capabilities, DeviceManifestEntrySpec, DeviceManifestSpec, DidExtensionSpec, DidProfile,
    ExternalPublicKeyMaterial, ExternalPublicKeySpec, KeyOrigin, KeyRole, ManagedKeySpec,
    ServiceSpec,
};

const PROCESS_ROOT_ENV: &str = "ANP_IDENTITY_TEST_PROCESS_ROOT";
const PROCESS_LABEL_ENV: &str = "ANP_IDENTITY_TEST_PROCESS_LABEL";
const ENV_PROVIDER_ROOT_ENV: &str = "ANP_IDENTITY_TEST_ENV_PROVIDER_ROOT";
const ENV_PROVIDER_MODE_ENV: &str = "ANP_IDENTITY_TEST_ENV_PROVIDER_MODE";
const ENV_PROVIDER_KEY_ENV: &str = "ANP_IDENTITY_TEST_ENV_PROVIDER_KEY";

#[test]
fn identity_creation_persists_multiple_isolated_e1_documents() {
    let root = tempfile::tempdir().unwrap();
    let mut store = DidStore::initialize_injected(root.path(), "host", [7_u8; 32]).unwrap();
    let first = store.create_identity(standard_spec("alice")).unwrap();
    let second = store.create_identity(standard_spec("bob")).unwrap();

    assert_ne!(first.did(), second.did());
    assert_eq!(first.state(), IdentityState::Active);
    assert_eq!(first.keys().len(), 4);
    assert!(validate_did_document_binding(first.document(), true));
    assert!(anp::authentication::validate_device_manifest(first.document()).is_ok());
    assert_eq!(store.list_identities().unwrap().len(), 2);
    assert_eq!(store.generation(), 2);
    assert_eq!(
        store.open_identity(first.did()).unwrap().document(),
        first.document()
    );
    assert!(matches!(
        store.open_identity("did:wba:example.com:missing"),
        Err(DidError::IdentityNotFound)
    ));

    let registry = std::fs::read_to_string(root.path().join("registry.json")).unwrap();
    assert!(!registry.contains("private"));
    assert!(!serde_json::to_string(first.document())
        .unwrap()
        .contains("\"d\""));
    drop(store);

    let reopened = DidStore::open_injected(root.path(), "host", [7_u8; 32]).unwrap();
    assert_eq!(reopened.list_identities().unwrap().len(), 2);
    assert_eq!(
        reopened.open_identity(second.did()).unwrap().did(),
        second.did()
    );
}

#[test]
fn identity_store_manifest_and_reload_are_usable() {
    let root = tempfile::tempdir().unwrap();
    let mut first = DidStore::initialize_injected(root.path(), "host", [12_u8; 32]).unwrap();
    assert_eq!(
        first.manifest().provider.kind,
        crate::RootKeyProviderKind::Injected
    );
    let mut stale = DidStore::open_injected(root.path(), "host", [12_u8; 32]).unwrap();

    first.create_identity(standard_spec("first")).unwrap();
    assert_eq!(
        stale.create_identity(standard_spec("stale")).err(),
        Some(DidError::Conflict)
    );
    stale.reload().unwrap();
    stale.create_identity(standard_spec("reloaded")).unwrap();
    assert_eq!(stale.generation(), 2);
}

#[test]
fn identity_env_provider_works_with_child_process_environment() {
    let root = tempfile::tempdir().unwrap();
    for mode in ["initialize", "open"] {
        let mut child = spawn_identity_env_process(root.path(), mode);
        let status = child.wait().unwrap();
        assert!(status.success(), "env provider child failed in {mode} mode");
    }
}

#[test]
#[ignore]
fn identity_env_provider_child() {
    let Some(root) = std::env::var_os(ENV_PROVIDER_ROOT_ENV) else {
        return;
    };
    let mode = std::env::var(ENV_PROVIDER_MODE_ENV).unwrap();
    let store = match mode.as_str() {
        "initialize" => DidStore::initialize_env(root, "host-env", ENV_PROVIDER_KEY_ENV).unwrap(),
        "open" => DidStore::open_env(root, "host-env", ENV_PROVIDER_KEY_ENV).unwrap(),
        _ => panic!("unknown env provider child mode"),
    };
    assert_eq!(
        store.manifest().provider.kind,
        crate::RootKeyProviderKind::Injected
    );
}

#[test]
fn identity_reload_recovers_a_stale_identity_handle() {
    let root = tempfile::tempdir().unwrap();
    let mut store = DidStore::initialize_injected(root.path(), "host", [13_u8; 32]).unwrap();
    let mut current = store.create_identity(standard_spec("reload")).unwrap();
    let mut stale = store.open_identity(current.did()).unwrap();

    let prepared = current
        .prepare_update(crate::DocumentUpdateSpec {
            request_signing_rotation: crate::RequestSigningRotation {
                old_kid: "#request".to_string(),
                new_fragment: "request-v2".to_string(),
            },
            services: None,
        })
        .unwrap();
    assert_eq!(
        stale
            .prepare_update(crate::DocumentUpdateSpec {
                request_signing_rotation: crate::RequestSigningRotation {
                    old_kid: "#request".to_string(),
                    new_fragment: "stale-request".to_string(),
                },
                services: None,
            })
            .err(),
        Some(DidError::Conflict)
    );
    current.abort_update(&prepared.revision_id).unwrap();
    stale.reload().unwrap();
    assert!(stale
        .prepare_update(crate::DocumentUpdateSpec {
            request_signing_rotation: crate::RequestSigningRotation {
                old_kid: "#request".to_string(),
                new_fragment: "reloaded-request".to_string(),
            },
            services: None,
        })
        .is_ok());
}

#[test]
fn identity_creation_supports_one_four_n_and_external_public_keys() {
    let root = tempfile::tempdir().unwrap();
    let mut store = DidStore::initialize_injected(root.path(), "host", [8_u8; 32]).unwrap();

    let root_only = DidCreateSpec {
        capabilities: Capabilities { did_wba: false },
        managed_keys: vec![managed("root", KeyRole::RootControl)],
        ..base_spec("root-only")
    };
    assert_eq!(store.create_identity(root_only).unwrap().keys().len(), 1);

    assert_eq!(
        store
            .create_identity(standard_spec("standard"))
            .unwrap()
            .keys()
            .len(),
        4
    );

    let mut many = standard_spec("many");
    for index in 0..5 {
        many.managed_keys.push(managed(
            &format!("request-{index}"),
            KeyRole::RequestSigning,
        ));
    }
    assert_eq!(store.create_identity(many).unwrap().keys().len(), 9);

    let external_private = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let mut external = standard_spec("external");
    external.external_keys.push(ExternalPublicKeySpec {
        kid: "#external-signing".to_string(),
        role: KeyRole::E2eeSigning,
        material: ExternalPublicKeyMaterial::Multibase {
            value: ed25519_multibase(&external_private.verifying_key()),
        },
    });
    let identity = store.create_identity(external).unwrap();
    assert_eq!(identity.keys().len(), 5);
    assert!(identity.keys().iter().any(|key| {
        key.kid.ends_with("#external-signing") && key.origin == KeyOrigin::External
    }));
    assert_eq!(
        identity.managed_key_metadata("#external-signing").err(),
        Some(DidError::ExternalKeyOperation)
    );
    assert_eq!(
        identity.sign("#external-signing", b"must fail").err(),
        Some(DidError::ExternalKeyOperation)
    );
    use ed25519_dalek::Signer;
    let external_signature = external_private.sign(b"external verification");
    identity
        .verify(
            "#external-signing",
            b"external verification",
            &external_signature.to_bytes(),
        )
        .unwrap();
    assert_eq!(
        identity.managed_key_metadata("#missing").err(),
        Some(DidError::KeyNotFound)
    );
    assert_eq!(
        identity
            .managed_key_metadata("did:wba:evil.example#external-signing")
            .err(),
        Some(DidError::ForeignKid)
    );
}

#[test]
fn identity_failure_injection_recovers_or_commits_every_persistence_point() {
    let points = [
        CreationFailurePoint::JournalPersisted,
        CreationFailurePoint::SecretPersisted(0),
        CreationFailurePoint::SecretPersisted(1),
        CreationFailurePoint::SecretPersisted(2),
        CreationFailurePoint::SecretPersisted(3),
        CreationFailurePoint::IdentityCreatingPersisted,
        CreationFailurePoint::RegistryCommitted,
        CreationFailurePoint::IdentityActivated,
    ];
    for point in points {
        let root = tempfile::tempdir().unwrap();
        let mut store = DidStore::initialize_injected(root.path(), "host", [9_u8; 32]).unwrap();
        assert!(store
            .create_identity_inner(standard_spec("failure"), Some(point))
            .is_err());
        drop(store);

        let mut recovered = DidStore::open_injected(root.path(), "host", [9_u8; 32]).unwrap();
        let committed = matches!(
            point,
            CreationFailurePoint::RegistryCommitted | CreationFailurePoint::IdentityActivated
        );
        if committed {
            assert_eq!(recovered.list_identities().unwrap().len(), 1, "{point:?}");
            let summary = recovered.list_identities().unwrap().pop().unwrap();
            assert_eq!(
                recovered.open_identity(&summary.did).unwrap().state(),
                IdentityState::Active
            );
        } else {
            assert!(recovered.list_identities().unwrap().is_empty(), "{point:?}");
            assert!(
                recovered.runtime.key_store().list().unwrap().is_empty(),
                "{point:?}"
            );
            assert!(recovered.create_identity(standard_spec("retry")).is_ok());
        }
        assert!(list_journals(root.path()).unwrap().is_empty());
    }
}

#[test]
fn identity_existing_secret_must_match_the_document_public_key() {
    let root = tempfile::tempdir().unwrap();
    let provider = InjectedRootKeyProvider::new("host", [10_u8; 32]);
    let runtime =
        StoreRuntime::initialize(root.path(), ProviderInitialization::Required(&provider)).unwrap();
    let built = build_identity(&standard_spec("mismatch")).unwrap();
    let managed = built.managed_keys.first().unwrap();
    let secret_ref = SecretRef {
        identity_id: "identity".to_string(),
        key_id: format!("{}#{}", built.did, managed.fragment),
        role: managed.role,
        version: 1,
    };
    let guard = runtime.acquire_write().unwrap();
    runtime
        .key_store()
        .seal_if_absent(
            &guard,
            runtime.root_key(),
            secret_ref.clone(),
            SecretBytes::new(vec![0_u8; 32]),
        )
        .unwrap();
    drop(guard);

    assert_eq!(
        verify_persisted_key(&runtime, &secret_ref, &managed.public_key()),
        Err(DidError::InvalidIdentity)
    );
}

#[test]
fn identity_multi_process_create_retries_conflict_without_lost_updates() {
    let root = tempfile::tempdir().unwrap();
    DidStore::initialize_injected(root.path(), "host", [11_u8; 32]).unwrap();
    let mut children = [
        spawn_identity_process(root.path(), "a"),
        spawn_identity_process(root.path(), "b"),
    ];
    wait_for_path(&root.path().join("ready-a"));
    wait_for_path(&root.path().join("ready-b"));
    std::fs::write(root.path().join("go"), b"go").unwrap();
    for child in &mut children {
        assert!(child.wait().unwrap().success());
    }
    let mut results = [
        std::fs::read_to_string(root.path().join("result-a")).unwrap(),
        std::fs::read_to_string(root.path().join("result-b")).unwrap(),
    ];
    results.sort();
    assert_eq!(results, ["ok", "retried"]);

    let store = DidStore::open_injected(root.path(), "host", [11_u8; 32]).unwrap();
    assert_eq!(store.list_identities().unwrap().len(), 2);
    assert_eq!(store.generation(), 2);
}

#[test]
#[ignore]
fn identity_process_create_child() {
    let Some(root) = std::env::var_os(PROCESS_ROOT_ENV) else {
        return;
    };
    let root = PathBuf::from(root);
    let label = std::env::var(PROCESS_LABEL_ENV).unwrap();
    let mut store = DidStore::open_injected(&root, "host", [11_u8; 32]).unwrap();
    std::fs::write(root.join(format!("ready-{label}")), b"ready").unwrap();
    wait_for_path(&root.join("go"));
    let first = store.create_identity(standard_spec(&format!("process-{label}")));
    let result = match first {
        Ok(_) => "ok",
        Err(DidError::Conflict) => {
            store.reload().unwrap();
            store
                .create_identity(standard_spec(&format!("process-{label}-retry")))
                .unwrap();
            "retried"
        }
        Err(error) => panic!("unexpected identity creation result: {error}"),
    };
    std::fs::write(root.join(format!("result-{label}")), result).unwrap();
}

fn base_spec(name: &str) -> DidCreateSpec {
    DidCreateSpec {
        profile: DidProfile::E1,
        domain: "example.com".to_string(),
        port: None,
        path_segments: vec!["agents".to_string(), name.to_string()],
        capabilities: Capabilities::default(),
        managed_keys: Vec::new(),
        external_keys: Vec::new(),
        services: vec![ServiceSpec {
            id: "message".to_string(),
            service_type: "ANPMessageService".to_string(),
            service_endpoint: "https://example.com/im".to_string(),
            profiles: vec!["anp.core.binding.v1".to_string()],
            security_profiles: vec!["transport-protected".to_string()],
        }],
        agent_description_url: Some("https://example.com/agents/description.json".to_string()),
        extensions: Vec::new(),
    }
}

fn standard_spec(name: &str) -> DidCreateSpec {
    let mut spec = base_spec(name);
    spec.capabilities.did_wba = true;
    spec.managed_keys = vec![
        managed("root", KeyRole::RootControl),
        managed("request", KeyRole::RequestSigning),
        managed("e2ee-signing", KeyRole::E2eeSigning),
        managed("agreement", KeyRole::E2eeAgreement),
    ];
    spec.extensions = vec![DidExtensionSpec::DeviceManifest(DeviceManifestSpec {
        devices: vec![DeviceManifestEntrySpec {
            device_id: "device-1".to_string(),
            signing_key_id: "#e2ee-signing".to_string(),
            e2ee_key_id: "#agreement".to_string(),
            profiles: vec!["anp.core.binding.v1".to_string()],
        }],
    })];
    spec
}

fn managed(fragment: &str, role: KeyRole) -> ManagedKeySpec {
    ManagedKeySpec {
        fragment: fragment.to_string(),
        role,
    }
}

fn ed25519_multibase(key: &ed25519_dalek::VerifyingKey) -> String {
    let mut bytes = vec![0xed, 0x01];
    bytes.extend_from_slice(&key.to_bytes());
    format!("z{}", bs58::encode(bytes).into_string())
}

fn spawn_identity_process(root: &Path, label: &str) -> Child {
    Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "identity::tests::identity_process_create_child",
            "--nocapture",
        ])
        .env(PROCESS_ROOT_ENV, root)
        .env(PROCESS_LABEL_ENV, label)
        .spawn()
        .unwrap()
}

fn spawn_identity_env_process(root: &Path, mode: &str) -> Child {
    Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "identity::tests::identity_env_provider_child",
            "--nocapture",
        ])
        .env(ENV_PROVIDER_ROOT_ENV, root)
        .env(ENV_PROVIDER_MODE_ENV, mode)
        .env(ENV_PROVIDER_KEY_ENV, URL_SAFE_NO_PAD.encode([12_u8; 32]))
        .spawn()
        .unwrap()
}

fn wait_for_path(path: &Path) {
    for _ in 0..300 {
        if path.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for {}", path.display());
}
