use super::*;
use crate::facade::{IdentityManager, IdentityManagerConfig, InjectedStoreKey, RootKeySource};
use crate::{Capabilities, DidCreateSpec, DidProfile, ManagedKeySpec};

#[test]
fn typed_proofs_match_engine_semantics_and_enforce_key_roles() {
    let root = tempfile::tempdir().unwrap();
    let mut manager = IdentityManager::initialize(IdentityManagerConfig {
        state_root: root.path().to_owned(),
        root_key: RootKeySource::Injected(InjectedStoreKey::new("proofs", [0xb1; 32])),
    })
    .unwrap();
    let identity = manager
        .create_engine_for_test(DidCreateSpec {
            profile: DidProfile::E1,
            domain: "example.com".to_owned(),
            port: None,
            path_segments: vec!["facade".to_owned(), "proofs".to_owned()],
            capabilities: Capabilities { did_wba: true },
            managed_keys: vec![
                managed("root", KeyRole::RootControl),
                managed("request", KeyRole::RequestSigning),
                managed("device", KeyRole::DeviceSigning),
            ],
            external_keys: Vec::new(),
            services: Vec::new(),
            agent_description_url: None,
            extensions: Vec::new(),
        })
        .unwrap();

    let object = serde_json::json!({"id": "urn:example:object"});
    let signed = identity
        .sign_object_proof(ObjectProofRequest {
            key: KeySelector::Default,
            document: object,
            issuer_did: identity.reference().did,
            created: Some("2026-08-22T00:00:00Z".to_owned()),
        })
        .unwrap();
    assert!(signed.get("proof").is_some());

    let mut unsigned = identity.public_identity().unwrap().document.into_value();
    let domain = unsigned["proof"]["domain"].as_str().map(ToOwned::to_owned);
    unsigned.as_object_mut().unwrap().remove("proof");
    let proof = identity
        .sign_document_proof(DocumentProofRequest {
            key: KeySelector::Default,
            document: unsigned,
            options: DocumentProofOptions {
                proof_purpose: Some("assertionMethod".to_owned()),
                proof_type: Some(anp::proof::PROOF_TYPE_DATA_INTEGRITY.to_owned()),
                cryptosuite: Some(anp::proof::CRYPTOSUITE_EDDSA_JCS_2022.to_owned()),
                domain,
                ..Default::default()
            },
        })
        .unwrap();
    assert!(proof.get("proof").is_some());

    assert_eq!(
        identity
            .sign_document_proof(DocumentProofRequest {
                key: KeySelector::Kid("#request".to_owned()),
                document: serde_json::json!({}),
                options: DocumentProofOptions::default(),
            })
            .err(),
        Some(IdentityError::KeyPurposeViolation)
    );
}

fn managed(fragment: &str, role: KeyRole) -> ManagedKeySpec {
    ManagedKeySpec {
        fragment: fragment.to_owned(),
        role,
    }
}
