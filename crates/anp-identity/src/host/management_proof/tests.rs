use super::*;
use crate::{
    CreateIdentityRequest, IdentityManager, IdentityManagerConfig, InjectedStoreKey, RootKeySource,
};
#[test]
fn management_proof_signs_existing_device_jcs_transcript_and_restricts_method() {
    let root = tempfile::tempdir().unwrap();
    let mut manager = IdentityManager::initialize(IdentityManagerConfig {
        state_root: root.path().into(),
        root_key: RootKeySource::Injected(InjectedStoreKey::new("management", [79; 32])),
    })
    .unwrap();
    let identity=manager.create(serde_json::from_value::<CreateIdentityRequest>(json!({"profile":"e1","domain":"example.test","port":null,"path_segments":["management"],"capabilities":{"did_wba":true},"managed_keys":[{"fragment":"root","role":"root_control"},{"fragment":"device","role":"device_signing"}],"agent_description_url":null})).unwrap()).unwrap();
    let params = json!({"operation_id":"prepare-one","http_path":"/user-service/v1/agent-clients/device/prepare","target_did":identity.reference().did});
    let proof = identity
        .sign_management_proof(ManagementProofRequest {
            key: KeySelector::Kid("#device".into()),
            method: "agent_client_prepare".into(),
            params: params.clone(),
            audience: None,
        })
        .unwrap();
    let transcript = json!({"type":proof["type"],"purpose":"awiki.agent-client.prepare.v2","method":"agent_client_prepare","key_id":proof["key_id"],"created_at":proof["created_at"],"expires_at":proof["expires_at"],"nonce":proof["nonce"],"params":params});
    let bytes = serde_json_canonicalizer::to_vec(&transcript).unwrap();
    let signature = URL_SAFE_NO_PAD
        .decode(proof["signature"].as_str().unwrap())
        .unwrap();
    identity
        .lock_engine()
        .unwrap()
        .verify("#device", &bytes, &signature)
        .unwrap();
    assert!(identity
        .sign_management_proof(ManagementProofRequest {
            key: KeySelector::Default,
            method: "arbitrary".into(),
            params: json!({}),
            audience: None
        })
        .is_err());
    assert!(identity
        .sign_management_proof(ManagementProofRequest {
            key: KeySelector::Kid("#root".into()),
            method: "device_oauth_keys_update".into(),
            params: json!({}),
            audience: None
        })
        .is_err());
}

#[test]
fn web_bootstrap_signs_local_projection_and_rejects_document_or_device_substitution() {
    use sha2::{Digest, Sha256};
    let root = tempfile::tempdir().unwrap();
    let mut manager = IdentityManager::initialize(IdentityManagerConfig {
        state_root: root.path().into(),
        root_key: RootKeySource::Injected(InjectedStoreKey::new("web-management", [97; 32])),
    })
    .unwrap();
    let identity=manager.create(serde_json::from_value::<CreateIdentityRequest>(json!({"profile":"web","domain":"identity.example","port":null,"path_segments":["awiki","web","123e4567e89b42d3a456426614174000"],"capabilities":{"did_wba":true},"managed_keys":[{"fragment":"device","role":"device_signing"},{"fragment":"agreement","role":"e2ee_agreement"}],"extensions":[{"type":"device_manifest","value":{"devices":[{"device_id":"web-one","signing_key_id":"#device","e2ee_key_id":"#agreement","profiles":["anp.core.binding.v1"]}]}}],"agent_description_url":null})).unwrap()).unwrap();
    let public = identity.public_identity().unwrap();
    let did = identity.reference().did;
    let projection = json!({"contract":"awiki.register.web.v1","audience":"awiki-user-service","registration_operation_id":"operation-one","full_handle":"user.identity.example","did":did,"bootstrap_device":{"device_id":"web-one","signing_key_id":format!("{did}#device"),"e2ee_key_id":format!("{did}#agreement")},"document_hash":crate::document::document_digest(public.document.as_value()).unwrap(),"account":{"phone":null,"email":"user@example.invalid"},"profile":{"name":"User","avatar":null,"role":null,"endpoint_url":null,"description":null,"is_public":false,"is_agent":true},"invite_code_hash":null});
    let proof = identity
        .sign_web_registration_proof(WebRegistrationProofRequest {
            key: KeySelector::Kid("#device".into()),
            business_projection: projection.clone(),
        })
        .unwrap();
    let hash = Sha256::digest(serde_json_canonicalizer::to_vec(&projection).unwrap())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let transcript = json!({"type":proof["type"],"purpose":"awiki.identity.register.web.v1","method":"register","audience":"awiki-user-service","operation_id":"operation-one","request_hash":hash,"key_id":proof["key_id"],"created_at":proof["created_at"],"expires_at":proof["expires_at"],"nonce":proof["nonce"]});
    identity
        .lock_engine()
        .unwrap()
        .verify(
            "#device",
            &serde_json_canonicalizer::to_vec(&transcript).unwrap(),
            &URL_SAFE_NO_PAD
                .decode(proof["signature"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
    for field in ["document_hash", "did"] {
        let mut changed = projection.clone();
        changed[field] = json!("wrong");
        assert!(identity
            .sign_web_registration_proof(WebRegistrationProofRequest {
                key: KeySelector::Kid("#device".into()),
                business_projection: changed
            })
            .is_err());
    }
    let mut changed = projection;
    changed["bootstrap_device"]["device_id"] = json!("other");
    assert!(identity
        .sign_web_registration_proof(WebRegistrationProofRequest {
            key: KeySelector::Kid("#device".into()),
            business_projection: changed
        })
        .is_err());
}
