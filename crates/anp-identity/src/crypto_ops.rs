use std::collections::BTreeMap;
use std::fmt;

use anp::authentication::{
    complete_http_signature_headers, complete_legacy_did_wba_auth_header, find_verification_method,
    prepare_http_signature_headers, prepare_legacy_did_wba_auth_header,
};
use anp::proof::{
    complete_object_proof, complete_rfc9421_origin_proof, complete_w3c_proof, prepare_object_proof,
    prepare_rfc9421_origin_proof, prepare_w3c_proof, ProofGenerationOptions, Rfc9421OriginProof,
    Rfc9421OriginProofGenerationOptions,
};
use zeroize::{Zeroize, Zeroizing};

use crate::secret::SecretBytes;
use crate::{DidError, DidIdentity, DidResult, KeyMetadata, KeyRole, KeyState};

pub struct SharedSecret {
    bytes: Zeroizing<[u8; 32]>,
}

impl SharedSecret {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SharedSecret")
            .field("value", &"[REDACTED]")
            .finish()
    }
}

impl DidIdentity {
    pub fn sign_pending_root_object_proof(
        &self,
        kid: &str,
        document: &serde_json::Value,
        issuer_did: &str,
        created: Option<String>,
    ) -> DidResult<serde_json::Value> {
        let current = crate::registry::read_identity(self.runtime().root(), self.identity_id())?;
        if current.generation != self.record().generation {
            return Err(DidError::Conflict);
        }
        if current.state != crate::IdentityState::Active
            || current.root_capability != crate::RootCapabilityState::Pending
            || current.pending_root_transfer.is_none()
        {
            return Err(DidError::RootCapabilityUnavailable);
        }
        let kid = crate::input::canonicalize_kid(&current.did, kid)?;
        let metadata = current
            .keys
            .iter()
            .find(|metadata| metadata.kid == kid)
            .ok_or(DidError::KeyNotFound)?;
        if metadata.role != KeyRole::RootControl
            || metadata.origin != crate::KeyOrigin::Managed
            || metadata.state != KeyState::Pending
            || metadata.material_erased
        {
            return Err(DidError::RootCapabilityUnavailable);
        }
        let method = find_verification_method(self.document(), &metadata.kid)
            .ok_or(DidError::InvalidIdentity)?;
        let public = anp::authentication::extract_public_key(&method)
            .map_err(|_| DidError::InvalidPublicKey)?;
        let prepared = prepare_object_proof(document, &public, &metadata.kid, issuer_did, created)
            .map_err(|_| DidError::Crypto)?;
        let signature = self.sign_prepared(metadata, prepared.signing_input())?;
        complete_object_proof(prepared, &signature).map_err(|_| DidError::Crypto)
    }

    pub fn sign_pending_enrollment(
        &self,
        enrollment_id: &str,
        kid: &str,
        message: &[u8],
    ) -> DidResult<Vec<u8>> {
        let record = self.current_pending_enrollment(enrollment_id)?;
        let local = record
            .local_authorization
            .as_ref()
            .ok_or(DidError::InvalidIdentity)?;
        let kid = crate::input::canonicalize_kid(&record.did, kid)?;
        if kid != local.signing_kid {
            return Err(DidError::KeyRoleViolation);
        }
        let metadata = record
            .keys
            .iter()
            .find(|metadata| metadata.kid == kid)
            .ok_or(DidError::KeyNotFound)?;
        if metadata.role != KeyRole::DeviceSigning
            || metadata.origin != crate::KeyOrigin::Managed
            || metadata.state != KeyState::Pending
            || metadata.material_erased
        {
            return Err(DidError::KeyNotUsable);
        }
        self.sign_prepared(metadata, message)
    }

    pub fn ecdh_pending_enrollment(
        &self,
        enrollment_id: &str,
        kid: &str,
        peer_public: &[u8],
    ) -> DidResult<SharedSecret> {
        let record = self.current_pending_enrollment(enrollment_id)?;
        let local = record
            .local_authorization
            .as_ref()
            .ok_or(DidError::InvalidIdentity)?;
        let kid = crate::input::canonicalize_kid(&record.did, kid)?;
        if kid != local.e2ee_kid {
            return Err(DidError::KeyRoleViolation);
        }
        let metadata = record
            .keys
            .iter()
            .find(|metadata| metadata.kid == kid)
            .ok_or(DidError::KeyNotFound)?;
        if metadata.role != KeyRole::E2eeAgreement
            || metadata.origin != crate::KeyOrigin::Managed
            || metadata.state != KeyState::Pending
            || metadata.material_erased
        {
            return Err(DidError::KeyNotUsable);
        }
        let peer: [u8; 32] = peer_public
            .try_into()
            .map_err(|_| DidError::InvalidPeerKey)?;
        let secret = self.load_managed_secret(metadata)?;
        let private = x25519_private_key(&secret)?;
        let shared = private.diffie_hellman(&x25519_dalek::PublicKey::from(peer));
        let bytes = Zeroizing::new(shared.to_bytes());
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(DidError::InvalidPeerKey);
        }
        Ok(SharedSecret { bytes })
    }

    pub fn sign(&self, kid: &str, message: &[u8]) -> DidResult<Vec<u8>> {
        self.require_operational()?;
        let metadata = self.managed_key_metadata(kid)?;
        require_active(metadata)?;
        if !matches!(
            metadata.role,
            KeyRole::DeviceSigning | KeyRole::RequestSigning | KeyRole::E2eeSigning
        ) {
            return Err(DidError::KeyRoleViolation);
        }
        let secret = self.load_managed_secret(metadata)?;
        let signing_key = ed25519_signing_key(&secret)?;
        use ed25519_dalek::Signer;
        Ok(signing_key.sign(message).to_bytes().to_vec())
    }

    #[cfg(test)]
    pub fn sign_device_assertion(&self, kid: &str, message: &[u8]) -> DidResult<Vec<u8>> {
        self.require_operational()?;
        let metadata = self.managed_key_metadata(kid)?;
        require_active(metadata)?;
        if metadata.role != KeyRole::DeviceSigning {
            return Err(DidError::KeyRoleViolation);
        }
        self.sign_prepared(metadata, message)
    }

    pub fn sign_object_proof(
        &self,
        kid: &str,
        document: &serde_json::Value,
        issuer_did: &str,
        created: Option<String>,
    ) -> DidResult<serde_json::Value> {
        let metadata = self.device_signing_metadata(kid)?;
        let method = find_verification_method(self.document(), &metadata.kid)
            .ok_or(DidError::InvalidIdentity)?;
        let public = anp::authentication::extract_public_key(&method)
            .map_err(|_| DidError::InvalidPublicKey)?;
        let prepared = prepare_object_proof(document, &public, &metadata.kid, issuer_did, created)
            .map_err(|_| DidError::Crypto)?;
        let signature = self.sign_prepared(metadata, prepared.signing_input())?;
        complete_object_proof(prepared, &signature).map_err(|_| DidError::Crypto)
    }

    pub fn sign_document_proof(
        &self,
        document: &serde_json::Value,
        verification_method: &str,
        options: ProofGenerationOptions,
    ) -> DidResult<serde_json::Value> {
        self.require_operational()?;
        if self.root_capability() != crate::RootCapabilityState::Active {
            return Err(DidError::RootCapabilityUnavailable);
        }
        let metadata = self.managed_key_metadata(verification_method)?;
        require_active(metadata)?;
        if metadata.role != KeyRole::RootControl {
            return Err(DidError::KeyRoleViolation);
        }
        let method = find_verification_method(self.document(), &metadata.kid)
            .ok_or(DidError::InvalidIdentity)?;
        let public = anp::authentication::extract_public_key(&method)
            .map_err(|_| DidError::InvalidPublicKey)?;
        let prepared = prepare_w3c_proof(document, &public, &metadata.kid, options)
            .map_err(|_| DidError::Crypto)?;
        let signature = self.sign_prepared(metadata, prepared.signing_input())?;
        complete_w3c_proof(prepared, &signature).map_err(|_| DidError::Crypto)
    }

    pub fn sign_origin_proof(
        &self,
        method: &str,
        meta: &serde_json::Value,
        body: &serde_json::Value,
        kid: &str,
        options: Rfc9421OriginProofGenerationOptions,
    ) -> DidResult<Rfc9421OriginProof> {
        let metadata = self.request_signing_metadata(kid)?;
        let verification_method = find_verification_method(self.document(), &metadata.kid)
            .ok_or(DidError::InvalidIdentity)?;
        let public = anp::authentication::extract_public_key(&verification_method)
            .map_err(|_| DidError::InvalidPublicKey)?;
        let prepared =
            prepare_rfc9421_origin_proof(method, meta, body, &public, &metadata.kid, options)
                .map_err(|_| DidError::Crypto)?;
        let signature = self.sign_prepared(metadata, prepared.signing_input())?;
        complete_rfc9421_origin_proof(prepared, &signature).map_err(|_| DidError::Crypto)
    }

    pub fn verify(&self, kid: &str, message: &[u8], signature: &[u8]) -> DidResult<()> {
        let metadata = self.key_metadata(kid)?;
        if metadata.state == KeyState::Revoked {
            return Err(DidError::KeyNotUsable);
        }
        if metadata.role == KeyRole::E2eeAgreement {
            return Err(DidError::KeyRoleViolation);
        }
        let method = find_verification_method(self.document(), &metadata.kid)
            .ok_or(DidError::InvalidIdentity)?;
        let public_key = anp::authentication::extract_public_key(&method)
            .map_err(|_| DidError::InvalidPublicKey)?;
        public_key
            .verify_message(message, signature)
            .map_err(|_| DidError::VerificationFailed)
    }

    pub fn ecdh(&self, kid: &str, peer_public: &[u8]) -> DidResult<SharedSecret> {
        self.require_operational()?;
        let metadata = self.managed_key_metadata(kid)?;
        require_active(metadata)?;
        if metadata.role != KeyRole::E2eeAgreement {
            return Err(DidError::KeyRoleViolation);
        }
        let peer: [u8; 32] = peer_public
            .try_into()
            .map_err(|_| DidError::InvalidPeerKey)?;
        let secret = self.load_managed_secret(metadata)?;
        let private = x25519_private_key(&secret)?;
        let shared = private.diffie_hellman(&x25519_dalek::PublicKey::from(peer));
        let bytes = Zeroizing::new(shared.to_bytes());
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(DidError::InvalidPeerKey);
        }
        Ok(SharedSecret { bytes })
    }

    pub fn legacy_did_wba_header(
        &self,
        kid: &str,
        service_domain: &str,
        version: &str,
    ) -> DidResult<String> {
        let metadata = self.request_signing_metadata(kid)?;
        let prepared = prepare_legacy_did_wba_auth_header(
            self.document(),
            service_domain,
            version,
            &metadata.kid,
        )
        .map_err(|_| DidError::InvalidIdentity)?;
        let signature = self.sign_prepared(metadata, prepared.signing_input())?;
        complete_legacy_did_wba_auth_header(prepared, &signature).map_err(|_| DidError::Crypto)
    }

    #[cfg(test)]
    pub fn http_signature_headers(
        &self,
        kid: &str,
        request_url: &str,
        request_method: &str,
        headers: Option<&BTreeMap<String, String>>,
        body: Option<&[u8]>,
    ) -> DidResult<BTreeMap<String, String>> {
        self.http_signature_headers_with_options(
            kid,
            request_url,
            request_method,
            headers,
            body,
            crate::HttpSignatureOptions::default(),
        )
    }

    pub fn http_signature_headers_with_options(
        &self,
        kid: &str,
        request_url: &str,
        request_method: &str,
        headers: Option<&BTreeMap<String, String>>,
        body: Option<&[u8]>,
        mut options: crate::HttpSignatureOptions,
    ) -> DidResult<BTreeMap<String, String>> {
        let metadata = self.request_signing_metadata(kid)?;
        options.keyid = Some(metadata.kid.clone());
        let prepared = prepare_http_signature_headers(
            self.document(),
            request_url,
            request_method,
            headers,
            body,
            options,
        )
        .map_err(|_| DidError::InvalidIdentity)?;
        let signature = self.sign_prepared(metadata, prepared.signing_input())?;
        complete_http_signature_headers(prepared, &signature).map_err(|_| DidError::Crypto)
    }

    fn request_signing_metadata(&self, kid: &str) -> DidResult<&KeyMetadata> {
        self.require_operational()?;
        let metadata = self.managed_key_metadata(kid)?;
        require_active(metadata)?;
        if !matches!(
            metadata.role,
            KeyRole::DeviceSigning | KeyRole::RequestSigning
        ) {
            return Err(DidError::KeyRoleViolation);
        }
        Ok(metadata)
    }

    fn device_signing_metadata(&self, kid: &str) -> DidResult<&KeyMetadata> {
        self.require_operational()?;
        let metadata = self.managed_key_metadata(kid)?;
        require_active(metadata)?;
        if metadata.role != KeyRole::DeviceSigning {
            return Err(DidError::KeyRoleViolation);
        }
        Ok(metadata)
    }

    fn sign_prepared(&self, metadata: &KeyMetadata, message: &[u8]) -> DidResult<Vec<u8>> {
        let secret = self.load_managed_secret(metadata)?;
        let signing_key = ed25519_signing_key(&secret)?;
        use ed25519_dalek::Signer;
        Ok(signing_key.sign(message).to_bytes().to_vec())
    }

    fn require_operational(&self) -> DidResult<()> {
        let current = crate::registry::read_identity(self.runtime().root(), self.identity_id())?;
        if current.generation != self.record().generation {
            return Err(DidError::Conflict);
        }
        if current.state != crate::IdentityState::Active {
            return Err(DidError::KeyNotUsable);
        }
        Ok(())
    }

    fn current_pending_enrollment(
        &self,
        enrollment_id: &str,
    ) -> DidResult<crate::registry::IdentityRecord> {
        let current = crate::registry::read_identity(self.runtime().root(), self.identity_id())?;
        if current.generation != self.record().generation {
            return Err(DidError::Conflict);
        }
        if current.state != crate::IdentityState::Enrolling
            || current
                .pending_enrollment
                .as_ref()
                .is_none_or(|pending| pending.enrollment_id != enrollment_id)
        {
            return Err(DidError::KeyNotUsable);
        }
        Ok(current)
    }
}

fn require_active(metadata: &KeyMetadata) -> DidResult<()> {
    if metadata.state != KeyState::Active {
        return Err(DidError::KeyNotUsable);
    }
    Ok(())
}

fn ed25519_signing_key(secret: &SecretBytes) -> DidResult<ed25519_dalek::SigningKey> {
    if secret.expose().len() != 32 {
        return Err(DidError::InvalidIdentity);
    }
    let mut bytes = Zeroizing::new([0_u8; 32]);
    bytes.copy_from_slice(secret.expose());
    Ok(ed25519_dalek::SigningKey::from_bytes(&bytes))
}

fn x25519_private_key(secret: &SecretBytes) -> DidResult<x25519_dalek::StaticSecret> {
    if secret.expose().len() != 32 {
        return Err(DidError::InvalidIdentity);
    }
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(secret.expose());
    let private = x25519_dalek::StaticSecret::from(bytes);
    bytes.zeroize();
    Ok(private)
}

#[cfg(test)]
mod tests {
    use anp::authentication::{verify_auth_header_signature, verify_http_message_signature};

    use super::*;
    use crate::{Capabilities, DidCreateSpec, DidProfile, DidStore, ManagedKeySpec};

    #[test]
    fn crypto_ops_enforce_roles_and_interoperate_with_anp_verifiers() {
        let alice_root = tempfile::tempdir().unwrap();
        let bob_root = tempfile::tempdir().unwrap();
        let mut alice_store =
            DidStore::initialize_injected(alice_root.path(), "host", [21_u8; 32]).unwrap();
        let mut bob_store =
            DidStore::initialize_injected(bob_root.path(), "host", [22_u8; 32]).unwrap();
        let alice = alice_store.create_identity(spec("alice")).unwrap();
        let bob = bob_store.create_identity(spec("bob")).unwrap();
        let message = b"message-to-sign";

        let signature = alice.sign("#request", message).unwrap();
        alice.verify("#request", message, &signature).unwrap();
        let device_signature = alice.sign_device_assertion("#device", message).unwrap();
        alice.verify("#device", message, &device_signature).unwrap();
        assert_eq!(
            alice.sign_device_assertion("#request", message),
            Err(DidError::KeyRoleViolation)
        );
        assert_eq!(
            alice.sign_device_assertion("#e2ee-signing", message),
            Err(DidError::KeyRoleViolation)
        );
        let object = serde_json::json!({"operation": "device.assertion"});
        let signed_object = alice
            .sign_object_proof("#device", &object, alice.did(), None)
            .unwrap();
        anp::proof::verify_object_proof(&signed_object, alice.did(), alice.document()).unwrap();
        assert_eq!(
            alice.sign_object_proof("#request", &object, alice.did(), None),
            Err(DidError::KeyRoleViolation)
        );
        let mut unsigned_document = alice.document().clone();
        unsigned_document.as_object_mut().unwrap().remove("proof");
        let signed_document = alice
            .sign_document_proof(
                &unsigned_document,
                &format!("{}#root", alice.did()),
                ProofGenerationOptions {
                    proof_purpose: Some("assertionMethod".to_string()),
                    proof_type: Some(anp::proof::PROOF_TYPE_DATA_INTEGRITY.to_string()),
                    cryptosuite: Some(anp::proof::CRYPTOSUITE_EDDSA_JCS_2022.to_string()),
                    domain: Some("example.com".to_string()),
                    ..ProofGenerationOptions::default()
                },
            )
            .unwrap();
        assert!(anp::authentication::validate_did_document_binding(
            &signed_document,
            true
        ));
        assert_eq!(
            alice.verify("#request", b"tampered", &signature),
            Err(DidError::VerificationFailed)
        );
        assert_eq!(
            alice.sign("#root", message),
            Err(DidError::KeyRoleViolation)
        );
        assert_eq!(
            alice.sign("#agreement", message),
            Err(DidError::KeyRoleViolation)
        );
        assert_eq!(
            alice.sign(&format!("{}#request", bob.did()), message),
            Err(DidError::ForeignKid)
        );

        let alice_agreement = public_x25519(&alice, "#agreement");
        let bob_agreement = public_x25519(&bob, "#agreement");
        assert_eq!(
            alice.public_key_bytes("#agreement").unwrap(),
            alice_agreement
        );
        assert_eq!(
            alice.public_key_bytes("#missing"),
            Err(DidError::KeyNotFound)
        );
        let alice_shared = alice.ecdh("#agreement", &bob_agreement).unwrap();
        let bob_shared = bob.ecdh("#agreement", &alice_agreement).unwrap();
        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
        assert_eq!(
            alice.ecdh("#agreement", &[0_u8; 31]).err(),
            Some(DidError::InvalidPeerKey)
        );
        assert_eq!(
            alice.ecdh("#agreement", &[0_u8; 32]).err(),
            Some(DidError::InvalidPeerKey)
        );
        let mut low_order = [0_u8; 32];
        low_order[0] = 1;
        assert_eq!(
            alice.ecdh("#agreement", &low_order).err(),
            Some(DidError::InvalidPeerKey)
        );

        let legacy = alice
            .legacy_did_wba_header("#request", "api.example.com", "1.1")
            .unwrap();
        verify_auth_header_signature(&legacy, alice.document(), "api.example.com").unwrap();
        let http = alice
            .http_signature_headers(
                "#request",
                "https://api.example.com/messages",
                "POST",
                None,
                Some(br#"{"message":"hello"}"#),
            )
            .unwrap();
        verify_http_message_signature(
            alice.document(),
            "POST",
            "https://api.example.com/messages",
            &http,
            Some(br#"{"message":"hello"}"#),
        )
        .unwrap();
        let challenged = alice
            .http_signature_headers_with_options(
                "#device",
                "https://api.example.com/messages",
                "POST",
                None,
                Some(br#"{"message":"hello"}"#),
                crate::HttpSignatureOptions {
                    keyid: Some("did:example:ignored#foreign".to_string()),
                    nonce: Some("challenge-123".to_string()),
                    created: Some(1_700_000_000),
                    expires: Some(1_700_000_300),
                    covered_components: Some(vec![
                        "@method".to_string(),
                        "@target-uri".to_string(),
                        "content-digest".to_string(),
                    ]),
                },
            )
            .unwrap();
        let signature_input = challenged.get("Signature-Input").unwrap();
        assert!(signature_input.contains("nonce=\"challenge-123\""));
        assert!(signature_input.contains("created=1700000000"));
        assert!(signature_input.contains("expires=1700000300"));
        assert!(signature_input.contains(&format!("keyid=\"{}#device\"", alice.did())));
        verify_http_message_signature(
            alice.document(),
            "POST",
            "https://api.example.com/messages",
            &challenged,
            Some(br#"{"message":"hello"}"#),
        )
        .unwrap();
    }

    fn spec(name: &str) -> DidCreateSpec {
        DidCreateSpec {
            profile: DidProfile::E1,
            domain: "example.com".to_string(),
            port: None,
            path_segments: vec!["agents".to_string(), name.to_string()],
            capabilities: Capabilities { did_wba: true },
            managed_keys: vec![
                managed("root", KeyRole::RootControl),
                managed("device", KeyRole::DeviceSigning),
                managed("request", KeyRole::RequestSigning),
                managed("e2ee-signing", KeyRole::E2eeSigning),
                managed("agreement", KeyRole::E2eeAgreement),
            ],
            external_keys: Vec::new(),
            services: Vec::new(),
            agent_description_url: None,
            extensions: Vec::new(),
        }
    }

    fn managed(fragment: &str, role: KeyRole) -> ManagedKeySpec {
        ManagedKeySpec {
            fragment: fragment.to_string(),
            role,
        }
    }

    fn public_x25519(identity: &DidIdentity, kid: &str) -> [u8; 32] {
        let kid = identity.key_metadata(kid).unwrap().kid.clone();
        let method = find_verification_method(identity.document(), &kid).unwrap();
        match anp::authentication::extract_public_key(&method).unwrap() {
            anp::PublicKeyMaterial::X25519(bytes) => bytes,
            _ => panic!("expected X25519 public key"),
        }
    }
}
