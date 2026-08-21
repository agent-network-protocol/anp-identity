use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use anp::authentication::{
    build_unsigned_e1_did_document, find_verification_method, validate_device_manifest,
    validate_did_document_binding, DeviceManifest, DeviceManifestEntry, DidKeyRole,
    DidVerificationRelationship, SuppliedDidKey, SuppliedE1DidDocumentOptions,
    DEVICE_MANIFEST_TYPE,
};
use anp::proof::{
    complete_w3c_proof, prepare_w3c_proof, ProofGenerationOptions, CRYPTOSUITE_EDDSA_JCS_2022,
    PROOF_TYPE_DATA_INTEGRITY,
};
use anp::{PrivateKeyMaterial, PublicKeyMaterial};

use crate::input::canonicalize_kid;
use crate::registry::{KeyMetadata, KeyOrigin, KeyState};
use crate::secret::SecretBytes;
use crate::{DidCreateSpec, DidError, DidExtensionSpec, DidResult, KeyRole, ServiceSpec};

pub(crate) struct ManagedPrivateKey {
    pub(crate) fragment: String,
    pub(crate) role: KeyRole,
    bytes: Zeroizing<[u8; 32]>,
}

impl ManagedPrivateKey {
    pub(crate) fn generate(fragment: String, role: KeyRole) -> Self {
        let mut bytes = match role {
            KeyRole::E2eeAgreement => x25519_dalek::StaticSecret::random_from_rng(OsRng).to_bytes(),
            KeyRole::RootControl
            | KeyRole::DeviceSigning
            | KeyRole::RequestSigning
            | KeyRole::E2eeSigning => ed25519_dalek::SigningKey::generate(&mut OsRng).to_bytes(),
        };
        let mut protected = Zeroizing::new([0_u8; 32]);
        protected.copy_from_slice(&bytes);
        bytes.zeroize();
        Self {
            fragment,
            role,
            bytes: protected,
        }
    }

    pub(crate) fn public_key(&self) -> PublicKeyMaterial {
        public_key_from_raw(self.role, &self.bytes)
    }

    pub(crate) fn secret_bytes(&self) -> SecretBytes {
        SecretBytes::new(self.bytes.to_vec())
    }

    fn sign(&self, message: &[u8]) -> DidResult<Vec<u8>> {
        if self.role != KeyRole::RootControl {
            return Err(DidError::InvalidIdentity);
        }
        let bytes = Zeroizing::new(*self.bytes);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&bytes);
        PrivateKeyMaterial::Ed25519(signing_key)
            .sign_message(message)
            .map_err(|_| DidError::Crypto)
    }
}

pub(crate) struct BuiltIdentity {
    pub(crate) did: String,
    pub(crate) document: Value,
    pub(crate) managed_keys: Vec<ManagedPrivateKey>,
    pub(crate) metadata: Vec<KeyMetadata>,
    pub(crate) created_at: String,
}

pub(crate) fn build_identity(spec: &DidCreateSpec) -> DidResult<BuiltIdentity> {
    spec.validate()?;
    let managed_keys = spec
        .managed_keys
        .iter()
        .map(|key| ManagedPrivateKey::generate(key.fragment.clone(), key.role))
        .collect::<Vec<_>>();
    let root = managed_keys
        .iter()
        .find(|key| key.role == KeyRole::RootControl)
        .ok_or(DidError::InvalidManagedRootCount)?;
    let root_supplied = supplied_managed_key(root);
    let root_only = build_unsigned_e1_did_document(
        &spec.domain,
        SuppliedE1DidDocumentOptions {
            port: spec.port,
            path_segments: spec.path_segments.clone(),
            agent_description_url: None,
            services: Vec::new(),
            root_key: root_supplied.clone(),
            additional_keys: Vec::new(),
        },
    )
    .map_err(|_| DidError::InvalidIdentity)?;
    let did = root_only["id"]
        .as_str()
        .ok_or(DidError::InvalidIdentity)?
        .to_string();
    spec.validate_for_did(&did)?;

    let mut supplied_keys = managed_keys
        .iter()
        .filter(|key| key.role != KeyRole::RootControl)
        .map(supplied_managed_key)
        .collect::<Vec<_>>();
    for external in &spec.external_keys {
        let kid = canonicalize_kid(&did, &external.kid)?;
        let fragment = kid
            .strip_prefix(&format!("{did}#"))
            .ok_or(DidError::ForeignKid)?
            .to_string();
        supplied_keys.push(SuppliedDidKey {
            fragment,
            role: anp_role(external.role),
            public_key: external.parse_public_key()?,
            relationships: relationships(external.role),
        });
    }
    let services = spec.services.iter().map(service_json).collect();
    let mut unsigned = build_unsigned_e1_did_document(
        &spec.domain,
        SuppliedE1DidDocumentOptions {
            port: spec.port,
            path_segments: spec.path_segments.clone(),
            agent_description_url: spec.agent_description_url.clone(),
            services,
            root_key: root_supplied,
            additional_keys: supplied_keys,
        },
    )
    .map_err(|_| DidError::InvalidIdentity)?;
    apply_extensions(&mut unsigned, &did, &spec.extensions)?;

    let created_at = Utc::now().to_rfc3339();
    let root_kid = format!("{did}#{}", root.fragment);
    let prepared = prepare_w3c_proof(
        &unsigned,
        &root.public_key(),
        &root_kid,
        ProofGenerationOptions {
            proof_purpose: Some("assertionMethod".to_string()),
            proof_type: Some(PROOF_TYPE_DATA_INTEGRITY.to_string()),
            cryptosuite: Some(CRYPTOSUITE_EDDSA_JCS_2022.to_string()),
            created: Some(created_at.clone()),
            domain: Some(spec.domain.clone()),
            challenge: Some(random_challenge()),
        },
    )
    .map_err(|_| DidError::InvalidIdentity)?;
    let signature = root.sign(prepared.signing_input())?;
    let document =
        complete_w3c_proof(prepared, &signature).map_err(|_| DidError::InvalidIdentity)?;
    if !validate_did_document_binding(&document, true) {
        return Err(DidError::InvalidIdentity);
    }
    validate_device_manifest(&document).map_err(|_| DidError::InvalidExtension)?;

    let mut metadata = Vec::new();
    for key in &managed_keys {
        metadata.push(key_metadata(
            &document,
            &format!("{did}#{}", key.fragment),
            key.role,
            KeyOrigin::Managed,
            &created_at,
        )?);
    }
    for key in &spec.external_keys {
        metadata.push(key_metadata(
            &document,
            &canonicalize_kid(&did, &key.kid)?,
            key.role,
            KeyOrigin::External,
            &created_at,
        )?);
    }

    Ok(BuiltIdentity {
        did,
        document,
        managed_keys,
        metadata,
        created_at,
    })
}

pub(crate) fn public_key_from_secret(
    role: KeyRole,
    secret: &SecretBytes,
) -> DidResult<PublicKeyMaterial> {
    if secret.expose().len() != 32 {
        return Err(DidError::InvalidIdentity);
    }
    let mut bytes = Zeroizing::new([0_u8; 32]);
    bytes.copy_from_slice(secret.expose());
    Ok(public_key_from_raw(role, &bytes))
}

pub(crate) fn public_keys_equal(left: &PublicKeyMaterial, right: &PublicKeyMaterial) -> bool {
    match (left, right) {
        (PublicKeyMaterial::Ed25519(left), PublicKeyMaterial::Ed25519(right)) => {
            left.to_bytes() == right.to_bytes()
        }
        (PublicKeyMaterial::X25519(left), PublicKeyMaterial::X25519(right)) => left == right,
        _ => false,
    }
}

pub(crate) fn sign_root_document(
    document: &Value,
    root_kid: &str,
    root_secret: &SecretBytes,
    domain: Option<String>,
) -> DidResult<Value> {
    if root_secret.expose().len() != 32 {
        return Err(DidError::InvalidIdentity);
    }
    let mut bytes = Zeroizing::new([0_u8; 32]);
    bytes.copy_from_slice(root_secret.expose());
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&bytes);
    let public_key = PublicKeyMaterial::Ed25519(signing_key.verifying_key());
    let prepared = prepare_w3c_proof(
        document,
        &public_key,
        root_kid,
        ProofGenerationOptions {
            proof_purpose: Some("assertionMethod".to_string()),
            proof_type: Some(PROOF_TYPE_DATA_INTEGRITY.to_string()),
            cryptosuite: Some(CRYPTOSUITE_EDDSA_JCS_2022.to_string()),
            created: Some(Utc::now().to_rfc3339()),
            domain,
            challenge: Some(random_challenge()),
        },
    )
    .map_err(|_| DidError::InvalidIdentity)?;
    let signature = PrivateKeyMaterial::Ed25519(signing_key)
        .sign_message(prepared.signing_input())
        .map_err(|_| DidError::Crypto)?;
    complete_w3c_proof(prepared, &signature).map_err(|_| DidError::InvalidIdentity)
}

pub(crate) fn ed25519_public_multibase(public_key: &PublicKeyMaterial) -> DidResult<String> {
    let PublicKeyMaterial::Ed25519(public_key) = public_key else {
        return Err(DidError::InvalidPublicKey);
    };
    let mut bytes = vec![0xed, 0x01];
    bytes.extend_from_slice(&public_key.to_bytes());
    Ok(format!("z{}", bs58::encode(bytes).into_string()))
}

pub(crate) fn public_key_multibase(public_key: &PublicKeyMaterial) -> DidResult<String> {
    match public_key {
        PublicKeyMaterial::Ed25519(_) => ed25519_public_multibase(public_key),
        PublicKeyMaterial::X25519(bytes) => {
            let mut encoded = vec![0xec, 0x01];
            encoded.extend_from_slice(bytes);
            Ok(format!("z{}", bs58::encode(encoded).into_string()))
        }
        _ => Err(DidError::InvalidPublicKey),
    }
}

pub(crate) fn document_digest(document: &Value) -> DidResult<String> {
    let canonical = serde_json_canonicalizer::to_vec(document)
        .map_err(|error| DidError::Serialization(error.to_string()))?;
    Ok(format!(
        "sha256:{}",
        URL_SAFE_NO_PAD.encode(Sha256::digest(canonical))
    ))
}

pub(crate) fn root_key_fingerprint(document: &Value) -> DidResult<String> {
    let root_kid = document
        .get("proof")
        .and_then(Value::as_object)
        .and_then(|proof| proof.get("verificationMethod"))
        .and_then(Value::as_str)
        .ok_or(DidError::InvalidIdentity)?;
    let method = find_verification_method(document, root_kid).ok_or(DidError::InvalidIdentity)?;
    let public =
        anp::authentication::extract_public_key(&method).map_err(|_| DidError::InvalidPublicKey)?;
    let PublicKeyMaterial::Ed25519(public) = public else {
        return Err(DidError::InvalidPublicKey);
    };
    let mut digest = Sha256::new();
    digest.update(b"anp-identity:root-public-fingerprint:v1\0");
    digest.update(public.to_bytes());
    Ok(format!(
        "sha256:{}",
        URL_SAFE_NO_PAD.encode(digest.finalize())
    ))
}

pub(crate) fn key_metadata_from_public(
    kid: &str,
    role: KeyRole,
    origin: KeyOrigin,
    state: KeyState,
    public_key: &PublicKeyMaterial,
    created_at: &str,
) -> DidResult<KeyMetadata> {
    Ok(KeyMetadata {
        kid: kid.to_string(),
        role,
        origin,
        state,
        material_erased: false,
        version: 1,
        public_key_multibase: public_key_multibase(public_key)?,
        created_at: created_at.to_string(),
    })
}

fn public_key_from_raw(role: KeyRole, bytes: &Zeroizing<[u8; 32]>) -> PublicKeyMaterial {
    match role {
        KeyRole::E2eeAgreement => {
            let secret = x25519_dalek::StaticSecret::from(**bytes);
            PublicKeyMaterial::X25519(x25519_dalek::PublicKey::from(&secret).to_bytes())
        }
        KeyRole::RootControl
        | KeyRole::DeviceSigning
        | KeyRole::RequestSigning
        | KeyRole::E2eeSigning => {
            let signing_key = ed25519_dalek::SigningKey::from_bytes(bytes);
            PublicKeyMaterial::Ed25519(signing_key.verifying_key())
        }
    }
}

fn supplied_managed_key(key: &ManagedPrivateKey) -> SuppliedDidKey {
    SuppliedDidKey {
        fragment: key.fragment.clone(),
        role: anp_role(key.role),
        public_key: key.public_key(),
        relationships: relationships(key.role),
    }
}

fn anp_role(role: KeyRole) -> DidKeyRole {
    match role {
        KeyRole::RootControl => DidKeyRole::RootControl,
        KeyRole::DeviceSigning => DidKeyRole::DeviceSigning,
        KeyRole::RequestSigning => DidKeyRole::RequestSigning,
        KeyRole::E2eeSigning => DidKeyRole::E2eeSigning,
        KeyRole::E2eeAgreement => DidKeyRole::E2eeAgreement,
    }
}

fn relationships(role: KeyRole) -> Vec<DidVerificationRelationship> {
    match role {
        KeyRole::RootControl => vec![
            DidVerificationRelationship::Authentication,
            DidVerificationRelationship::AssertionMethod,
        ],
        KeyRole::DeviceSigning => vec![
            DidVerificationRelationship::Authentication,
            DidVerificationRelationship::AssertionMethod,
        ],
        KeyRole::RequestSigning => vec![DidVerificationRelationship::Authentication],
        KeyRole::E2eeSigning => vec![DidVerificationRelationship::AssertionMethod],
        KeyRole::E2eeAgreement => vec![DidVerificationRelationship::KeyAgreement],
    }
}

pub(crate) fn service_json(service: &ServiceSpec) -> Value {
    let mut value = json!({
        "id": if service.id.starts_with('#') {
            service.id.clone()
        } else {
            format!("#{}", service.id)
        },
        "type": service.service_type,
        "serviceEndpoint": service.service_endpoint,
    });
    if !service.profiles.is_empty() {
        value["profiles"] = json!(service.profiles);
    }
    if !service.security_profiles.is_empty() {
        value["securityProfiles"] = json!(service.security_profiles);
    }
    value
}

fn apply_extensions(
    document: &mut Value,
    did: &str,
    extensions: &[DidExtensionSpec],
) -> DidResult<()> {
    let object = document.as_object_mut().ok_or(DidError::InvalidIdentity)?;
    for extension in extensions {
        match extension {
            DidExtensionSpec::DeviceManifest(manifest) => {
                if object.contains_key("deviceManifest") {
                    return Err(DidError::InvalidExtension);
                }
                let devices = manifest
                    .devices
                    .iter()
                    .map(|device| {
                        Ok(DeviceManifestEntry {
                            device_id: device.device_id.clone(),
                            signing_key_id: canonicalize_kid(did, &device.signing_key_id)?,
                            e2ee_key_id: canonicalize_kid(did, &device.e2ee_key_id)?,
                            profiles: device.profiles.clone(),
                        })
                    })
                    .collect::<DidResult<Vec<_>>>()?;
                object.insert(
                    "deviceManifest".to_string(),
                    serde_json::to_value(DeviceManifest {
                        manifest_type: DEVICE_MANIFEST_TYPE.to_string(),
                        devices,
                    })
                    .map_err(|_| DidError::InvalidExtension)?,
                );
            }
        }
    }
    Ok(())
}

pub(crate) fn key_metadata(
    document: &Value,
    kid: &str,
    role: KeyRole,
    origin: KeyOrigin,
    created_at: &str,
) -> DidResult<KeyMetadata> {
    let method = find_verification_method(document, kid).ok_or(DidError::InvalidIdentity)?;
    let multibase = method
        .get("publicKeyMultibase")
        .and_then(Value::as_str)
        .ok_or(DidError::InvalidPublicKey)?;
    Ok(KeyMetadata {
        kid: kid.to_string(),
        role,
        origin,
        state: KeyState::Active,
        material_erased: false,
        version: 1,
        public_key_multibase: multibase.to_string(),
        created_at: created_at.to_string(),
    })
}

fn random_challenge() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
