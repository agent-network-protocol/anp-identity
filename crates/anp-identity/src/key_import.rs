use chrono::Utc;
use serde_json::Value;
use zeroize::Zeroizing;

use anp::{PrivateKeyMaterial, PublicKeyMaterial};

use crate::document::{
    key_metadata, public_key_from_secret, public_keys_equal, root_key_fingerprint,
};
use crate::input::canonicalize_kid;
use crate::keystore::{SealIfAbsent, SecretRef};
use crate::registry::{
    new_identity_record, read_registry, write_identity, write_journal, write_registry,
    CreationJournal, NewIdentityRecord, RootCapabilityState,
};
use crate::secret::SecretBytes;
use crate::{
    Capabilities, DidError, DidIdentity, DidResult, DidStore, KeyOrigin, KeyRole,
    VerifiedDocumentEvidence,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateKeyEncoding {
    Raw32,
    Pkcs8Der,
}

pub struct ImportedPrivateKey {
    kid: String,
    role: KeyRole,
    encoding: PrivateKeyEncoding,
    secret: Zeroizing<Vec<u8>>,
}

impl ImportedPrivateKey {
    pub fn new(
        kid: impl Into<String>,
        role: KeyRole,
        encoding: PrivateKeyEncoding,
        secret: Zeroizing<Vec<u8>>,
    ) -> Self {
        Self {
            kid: kid.into(),
            role,
            encoding,
            secret,
        }
    }
}

pub struct IdentityImportSpec {
    pub verified_document: Value,
    pub evidence: VerifiedDocumentEvidence,
    pub capabilities: Capabilities,
    pub private_keys: Vec<ImportedPrivateKey>,
}

impl DidStore {
    pub fn import_identity(&mut self, spec: IdentityImportSpec) -> DidResult<DidIdentity> {
        crate::adoption::validate_verified_document(&spec.verified_document, &spec.evidence)?;
        let did = spec
            .verified_document
            .get("id")
            .and_then(Value::as_str)
            .ok_or(DidError::InvalidIdentity)?
            .to_string();
        let imported = prepare_imported_keys(&did, &spec.verified_document, spec.private_keys)?;
        validate_imported_roles(&spec.verified_document, &spec.capabilities, &imported)?;

        let guard = self.runtime.acquire_write()?;
        let mut registry = read_registry(self.runtime.root())?;
        if registry.generation != self.registry_generation {
            return Err(DidError::Conflict);
        }
        if registry.identities.contains_key(&did) {
            return Err(DidError::DuplicateIdentity);
        }
        let identity_id = crate::identity::random_id();
        let transaction_id = crate::identity::random_id();
        let created_at = Utc::now().to_rfc3339();
        let secret_refs = imported
            .iter()
            .map(|key| SecretRef {
                identity_id: identity_id.clone(),
                key_id: key.kid.clone(),
                role: key.role,
                version: 1,
            })
            .collect::<Vec<_>>();
        let journal = CreationJournal::new(
            transaction_id.clone(),
            identity_id.clone(),
            did.clone(),
            secret_refs.clone(),
            created_at.clone(),
        );
        write_journal(self.runtime.root(), &guard, &journal)?;
        for (key, secret_ref) in imported.iter().zip(&secret_refs) {
            let sealed = self.runtime.key_store().seal_if_absent(
                &guard,
                self.runtime.root_key(),
                secret_ref.clone(),
                SecretBytes::new(key.raw.to_vec()),
            )?;
            if sealed == SealIfAbsent::AlreadyExists {
                let persisted = self
                    .runtime
                    .key_store()
                    .open(self.runtime.root_key(), secret_ref)?;
                let actual = public_key_from_secret(key.role, &persisted)?;
                if !public_keys_equal(&actual, &key.public) {
                    return Err(DidError::InvalidIdentity);
                }
            }
        }
        let metadata = imported
            .iter()
            .map(|key| {
                key_metadata(
                    &spec.verified_document,
                    &key.kid,
                    key.role,
                    KeyOrigin::Managed,
                    &created_at,
                )
            })
            .collect::<DidResult<Vec<_>>>()?;
        let local_authorization =
            crate::adoption::infer_local_authorization(&spec.verified_document, &metadata)?;
        let mut record = new_identity_record(NewIdentityRecord {
            identity_id,
            did: did.clone(),
            document: spec.verified_document,
            keys: metadata,
            capabilities: spec.capabilities,
            root_capability: RootCapabilityState::Active,
            root_key_fingerprint: root_key_fingerprint_from_import(&imported)?,
            checkpoint: crate::DocumentCheckpoint {
                document_version: spec.evidence.document_version,
                registry_version: spec.evidence.registry_version,
                document_digest: spec.evidence.document_digest,
            },
            local_authorization,
            created_at,
        });
        record.state = crate::IdentityState::Active;
        write_identity(self.runtime.root(), &guard, &record)?;
        let next_generation = registry
            .generation
            .checked_add(1)
            .ok_or(DidError::Conflict)?;
        registry.identities.insert(did, record.summary());
        registry.generation = next_generation;
        write_registry(self.runtime.root(), &guard, &registry)?;
        crate::registry::remove_journal(self.runtime.root(), &guard, &transaction_id)?;
        drop(guard);
        self.registry_generation = next_generation;
        Ok(DidIdentity {
            runtime: std::sync::Arc::clone(&self.runtime),
            record,
        })
    }
}

struct PreparedImportedKey {
    kid: String,
    role: KeyRole,
    raw: Zeroizing<[u8; 32]>,
    public: PublicKeyMaterial,
}

fn prepare_imported_keys(
    did: &str,
    document: &Value,
    keys: Vec<ImportedPrivateKey>,
) -> DidResult<Vec<PreparedImportedKey>> {
    if keys.is_empty() {
        return Err(DidError::KeyNotFound);
    }
    let mut output = Vec::with_capacity(keys.len());
    for key in keys {
        let kid = canonicalize_kid(did, &key.kid)?;
        if output
            .iter()
            .any(|existing: &PreparedImportedKey| existing.kid == kid)
        {
            return Err(DidError::DuplicateKid);
        }
        let material = parse_private_key(key.role, key.encoding, &key.secret)?;
        let public = material.public_key();
        let method = anp::authentication::find_verification_method(document, &kid)
            .ok_or(DidError::KeyNotFound)?;
        let expected = anp::authentication::extract_public_key(&method)
            .map_err(|_| DidError::InvalidPublicKey)?;
        if !public_keys_equal(&public, &expected) {
            return Err(DidError::InvalidPublicKey);
        }
        output.push(PreparedImportedKey {
            kid,
            role: key.role,
            raw: raw_private_key(material, key.role)?,
            public,
        });
    }
    Ok(output)
}

fn validate_imported_roles(
    document: &Value,
    capabilities: &Capabilities,
    keys: &[PreparedImportedKey],
) -> DidResult<()> {
    let root_kid = document
        .get("proof")
        .and_then(Value::as_object)
        .and_then(|proof| proof.get("verificationMethod"))
        .and_then(Value::as_str)
        .ok_or(DidError::InvalidIdentity)?;
    let roots = keys
        .iter()
        .filter(|key| key.role == KeyRole::RootControl)
        .collect::<Vec<_>>();
    if roots.len() != 1 || roots[0].kid != root_kid {
        return Err(DidError::InvalidManagedRootCount);
    }
    if capabilities.did_wba
        && !keys
            .iter()
            .any(|key| matches!(key.role, KeyRole::DeviceSigning | KeyRole::RequestSigning))
    {
        return Err(DidError::MissingManagedRequestSigning);
    }
    Ok(())
}

pub(crate) fn parse_private_key(
    role: KeyRole,
    encoding: PrivateKeyEncoding,
    secret: &[u8],
) -> DidResult<PrivateKeyMaterial> {
    let material = match encoding {
        PrivateKeyEncoding::Raw32 => {
            let raw: [u8; 32] = secret.try_into().map_err(|_| DidError::InvalidIdentity)?;
            match role {
                KeyRole::E2eeAgreement => {
                    PrivateKeyMaterial::X25519(x25519_dalek::StaticSecret::from(raw))
                }
                KeyRole::RootControl
                | KeyRole::DeviceSigning
                | KeyRole::RequestSigning
                | KeyRole::E2eeSigning => {
                    PrivateKeyMaterial::Ed25519(ed25519_dalek::SigningKey::from_bytes(&raw))
                }
            }
        }
        PrivateKeyEncoding::Pkcs8Der => {
            PrivateKeyMaterial::from_pkcs8_der(secret).map_err(|_| DidError::InvalidIdentity)?
        }
    };
    match (&role, &material) {
        (KeyRole::E2eeAgreement, PrivateKeyMaterial::X25519(_))
        | (
            KeyRole::RootControl
            | KeyRole::DeviceSigning
            | KeyRole::RequestSigning
            | KeyRole::E2eeSigning,
            PrivateKeyMaterial::Ed25519(_),
        ) => Ok(material),
        _ => Err(DidError::KeyRoleViolation),
    }
}

pub(crate) fn raw_private_key(
    material: PrivateKeyMaterial,
    role: KeyRole,
) -> DidResult<Zeroizing<[u8; 32]>> {
    match (role, material) {
        (KeyRole::E2eeAgreement, PrivateKeyMaterial::X25519(key)) => {
            Ok(Zeroizing::new(key.to_bytes()))
        }
        (
            KeyRole::RootControl
            | KeyRole::DeviceSigning
            | KeyRole::RequestSigning
            | KeyRole::E2eeSigning,
            PrivateKeyMaterial::Ed25519(key),
        ) => Ok(Zeroizing::new(key.to_bytes())),
        _ => Err(DidError::KeyRoleViolation),
    }
}

fn root_key_fingerprint_from_import(keys: &[PreparedImportedKey]) -> DidResult<String> {
    let root = keys
        .iter()
        .find(|key| key.role == KeyRole::RootControl)
        .ok_or(DidError::InvalidManagedRootCount)?;
    let mut document = serde_json::Map::new();
    document.insert(
        "proof".to_string(),
        serde_json::json!({"verificationMethod": root.kid}),
    );
    document.insert(
        "verificationMethod".to_string(),
        serde_json::json!([{
            "id": root.kid,
            "type": "Multikey",
            "publicKeyMultibase": crate::document::public_key_multibase(&root.public)?,
        }]),
    );
    root_key_fingerprint(&Value::Object(document))
}

#[cfg(test)]
mod tests;
