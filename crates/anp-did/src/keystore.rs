use std::fs;
use std::path::PathBuf;

#[cfg(test)]
use std::collections::BTreeMap;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use chrono::Utc;
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::fs_util::{ensure_private_dir, write_atomic_private};
use crate::platform::RootKey;
use crate::secret::SecretBytes;
use crate::store_lock::StoreWriteGuard;
use crate::{DidError, DidResult, KeyRole};

const RECORD_SCHEMA_VERSION: u32 = 1;
const RECORD_NONCE_LEN: usize = 12;
const RECORD_HKDF_SALT: &[u8] = b"anp-did:keystore:hkdf-salt:v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct SecretRef {
    pub(crate) identity_id: String,
    pub(crate) key_id: String,
    pub(crate) role: KeyRole,
    pub(crate) version: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SealIfAbsent {
    Sealed,
    AlreadyExists,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct EncryptedRecord {
    schema_version: u32,
    secret_ref: SecretRef,
    cipher: String,
    kdf: String,
    nonce_b64u: String,
    aad_b64u: String,
    ciphertext_b64u: String,
    created_at: String,
}

impl std::fmt::Debug for EncryptedRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EncryptedRecord")
            .field("schema_version", &self.schema_version)
            .field("secret_ref", &self.secret_ref)
            .field("cipher", &self.cipher)
            .field("kdf", &self.kdf)
            .field("nonce", &"[REDACTED]")
            .field("aad", &"[REDACTED]")
            .field("ciphertext", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct FileKeyStore {
    store_root: PathBuf,
    records_root: PathBuf,
}

impl FileKeyStore {
    pub(crate) fn new(store_root: impl Into<PathBuf>) -> Self {
        let store_root = store_root.into();
        let records_root = store_root.join("records");
        Self {
            store_root,
            records_root,
        }
    }

    pub(crate) fn seal_if_absent(
        &self,
        guard: &StoreWriteGuard,
        root_key: &RootKey,
        secret_ref: SecretRef,
        plaintext: SecretBytes,
    ) -> DidResult<SealIfAbsent> {
        guard.require_store(&self.store_root)?;
        validate_secret_ref(&secret_ref)?;
        ensure_private_dir(&self.records_root)?;
        let path = self.record_path(&secret_ref);
        if path.exists() {
            return Ok(SealIfAbsent::AlreadyExists);
        }
        let record = seal_record(root_key, secret_ref, &plaintext)?;
        let bytes = serde_json::to_vec_pretty(&record)
            .map_err(|error| DidError::Serialization(error.to_string()))?;
        write_atomic_private(&path, &bytes)?;
        Ok(SealIfAbsent::Sealed)
    }

    pub(crate) fn open(
        &self,
        root_key: &RootKey,
        secret_ref: &SecretRef,
    ) -> DidResult<SecretBytes> {
        validate_secret_ref(secret_ref)?;
        let path = self.record_path(secret_ref);
        let bytes = fs::read(&path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                DidError::SecretNotFound
            } else {
                DidError::Io(error.to_string())
            }
        })?;
        let record: EncryptedRecord =
            serde_json::from_slice(&bytes).map_err(|_| DidError::CorruptRecord)?;
        if record.secret_ref != *secret_ref {
            return Err(DidError::CorruptRecord);
        }
        open_record(root_key, &record)
    }

    pub(crate) fn delete(&self, guard: &StoreWriteGuard, secret_ref: &SecretRef) -> DidResult<()> {
        guard.require_store(&self.store_root)?;
        let path = self.record_path(secret_ref);
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(DidError::Io(error.to_string())),
        }
    }

    #[cfg(test)]
    pub(crate) fn list(&self) -> DidResult<Vec<SecretRef>> {
        let entries = match fs::read_dir(&self.records_root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(DidError::Io(error.to_string())),
        };
        let mut refs = BTreeMap::new();
        for entry in entries {
            let entry = entry.map_err(|error| DidError::Io(error.to_string()))?;
            if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let bytes = fs::read(entry.path()).map_err(|_| DidError::CorruptRecord)?;
            let record: EncryptedRecord =
                serde_json::from_slice(&bytes).map_err(|_| DidError::CorruptRecord)?;
            refs.insert(record_storage_key(&record.secret_ref), record.secret_ref);
        }
        Ok(refs.into_values().collect())
    }

    pub(crate) fn record_path(&self, secret_ref: &SecretRef) -> PathBuf {
        self.records_root
            .join(format!("{}.json", record_storage_key(secret_ref)))
    }
}

fn seal_record(
    root_key: &RootKey,
    secret_ref: SecretRef,
    plaintext: &SecretBytes,
) -> DidResult<EncryptedRecord> {
    let aad = aad_for_ref(RECORD_SCHEMA_VERSION, &secret_ref);
    let record_key = derive_record_key(root_key, &aad)?;
    let mut nonce = [0_u8; RECORD_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let cipher =
        ChaCha20Poly1305::new_from_slice(record_key.as_slice()).map_err(|_| DidError::Crypto)?;
    let nonce = Nonce::from(nonce);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext.expose(),
                aad: &aad,
            },
        )
        .map_err(|_| DidError::Crypto)?;
    Ok(EncryptedRecord {
        schema_version: RECORD_SCHEMA_VERSION,
        secret_ref,
        cipher: "chacha20-poly1305".to_string(),
        kdf: "hkdf-sha256".to_string(),
        nonce_b64u: URL_SAFE_NO_PAD.encode(nonce),
        aad_b64u: URL_SAFE_NO_PAD.encode(aad),
        ciphertext_b64u: URL_SAFE_NO_PAD.encode(ciphertext),
        created_at: Utc::now().to_rfc3339(),
    })
}

fn open_record(root_key: &RootKey, record: &EncryptedRecord) -> DidResult<SecretBytes> {
    if record.schema_version != RECORD_SCHEMA_VERSION
        || record.cipher != "chacha20-poly1305"
        || record.kdf != "hkdf-sha256"
    {
        return Err(DidError::CorruptRecord);
    }
    let aad = aad_for_ref(record.schema_version, &record.secret_ref);
    if URL_SAFE_NO_PAD.encode(&aad) != record.aad_b64u {
        return Err(DidError::CorruptRecord);
    }
    let nonce: [u8; RECORD_NONCE_LEN] = URL_SAFE_NO_PAD
        .decode(&record.nonce_b64u)
        .map_err(|_| DidError::CorruptRecord)?
        .try_into()
        .map_err(|_| DidError::CorruptRecord)?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&record.ciphertext_b64u)
        .map_err(|_| DidError::CorruptRecord)?;
    let record_key = derive_record_key(root_key, &aad)?;
    let cipher =
        ChaCha20Poly1305::new_from_slice(record_key.as_slice()).map_err(|_| DidError::Crypto)?;
    let nonce = Nonce::from(nonce);
    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| DidError::CorruptRecord)?;
    Ok(SecretBytes::new(plaintext))
}

fn derive_record_key(root_key: &RootKey, aad: &[u8]) -> DidResult<Zeroizing<[u8; 32]>> {
    let hkdf = Hkdf::<Sha256>::new(Some(RECORD_HKDF_SALT), root_key.expose());
    let mut key = Zeroizing::new([0_u8; 32]);
    hkdf.expand(aad, key.as_mut())
        .map_err(|_| DidError::Crypto)?;
    Ok(key)
}

fn aad_for_ref(schema_version: u32, secret_ref: &SecretRef) -> Vec<u8> {
    let mut aad = Vec::new();
    push_field(&mut aad, "domain", "anp-did:keystore:v1");
    push_field(&mut aad, "schema", &schema_version.to_string());
    push_field(&mut aad, "identity", &secret_ref.identity_id);
    push_field(&mut aad, "kid", &secret_ref.key_id);
    push_field(&mut aad, "role", key_role_name(secret_ref.role));
    push_field(&mut aad, "version", &secret_ref.version.to_string());
    aad
}

fn push_field(output: &mut Vec<u8>, name: &str, value: &str) {
    output.extend_from_slice(name.as_bytes());
    output.push(0);
    output.extend_from_slice(value.len().to_string().as_bytes());
    output.push(0);
    output.extend_from_slice(value.as_bytes());
    output.push(0xff);
}

fn key_role_name(role: KeyRole) -> &'static str {
    match role {
        KeyRole::RootControl => "root-control",
        KeyRole::RequestSigning => "request-signing",
        KeyRole::E2eeSigning => "e2ee-signing",
        KeyRole::E2eeAgreement => "e2ee-agreement",
    }
}

fn validate_secret_ref(secret_ref: &SecretRef) -> DidResult<()> {
    if secret_ref.identity_id.trim().is_empty()
        || secret_ref.key_id.trim().is_empty()
        || secret_ref.version == 0
    {
        return Err(DidError::InvalidKidFragment);
    }
    Ok(())
}

fn record_storage_key(secret_ref: &SecretRef) -> String {
    let mut digest = Sha256::new();
    push_hash_field(&mut digest, "identity", &secret_ref.identity_id);
    push_hash_field(&mut digest, "kid", &secret_ref.key_id);
    push_hash_field(&mut digest, "role", key_role_name(secret_ref.role));
    push_hash_field(&mut digest, "version", &secret_ref.version.to_string());
    URL_SAFE_NO_PAD.encode(digest.finalize())
}

fn push_hash_field(digest: &mut Sha256, name: &str, value: &str) {
    digest.update(name.as_bytes());
    digest.update([0]);
    digest.update(value.len().to_string().as_bytes());
    digest.update([0]);
    digest.update(value.as_bytes());
    digest.update([0xff]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store_lock::StoreLock;

    fn secret_ref(identity: &str) -> SecretRef {
        SecretRef {
            identity_id: identity.to_string(),
            key_id: "did:wba:example.com:agents:alice:e1_test#root".to_string(),
            role: KeyRole::RootControl,
            version: 1,
        }
    }

    #[test]
    fn keystore_encrypts_roundtrips_and_isolates_identity_refs() {
        let root = tempfile::tempdir().unwrap();
        let key_store = FileKeyStore::new(root.path());
        let root_key = RootKey::from_bytes([7_u8; 32]);
        let guard = StoreLock::new(root.path()).acquire_exclusive().unwrap();
        let alice = secret_ref("alice");
        assert_eq!(
            key_store
                .seal_if_absent(
                    &guard,
                    &root_key,
                    alice.clone(),
                    SecretBytes::new(b"private-key-material".to_vec()),
                )
                .unwrap(),
            SealIfAbsent::Sealed
        );
        assert_eq!(
            key_store
                .seal_if_absent(
                    &guard,
                    &root_key,
                    alice.clone(),
                    SecretBytes::new(b"different-material".to_vec()),
                )
                .unwrap(),
            SealIfAbsent::AlreadyExists
        );
        drop(guard);

        let opened = key_store.open(&root_key, &alice).unwrap();
        assert_eq!(opened.expose(), b"private-key-material");
        let raw = fs::read(key_store.record_path(&alice)).unwrap();
        assert!(!raw
            .windows(b"private-key-material".len())
            .any(|window| window == b"private-key-material"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(
                fs::metadata(key_store.record_path(&alice))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(&key_store.records_root)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
        assert!(matches!(
            key_store.open(&root_key, &secret_ref("bob")),
            Err(DidError::SecretNotFound)
        ));
        assert_eq!(key_store.list().unwrap(), vec![alice]);
    }

    #[test]
    fn keystore_rejects_record_tamper() {
        let root = tempfile::tempdir().unwrap();
        let key_store = FileKeyStore::new(root.path());
        let root_key = RootKey::from_bytes([7_u8; 32]);
        let secret_ref = secret_ref("alice");
        let guard = StoreLock::new(root.path()).acquire_exclusive().unwrap();
        key_store
            .seal_if_absent(
                &guard,
                &root_key,
                secret_ref.clone(),
                SecretBytes::new(b"private-key-material".to_vec()),
            )
            .unwrap();
        drop(guard);
        let path = key_store.record_path(&secret_ref);
        let mut record: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        record["secret_ref"]["identity_id"] = serde_json::Value::String("bob".to_string());
        fs::write(path, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(matches!(
            key_store.open(&root_key, &secret_ref),
            Err(DidError::CorruptRecord)
        ));
    }
}
