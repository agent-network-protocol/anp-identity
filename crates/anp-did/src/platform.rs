use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::fs_util::write_private_if_absent;
use crate::store_lock::StoreWriteGuard;
use crate::{DidError, DidResult, RootKeyProviderBinding, RootKeyProviderKind};

pub(crate) const ROOT_KEY_LEN: usize = 32;

pub(crate) struct RootKey {
    bytes: Zeroizing<[u8; ROOT_KEY_LEN]>,
}

impl RootKey {
    pub(crate) fn generate() -> Self {
        let mut bytes = [0_u8; ROOT_KEY_LEN];
        OsRng.fill_bytes(&mut bytes);
        let root_key = Self::from_bytes(bytes);
        bytes.zeroize();
        root_key
    }

    pub(crate) fn from_bytes(mut bytes: [u8; ROOT_KEY_LEN]) -> Self {
        let mut protected = Zeroizing::new([0_u8; ROOT_KEY_LEN]);
        protected.copy_from_slice(&bytes);
        bytes.zeroize();
        Self { bytes: protected }
    }

    pub(crate) fn expose(&self) -> &[u8; ROOT_KEY_LEN] {
        &self.bytes
    }
}

pub(crate) trait RootKeyProvider: Send + Sync {
    fn binding(&self) -> RootKeyProviderBinding;
    fn load_existing(&self) -> DidResult<RootKey>;
    fn create_if_missing(&self, guard: &StoreWriteGuard) -> DidResult<RootKey>;
}

pub(crate) struct InjectedRootKeyProvider {
    binding: RootKeyProviderBinding,
    root_key: RootKey,
}

impl InjectedRootKeyProvider {
    pub(crate) fn new(key_id: impl Into<String>, mut bytes: [u8; ROOT_KEY_LEN]) -> Self {
        let provider = Self {
            binding: RootKeyProviderBinding {
                kind: RootKeyProviderKind::Injected,
                key_id: key_id.into(),
                account: None,
            },
            root_key: RootKey::from_bytes(bytes),
        };
        bytes.zeroize();
        provider
    }

    pub(crate) fn from_env(key_id: impl Into<String>, name: &str) -> DidResult<Self> {
        let encoded =
            Zeroizing::new(std::env::var(name).map_err(|_| DidError::ProviderUnavailable)?);
        let mut bytes = decode_root_key(encoded.as_bytes())?;
        let provider = Self::new(key_id, bytes);
        bytes.zeroize();
        Ok(provider)
    }
}

impl RootKeyProvider for InjectedRootKeyProvider {
    fn binding(&self) -> RootKeyProviderBinding {
        self.binding.clone()
    }

    fn load_existing(&self) -> DidResult<RootKey> {
        Ok(RootKey::from_bytes(*self.root_key.expose()))
    }

    fn create_if_missing(&self, _guard: &StoreWriteGuard) -> DidResult<RootKey> {
        self.load_existing()
    }
}

pub(crate) struct FileRootKeyProvider {
    binding: RootKeyProviderBinding,
    path: PathBuf,
}

impl FileRootKeyProvider {
    pub(crate) fn new(key_id: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            binding: RootKeyProviderBinding {
                kind: RootKeyProviderKind::LocalPrivateFile,
                key_id: key_id.into(),
                account: None,
            },
            path: path.into(),
        }
    }

    fn read(&self) -> DidResult<RootKey> {
        let encoded =
            Zeroizing::new(std::fs::read(&self.path).map_err(|_| DidError::ProviderUnavailable)?);
        require_private_file_mode(&self.path)?;
        Ok(RootKey::from_bytes(decode_root_key(&encoded)?))
    }
}

impl RootKeyProvider for FileRootKeyProvider {
    fn binding(&self) -> RootKeyProviderBinding {
        self.binding.clone()
    }

    fn load_existing(&self) -> DidResult<RootKey> {
        self.read()
    }

    fn create_if_missing(&self, guard: &StoreWriteGuard) -> DidResult<RootKey> {
        let store_root = self
            .path
            .parent()
            .ok_or_else(|| DidError::Io("root-key file has no parent".to_string()))?;
        guard.require_store(store_root)?;
        if self.path.exists() {
            return self.read();
        }
        let root_key = RootKey::generate();
        let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(root_key.expose()));
        if !write_private_if_absent(&self.path, encoded.as_bytes())? {
            return self.read();
        }
        Ok(root_key)
    }
}

pub(crate) struct KeyringRootKeyProvider {
    binding: RootKeyProviderBinding,
    service: String,
    account: String,
}

impl KeyringRootKeyProvider {
    pub(crate) fn new(service: impl Into<String>, account: impl Into<String>) -> Self {
        let service = service.into();
        let account = account.into();
        Self {
            binding: RootKeyProviderBinding {
                kind: RootKeyProviderKind::OsKeyring,
                key_id: service.clone(),
                account: Some(account.clone()),
            },
            service,
            account,
        }
    }

    fn entry(&self) -> DidResult<keyring::Entry> {
        keyring::Entry::new(&self.service, &self.account).map_err(|_| DidError::ProviderUnavailable)
    }
}

impl RootKeyProvider for KeyringRootKeyProvider {
    fn binding(&self) -> RootKeyProviderBinding {
        self.binding.clone()
    }

    fn load_existing(&self) -> DidResult<RootKey> {
        let value = Zeroizing::new(
            self.entry()?
                .get_password()
                .map_err(|_| DidError::ProviderUnavailable)?,
        );
        Ok(RootKey::from_bytes(decode_root_key(value.as_bytes())?))
    }

    fn create_if_missing(&self, _guard: &StoreWriteGuard) -> DidResult<RootKey> {
        let entry = self.entry()?;
        match entry.get_password() {
            Ok(value) => {
                let value = Zeroizing::new(value);
                return Ok(RootKey::from_bytes(decode_root_key(value.as_bytes())?));
            }
            Err(keyring::Error::NoEntry) => {}
            Err(_) => return Err(DidError::ProviderUnavailable),
        }
        let root_key = RootKey::generate();
        let value = Zeroizing::new(URL_SAFE_NO_PAD.encode(root_key.expose()));
        entry
            .set_password(&value)
            .map_err(|_| DidError::ProviderUnavailable)?;
        Ok(root_key)
    }
}

pub(crate) fn root_key_fingerprint(root_key: &RootKey) -> String {
    let mut digest = Sha256::new();
    digest.update(b"anp-did:root-key-verifier:v1");
    digest.update(root_key.expose());
    URL_SAFE_NO_PAD.encode(digest.finalize())
}

pub(crate) fn default_file_root_key_path(store_root: &Path) -> PathBuf {
    store_root.join("root-key.b64u")
}

fn decode_root_key(encoded: &[u8]) -> DidResult<[u8; ROOT_KEY_LEN]> {
    let encoded = trim_ascii_whitespace(encoded);
    let bytes = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| DidError::RootKeyMismatch)?,
    );
    if bytes.len() != ROOT_KEY_LEN {
        return Err(DidError::RootKeyMismatch);
    }
    let mut output = [0_u8; ROOT_KEY_LEN];
    output.copy_from_slice(&bytes);
    Ok(output)
}

fn trim_ascii_whitespace(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

#[cfg(unix)]
fn require_private_file_mode(path: &Path) -> DidResult<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = std::fs::metadata(path)
        .map_err(|error| DidError::Io(error.to_string()))?
        .permissions()
        .mode()
        & 0o777;
    if mode != 0o600 {
        return Err(DidError::ProviderUnavailable);
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_private_file_mode(_path: &Path) -> DidResult<()> {
    Ok(())
}

#[cfg(test)]
pub(crate) struct MemoryRootKeyProvider {
    binding: RootKeyProviderBinding,
    bytes: [u8; ROOT_KEY_LEN],
}

#[cfg(test)]
impl MemoryRootKeyProvider {
    pub(crate) fn new(kind: RootKeyProviderKind, key_id: &str, bytes: [u8; ROOT_KEY_LEN]) -> Self {
        Self {
            binding: RootKeyProviderBinding {
                kind,
                key_id: key_id.to_string(),
                account: None,
            },
            bytes,
        }
    }
}

#[cfg(test)]
impl RootKeyProvider for MemoryRootKeyProvider {
    fn binding(&self) -> RootKeyProviderBinding {
        self.binding.clone()
    }

    fn load_existing(&self) -> DidResult<RootKey> {
        Ok(RootKey::from_bytes(self.bytes))
    }

    fn create_if_missing(&self, _guard: &StoreWriteGuard) -> DidResult<RootKey> {
        self.load_existing()
    }
}

#[cfg(test)]
pub(crate) struct UnavailableRootKeyProvider {
    binding: RootKeyProviderBinding,
}

#[cfg(test)]
impl UnavailableRootKeyProvider {
    pub(crate) fn new(kind: RootKeyProviderKind, key_id: &str) -> Self {
        Self {
            binding: RootKeyProviderBinding {
                kind,
                key_id: key_id.to_string(),
                account: None,
            },
        }
    }
}

#[cfg(test)]
impl RootKeyProvider for UnavailableRootKeyProvider {
    fn binding(&self) -> RootKeyProviderBinding {
        self.binding.clone()
    }

    fn load_existing(&self) -> DidResult<RootKey> {
        Err(DidError::ProviderUnavailable)
    }

    fn create_if_missing(&self, _guard: &StoreWriteGuard) -> DidResult<RootKey> {
        Err(DidError::ProviderUnavailable)
    }
}
