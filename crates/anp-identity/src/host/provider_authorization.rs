use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Mutex;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

const TOKEN_VERSION: &str = "anp-identity-capability/1";
const MAX_TOKEN_BYTES: usize = 16 * 1024;
const MAX_LEASE_TTL_SECONDS: i64 = 24 * 60 * 60;
const MAX_OPERATION_TTL_SECONDS: i64 = 5 * 60;

/// Rust-enforced capabilities understood by a Host-only provider lease.
pub mod capability {
    pub const IDENTITY_READ: &str = "IDENTITY_READ";
    pub const IDENTITY_CREATE: &str = "IDENTITY_CREATE";
    pub const IDENTITY_IMPORT: &str = "IDENTITY_IMPORT";
    pub const IDENTITY_SIGN: &str = "IDENTITY_SIGN";
    pub const IDENTITY_ECDH_SEALED: &str = "IDENTITY_ECDH_SEALED";
    pub const IDENTITY_DOCUMENT_UPDATE: &str = "IDENTITY_DOCUMENT_UPDATE";
    pub const IDENTITY_KEY_LIFECYCLE: &str = "IDENTITY_KEY_LIFECYCLE";
    pub const IDENTITY_DELETE: &str = "IDENTITY_DELETE";
    pub const IDENTITY_HTTP_SIGNATURE: &str = "IDENTITY_HTTP_SIGNATURE";
    pub const AWIKI_LEGACY_ROOT_TRANSFER_V1: &str = "AWIKI_LEGACY_ROOT_TRANSFER_V1";
}

/// Stable, non-secret binding for one high-risk provider operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OneTimeOperationBinding {
    pub capability: String,
    pub identity_id: String,
    pub operation: String,
    pub kid: Option<String>,
    pub request_id: String,
    pub recipient_public_key: [u8; 32],
    pub operation_input_digest: String,
}

/// Opaque authorization material. It is intentionally not `Debug` or serde-enabled.
pub struct OneTimeCapabilityToken(String);

impl OneTimeCapabilityToken {
    pub fn from_encoded(encoded: String) -> Self {
        Self(encoded)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_encoded(self) -> String {
        self.0
    }
}

/// A Rust-issued parent lease. Dropping this value does not dispose it; hosts must call
/// [`ProviderAuthorization::dispose_lease`] during their deterministic lifecycle cleanup.
pub struct ProviderCapabilityLease {
    provider_instance_id: String,
    lease_id: String,
}

impl ProviderCapabilityLease {
    pub fn provider_instance_id(&self) -> &str {
        &self.provider_instance_id
    }

    pub fn lease_id(&self) -> &str {
        &self.lease_id
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ProviderAuthorizationError {
    #[error("the provider lease is invalid")]
    LeaseInvalid,
    #[error("the provider capability is not granted")]
    CapabilityDenied,
    #[error("the one-time authorization is invalid")]
    TokenInvalid,
    #[error("the one-time authorization has expired")]
    TokenExpired,
    #[error("the one-time authorization was already consumed")]
    TokenConsumed,
    #[error("provider authorization processing failed")]
    Internal,
}

/// Per-process capability and one-time-token authority. Its HMAC key is never serialized.
pub struct ProviderAuthorization {
    provider_instance_id: String,
    hmac_key: Zeroizing<[u8; 32]>,
    state: Mutex<AuthorizationState>,
}

struct AuthorizationState {
    leases: HashMap<String, LeaseState>,
    consumed_tokens: HashSet<[u8; 32]>,
}

struct LeaseState {
    consumer: String,
    capabilities: BTreeSet<String>,
    store_id: String,
    expires_at: i64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenClaims {
    version: String,
    provider_instance_id: String,
    parent_lease_id: String,
    consumer: String,
    capability: String,
    store_id: String,
    identity_id: String,
    operation: String,
    kid: Option<String>,
    request_id: String,
    recipient_public_key_digest: String,
    operation_input_digest: String,
    expires_at: i64,
}

pub(super) struct ConsumedOneTimeAuthorization {
    pub(super) provider_instance_id: String,
    pub(super) parent_lease_id: String,
    pub(super) consumer: String,
    pub(super) capability: String,
    pub(super) store_id: String,
}

impl ProviderAuthorization {
    pub fn new() -> Self {
        let mut hmac_key = [0_u8; 32];
        rand::thread_rng().fill_bytes(&mut hmac_key);
        Self {
            provider_instance_id: random_id(),
            hmac_key: Zeroizing::new(hmac_key),
            state: Mutex::new(AuthorizationState {
                leases: HashMap::new(),
                consumed_tokens: HashSet::new(),
            }),
        }
    }

    pub fn provider_instance_id(&self) -> &str {
        &self.provider_instance_id
    }

    pub fn acquire_lease(
        &self,
        consumer: String,
        capabilities: impl IntoIterator<Item = String>,
        store_id: String,
        ttl_seconds: i64,
    ) -> Result<ProviderCapabilityLease, ProviderAuthorizationError> {
        self.acquire_lease_at(consumer, capabilities, store_id, ttl_seconds, unix_now())
    }

    pub fn dispose_lease(
        &self,
        lease: &ProviderCapabilityLease,
    ) -> Result<(), ProviderAuthorizationError> {
        if lease.provider_instance_id != self.provider_instance_id {
            return Err(ProviderAuthorizationError::LeaseInvalid);
        }
        let removed = self
            .state
            .lock()
            .map_err(|_| ProviderAuthorizationError::Internal)?
            .leases
            .remove(&lease.lease_id);
        removed
            .map(|_| ())
            .ok_or(ProviderAuthorizationError::LeaseInvalid)
    }

    pub fn issue_one_time(
        &self,
        lease: &ProviderCapabilityLease,
        binding: &OneTimeOperationBinding,
        ttl_seconds: i64,
    ) -> Result<OneTimeCapabilityToken, ProviderAuthorizationError> {
        self.issue_one_time_at(lease, binding, ttl_seconds, unix_now())
    }

    pub fn consume_one_time(
        &self,
        token: &OneTimeCapabilityToken,
        expected: &OneTimeOperationBinding,
    ) -> Result<(), ProviderAuthorizationError> {
        self.consume_for_operation_at(token, expected, unix_now())
            .map(|_| ())
    }

    pub(super) fn consume_for_operation(
        &self,
        token: &OneTimeCapabilityToken,
        expected: &OneTimeOperationBinding,
    ) -> Result<ConsumedOneTimeAuthorization, ProviderAuthorizationError> {
        self.consume_for_operation_at(token, expected, unix_now())
    }

    fn acquire_lease_at(
        &self,
        consumer: String,
        capabilities: impl IntoIterator<Item = String>,
        store_id: String,
        ttl_seconds: i64,
        now: i64,
    ) -> Result<ProviderCapabilityLease, ProviderAuthorizationError> {
        validate_nonempty(&consumer)?;
        validate_nonempty(&store_id)?;
        if !(1..=MAX_LEASE_TTL_SECONDS).contains(&ttl_seconds) {
            return Err(ProviderAuthorizationError::LeaseInvalid);
        }
        let capabilities = capabilities.into_iter().collect::<BTreeSet<_>>();
        if capabilities.is_empty() || capabilities.iter().any(|value| value.trim().is_empty()) {
            return Err(ProviderAuthorizationError::LeaseInvalid);
        }
        let lease_id = random_id();
        self.state
            .lock()
            .map_err(|_| ProviderAuthorizationError::Internal)?
            .leases
            .insert(
                lease_id.clone(),
                LeaseState {
                    consumer,
                    capabilities,
                    store_id,
                    expires_at: now + ttl_seconds,
                },
            );
        Ok(ProviderCapabilityLease {
            provider_instance_id: self.provider_instance_id.clone(),
            lease_id,
        })
    }

    fn issue_one_time_at(
        &self,
        lease: &ProviderCapabilityLease,
        binding: &OneTimeOperationBinding,
        ttl_seconds: i64,
        now: i64,
    ) -> Result<OneTimeCapabilityToken, ProviderAuthorizationError> {
        validate_binding(binding)?;
        if lease.provider_instance_id != self.provider_instance_id
            || !(1..=MAX_OPERATION_TTL_SECONDS).contains(&ttl_seconds)
        {
            return Err(ProviderAuthorizationError::LeaseInvalid);
        }
        let state = self
            .state
            .lock()
            .map_err(|_| ProviderAuthorizationError::Internal)?;
        let parent = state
            .leases
            .get(&lease.lease_id)
            .ok_or(ProviderAuthorizationError::LeaseInvalid)?;
        if parent.expires_at <= now {
            return Err(ProviderAuthorizationError::LeaseInvalid);
        }
        if !parent.capabilities.contains(&binding.capability) {
            return Err(ProviderAuthorizationError::CapabilityDenied);
        }
        let expires_at = (now + ttl_seconds).min(parent.expires_at);
        let claims = TokenClaims {
            version: TOKEN_VERSION.to_owned(),
            provider_instance_id: self.provider_instance_id.clone(),
            parent_lease_id: lease.lease_id.clone(),
            consumer: parent.consumer.clone(),
            capability: binding.capability.clone(),
            store_id: parent.store_id.clone(),
            identity_id: binding.identity_id.clone(),
            operation: binding.operation.clone(),
            kid: binding.kid.clone(),
            request_id: binding.request_id.clone(),
            recipient_public_key_digest: recipient_public_key_digest(&binding.recipient_public_key),
            operation_input_digest: binding.operation_input_digest.clone(),
            expires_at,
        };
        drop(state);
        let payload = serde_json_canonicalizer::to_vec(&claims)
            .map_err(|_| ProviderAuthorizationError::Internal)?;
        let tag = self.sign(&payload)?;
        Ok(OneTimeCapabilityToken(format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(payload),
            URL_SAFE_NO_PAD.encode(tag)
        )))
    }

    fn consume_for_operation_at(
        &self,
        token: &OneTimeCapabilityToken,
        expected: &OneTimeOperationBinding,
        now: i64,
    ) -> Result<ConsumedOneTimeAuthorization, ProviderAuthorizationError> {
        validate_binding(expected)?;
        if token.0.len() > MAX_TOKEN_BYTES {
            return Err(ProviderAuthorizationError::TokenInvalid);
        }
        let (payload_text, tag_text) = token
            .0
            .split_once('.')
            .filter(|(_, tag)| !tag.contains('.'))
            .ok_or(ProviderAuthorizationError::TokenInvalid)?;
        let payload = URL_SAFE_NO_PAD
            .decode(payload_text)
            .map_err(|_| ProviderAuthorizationError::TokenInvalid)?;
        let tag = URL_SAFE_NO_PAD
            .decode(tag_text)
            .map_err(|_| ProviderAuthorizationError::TokenInvalid)?;
        self.verify(&payload, &tag)?;
        let claims: TokenClaims = serde_json::from_slice(&payload)
            .map_err(|_| ProviderAuthorizationError::TokenInvalid)?;
        if claims.version != TOKEN_VERSION
            || claims.provider_instance_id != self.provider_instance_id
            || claims.capability != expected.capability
            || claims.identity_id != expected.identity_id
            || claims.operation != expected.operation
            || claims.kid != expected.kid
            || claims.request_id != expected.request_id
            || claims.recipient_public_key_digest
                != recipient_public_key_digest(&expected.recipient_public_key)
            || claims.operation_input_digest != expected.operation_input_digest
        {
            return Err(ProviderAuthorizationError::TokenInvalid);
        }
        if claims.expires_at <= now {
            return Err(ProviderAuthorizationError::TokenExpired);
        }
        let token_digest: [u8; 32] = Sha256::digest(token.0.as_bytes()).into();
        let mut state = self
            .state
            .lock()
            .map_err(|_| ProviderAuthorizationError::Internal)?;
        let parent = state
            .leases
            .get(&claims.parent_lease_id)
            .ok_or(ProviderAuthorizationError::LeaseInvalid)?;
        if parent.expires_at <= now
            || parent.consumer != claims.consumer
            || parent.store_id != claims.store_id
            || !parent.capabilities.contains(&claims.capability)
        {
            return Err(ProviderAuthorizationError::LeaseInvalid);
        }
        if !state.consumed_tokens.insert(token_digest) {
            return Err(ProviderAuthorizationError::TokenConsumed);
        }
        Ok(ConsumedOneTimeAuthorization {
            provider_instance_id: claims.provider_instance_id,
            parent_lease_id: claims.parent_lease_id,
            consumer: claims.consumer,
            capability: claims.capability,
            store_id: claims.store_id,
        })
    }

    fn sign(&self, payload: &[u8]) -> Result<[u8; 32], ProviderAuthorizationError> {
        let mut mac = HmacSha256::new_from_slice(self.hmac_key.as_ref())
            .map_err(|_| ProviderAuthorizationError::Internal)?;
        mac.update(payload);
        Ok(mac.finalize().into_bytes().into())
    }

    fn verify(&self, payload: &[u8], tag: &[u8]) -> Result<(), ProviderAuthorizationError> {
        let mut mac = HmacSha256::new_from_slice(self.hmac_key.as_ref())
            .map_err(|_| ProviderAuthorizationError::Internal)?;
        mac.update(payload);
        mac.verify_slice(tag)
            .map_err(|_| ProviderAuthorizationError::TokenInvalid)
    }
}

impl Default for ProviderAuthorization {
    fn default() -> Self {
        Self::new()
    }
}

pub fn recipient_public_key_digest(public_key: &[u8; 32]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"anp.identity.recipient-public-key.v1\0");
    digest.update(public_key);
    format!("sha256:{}", URL_SAFE_NO_PAD.encode(digest.finalize()))
}

fn validate_binding(binding: &OneTimeOperationBinding) -> Result<(), ProviderAuthorizationError> {
    validate_nonempty(&binding.capability)?;
    validate_nonempty(&binding.identity_id)?;
    validate_nonempty(&binding.operation)?;
    validate_nonempty(&binding.request_id)?;
    validate_nonempty(&binding.operation_input_digest)?;
    if binding
        .kid
        .as_deref()
        .is_some_and(|kid| kid.trim().is_empty())
    {
        return Err(ProviderAuthorizationError::TokenInvalid);
    }
    Ok(())
}

fn validate_nonempty(value: &str) -> Result<(), ProviderAuthorizationError> {
    if value.trim().is_empty() {
        return Err(ProviderAuthorizationError::TokenInvalid);
    }
    Ok(())
}

fn random_id() -> String {
    let mut bytes = [0_u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn unix_now() -> i64 {
    chrono::Utc::now().timestamp()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> OneTimeOperationBinding {
        OneTimeOperationBinding {
            capability: capability::IDENTITY_ECDH_SEALED.to_owned(),
            identity_id: "identity-1".to_owned(),
            operation: "ecdh_sealed".to_owned(),
            kid: Some("did:wba:example.com#agreement".to_owned()),
            request_id: "request-1".to_owned(),
            recipient_public_key: [0x41; 32],
            operation_input_digest: "sha256:request-1".to_owned(),
        }
    }

    #[test]
    fn one_time_token_binds_every_operation_field_and_rejects_replay() {
        let authority = ProviderAuthorization::new();
        let lease = authority
            .acquire_lease_at(
                "dsh-awiki".to_owned(),
                [capability::IDENTITY_ECDH_SEALED.to_owned()],
                "store-1".to_owned(),
                600,
                1_000,
            )
            .unwrap();
        let expected = binding();
        let token = authority
            .issue_one_time_at(&lease, &expected, 60, 1_000)
            .unwrap();

        let mut substituted = expected.clone();
        substituted.recipient_public_key = [0x42; 32];
        assert_eq!(
            authority
                .consume_for_operation_at(&token, &substituted, 1_001)
                .map(|_| ()),
            Err(ProviderAuthorizationError::TokenInvalid)
        );
        let mut substituted = expected.clone();
        substituted.operation_input_digest = "sha256:request-2".to_owned();
        assert_eq!(
            authority
                .consume_for_operation_at(&token, &substituted, 1_001)
                .map(|_| ()),
            Err(ProviderAuthorizationError::TokenInvalid)
        );
        assert_eq!(
            authority
                .consume_for_operation_at(&token, &expected, 1_001)
                .map(|_| ()),
            Ok(())
        );
        assert_eq!(
            authority
                .consume_for_operation_at(&token, &expected, 1_001)
                .map(|_| ()),
            Err(ProviderAuthorizationError::TokenConsumed)
        );
    }

    #[test]
    fn token_is_bound_to_instance_lease_capability_and_expiry() {
        let authority = ProviderAuthorization::new();
        let lease = authority
            .acquire_lease_at(
                "dsh-awiki".to_owned(),
                [capability::IDENTITY_ECDH_SEALED.to_owned()],
                "store-1".to_owned(),
                600,
                1_000,
            )
            .unwrap();
        let expected = binding();
        let token = authority
            .issue_one_time_at(&lease, &expected, 10, 1_000)
            .unwrap();
        assert_eq!(
            authority
                .consume_for_operation_at(&token, &expected, 1_011)
                .map(|_| ()),
            Err(ProviderAuthorizationError::TokenExpired)
        );
        let other = ProviderAuthorization::new();
        assert_eq!(
            other
                .consume_for_operation_at(&token, &expected, 1_001)
                .map(|_| ()),
            Err(ProviderAuthorizationError::TokenInvalid)
        );

        let denied = expected.clone();
        let denied_lease = authority
            .acquire_lease_at(
                "viewer".to_owned(),
                [capability::IDENTITY_READ.to_owned()],
                "store-1".to_owned(),
                600,
                1_000,
            )
            .unwrap();
        assert!(matches!(
            authority.issue_one_time_at(&denied_lease, &denied, 10, 1_000),
            Err(ProviderAuthorizationError::CapabilityDenied)
        ));
    }
}
