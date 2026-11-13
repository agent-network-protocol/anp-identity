//! Local purpose-bound PAP and DPoP custody. Handles never grant authorization.
use super::oauth::{
    jws_input, nonce, select_oauth_key, sign_identity_jws, validate_https_identifier,
};
use super::{IdentityError, IdentityResult, KeySelector, ManagedIdentity};
use crate::keystore::{SealIfAbsent, SecretRef};
use crate::registry::{
    read_identity, remove_update_journal, write_identity, write_update_journal, UpdateJournal,
    UpdateJournalKind,
};
use crate::{KeyRole, KeyState};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct P256PublicJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}
impl P256PublicJwk {
    fn from_key(key: &p256::ecdsa::VerifyingKey) -> Self {
        let point = key.to_encoded_point(false);
        Self {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: URL_SAFE_NO_PAD.encode(point.x().expect("uncompressed point")),
            y: URL_SAFE_NO_PAD.encode(point.y().expect("uncompressed point")),
        }
    }
    pub fn thumbprint(&self) -> IdentityResult<String> {
        self.verifier()?;
        let bytes =
            serde_json::to_vec(&json!({"crv":self.crv,"kty":self.kty,"x":self.x,"y":self.y}))
                .map_err(|_| IdentityError::Internal)?;
        Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)))
    }
    fn verifier(&self) -> IdentityResult<p256::ecdsa::VerifyingKey> {
        if self.kty != "EC" || self.crv != "P-256" {
            return Err(IdentityError::InvalidRequest);
        }
        let mut point = vec![4u8];
        for coordinate in [&self.x, &self.y] {
            let bytes = URL_SAFE_NO_PAD
                .decode(coordinate)
                .map_err(|_| IdentityError::InvalidRequest)?;
            if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != *coordinate {
                return Err(IdentityError::InvalidRequest);
            }
            point.extend(bytes);
        }
        p256::ecdsa::VerifyingKey::from_sec1_bytes(&point)
            .map_err(|_| IdentityError::InvalidRequest)
    }
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TemporaryKeyPurpose {
    PapSession,
    PapDpop,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TemporaryKeyScope {
    pub owner: String,
    pub company_id: String,
    pub user_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_slot: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CreateTemporaryKeyRequest {
    pub operation_id: String,
    pub scope: TemporaryKeyScope,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TemporaryKey {
    pub handle: String,
    pub purpose: TemporaryKeyPurpose,
    pub generation: u64,
    pub public_jwk: P256PublicJwk,
    pub thumbprint: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TemporaryKeyReference {
    pub handle: String,
    pub generation: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RetireTemporaryKeyRequest {
    pub handle: String,
    pub generation: u64,
    pub scope: TemporaryKeyScope,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DescribeTemporaryKeyRequest {
    pub handle: String,
    pub generation: u64,
    pub scope: TemporaryKeyScope,
    pub purpose: TemporaryKeyPurpose,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PapDelegationRequest {
    pub client_id: String,
    pub key: KeySelector,
    pub delegated_key: TemporaryKeyReference,
    pub scope: TemporaryKeyScope,
    pub ttl_seconds: u32,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PapSessionRequest {
    pub handle: String,
    pub generation: u64,
    pub scope: TemporaryKeyScope,
    pub delegation: String,
    pub client_id: String,
    pub sid: String,
    pub sub: String,
    #[serde(default)]
    pub agent_id: Option<String>,
    pub http_method: String,
    pub http_uri: String,
    #[serde(default)]
    pub access_token: Option<String>,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DpopProofRequest {
    pub handle: String,
    pub generation: u64,
    pub scope: TemporaryKeyScope,
    pub http_method: String,
    pub http_uri: String,
    #[serde(default)]
    pub access_token: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct TemporaryKeyRecord {
    pub(crate) public: TemporaryKey,
    pub(crate) operation_id: String,
    pub(crate) scope_digest: String,
    pub(crate) active: bool,
}
impl TemporaryKeyRecord {
    pub(crate) fn secret_ref(&self, identity_id: &str) -> SecretRef {
        SecretRef {
            identity_id: identity_id.into(),
            key_id: self.public.handle.clone(),
            role: KeyRole::OAuthAuthentication,
            version: 1,
        }
    }
}
impl ManagedIdentity {
    pub fn describe_temporary_key(
        &self,
        request: DescribeTemporaryKeyRequest,
    ) -> IdentityResult<TemporaryKey> {
        let engine = self.lock_engine()?;
        let _guard = engine.runtime().acquire_write()?;
        engine.require_operational()?;
        let stored = select_temporary(
            &engine,
            &request.handle,
            request.generation,
            &request.scope,
            request.purpose,
        )?;
        let secret = engine.runtime().key_store().open(
            engine.runtime().root_key(),
            &stored.secret_ref(engine.identity_id()),
        )?;
        let private = p256::ecdsa::SigningKey::from_slice(secret.expose())
            .map_err(|_| IdentityError::CorruptState)?;
        if P256PublicJwk::from_key(private.verifying_key()) != stored.public.public_jwk {
            return Err(IdentityError::CorruptState);
        }
        Ok(stored.public.clone())
    }
    pub fn create_delegated_key(
        &self,
        request: CreateTemporaryKeyRequest,
    ) -> IdentityResult<TemporaryKey> {
        self.create_temporary_key(request, TemporaryKeyPurpose::PapSession)
    }
    pub fn create_dpop_key(
        &self,
        request: CreateTemporaryKeyRequest,
    ) -> IdentityResult<TemporaryKey> {
        self.create_temporary_key(request, TemporaryKeyPurpose::PapDpop)
    }
    fn create_temporary_key(
        &self,
        request: CreateTemporaryKeyRequest,
        purpose: TemporaryKeyPurpose,
    ) -> IdentityResult<TemporaryKey> {
        validate_string(&request.operation_id, 128)?;
        let digest = scope_digest(&request.scope)?;
        let mut engine = self.lock_engine()?;
        let guard = engine.runtime().acquire_write()?;
        engine.require_operational()?;
        let mut record = read_identity(engine.runtime().root(), engine.identity_id())?;
        if let Some(existing) = record
            .temporary_keys
            .iter()
            .find(|key| key.operation_id == request.operation_id)
        {
            if existing.scope_digest != digest
                || existing.public.purpose != purpose
                || !existing.active
            {
                return Err(IdentityError::Conflict);
            }
            engine.runtime().key_store().open(
                engine.runtime().root_key(),
                &existing.secret_ref(engine.identity_id()),
            )?;
            return Ok(existing.public.clone());
        }
        if record.temporary_keys.len() >= 1024 {
            return Err(IdentityError::KeyUnavailable);
        }
        let private = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let public_jwk = P256PublicJwk::from_key(private.verifying_key());
        let public = TemporaryKey {
            handle: format!(
                "urn:anp:temporary:{}:{}:{}",
                match purpose {
                    TemporaryKeyPurpose::PapSession => "session",
                    TemporaryKeyPurpose::PapDpop => "dpop",
                },
                digest,
                nonce()
            ),
            purpose,
            generation: 1,
            thumbprint: public_jwk.thumbprint()?,
            public_jwk,
        };
        let stored = TemporaryKeyRecord {
            public: public.clone(),
            operation_id: request.operation_id,
            scope_digest: digest,
            active: true,
        };
        let secret_ref = stored.secret_ref(engine.identity_id());
        let journal_id = format!("temporary-{}", nonce());
        let journal = UpdateJournal::new(
            journal_id.clone(),
            engine.identity_id().into(),
            vec![secret_ref.clone()],
            UpdateJournalKind::Prepare,
            chrono::Utc::now().to_rfc3339(),
        );
        write_update_journal(engine.runtime().root(), &guard, &journal)?;
        let mut scalar = private.to_bytes();
        let secret = crate::secret::SecretBytes::new(scalar.to_vec());
        use zeroize::Zeroize;
        scalar.zeroize();
        if engine.runtime().key_store().seal_if_absent(
            &guard,
            engine.runtime().root_key(),
            secret_ref,
            secret,
        )? != SealIfAbsent::Sealed
        {
            return Err(IdentityError::Conflict);
        }
        record.temporary_keys.push(stored);
        record.generation = record
            .generation
            .checked_add(1)
            .ok_or(IdentityError::Conflict)?;
        write_identity(engine.runtime().root(), &guard, &record)?;
        remove_update_journal(engine.runtime().root(), &guard, &journal_id)?;
        engine.replace_record(record);
        Ok(public)
    }
    pub fn retire_temporary_key(&self, request: RetireTemporaryKeyRequest) -> IdentityResult<()> {
        let digest = scope_digest(&request.scope)?;
        let mut engine = self.lock_engine()?;
        let guard = engine.runtime().acquire_write()?;
        engine.require_operational()?;
        let mut record = read_identity(engine.runtime().root(), engine.identity_id())?;
        let stored = record
            .temporary_keys
            .iter_mut()
            .find(|key| key.public.handle == request.handle)
            .ok_or(IdentityError::KeyNotFound)?;
        if stored.scope_digest != digest || stored.public.generation != request.generation {
            return Err(IdentityError::Conflict);
        }
        if !stored.active {
            return Err(IdentityError::KeyUnavailable);
        }
        let secret_ref = stored.secret_ref(engine.identity_id());
        stored.active = false;
        stored.public.generation = stored
            .public
            .generation
            .checked_add(1)
            .ok_or(IdentityError::Conflict)?;
        let journal_id = format!("retire-{}", nonce());
        write_update_journal(
            engine.runtime().root(),
            &guard,
            &UpdateJournal::new(
                journal_id.clone(),
                engine.identity_id().into(),
                vec![secret_ref.clone()],
                UpdateJournalKind::Cleanup,
                chrono::Utc::now().to_rfc3339(),
            ),
        )?;
        record.generation = record
            .generation
            .checked_add(1)
            .ok_or(IdentityError::Conflict)?;
        write_identity(engine.runtime().root(), &guard, &record)?;
        engine.runtime().key_store().delete(&guard, &secret_ref)?;
        remove_update_journal(engine.runtime().root(), &guard, &journal_id)?;
        engine.replace_record(record);
        Ok(())
    }
    pub fn issue_pap_delegation(&self, request: PapDelegationRequest) -> IdentityResult<String> {
        validate_https_identifier(&request.client_id, true)?;
        if !(1..=86400).contains(&request.ttl_seconds) {
            return Err(IdentityError::InvalidRequest);
        }
        let engine = self.lock_engine()?;
        let _guard = engine.runtime().acquire_write()?;
        engine.require_operational()?;
        let temporary = select_temporary(
            &engine,
            &request.delegated_key.handle,
            request.delegated_key.generation,
            &request.scope,
            TemporaryKeyPurpose::PapSession,
        )?;
        let identity_key = select_oauth_key(&engine, &request.key)?;
        if identity_key.role != KeyRole::OAuthAuthentication {
            return Err(IdentityError::KeyPurposeViolation);
        }
        let now = chrono::Utc::now().timestamp();
        let token = sign_identity_jws(
            &engine,
            identity_key,
            json!({"typ":"poppy-delegation+jwt","alg":"ES256","kid":identity_key.kid}),
            json!({
                "iss":request.client_id,"cnf":{"jwk":temporary.public.public_jwk},"iat":now,"exp":now+i64::from(request.ttl_seconds),"jti":nonce()
            }),
        )?;
        engine.require_operational()?;
        Ok(token)
    }
    pub fn sign_pap_session_request(&self, request: PapSessionRequest) -> IdentityResult<String> {
        validate_https_identifier(&request.client_id, true)?;
        validate_string(&request.sid, 256)?;
        validate_string(&request.sub, 1024)?;
        if request.sub != request.scope.user_id {
            return Err(IdentityError::KeyPurposeViolation);
        }
        if let Some(agent) = &request.agent_id {
            validate_string(agent, 1024)?;
        }
        let uri = http_context(&request.http_method, &request.http_uri)?;
        let engine = self.lock_engine()?;
        let _guard = engine.runtime().acquire_write()?;
        engine.require_operational()?;
        let temporary = select_temporary(
            &engine,
            &request.handle,
            request.generation,
            &request.scope,
            TemporaryKeyPurpose::PapSession,
        )?;
        verify_delegation(
            &engine,
            &request.delegation,
            &request.client_id,
            &temporary.public.public_jwk,
        )?;
        let mut claims = json!({"iss":request.client_id,"aud":request.scope.company_id,"sid":request.sid,"sub":request.sub,"htm":request.http_method,"htu":uri,"iat":chrono::Utc::now().timestamp(),"jti":nonce()});
        if let Some(agent) = request.agent_id {
            claims["agent_id"] = json!(agent);
        }
        add_ath(&mut claims, request.access_token.as_deref())?;
        let token = sign_temporary(
            &engine,
            temporary,
            json!({"typ":"poppy-session+jwt","alg":"ES256","kid":temporary.public.thumbprint,"poppy_dlg":request.delegation}),
            claims,
        )?;
        engine.require_operational()?;
        Ok(token)
    }
    pub fn sign_dpop_proof(&self, request: DpopProofRequest) -> IdentityResult<String> {
        let uri = http_context(&request.http_method, &request.http_uri)?;
        if let Some(nonce) = &request.nonce {
            validate_string(nonce, 1024)?;
        }
        let engine = self.lock_engine()?;
        let _guard = engine.runtime().acquire_write()?;
        engine.require_operational()?;
        let temporary = select_temporary(
            &engine,
            &request.handle,
            request.generation,
            &request.scope,
            TemporaryKeyPurpose::PapDpop,
        )?;
        let mut claims = json!({"htm":request.http_method,"htu":uri,"iat":chrono::Utc::now().timestamp(),"jti":nonce()});
        if let Some(nonce) = request.nonce {
            claims["nonce"] = json!(nonce);
        }
        add_ath(&mut claims, request.access_token.as_deref())?;
        let token = sign_temporary(
            &engine,
            temporary,
            json!({"typ":"dpop+jwt","alg":"ES256","jwk":temporary.public.public_jwk}),
            claims,
        )?;
        engine.require_operational()?;
        Ok(token)
    }
}
fn select_temporary<'a>(
    engine: &'a crate::DidIdentity,
    handle: &str,
    generation: u64,
    scope: &TemporaryKeyScope,
    purpose: TemporaryKeyPurpose,
) -> IdentityResult<&'a TemporaryKeyRecord> {
    let stored = engine
        .record()
        .temporary_keys
        .iter()
        .find(|key| key.public.handle == handle)
        .ok_or(IdentityError::KeyNotFound)?;
    let digest = scope_digest(scope)?;
    let prefix = format!(
        "urn:anp:temporary:{}:{digest}:",
        match purpose {
            TemporaryKeyPurpose::PapSession => "session",
            TemporaryKeyPurpose::PapDpop => "dpop",
        }
    );
    if stored.public.purpose != purpose
        || stored.scope_digest != digest
        || !stored.public.handle.starts_with(&prefix)
    {
        return Err(IdentityError::KeyPurposeViolation);
    }
    if !stored.active || stored.public.generation != generation {
        return Err(IdentityError::KeyUnavailable);
    }
    Ok(stored)
}
fn sign_temporary(
    engine: &crate::DidIdentity,
    stored: &TemporaryKeyRecord,
    header: Value,
    claims: Value,
) -> IdentityResult<String> {
    let input = jws_input(header, claims)?;
    let secret = engine.runtime().key_store().open(
        engine.runtime().root_key(),
        &stored.secret_ref(engine.identity_id()),
    )?;
    let private = p256::ecdsa::SigningKey::from_slice(secret.expose())
        .map_err(|_| IdentityError::CorruptState)?;
    if P256PublicJwk::from_key(private.verifying_key()) != stored.public.public_jwk {
        return Err(IdentityError::CorruptState);
    }
    let signature = anp::PrivateKeyMaterial::Secp256r1(private)
        .sign_message(input.as_bytes())
        .map_err(|_| IdentityError::Internal)?;
    Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
}
fn verify_delegation(
    engine: &crate::DidIdentity,
    token: &str,
    client_id: &str,
    jwk: &P256PublicJwk,
) -> IdentityResult<()> {
    if token.len() > 16384 {
        return Err(IdentityError::InvalidRequest);
    }
    let parts = token.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err(IdentityError::InvalidRequest);
    }
    let decode = |part: &str| -> IdentityResult<Value> {
        serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(part)
                .map_err(|_| IdentityError::InvalidRequest)?,
        )
        .map_err(|_| IdentityError::InvalidRequest)
    };
    let header = decode(parts[0])?;
    let claims = decode(parts[1])?;
    let kid = header["kid"]
        .as_str()
        .ok_or(IdentityError::InvalidRequest)?;
    if header.as_object().is_none_or(|h| h.len() != 3)
        || header["alg"] != "ES256"
        || header["typ"] != "poppy-delegation+jwt"
    {
        return Err(IdentityError::InvalidRequest);
    }
    let metadata = select_oauth_key(engine, &KeySelector::Kid(kid.into()))?;
    if metadata.role != KeyRole::OAuthAuthentication || metadata.state != KeyState::Active {
        return Err(IdentityError::KeyPurposeViolation);
    }
    let signature = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| IdentityError::InvalidRequest)?;
    if signature.len() != 64 {
        return Err(IdentityError::InvalidRequest);
    }
    engine.verify(
        kid,
        format!("{}.{}", parts[0], parts[1]).as_bytes(),
        &signature,
    )?;
    let iat = claims["iat"]
        .as_i64()
        .ok_or(IdentityError::InvalidRequest)?;
    let exp = claims["exp"]
        .as_i64()
        .ok_or(IdentityError::InvalidRequest)?;
    let now = chrono::Utc::now().timestamp();
    if claims.as_object().is_none_or(|c| c.len() != 5)
        || claims["iss"] != client_id
        || claims["cnf"] != json!({"jwk":jwk})
        || iat > now + 5
        || exp <= now
        || exp
            .checked_sub(iat)
            .is_none_or(|ttl| !(1..=86400).contains(&ttl))
        || claims["jti"].as_str().is_none_or(str::is_empty)
    {
        return Err(IdentityError::InvalidRequest);
    }
    Ok(())
}
fn scope_digest(scope: &TemporaryKeyScope) -> IdentityResult<String> {
    validate_string(&scope.owner, 256)?;
    validate_string(&scope.user_id, 1024)?;
    validate_https_identifier(&scope.company_id, false)?;
    if let Some(slot) = &scope.account_slot {
        validate_string(slot, 256)?;
    }
    let bytes = serde_json::to_vec(scope).map_err(|_| IdentityError::Internal)?;
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)))
}
fn validate_string(value: &str, max: usize) -> IdentityResult<()> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(IdentityError::InvalidRequest);
    }
    Ok(())
}
fn http_context(method: &str, uri: &str) -> IdentityResult<String> {
    if method.is_empty()
        || method.len() > 32
        || !method.bytes().all(|b| b.is_ascii_uppercase() || b == b'-')
    {
        return Err(IdentityError::InvalidRequest);
    }
    let htu = uri
        .split(['?', '#'])
        .next()
        .ok_or(IdentityError::InvalidRequest)?;
    validate_https_identifier(htu, true)?;
    Ok(htu.into())
}
fn add_ath(claims: &mut Value, token: Option<&str>) -> IdentityResult<()> {
    if let Some(token) = token {
        validate_string(token, 65536)?;
        claims["ath"] = json!(URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes())));
    }
    Ok(())
}
#[cfg(test)]
mod tests;
