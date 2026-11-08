//! Typed local OAuth signing. The Host approves publication and exact target policy.
use super::{signing::select_key, IdentityError, IdentityResult, KeySelector, ManagedIdentity};
use crate::{KeyMetadata, KeyRole};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OAuthPublicJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    pub kid: String,
    pub alg: String,
    #[serde(rename = "use")]
    pub key_use: String,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OAuthClientAssertionRequest {
    pub client_id: String,
    pub audience: String,
    pub key: KeySelector,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OAuthKeyChangeRequest {
    pub fragment: String,
    pub operation_id: String,
    pub expected_revision: u64,
}

impl ManagedIdentity {
    pub fn prepare_oauth_key_change(
        &mut self,
        request: OAuthKeyChangeRequest,
    ) -> IdentityResult<super::DocumentChangeSession> {
        {
            let engine = self.lock_engine()?;
            engine.require_operational()?;
            if crate::DidProfile::for_did(engine.did())?.supports_root_control()
                && engine.root_capability() != crate::RootCapabilityState::Active
            {
                return Err(IdentityError::CapabilityUnavailable);
            }
            if let Some(pending) = &engine.record().pending_revision {
                let kid = crate::input::canonicalize_kid(engine.did(), &request.fragment)?;
                if pending.revision_id != request.operation_id
                    || pending.parent_revision != request.expected_revision
                    || pending.new_key_metadata.len() != 1
                    || pending.new_key_metadata[0].kid != kid
                    || pending.new_key_metadata[0].role != KeyRole::OAuthAuthentication
                {
                    return Err(IdentityError::Conflict);
                }
                drop(engine);
                return self
                    .resume_document_change()?
                    .ok_or(IdentityError::Internal);
            }
        }
        self.prepare_document_change(super::DocumentChangeRequest {
            changes: vec![super::DocumentChange::CreateOAuthKey {
                fragment: request.fragment,
                operation_id: request.operation_id,
                expected_revision: request.expected_revision,
            }],
        })
    }
    pub fn oauth_public_jwk(&self, key: KeySelector) -> IdentityResult<OAuthPublicJwk> {
        let engine = self.lock_engine()?;
        engine.require_operational()?;
        let metadata = select_oauth_key(&engine, &key)?;
        public_jwk(engine.document(), &metadata.kid)
    }
    pub fn export_candidate_oauth_public_jwk(&self, kid: String) -> IdentityResult<OAuthPublicJwk> {
        let engine = self.lock_engine()?;
        engine.require_operational()?;
        let kid = crate::input::canonicalize_kid(engine.did(), &kid)?;
        let pending = engine
            .record()
            .pending_revision
            .as_ref()
            .ok_or(IdentityError::DocumentChangeNotFound)?;
        if !pending
            .new_key_metadata
            .iter()
            .any(|key| key.kid == kid && key.role == KeyRole::OAuthAuthentication)
        {
            return Err(IdentityError::KeyPurposeViolation);
        }
        public_jwk(&pending.candidate_document, &kid)
    }
    pub fn sign_oauth_client_assertion(
        &self,
        request: OAuthClientAssertionRequest,
    ) -> IdentityResult<String> {
        validate_https_identifier(&request.client_id, true)?;
        validate_https_identifier(&request.audience, false)?;
        let engine = self.lock_engine()?;
        let _guard = engine.runtime().acquire_write()?;
        engine.require_operational()?;
        let metadata = select_oauth_key(&engine, &request.key)?;
        let jwk = public_jwk(engine.document(), &metadata.kid)?;
        let now = chrono::Utc::now().timestamp();
        let token = sign_identity_jws(
            &engine,
            metadata,
            json!({"alg":jwk.alg,"typ":"JWT","kid":metadata.kid}),
            json!({
                "iss":request.client_id,"sub":request.client_id,"aud":request.audience,
                "iat":now,"exp":now+60,"jti":nonce(),
            }),
        )?;
        engine.require_operational()?;
        Ok(token)
    }
}
pub(crate) fn select_oauth_key<'a>(
    engine: &'a crate::DidIdentity,
    key: &KeySelector,
) -> IdentityResult<&'a KeyMetadata> {
    match key {
        KeySelector::Kid(kid) => {
            let metadata = engine.key_metadata(kid)?;
            if !matches!(
                metadata.role,
                KeyRole::RequestSigning | KeyRole::OAuthAuthentication
            ) {
                return Err(IdentityError::KeyPurposeViolation);
            }
            select_key(engine, key, metadata.role)
        }
        KeySelector::Default => {
            let mut candidates = engine.keys().iter().filter(|m| {
                matches!(
                    m.role,
                    KeyRole::RequestSigning | KeyRole::OAuthAuthentication
                ) && select_key(engine, &KeySelector::Kid(m.kid.clone()), m.role).is_ok()
            });
            let selected = candidates.next().ok_or(IdentityError::KeyUnavailable)?;
            if candidates.next().is_some() {
                return Err(IdentityError::AmbiguousKey);
            }
            Ok(selected)
        }
    }
}
pub(crate) fn public_jwk(document: &Value, kid: &str) -> IdentityResult<OAuthPublicJwk> {
    let method = anp::authentication::find_verification_method(document, kid)
        .ok_or(IdentityError::KeyUnavailable)?;
    let public = anp::authentication::extract_public_key(&method)
        .map_err(|_| IdentityError::KeyUnavailable)?;
    let (kty, crv, x, y, alg) = match public {
        anp::PublicKeyMaterial::Ed25519(key) => (
            "OKP",
            "Ed25519",
            URL_SAFE_NO_PAD.encode(key.as_bytes()),
            None,
            "EdDSA",
        ),
        anp::PublicKeyMaterial::Secp256r1(key) => {
            let point = key.to_encoded_point(false);
            (
                "EC",
                "P-256",
                URL_SAFE_NO_PAD.encode(point.x().ok_or(IdentityError::Internal)?),
                Some(URL_SAFE_NO_PAD.encode(point.y().ok_or(IdentityError::Internal)?)),
                "ES256",
            )
        }
        _ => return Err(IdentityError::KeyPurposeViolation),
    };
    Ok(OAuthPublicJwk {
        kty: kty.into(),
        crv: crv.into(),
        x,
        y,
        kid: kid.into(),
        alg: alg.into(),
        key_use: "sig".into(),
    })
}
pub(crate) fn sign_identity_jws(
    engine: &crate::DidIdentity,
    metadata: &KeyMetadata,
    header: Value,
    claims: Value,
) -> IdentityResult<String> {
    let input = jws_input(header, claims)?;
    let signature = engine.sign_prepared(metadata, input.as_bytes())?;
    Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
}
pub(crate) fn jws_input(header: Value, claims: Value) -> IdentityResult<String> {
    Ok(format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).map_err(|_| IdentityError::Internal)?),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).map_err(|_| IdentityError::Internal)?)
    ))
}
pub(crate) fn nonce() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn validate_https_identifier(value: &str, require_path: bool) -> IdentityResult<()> {
    if value.len() > 2048
        || !value.starts_with("https://")
        || value.bytes().any(|b| b <= 0x20 || b >= 0x7f || b == b'\\')
    {
        return Err(IdentityError::InvalidRequest);
    }
    for (index, byte) in value.bytes().enumerate() {
        if byte == b'%'
            && !value
                .as_bytes()
                .get(index + 1..index + 3)
                .is_some_and(|digits| digits.iter().all(u8::is_ascii_hexdigit))
        {
            return Err(IdentityError::InvalidRequest);
        }
    }
    let parsed = url::Url::parse(value).map_err(|_| IdentityError::InvalidRequest)?;
    let authority_and_path = &value[8..];
    let authority = authority_and_path.split('/').next().unwrap_or_default();
    let raw_path = authority_and_path.split_once('/').map(|(_, path)| path);
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || authority.is_empty()
        || authority.contains('@')
        || parsed.fragment().is_some()
        || parsed.query().is_some()
        || (require_path && raw_path.is_none())
        || raw_path.is_some_and(|path| {
            path.split('/').any(|segment| {
                let decoded = segment.to_ascii_lowercase().replace("%2e", ".");
                decoded == "." || decoded == ".."
            })
        })
    {
        return Err(IdentityError::InvalidRequest);
    }
    Ok(())
}
#[cfg(test)]
mod tests;
