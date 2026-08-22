use std::collections::{BTreeMap, BTreeSet};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    IdentityError, IdentityResult, KeyOrigin, KeyRole, KeySelector, KeyState, ManagedIdentity,
};

pub const MAX_HTTP_SIGNING_BODY_BYTES: usize = 4 * 1024 * 1024;

const MANAGED_HEADERS: [&str; 4] = [
    "authorization",
    "content-digest",
    "signature",
    "signature-input",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct HttpRequestSigningOptions {
    pub nonce: Option<String>,
    pub created: Option<i64>,
    pub expires: Option<i64>,
    pub covered_components: Option<Vec<String>>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExactHttpRequest {
    pub key: KeySelector,
    pub url: String,
    pub method: String,
    pub headers: Vec<HttpHeader>,
    pub body: Option<Vec<u8>>,
    #[serde(default)]
    pub options: HttpRequestSigningOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedHttpSignatureAttempt {
    pub binding_digest: String,
    pub kid: String,
    pub header_patch: Vec<HttpHeader>,
}

pub trait HttpRequestSigningPort {
    fn prepare_http_signature(
        &self,
        request: ExactHttpRequest,
    ) -> IdentityResult<PreparedHttpSignatureAttempt>;
}

pub trait LegacyDidWbaPort {
    fn prepare_legacy_did_wba(
        &self,
        key: KeySelector,
        service_domain: &str,
        version: &str,
    ) -> IdentityResult<String>;
}

impl HttpRequestSigningPort for ManagedIdentity {
    fn prepare_http_signature(
        &self,
        request: ExactHttpRequest,
    ) -> IdentityResult<PreparedHttpSignatureAttempt> {
        let normalized_headers = normalize_headers(&request.headers)?;
        if request.method.trim().is_empty() || request.url.trim() != request.url {
            return Err(IdentityError::InvalidRequest);
        }
        if request
            .body
            .as_ref()
            .is_some_and(|body| body.len() > MAX_HTTP_SIGNING_BODY_BYTES)
        {
            return Err(IdentityError::InvalidRequest);
        }
        let engine = self.lock_engine()?;
        let metadata = select_authentication_key(&engine, &request.key)?;
        let binding_digest = request_binding_digest(&request, &normalized_headers)?;
        let patch = engine.http_signature_headers_with_options(
            &metadata.kid,
            &request.url,
            &request.method,
            Some(&normalized_headers),
            request.body.as_deref(),
            anp::authentication::HttpSignatureOptions {
                keyid: None,
                nonce: request.options.nonce,
                created: request.options.created,
                expires: request.options.expires,
                covered_components: request.options.covered_components,
            },
        )?;
        Ok(PreparedHttpSignatureAttempt {
            binding_digest,
            kid: metadata.kid.clone(),
            header_patch: patch
                .into_iter()
                .map(|(name, value)| HttpHeader { name, value })
                .collect(),
        })
    }
}

impl LegacyDidWbaPort for ManagedIdentity {
    fn prepare_legacy_did_wba(
        &self,
        key: KeySelector,
        service_domain: &str,
        version: &str,
    ) -> IdentityResult<String> {
        if service_domain.trim().is_empty() || version.trim().is_empty() {
            return Err(IdentityError::InvalidRequest);
        }
        let engine = self.lock_engine()?;
        let metadata = select_authentication_key(&engine, &key)?;
        engine
            .legacy_did_wba_header(&metadata.kid, service_domain, version)
            .map_err(Into::into)
    }
}

fn select_authentication_key<'a>(
    identity: &'a crate::DidIdentity,
    selector: &KeySelector,
) -> IdentityResult<&'a crate::KeyMetadata> {
    let usable = |metadata: &&crate::KeyMetadata| {
        matches!(
            metadata.role,
            KeyRole::DeviceSigning | KeyRole::RequestSigning
        ) && metadata.origin == KeyOrigin::Managed
            && metadata.state == KeyState::Active
            && !metadata.material_erased
            && anp::authentication::is_authentication_authorized(identity.document(), &metadata.kid)
    };
    match selector {
        KeySelector::Kid(kid) => {
            let metadata = identity.key_metadata(kid)?;
            if !usable(&metadata) {
                return Err(
                    if matches!(
                        metadata.role,
                        KeyRole::DeviceSigning | KeyRole::RequestSigning
                    ) {
                        IdentityError::KeyUnavailable
                    } else {
                        IdentityError::KeyPurposeViolation
                    },
                );
            }
            Ok(metadata)
        }
        KeySelector::Default => {
            let mut candidates = identity.keys().iter().filter(usable);
            let selected = candidates.next().ok_or(IdentityError::KeyUnavailable)?;
            if candidates.next().is_some() {
                return Err(IdentityError::AmbiguousKey);
            }
            Ok(selected)
        }
    }
}

fn normalize_headers(headers: &[HttpHeader]) -> IdentityResult<BTreeMap<String, String>> {
    let mut normalized = BTreeMap::new();
    let mut names = BTreeSet::new();
    for header in headers {
        let name = header.name.trim().to_ascii_lowercase();
        if name.is_empty()
            || header.value.contains('\r')
            || header.value.contains('\n')
            || MANAGED_HEADERS.contains(&name.as_str())
            || !names.insert(name.clone())
        {
            return Err(IdentityError::InvalidRequest);
        }
        normalized.insert(name, header.value.clone());
    }
    Ok(normalized)
}

fn request_binding_digest(
    request: &ExactHttpRequest,
    normalized_headers: &BTreeMap<String, String>,
) -> IdentityResult<String> {
    #[derive(Serialize)]
    struct Binding<'a> {
        url: &'a str,
        method: &'a str,
        headers: &'a BTreeMap<String, String>,
        body_digest: String,
    }

    let body_digest =
        URL_SAFE_NO_PAD.encode(Sha256::digest(request.body.as_deref().unwrap_or_default()));
    let canonical = serde_json_canonicalizer::to_vec(&Binding {
        url: &request.url,
        method: &request.method,
        headers: normalized_headers,
        body_digest,
    })
    .map_err(|_| IdentityError::Internal)?;
    Ok(format!(
        "sha256:{}",
        URL_SAFE_NO_PAD.encode(Sha256::digest(canonical))
    ))
}

#[cfg(test)]
mod tests;
