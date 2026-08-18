use std::collections::BTreeSet;
use std::net::IpAddr;
use std::str::FromStr;

use anp::PublicKeyMaterial;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{DidError, DidResult};

const MAX_DOMAIN_LEN: usize = 253;
const MAX_PATH_SEGMENT_LEN: usize = 128;
const MAX_KID_FRAGMENT_LEN: usize = 128;
const MAX_SERVICE_VALUE_LEN: usize = 2048;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DidProfile {
    E1,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum KeyRole {
    RootControl,
    RequestSigning,
    E2eeSigning,
    E2eeAgreement,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    #[serde(default)]
    pub did_wba: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedKeySpec {
    pub fragment: String,
    pub role: KeyRole,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublicOkpJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "format", rename_all = "snake_case")]
pub enum ExternalPublicKeyMaterial {
    Multibase { value: String },
    Jwk { public_key_jwk: PublicOkpJwk },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExternalPublicKeySpec {
    pub kid: String,
    pub role: KeyRole,
    pub material: ExternalPublicKeyMaterial,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServiceSpec {
    pub id: String,
    pub service_type: String,
    pub service_endpoint: String,
    #[serde(default)]
    pub profiles: Vec<String>,
    #[serde(default)]
    pub security_profiles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceManifestEntrySpec {
    pub device_id: String,
    pub signing_key_id: String,
    pub e2ee_key_id: String,
    #[serde(default)]
    pub profiles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceManifestSpec {
    pub devices: Vec<DeviceManifestEntrySpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum DidExtensionSpec {
    DeviceManifest(DeviceManifestSpec),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DidCreateSpec {
    pub profile: DidProfile,
    pub domain: String,
    pub port: Option<u16>,
    pub path_segments: Vec<String>,
    #[serde(default)]
    pub capabilities: Capabilities,
    pub managed_keys: Vec<ManagedKeySpec>,
    #[serde(default)]
    pub external_keys: Vec<ExternalPublicKeySpec>,
    #[serde(default)]
    pub services: Vec<ServiceSpec>,
    pub agent_description_url: Option<String>,
    #[serde(default)]
    pub extensions: Vec<DidExtensionSpec>,
}

impl DidCreateSpec {
    pub fn validate(&self) -> DidResult<()> {
        validate_domain(&self.domain)?;
        if self.path_segments.is_empty() {
            return Err(DidError::EmptyPath);
        }
        for segment in &self.path_segments {
            validate_path_segment(segment)?;
        }
        let root_count = self
            .managed_keys
            .iter()
            .filter(|key| key.role == KeyRole::RootControl)
            .count();
        if root_count != 1 {
            return Err(DidError::InvalidManagedRootCount);
        }
        if self
            .external_keys
            .iter()
            .any(|key| key.role == KeyRole::RootControl)
        {
            return Err(DidError::ExternalRootControl);
        }
        if self.capabilities.did_wba
            && !self
                .managed_keys
                .iter()
                .any(|key| key.role == KeyRole::RequestSigning)
        {
            return Err(DidError::MissingManagedRequestSigning);
        }
        let mut managed_fragments = BTreeSet::new();
        for key in &self.managed_keys {
            validate_fragment(&key.fragment)?;
            if !managed_fragments.insert(key.fragment.as_str()) {
                return Err(DidError::DuplicateKid);
            }
        }
        for key in &self.external_keys {
            key.parse_public_key()?;
        }
        for service in &self.services {
            service.validate()?;
        }
        if self
            .agent_description_url
            .as_ref()
            .is_some_and(|value| value.trim().is_empty() || value.len() > MAX_SERVICE_VALUE_LEN)
        {
            return Err(DidError::InvalidService);
        }
        for extension in &self.extensions {
            extension.validate()?;
        }
        Ok(())
    }

    pub fn validate_for_did(&self, did: &str) -> DidResult<()> {
        self.validate()?;
        let managed = self.managed_keys.iter().map(|key| key.fragment.as_str());
        let external = self.external_keys.iter().map(|key| key.kid.as_str());
        validate_unique_kids(did, managed.chain(external))
    }
}

impl ExternalPublicKeySpec {
    pub fn parse_public_key(&self) -> DidResult<PublicKeyMaterial> {
        if self.role == KeyRole::RootControl {
            return Err(DidError::ExternalRootControl);
        }
        let method_type = match self.role {
            KeyRole::RequestSigning | KeyRole::E2eeSigning => "Multikey",
            KeyRole::E2eeAgreement => "X25519KeyAgreementKey2019",
            KeyRole::RootControl => return Err(DidError::ExternalRootControl),
        };
        let method = match &self.material {
            ExternalPublicKeyMaterial::Multibase { value } => json!({
                "id": "#external",
                "type": method_type,
                "publicKeyMultibase": value,
            }),
            ExternalPublicKeyMaterial::Jwk { public_key_jwk } => json!({
                "id": "#external",
                "type": "JsonWebKey2020",
                "publicKeyJwk": public_key_jwk,
            }),
        };
        let key = anp::authentication::extract_public_key(&method)
            .map_err(|_| DidError::InvalidPublicKey)?;
        match (&self.role, &key) {
            (KeyRole::RequestSigning | KeyRole::E2eeSigning, PublicKeyMaterial::Ed25519(_))
            | (KeyRole::E2eeAgreement, PublicKeyMaterial::X25519(_)) => Ok(key),
            _ => Err(DidError::InvalidPublicKey),
        }
    }
}

impl ServiceSpec {
    pub(crate) fn validate(&self) -> DidResult<()> {
        let fragment = self.id.strip_prefix('#').unwrap_or(&self.id);
        if fragment.starts_with('#') {
            return Err(DidError::InvalidService);
        }
        validate_fragment(fragment).map_err(|_| DidError::InvalidService)?;
        if self.service_type.trim().is_empty()
            || self.service_endpoint.trim().is_empty()
            || self.service_type.len() > MAX_SERVICE_VALUE_LEN
            || self.service_endpoint.len() > MAX_SERVICE_VALUE_LEN
        {
            return Err(DidError::InvalidService);
        }
        Ok(())
    }
}

impl DidExtensionSpec {
    fn validate(&self) -> DidResult<()> {
        match self {
            Self::DeviceManifest(manifest) if manifest.devices.is_empty() => {
                Err(DidError::InvalidExtension)
            }
            Self::DeviceManifest(manifest) => {
                for device in &manifest.devices {
                    if device.device_id.trim().is_empty()
                        || device.device_id.len() > MAX_KID_FRAGMENT_LEN
                        || device.signing_key_id.trim().is_empty()
                        || device.signing_key_id.len() > MAX_SERVICE_VALUE_LEN
                        || device.e2ee_key_id.trim().is_empty()
                        || device.e2ee_key_id.len() > MAX_SERVICE_VALUE_LEN
                        || device
                            .profiles
                            .iter()
                            .any(|profile| profile.trim().is_empty())
                    {
                        return Err(DidError::InvalidExtension);
                    }
                }
                Ok(())
            }
        }
    }
}

fn validate_domain(domain: &str) -> DidResult<()> {
    if domain.is_empty()
        || domain.len() > MAX_DOMAIN_LEN
        || domain.trim() != domain
        || IpAddr::from_str(domain).is_ok()
        || !domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
    {
        return Err(DidError::InvalidDomain);
    }
    Ok(())
}

fn validate_path_segment(segment: &str) -> DidResult<()> {
    if segment.is_empty()
        || segment.len() > MAX_PATH_SEGMENT_LEN
        || !segment.bytes().all(is_identifier_byte)
    {
        return Err(DidError::InvalidPathSegment);
    }
    Ok(())
}

pub(crate) fn validate_fragment(fragment: &str) -> DidResult<()> {
    if fragment.is_empty()
        || fragment.len() > MAX_KID_FRAGMENT_LEN
        || !fragment.bytes().all(is_identifier_byte)
    {
        return Err(DidError::InvalidKidFragment);
    }
    Ok(())
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~')
}

pub(crate) fn canonicalize_kid(did: &str, kid: &str) -> DidResult<String> {
    let prefix = format!("{did}#");
    let fragment = if let Some(fragment) = kid.strip_prefix('#') {
        fragment
    } else if let Some(fragment) = kid.strip_prefix(&prefix) {
        fragment
    } else if !kid.contains(':') && !kid.contains('#') {
        kid
    } else {
        return Err(DidError::ForeignKid);
    };
    validate_fragment(fragment)?;
    Ok(format!("{prefix}{fragment}"))
}

fn validate_unique_kids<'a>(did: &str, kids: impl IntoIterator<Item = &'a str>) -> DidResult<()> {
    let mut canonical = BTreeSet::new();
    for kid in kids {
        if !canonical.insert(canonicalize_kid(did, kid)?) {
            return Err(DidError::DuplicateKid);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_spec() -> DidCreateSpec {
        DidCreateSpec {
            profile: DidProfile::E1,
            domain: "example.com".to_string(),
            port: None,
            path_segments: vec!["agents".to_string(), "alice".to_string()],
            capabilities: Capabilities { did_wba: true },
            managed_keys: vec![
                ManagedKeySpec {
                    fragment: "root".to_string(),
                    role: KeyRole::RootControl,
                },
                ManagedKeySpec {
                    fragment: "request".to_string(),
                    role: KeyRole::RequestSigning,
                },
            ],
            external_keys: Vec::new(),
            services: Vec::new(),
            agent_description_url: None,
            extensions: Vec::new(),
        }
    }

    #[test]
    fn valid_e1_shape_passes() {
        assert_eq!(valid_spec().validate(), Ok(()));
    }

    #[test]
    fn canonical_kid_validation_rejects_equivalent_and_foreign_ids() {
        let mut spec = valid_spec();
        let did = "did:wba:example.com:agents:alice:e1_test";
        spec.external_keys.push(ExternalPublicKeySpec {
            kid: format!("{did}#request"),
            role: KeyRole::RequestSigning,
            material: ExternalPublicKeyMaterial::Multibase {
                value: "z6MkiTBz1yZ9fCkmQCQqfYbANPAG7dJbqvBKTqYBq4pXx7nG".to_string(),
            },
        });
        assert_eq!(spec.validate_for_did(did), Err(DidError::DuplicateKid));
        spec.external_keys[0].kid = "did:wba:evil.example#request".to_string();
        assert_eq!(spec.validate_for_did(did), Err(DidError::ForeignKid));
    }
}
