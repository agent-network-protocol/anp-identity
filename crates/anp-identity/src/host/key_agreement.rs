use zeroize::Zeroizing;

use crate::{
    IdentityError, IdentityResult, KeyOrigin, KeyRole, KeySelector, KeyState, ManagedIdentity,
};

#[derive(Clone, PartialEq, Eq)]
pub struct KeyAgreementRequest {
    pub key: KeySelector,
    pub peer_public: [u8; 32],
}

pub struct ZeroizingSharedSecret {
    bytes: Zeroizing<[u8; 32]>,
}

impl ZeroizingSharedSecret {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

pub trait KeyAgreementPort {
    fn derive_shared_secret(
        &self,
        request: KeyAgreementRequest,
    ) -> IdentityResult<ZeroizingSharedSecret>;
}

impl KeyAgreementPort for ManagedIdentity {
    fn derive_shared_secret(
        &self,
        request: KeyAgreementRequest,
    ) -> IdentityResult<ZeroizingSharedSecret> {
        let engine = self.lock_engine()?;
        let kid = select_agreement_key(&engine, &request.key)?;
        let shared = engine.ecdh(&kid, &request.peer_public)?;
        Ok(ZeroizingSharedSecret {
            bytes: Zeroizing::new(*shared.as_bytes()),
        })
    }
}

fn select_agreement_key(
    identity: &crate::DidIdentity,
    selector: &KeySelector,
) -> IdentityResult<String> {
    let usable = |metadata: &&crate::KeyMetadata| {
        metadata.role == KeyRole::E2eeAgreement
            && metadata.origin == KeyOrigin::Managed
            && metadata.state == KeyState::Active
            && !metadata.material_erased
            && relationship_contains(identity.document(), "keyAgreement", &metadata.kid)
    };
    match selector {
        KeySelector::Kid(kid) => {
            let metadata = identity.key_metadata(kid)?;
            if !usable(&metadata) {
                return Err(if metadata.role == KeyRole::E2eeAgreement {
                    IdentityError::KeyUnavailable
                } else {
                    IdentityError::KeyPurposeViolation
                });
            }
            Ok(metadata.kid.clone())
        }
        KeySelector::Default => {
            let mut candidates = identity.keys().iter().filter(usable);
            let selected = candidates.next().ok_or(IdentityError::KeyUnavailable)?;
            if candidates.next().is_some() {
                return Err(IdentityError::AmbiguousKey);
            }
            Ok(selected.kid.clone())
        }
    }
}

fn relationship_contains(document: &serde_json::Value, relationship: &str, kid: &str) -> bool {
    document
        .get(relationship)
        .and_then(serde_json::Value::as_array)
        .is_some_and(|entries| {
            entries.iter().any(|entry| {
                entry.as_str() == Some(kid)
                    || entry.get("id").and_then(serde_json::Value::as_str) == Some(kid)
            })
        })
}

#[cfg(test)]
mod tests;
