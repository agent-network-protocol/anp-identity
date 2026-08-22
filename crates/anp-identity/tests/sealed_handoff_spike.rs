use std::collections::HashSet;

use anp::sealed_handoff::{SealedHandoff, SealedHandoffRecipient};
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, PartialEq, Eq, Serialize)]
struct RequestBinding {
    protocol_version: u8,
    provider_instance_id: String,
    parent_lease_id: String,
    consumer: String,
    capability: String,
    store_id: String,
    identity_id: String,
    operation: String,
    kid: String,
    request_id: String,
    recipient_public_key_digest: String,
    operation_input_digest: String,
    expiry: u64,
    nonce: String,
}

struct OneTimeToken {
    binding: RequestBinding,
    mac: [u8; 32],
}

struct PrototypeTokenIssuer {
    key: Zeroizing<[u8; 32]>,
    consumed: HashSet<String>,
}

impl PrototypeTokenIssuer {
    fn new() -> Self {
        Self {
            key: Zeroizing::new([0x91; 32]),
            consumed: HashSet::new(),
        }
    }

    fn issue(&self, binding: RequestBinding) -> OneTimeToken {
        let mut mac = HmacSha256::new_from_slice(self.key.as_ref()).unwrap();
        mac.update(&canonical_binding(&binding));
        OneTimeToken {
            binding,
            mac: mac.finalize().into_bytes().into(),
        }
    }

    fn consume(&mut self, token: &OneTimeToken, expected: &RequestBinding, now: u64) -> bool {
        if token.binding != *expected || token.binding.expiry < now {
            return false;
        }
        let mut mac = HmacSha256::new_from_slice(self.key.as_ref()).unwrap();
        mac.update(&canonical_binding(&token.binding));
        if mac.verify_slice(&token.mac).is_err() {
            return false;
        }
        self.consumed.insert(token.binding.nonce.clone())
    }
}

#[test]
fn hpke_forward_export_and_reverse_import_bind_and_consume_one_time_tokens() {
    let mut issuer = PrototypeTokenIssuer::new();

    let im_core_recipient = SealedHandoffRecipient::generate();
    let exported_root = Zeroizing::new(vec![0x42; 32]);
    let export_binding = binding(
        "root-export",
        "request-export",
        im_core_recipient.public_key(),
        exported_root.as_ref(),
        "nonce-export",
    );
    let export_token = issuer.issue(export_binding.clone());
    assert!(issuer.consume(&export_token, &export_binding, 1_787_403_600));
    assert!(!issuer.consume(&export_token, &export_binding, 1_787_403_600));
    let export_aad = canonical_binding(&export_binding);
    let sealed_export = SealedHandoff::seal(
        im_core_recipient.public_key(),
        b"anp.identity.sealed-handoff.v1",
        &export_aad,
        exported_root.as_ref(),
    )
    .unwrap();
    assert_eq!(
        im_core_recipient
            .open(
                &sealed_export,
                b"anp.identity.sealed-handoff.v1",
                &export_aad,
            )
            .unwrap()
            .as_slice(),
        exported_root.as_slice()
    );

    let identity_recipient = SealedHandoffRecipient::generate();
    let imported_private_key = Zeroizing::new(vec![0x73; 48]);
    let import_binding = binding(
        "identity-import",
        "request-import",
        identity_recipient.public_key(),
        imported_private_key.as_ref(),
        "nonce-import",
    );
    let import_token = issuer.issue(import_binding.clone());
    assert!(issuer.consume(&import_token, &import_binding, 1_787_403_600));
    let import_aad = canonical_binding(&import_binding);
    let sealed_import = SealedHandoff::seal(
        identity_recipient.public_key(),
        b"anp.identity.sealed-handoff.v1",
        &import_aad,
        imported_private_key.as_ref(),
    )
    .unwrap();
    assert_eq!(
        identity_recipient
            .open(
                &sealed_import,
                b"anp.identity.sealed-handoff.v1",
                &import_aad,
            )
            .unwrap()
            .as_slice(),
        imported_private_key.as_slice()
    );

    let substituted = binding(
        "identity-import",
        "request-import",
        im_core_recipient.public_key(),
        imported_private_key.as_ref(),
        "nonce-import",
    );
    assert!(!issuer.consume(&import_token, &substituted, 1_787_403_600));
    assert!(identity_recipient
        .open(
            &sealed_import,
            b"anp.identity.sealed-handoff.v1",
            &canonical_binding(&substituted),
        )
        .is_err());
}

fn binding(
    operation: &str,
    request_id: &str,
    recipient_public_key: &[u8],
    operation_input: &[u8],
    nonce: &str,
) -> RequestBinding {
    RequestBinding {
        protocol_version: 1,
        provider_instance_id: "provider-spike".to_owned(),
        parent_lease_id: "lease-spike".to_owned(),
        consumer: "awiki-im-core".to_owned(),
        capability: operation.to_owned(),
        store_id: "store-spike".to_owned(),
        identity_id: "identity-spike".to_owned(),
        operation: operation.to_owned(),
        kid: "did:wba:example.com:agents:spike#root".to_owned(),
        request_id: request_id.to_owned(),
        recipient_public_key_digest: digest(recipient_public_key),
        operation_input_digest: digest(operation_input),
        expiry: 1_787_403_900,
        nonce: nonce.to_owned(),
    }
}

fn canonical_binding(binding: &RequestBinding) -> Vec<u8> {
    serde_json_canonicalizer::to_vec(binding).unwrap()
}

fn digest(value: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(value))
}
