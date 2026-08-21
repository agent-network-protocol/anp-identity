use anp::authentication::{create_did_wba_document, DidDocumentOptions};
use zeroize::Zeroizing;

use super::*;

#[test]
fn one_way_import_verifies_keys_and_rejects_an_existing_target() {
    let bundle = create_did_wba_document(
        "example.com",
        DidDocumentOptions {
            path_segments: vec!["users".to_string(), "imported".to_string()],
            ..DidDocumentOptions::default()
        },
    )
    .unwrap();
    let evidence = VerifiedDocumentEvidence {
        document_version: 7,
        registry_version: 9,
        document_digest: crate::canonical_document_digest(&bundle.did_document).unwrap(),
    };
    let private_keys = vec![
        imported(&bundle, "key-1", KeyRole::RootControl),
        imported(&bundle, "key-3", KeyRole::E2eeAgreement),
    ];
    let root = tempfile::tempdir().unwrap();
    let mut store = DidStore::initialize_injected(root.path(), "host", [81_u8; 32]).unwrap();
    let identity = store
        .import_identity(IdentityImportSpec {
            verified_document: bundle.did_document.clone(),
            evidence: evidence.clone(),
            capabilities: Capabilities { did_wba: false },
            private_keys,
        })
        .unwrap();

    assert_eq!(identity.root_capability(), RootCapabilityState::Active);
    assert_eq!(identity.checkpoint().unwrap().document_version, 7);
    let peer = x25519_dalek::StaticSecret::from([11_u8; 32]);
    identity
        .ecdh("#key-3", &x25519_dalek::PublicKey::from(&peer).to_bytes())
        .unwrap();
    assert_eq!(
        identity.sign("#key-1", b"root is not generic signing"),
        Err(DidError::KeyRoleViolation)
    );

    assert_eq!(
        store
            .import_identity(IdentityImportSpec {
                verified_document: bundle.did_document.clone(),
                evidence,
                capabilities: Capabilities { did_wba: false },
                private_keys: vec![imported(&bundle, "key-1", KeyRole::RootControl)],
            })
            .err(),
        Some(DidError::DuplicateIdentity)
    );
}

#[test]
fn import_rejects_a_private_key_that_does_not_match_the_document() {
    let bundle = create_did_wba_document(
        "example.com",
        DidDocumentOptions {
            path_segments: vec!["users".to_string(), "mismatch".to_string()],
            ..DidDocumentOptions::default()
        },
    )
    .unwrap();
    let root = tempfile::tempdir().unwrap();
    let mut store = DidStore::initialize_injected(root.path(), "host", [82_u8; 32]).unwrap();
    let wrong = ed25519_dalek::SigningKey::from_bytes(&[99_u8; 32]);

    assert_eq!(
        store
            .import_identity(IdentityImportSpec {
                verified_document: bundle.did_document.clone(),
                evidence: VerifiedDocumentEvidence {
                    document_version: 1,
                    registry_version: 1,
                    document_digest: crate::canonical_document_digest(&bundle.did_document)
                        .unwrap(),
                },
                capabilities: Capabilities { did_wba: false },
                private_keys: vec![ImportedPrivateKey::new(
                    "#key-1",
                    KeyRole::RootControl,
                    PrivateKeyEncoding::Raw32,
                    Zeroizing::new(wrong.to_bytes().to_vec()),
                )],
            })
            .err(),
        Some(DidError::InvalidPublicKey)
    );
    assert!(store.list_identities().unwrap().is_empty());
}

fn imported(
    bundle: &anp::authentication::DidDocumentBundle,
    fragment: &str,
    role: KeyRole,
) -> ImportedPrivateKey {
    let material = bundle.load_private_key(fragment).unwrap();
    let raw = match material {
        PrivateKeyMaterial::Ed25519(key) => key.to_bytes(),
        PrivateKeyMaterial::X25519(key) => key.to_bytes(),
        _ => panic!("test requires an OKP key"),
    };
    let (encoding, secret) = if role == KeyRole::RootControl {
        let mut der = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        der.extend_from_slice(&raw);
        (PrivateKeyEncoding::Pkcs8Der, der)
    } else {
        (PrivateKeyEncoding::Raw32, raw.to_vec())
    };
    ImportedPrivateKey::new(
        format!("#{fragment}"),
        role,
        encoding,
        Zeroizing::new(secret),
    )
}
