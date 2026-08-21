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

#[test]
fn request_signing_import_creates_an_active_rootless_daemon_identity() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    let request_key = ed25519_dalek::SigningKey::from_bytes(&[83_u8; 32]);
    let source_root = tempfile::tempdir().unwrap();
    let mut source_store =
        DidStore::initialize_injected(source_root.path(), "source", [83_u8; 32]).unwrap();
    let source = source_store
        .create_identity(crate::DidCreateSpec {
            profile: crate::DidProfile::E1,
            domain: "example.com".to_owned(),
            port: None,
            path_segments: vec!["users".to_owned(), "daemon-import".to_owned()],
            capabilities: Capabilities { did_wba: false },
            managed_keys: vec![crate::ManagedKeySpec {
                fragment: "key-1".to_owned(),
                role: KeyRole::RootControl,
            }],
            external_keys: vec![crate::ExternalPublicKeySpec {
                kid: "#daemon-key-1".to_owned(),
                role: KeyRole::RequestSigning,
                material: crate::ExternalPublicKeyMaterial::Jwk {
                    public_key_jwk: crate::PublicOkpJwk {
                        kty: "OKP".to_owned(),
                        crv: "Ed25519".to_owned(),
                        x: URL_SAFE_NO_PAD.encode(request_key.verifying_key().to_bytes()),
                    },
                },
            }],
            services: Vec::new(),
            agent_description_url: None,
            extensions: Vec::new(),
        })
        .unwrap();
    let evidence = VerifiedDocumentEvidence {
        document_version: 1,
        registry_version: 1,
        document_digest: crate::canonical_document_digest(source.document()).unwrap(),
    };
    let root = tempfile::tempdir().unwrap();
    let mut store = DidStore::initialize_injected(root.path(), "daemon", [84_u8; 32]).unwrap();
    let imported = store
        .import_request_signing_identity(RequestSigningIdentityImportSpec {
            verified_document: source.document().clone(),
            evidence,
            capabilities: Capabilities { did_wba: true },
            private_key: ImportedPrivateKey::new(
                "#daemon-key-1",
                KeyRole::RequestSigning,
                PrivateKeyEncoding::Raw32,
                Zeroizing::new(request_key.to_bytes().to_vec()),
            ),
        })
        .unwrap();

    assert_eq!(imported.state(), crate::IdentityState::Active);
    assert_eq!(imported.root_capability(), RootCapabilityState::Absent);
    let signature = imported.sign("#daemon-key-1", b"daemon").unwrap();
    imported
        .verify("#daemon-key-1", b"daemon", &signature)
        .unwrap();
    assert_eq!(
        imported.sign_device_assertion("#daemon-key-1", b"assertion"),
        Err(DidError::KeyRoleViolation)
    );
}

#[test]
fn device_import_creates_an_active_rootless_member_identity() {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[85_u8; 32]);
    let agreement_key = x25519_dalek::StaticSecret::from([86_u8; 32]);
    let signing_multibase = crate::document::public_key_multibase(
        &anp::PublicKeyMaterial::Ed25519(signing_key.verifying_key()),
    )
    .unwrap();
    let agreement_multibase = crate::document::public_key_multibase(
        &anp::PublicKeyMaterial::X25519(x25519_dalek::PublicKey::from(&agreement_key).to_bytes()),
    )
    .unwrap();
    let source_root = tempfile::tempdir().unwrap();
    let mut source_store =
        DidStore::initialize_injected(source_root.path(), "source", [85_u8; 32]).unwrap();
    let source = source_store
        .create_identity(crate::DidCreateSpec {
            profile: crate::DidProfile::E1,
            domain: "example.com".to_owned(),
            port: None,
            path_segments: vec!["users".to_owned(), "device-import".to_owned()],
            capabilities: Capabilities { did_wba: false },
            managed_keys: vec![crate::ManagedKeySpec {
                fragment: "key-1".to_owned(),
                role: KeyRole::RootControl,
            }],
            external_keys: vec![
                crate::ExternalPublicKeySpec {
                    kid: "#device-signing".to_owned(),
                    role: KeyRole::DeviceSigning,
                    material: crate::ExternalPublicKeyMaterial::Multibase {
                        value: signing_multibase,
                    },
                },
                crate::ExternalPublicKeySpec {
                    kid: "#device-e2ee".to_owned(),
                    role: KeyRole::E2eeAgreement,
                    material: crate::ExternalPublicKeyMaterial::Multibase {
                        value: agreement_multibase,
                    },
                },
            ],
            services: Vec::new(),
            agent_description_url: None,
            extensions: vec![crate::DidExtensionSpec::DeviceManifest(
                crate::DeviceManifestSpec {
                    devices: vec![crate::DeviceManifestEntrySpec {
                        device_id: "device-import".to_owned(),
                        signing_key_id: "#device-signing".to_owned(),
                        e2ee_key_id: "#device-e2ee".to_owned(),
                        profiles: vec!["p5".to_owned(), "p6".to_owned()],
                    }],
                },
            )],
        })
        .unwrap();
    let root = tempfile::tempdir().unwrap();
    let mut store = DidStore::initialize_injected(root.path(), "device", [86_u8; 32]).unwrap();
    let imported = store
        .import_device_identity(DeviceIdentityImportSpec {
            verified_document: source.document().clone(),
            evidence: VerifiedDocumentEvidence {
                document_version: 4,
                registry_version: 5,
                document_digest: crate::canonical_document_digest(source.document()).unwrap(),
            },
            capabilities: Capabilities { did_wba: true },
            signing_key: ImportedPrivateKey::new(
                "#device-signing",
                KeyRole::DeviceSigning,
                PrivateKeyEncoding::Raw32,
                Zeroizing::new(signing_key.to_bytes().to_vec()),
            ),
            e2ee_key: ImportedPrivateKey::new(
                "#device-e2ee",
                KeyRole::E2eeAgreement,
                PrivateKeyEncoding::Raw32,
                Zeroizing::new(agreement_key.to_bytes().to_vec()),
            ),
        })
        .unwrap();

    assert_eq!(imported.state(), crate::IdentityState::Active);
    assert_eq!(imported.root_capability(), RootCapabilityState::Absent);
    imported
        .sign_device_assertion("#device-signing", b"device assertion")
        .unwrap();
    let peer = x25519_dalek::StaticSecret::from([87_u8; 32]);
    imported
        .ecdh(
            "#device-e2ee",
            &x25519_dalek::PublicKey::from(&peer).to_bytes(),
        )
        .unwrap();
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
