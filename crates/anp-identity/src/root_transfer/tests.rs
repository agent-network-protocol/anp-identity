use anp::authentication::extract_public_key;
use serde_json::json;

use super::*;
use crate::{
    canonical_document_digest, Capabilities, DeviceAddSpec, DeviceManifestEntrySpec,
    DeviceManifestSpec, DeviceMutationSpec, DevicePublicKeySpec, DidCreateSpec, DidExtensionSpec,
    DidProfile, DidStore, EnrollmentSpec, KeyRole, ManagedKeySpec,
};

#[test]
#[cfg(feature = "root-export")]
fn root_private_key_export_returns_zeroizing_pkcs8_for_active_root_only() {
    let root = tempfile::tempdir().unwrap();
    let mut store = DidStore::initialize_injected(root.path(), "source", [90_u8; 32]).unwrap();
    let source = store.create_identity(source_spec()).unwrap();
    let root_kid = source
        .keys()
        .iter()
        .find(|key| key.role == KeyRole::RootControl)
        .unwrap()
        .kid
        .clone();

    let exported = source.export_root_private_key(&root_kid).unwrap();
    assert_eq!(exported.as_pkcs8_der().len(), 48);
    assert_eq!(
        &exported.as_pkcs8_der()[..ED25519_PKCS8_PREFIX.len()],
        &ED25519_PKCS8_PREFIX
    );
    let private = anp::PrivateKeyMaterial::from_pkcs8_der(exported.as_pkcs8_der()).unwrap();
    let signature = private.sign_message(b"root transfer export").unwrap();
    source
        .verify(&root_kid, b"root transfer export", &signature)
        .unwrap();

    let e2ee_kid = source
        .keys()
        .iter()
        .find(|key| key.role == KeyRole::E2eeAgreement)
        .unwrap()
        .kid
        .clone();
    assert!(matches!(
        source.export_root_private_key(&e2ee_kid),
        Err(DidError::RootCapabilityUnavailable)
    ));
}

#[test]
fn wrapped_root_roundtrip_is_target_bound_replay_safe_and_promotable() {
    let source_root = tempfile::tempdir().unwrap();
    let recipient_root = tempfile::tempdir().unwrap();
    let mut source_store =
        DidStore::initialize_injected(source_root.path(), "source", [91_u8; 32]).unwrap();
    let mut source = source_store.create_identity(source_spec()).unwrap();
    let initial = source.document().clone();
    let mut recipient_store =
        DidStore::initialize_injected(recipient_root.path(), "recipient", [92_u8; 32]).unwrap();
    let (mut recipient, prepared) = recipient_store
        .prepare_enrollment(EnrollmentSpec {
            verified_document: initial.clone(),
            evidence: evidence(&initial, 1, 1),
            device_id: "recipient-device".to_string(),
            device_signing_fragment: "recipient-sign".to_string(),
            device_e2ee_fragment: "recipient-e2ee".to_string(),
            profiles: vec!["anp.core.binding.v1".to_string()],
            capabilities: Capabilities { did_wba: true },
        })
        .unwrap();
    let update = source
        .prepare_update(crate::DocumentUpdateSpec {
            request_signing_rotation: None,
            request_signing_mutations: Vec::new(),
            device_mutations: vec![DeviceMutationSpec::Add {
                device: DeviceAddSpec {
                    device_id: prepared.device_id.clone(),
                    signing_key: DevicePublicKeySpec {
                        kid: prepared.device_signing_key.kid.clone(),
                        public_key_multibase: prepared
                            .device_signing_key
                            .public_key_multibase
                            .clone(),
                    },
                    e2ee_key: DevicePublicKeySpec {
                        kid: prepared.device_e2ee_key.kid.clone(),
                        public_key_multibase: prepared.device_e2ee_key.public_key_multibase.clone(),
                    },
                    profiles: prepared.profiles.clone(),
                },
            }],
            services: None,
        })
        .unwrap();
    source.begin_publication(&update.revision_id).unwrap();
    source.mark_published(&update.revision_id).unwrap();
    source.commit_update(&update.revision_id).unwrap();
    let accepted = update.candidate_document;
    recipient
        .adopt_verified_document(crate::AdoptVerifiedDocumentSpec {
            document: accepted.clone(),
            evidence: evidence(&accepted, 2, 2),
        })
        .unwrap();
    assert_eq!(source.checkpoint(), recipient.checkpoint());

    let root_kid = source
        .keys()
        .iter()
        .find(|key| key.role == KeyRole::RootControl)
        .unwrap()
        .kid
        .clone();
    let envelope = source
        .export_wrapped_root(RootTransferExportSpec {
            target_did: source.did().to_string(),
            sender_device_id: "source-device".to_string(),
            recipient_device_id: prepared.device_id.clone(),
            recipient_agreement_kid: prepared.device_e2ee_key.kid.clone(),
            recipient_agreement_public: public_x25519(
                &prepared.device_e2ee_key.kid,
                &prepared.device_e2ee_key.public_key_multibase,
            ),
            root_kid: root_kid.clone(),
            ttl_seconds: 300,
        })
        .unwrap();
    assert_eq!(envelope.envelope_type, WRAPPED_ROOT_ENVELOPE_TYPE);
    assert_eq!(envelope.version, WRAPPED_ROOT_ENVELOPE_VERSION);
    let serialized = serde_json::to_string(&envelope).unwrap();
    assert!(!serialized.contains("private"));
    let source_root_secret = source
        .load_managed_secret(source.key_metadata(&root_kid).unwrap())
        .unwrap();
    assert!(!serialized
        .as_bytes()
        .windows(32)
        .any(|window| { window == source_root_secret.expose() }));

    let mut tampered = envelope.clone();
    tampered.ciphertext_b64u.push('A');
    assert_eq!(
        recipient.import_wrapped_root(&tampered),
        Err(DidError::InvalidRootTransfer)
    );
    assert_eq!(
        recipient.import_wrapped_root(&envelope).unwrap(),
        RootTransferImportOutcome::Pending
    );
    assert_eq!(recipient.root_capability(), RootCapabilityState::Pending);
    let possession = recipient
        .sign_pending_root_object_proof(
            &root_kid,
            &json!({"type": "root-possession"}),
            recipient.did(),
            None,
        )
        .unwrap();
    anp::proof::verify_object_proof(&possession, recipient.did(), recipient.document()).unwrap();
    assert_eq!(
        recipient.import_wrapped_root(&envelope).unwrap(),
        RootTransferImportOutcome::Pending
    );
    let competing = source
        .export_wrapped_root(RootTransferExportSpec {
            target_did: source.did().to_string(),
            sender_device_id: "source-device".to_string(),
            recipient_device_id: prepared.device_id.clone(),
            recipient_agreement_kid: prepared.device_e2ee_key.kid.clone(),
            recipient_agreement_public: public_x25519(
                &prepared.device_e2ee_key.kid,
                &prepared.device_e2ee_key.public_key_multibase,
            ),
            root_kid: root_kid.clone(),
            ttl_seconds: 300,
        })
        .unwrap();
    assert_eq!(
        recipient.import_wrapped_root(&competing),
        Err(DidError::PendingRootTransferExists)
    );
    recipient
        .confirm_root_promotion(RootPromotionSpec {
            document: accepted.clone(),
            evidence: evidence(&accepted, 3, 3),
        })
        .unwrap();
    assert_eq!(recipient.root_capability(), RootCapabilityState::Active);
    assert_eq!(
        recipient.sign_pending_root_object_proof(
            &root_kid,
            &json!({"type": "late"}),
            recipient.did(),
            None,
        ),
        Err(DidError::RootCapabilityUnavailable)
    );
    assert_eq!(
        recipient.import_wrapped_root(&envelope).unwrap(),
        RootTransferImportOutcome::Active
    );
    assert_eq!(
        recipient.sign(&root_kid, b"root remains non-generic"),
        Err(DidError::KeyRoleViolation)
    );
}

#[test]
fn wrapped_root_rejects_expired_unknown_and_low_order_envelopes_without_downgrade() {
    let root = tempfile::tempdir().unwrap();
    let mut store = DidStore::initialize_injected(root.path(), "source", [93_u8; 32]).unwrap();
    let source = store.create_identity(source_spec()).unwrap();
    let root_kid = source
        .keys()
        .iter()
        .find(|key| key.role == KeyRole::RootControl)
        .unwrap()
        .kid
        .clone();
    let export = RootTransferExportSpec {
        target_did: source.did().to_string(),
        sender_device_id: "source-device".to_string(),
        recipient_device_id: "source-device".to_string(),
        recipient_agreement_kid: format!("{}#source-e2ee", source.did()),
        recipient_agreement_public: [0_u8; 32],
        root_kid: root_kid.clone(),
        ttl_seconds: 300,
    };
    assert_eq!(
        source.export_wrapped_root(export),
        Err(DidError::InvalidPeerKey)
    );

    let created = DateTime::parse_from_rfc3339("2026-08-21T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let envelope = source
        .export_wrapped_root_inner(
            RootTransferExportSpec {
                target_did: source.did().to_string(),
                sender_device_id: "source-device".to_string(),
                recipient_device_id: "source-device".to_string(),
                recipient_agreement_kid: format!("{}#source-e2ee", source.did()),
                recipient_agreement_public: source
                    .public_key_bytes("#source-e2ee")
                    .unwrap()
                    .try_into()
                    .unwrap(),
                root_kid,
                ttl_seconds: 300,
            },
            created,
            [22_u8; 32],
            [23_u8; NONCE_LEN],
        )
        .unwrap();
    assert_eq!(envelope.context.created_at, "2026-08-21T00:00:00Z");
    assert_eq!(envelope.context.expires_at, "2026-08-21T00:05:00Z");
    assert_eq!(
        validate_time_window(&envelope.context, created + Duration::seconds(1_000)),
        Err(DidError::RootTransferExpired)
    );
    let mut unknown = envelope;
    unknown.version = 99;
    assert_eq!(
        validate_wrapped_envelope(&source, &unknown, created, false),
        Err(DidError::InvalidRootTransfer)
    );
}

#[cfg(feature = "key-import")]
#[test]
fn authenticated_legacy_root_ingress_is_receive_only_and_uses_the_same_pending_state() {
    let source_root = tempfile::tempdir().unwrap();
    let recipient_root = tempfile::tempdir().unwrap();
    let mut source_store =
        DidStore::initialize_injected(source_root.path(), "source", [94_u8; 32]).unwrap();
    let mut source = source_store.create_identity(source_spec()).unwrap();
    let initial = source.document().clone();
    let mut recipient_store =
        DidStore::initialize_injected(recipient_root.path(), "recipient", [95_u8; 32]).unwrap();
    let (mut recipient, prepared) = recipient_store
        .prepare_enrollment(EnrollmentSpec {
            verified_document: initial.clone(),
            evidence: evidence(&initial, 1, 1),
            device_id: "legacy-recipient".to_string(),
            device_signing_fragment: "legacy-recipient-sign".to_string(),
            device_e2ee_fragment: "legacy-recipient-e2ee".to_string(),
            profiles: vec!["anp.core.binding.v1".to_string()],
            capabilities: Capabilities { did_wba: true },
        })
        .unwrap();
    let update = source
        .prepare_update(crate::DocumentUpdateSpec {
            request_signing_rotation: None,
            request_signing_mutations: Vec::new(),
            device_mutations: vec![DeviceMutationSpec::Add {
                device: DeviceAddSpec {
                    device_id: prepared.device_id.clone(),
                    signing_key: DevicePublicKeySpec {
                        kid: prepared.device_signing_key.kid.clone(),
                        public_key_multibase: prepared
                            .device_signing_key
                            .public_key_multibase
                            .clone(),
                    },
                    e2ee_key: DevicePublicKeySpec {
                        kid: prepared.device_e2ee_key.kid.clone(),
                        public_key_multibase: prepared.device_e2ee_key.public_key_multibase.clone(),
                    },
                    profiles: prepared.profiles.clone(),
                },
            }],
            services: None,
        })
        .unwrap();
    source.begin_publication(&update.revision_id).unwrap();
    source.mark_published(&update.revision_id).unwrap();
    source.commit_update(&update.revision_id).unwrap();
    let accepted = update.candidate_document;
    recipient
        .adopt_verified_document(crate::AdoptVerifiedDocumentSpec {
            document: accepted.clone(),
            evidence: evidence(&accepted, 2, 2),
        })
        .unwrap();
    let root = source
        .keys()
        .iter()
        .find(|key| key.role == KeyRole::RootControl)
        .unwrap();
    let raw = source.load_managed_secret(root).unwrap();
    let evidence = LegacyRootTransferEvidence {
        transfer_id: "legacy-transfer-1".to_string(),
        source_did: source.did().to_string(),
        target_did: source.did().to_string(),
        sender_device_id: "source-device".to_string(),
        recipient_device_id: prepared.device_id,
        recipient_agreement_kid: prepared.device_e2ee_key.kid,
        root_kid: root.kid.clone(),
        checkpoint: recipient.checkpoint().unwrap().clone(),
        accepted_at: "2026-08-21T00:00:00Z".to_string(),
    };
    assert_eq!(
        recipient
            .import_legacy_root_transfer(LegacyRootTransferImportSpec {
                evidence,
                encoding: crate::PrivateKeyEncoding::Raw32,
                root_key: Zeroizing::new(raw.expose().to_vec()),
            })
            .unwrap(),
        RootTransferImportOutcome::Pending
    );
    assert_eq!(recipient.root_capability(), RootCapabilityState::Pending);
}

#[cfg(feature = "key-import")]
#[test]
fn wrapped_root_fixed_vector_matches_reviewed_fixture() {
    use anp::authentication::{
        build_unsigned_e1_did_document, DidKeyRole, DidVerificationRelationship, SuppliedDidKey,
        SuppliedE1DidDocumentOptions,
    };
    use anp::proof::{
        generate_w3c_proof, ProofGenerationOptions, CRYPTOSUITE_EDDSA_JCS_2022,
        PROOF_TYPE_DATA_INTEGRITY,
    };

    let root_private = ed25519_dalek::SigningKey::from_bytes(&[1_u8; 32]);
    let device_private = ed25519_dalek::SigningKey::from_bytes(&[2_u8; 32]);
    let agreement_private = x25519_dalek::StaticSecret::from([3_u8; 32]);
    let root_public = anp::PublicKeyMaterial::Ed25519(root_private.verifying_key());
    let device_public = anp::PublicKeyMaterial::Ed25519(device_private.verifying_key());
    let agreement_public = anp::PublicKeyMaterial::X25519(
        x25519_dalek::PublicKey::from(&agreement_private).to_bytes(),
    );
    let mut document = build_unsigned_e1_did_document(
        "example.com",
        SuppliedE1DidDocumentOptions {
            port: None,
            path_segments: vec!["vectors".to_string(), "root-transfer".to_string()],
            agent_description_url: None,
            services: Vec::new(),
            root_key: SuppliedDidKey {
                fragment: "root".to_string(),
                role: DidKeyRole::RootControl,
                public_key: root_public.clone(),
                relationships: vec![
                    DidVerificationRelationship::Authentication,
                    DidVerificationRelationship::AssertionMethod,
                ],
            },
            additional_keys: vec![
                SuppliedDidKey {
                    fragment: "device".to_string(),
                    role: DidKeyRole::DeviceSigning,
                    public_key: device_public,
                    relationships: vec![
                        DidVerificationRelationship::Authentication,
                        DidVerificationRelationship::AssertionMethod,
                    ],
                },
                SuppliedDidKey {
                    fragment: "agreement".to_string(),
                    role: DidKeyRole::E2eeAgreement,
                    public_key: agreement_public,
                    relationships: vec![DidVerificationRelationship::KeyAgreement],
                },
            ],
        },
    )
    .unwrap();
    let did = document["id"].as_str().unwrap().to_string();
    document["deviceManifest"] = json!({
        "type": anp::authentication::DEVICE_MANIFEST_TYPE,
        "devices": [{
            "device_id": "device-vector",
            "signing_key_id": format!("{did}#device"),
            "e2ee_key_id": format!("{did}#agreement"),
            "profiles": ["anp.core.binding.v1"],
        }],
    });
    document = generate_w3c_proof(
        &document,
        &anp::PrivateKeyMaterial::Ed25519(root_private.clone()),
        &format!("{did}#root"),
        ProofGenerationOptions {
            proof_purpose: Some("assertionMethod".to_string()),
            proof_type: Some(PROOF_TYPE_DATA_INTEGRITY.to_string()),
            cryptosuite: Some(CRYPTOSUITE_EDDSA_JCS_2022.to_string()),
            created: Some("2026-08-21T00:00:00Z".to_string()),
            domain: Some("example.com".to_string()),
            challenge: Some("root-transfer-vector".to_string()),
        },
    )
    .unwrap();
    let temp = tempfile::tempdir().unwrap();
    let mut store = DidStore::initialize_injected(temp.path(), "vector", [96_u8; 32]).unwrap();
    let identity = store
        .import_identity(crate::IdentityImportSpec {
            verified_document: document.clone(),
            evidence: evidence(&document, 1, 1),
            capabilities: Capabilities { did_wba: true },
            private_keys: vec![
                crate::ImportedPrivateKey::new(
                    "#root",
                    KeyRole::RootControl,
                    crate::PrivateKeyEncoding::Raw32,
                    Zeroizing::new(root_private.to_bytes().to_vec()),
                ),
                crate::ImportedPrivateKey::new(
                    "#device",
                    KeyRole::DeviceSigning,
                    crate::PrivateKeyEncoding::Raw32,
                    Zeroizing::new(device_private.to_bytes().to_vec()),
                ),
                crate::ImportedPrivateKey::new(
                    "#agreement",
                    KeyRole::E2eeAgreement,
                    crate::PrivateKeyEncoding::Raw32,
                    Zeroizing::new(agreement_private.to_bytes().to_vec()),
                ),
            ],
        })
        .unwrap();
    let created = DateTime::parse_from_rfc3339("2026-08-21T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let envelope = identity
        .export_wrapped_root_inner(
            RootTransferExportSpec {
                target_did: did.clone(),
                sender_device_id: "device-vector".to_string(),
                recipient_device_id: "device-vector".to_string(),
                recipient_agreement_kid: format!("{did}#agreement"),
                recipient_agreement_public: identity
                    .public_key_bytes("#agreement")
                    .unwrap()
                    .try_into()
                    .unwrap(),
                root_kid: format!("{did}#root"),
                ttl_seconds: 300,
            },
            created,
            [22_u8; 32],
            [23_u8; NONCE_LEN],
        )
        .unwrap();
    let reviewed: WrappedRootEnvelope = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/root-transfer-v1-vector.json"
    )))
    .unwrap();
    assert_eq!(envelope, reviewed);
}

fn source_spec() -> DidCreateSpec {
    DidCreateSpec {
        profile: DidProfile::E1,
        domain: "example.com".to_string(),
        port: None,
        path_segments: vec!["users".to_string(), "root-transfer".to_string()],
        capabilities: Capabilities { did_wba: true },
        managed_keys: vec![
            managed("root", KeyRole::RootControl),
            managed("source-sign", KeyRole::DeviceSigning),
            managed("source-e2ee", KeyRole::E2eeAgreement),
        ],
        external_keys: Vec::new(),
        services: Vec::new(),
        agent_description_url: None,
        extensions: vec![DidExtensionSpec::DeviceManifest(DeviceManifestSpec {
            devices: vec![DeviceManifestEntrySpec {
                device_id: "source-device".to_string(),
                signing_key_id: "#source-sign".to_string(),
                e2ee_key_id: "#source-e2ee".to_string(),
                profiles: vec!["anp.core.binding.v1".to_string()],
            }],
        })],
    }
}

fn managed(fragment: &str, role: KeyRole) -> ManagedKeySpec {
    ManagedKeySpec {
        fragment: fragment.to_string(),
        role,
    }
}

fn evidence(
    document: &Value,
    document_version: u64,
    registry_version: u64,
) -> VerifiedDocumentEvidence {
    VerifiedDocumentEvidence {
        document_version,
        registry_version,
        document_digest: canonical_document_digest(document).unwrap(),
    }
}

fn public_x25519(kid: &str, multibase: &str) -> [u8; 32] {
    let method = json!({
        "id": kid,
        "type": "X25519KeyAgreementKey2019",
        "publicKeyMultibase": multibase,
    });
    match extract_public_key(&method).unwrap() {
        anp::PublicKeyMaterial::X25519(bytes) => bytes,
        _ => panic!("test requires X25519"),
    }
}
