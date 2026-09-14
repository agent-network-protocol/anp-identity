use std::collections::BTreeMap;
use std::path::Path;

use anp_identity::host::{
    ConvergenceOutcome, ConvergenceWorkflow, DeviceEnrollmentRequest, EnrollmentCapabilities,
    EnrollmentProposalKind, EnrollmentWorkflow, ExactHttpRequest, HostRootCapability,
    HttpRequestSigningOptions, HttpRequestSigningPort, IdentityStatusPort, LegacyDidWbaPort,
};
use anp_identity::*;

fn config(path: &Path) -> IdentityManagerConfig {
    IdentityManagerConfig {
        state_root: path.to_path_buf(),
        root_key: RootKeySource::Injected(InjectedStoreKey::new("web-test", [0x52; 32])),
    }
}

fn profiles() -> Vec<String> {
    [
        "anp.core.binding.v1",
        "anp.identity.discovery.v1",
        "anp.direct.base.v1",
        "anp.group.base.v2",
        "anp.direct.e2ee.v2",
        "anp.group.e2ee.v2",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn request() -> CreateIdentityRequest {
    CreateIdentityRequest {
        profile: CreateIdentityProfile::Web,
        domain: "identity.example".into(),
        port: None,
        path_segments: vec![
            "awiki".into(),
            "web".into(),
            "123e4567e89b42d3a456426614174000".into(),
        ],
        capabilities: CreateIdentityCapabilities { did_wba: true },
        managed_keys: vec![
            ManagedKeyInput {
                fragment: "device-a-sign".into(),
                role: ManagedKeyRole::DeviceSigning,
            },
            ManagedKeyInput {
                fragment: "device-a-ka".into(),
                role: ManagedKeyRole::E2eeAgreement,
            },
        ],
        external_keys: vec![],
        services: vec![],
        agent_description_url: None,
        extensions: vec![CreateIdentityExtension::DeviceManifest {
            devices: vec![DeviceManifestEntryInput {
                device_id: "device-a".into(),
                signing_key_id: "#device-a-sign".into(),
                e2ee_key_id: "#device-a-ka".into(),
                profiles: profiles(),
            }],
        }],
    }
}

fn remote(document: DidDocument, version: u64, registry: u64) -> VerifiedRemoteDocument {
    VerifiedRemoteDocument {
        evidence: VerifiedPublicationEvidence {
            document_version: version,
            registry_version: registry,
            document_digest: document.canonical_digest().unwrap(),
        },
        document,
    }
}

fn publish(session: &mut DocumentChangeSession, version: u64) -> DidDocument {
    let document = session.candidate().candidate_document.clone();
    let evidence = VerifiedPublicationEvidence {
        document_version: version,
        registry_version: version,
        document_digest: session.candidate().candidate_digest.clone(),
    };
    let attempt = session.begin_publication().unwrap();
    assert!(matches!(
        session
            .complete(attempt, PublicationResult::Confirmed { evidence })
            .unwrap(),
        DocumentChangeOutcome::Committed { .. }
    ));
    document
}

#[test]
fn web_creation_reopens_with_same_keys_and_coexists_with_e1() {
    let root = tempfile::tempdir().unwrap();
    let mut manager = IdentityManager::initialize(config(root.path())).unwrap();
    let identity = manager.create(request()).unwrap();
    let public = identity.public_identity().unwrap();
    assert!(public
        .reference
        .did
        .starts_with("did:web:identity.example:awiki:web:"));
    assert_eq!(public.active_keys.len(), 2);
    assert!(public.document.as_value().get("proof").is_none());
    assert_eq!(
        identity.host_status().unwrap().root_capability,
        HostRootCapability::Absent
    );
    assert_eq!(identity.host_status().unwrap().root_key_fingerprint, None);
    let mut e1 = request();
    e1.profile = CreateIdentityProfile::E1;
    e1.managed_keys.push(ManagedKeyInput {
        fragment: "root".into(),
        role: ManagedKeyRole::RootControl,
    });
    let legacy = manager.create(e1).unwrap();
    assert!(legacy.host_status().unwrap().root_key_fingerprint.is_some());
    assert!(legacy
        .public_identity()
        .unwrap()
        .document
        .as_value()
        .get("proof")
        .is_some());
    let signature = identity
        .sign(SignRequest {
            purpose: SigningPurpose::DeviceAssertion,
            key: KeySelector::Default,
            payload: b"custody check".to_vec(),
        })
        .unwrap();
    drop(identity);
    drop(legacy);
    drop(manager);
    let reopened = IdentityManager::open(config(root.path())).unwrap();
    assert_eq!(reopened.list().unwrap().len(), 2);
    let identity = reopened.get(&public.reference).unwrap();
    assert_eq!(identity.public_identity().unwrap(), public);
    assert_eq!(
        identity
            .verify(VerifyRequest {
                purpose: SigningPurpose::DeviceAssertion,
                kid: signature.kid,
                payload: b"custody check".to_vec(),
                signature: signature.bytes
            })
            .unwrap(),
        VerificationOutcome::Valid
    );
}

#[test]
fn web_http_signature_uses_device_authentication_without_root_proof() {
    let root = tempfile::tempdir().unwrap();
    let mut manager = IdentityManager::initialize(config(root.path())).unwrap();
    let identity = manager.create(request()).unwrap();
    let prepared = identity
        .prepare_http_signature(ExactHttpRequest {
            key: KeySelector::Default,
            url: "https://identity.example/user/rpc".into(),
            method: "POST".into(),
            headers: vec![],
            body: Some(b"{}".to_vec()),
            options: HttpRequestSigningOptions::default(),
        })
        .unwrap();
    let headers: BTreeMap<_, _> = prepared
        .header_patch
        .into_iter()
        .map(|h| (h.name, h.value))
        .collect();
    let document = identity.public_identity().unwrap().document;
    anp::authentication::verify_http_message_signature(
        document.as_value(),
        "POST",
        "https://identity.example/user/rpc",
        &headers,
        Some(b"{}"),
    )
    .unwrap();
    assert!(anp::authentication::verify_http_message_signature(
        document.as_value(),
        "POST",
        "https://identity.example/user/rpc",
        &headers,
        Some(b"{\"changed\":true}")
    )
    .is_err());
    assert!(identity
        .prepare_legacy_did_wba(KeySelector::Default, "identity.example", "1.1")
        .is_err());
}

#[test]
fn web_join_adopts_exact_device_and_revoke_does_not_restore_it() {
    let root_a = tempfile::tempdir().unwrap();
    let root_b = tempfile::tempdir().unwrap();
    let mut manager_a = IdentityManager::initialize(config(root_a.path())).unwrap();
    let mut manager_b = IdentityManager::initialize(config(root_b.path())).unwrap();
    let mut identity_a = manager_a.create(request()).unwrap();
    let initial = identity_a.public_identity().unwrap().document;
    let mut enrollment = manager_b
        .begin_device_enrollment(DeviceEnrollmentRequest {
            remote: remote(initial.clone(), 1, 1),
            device_id: "device-b".into(),
            device_signing_fragment: "device-b-sign".into(),
            device_agreement_fragment: "device-b-ka".into(),
            profiles: profiles(),
            capabilities: EnrollmentCapabilities { did_wba: true },
        })
        .unwrap();
    assert_eq!(enrollment.proposal().root_key_fingerprint, None);
    let reference = enrollment.proposal().identity.clone();
    assert!(manager_b
        .get(&reference)
        .unwrap()
        .sign(SignRequest {
            purpose: SigningPurpose::DeviceAssertion,
            key: KeySelector::Default,
            payload: b"pending".to_vec(),
        })
        .is_err());
    assert_eq!(
        enrollment
            .sign_device_assertion(b"bound Join transcript")
            .unwrap()
            .len(),
        64
    );
    assert!(enrollment.activate(remote(initial, 1, 1)).is_err());
    let EnrollmentProposalKind::Device {
        device_id,
        signing_key,
        agreement_key,
        profiles: device_profiles,
    } = enrollment.proposal().kind.clone()
    else {
        panic!("device")
    };
    let mut change = identity_a
        .prepare_document_change(DocumentChangeRequest {
            changes: vec![DocumentChange::AddDevice {
                device: DeviceInput {
                    device_id,
                    signing_key: PublicKeyInput {
                        kid: signing_key.kid,
                        public_key_multibase: signing_key.public_key_multibase,
                    },
                    agreement_key: PublicKeyInput {
                        kid: agreement_key.kid,
                        public_key_multibase: agreement_key.public_key_multibase,
                    },
                    profiles: device_profiles,
                },
            }],
        })
        .unwrap();
    let joined = publish(&mut change, 2);
    assert_eq!(
        enrollment.activate(remote(joined.clone(), 2, 2)).unwrap(),
        ConvergenceOutcome::Activated
    );
    let mut identity_b = manager_b.get(&reference).unwrap();
    assert_eq!(identity_b.public_identity().unwrap().active_keys.len(), 2);
    let mut change = identity_a
        .prepare_document_change(DocumentChangeRequest {
            changes: vec![DocumentChange::RemoveDevice {
                device_id: "device-b".into(),
            }],
        })
        .unwrap();
    let revoked = publish(&mut change, 3);
    assert_eq!(
        identity_b
            .adopt_verified_document(remote(revoked.clone(), 3, 3))
            .unwrap(),
        ConvergenceOutcome::Revoked
    );
    assert_eq!(
        identity_b
            .adopt_verified_document(remote(revoked, 3, 3))
            .unwrap(),
        ConvergenceOutcome::Revoked
    );
    assert!(identity_b
        .sign(SignRequest {
            purpose: SigningPurpose::DeviceAssertion,
            key: KeySelector::Default,
            payload: b"revoked".to_vec()
        })
        .is_err());
    assert_eq!(
        identity_a.public_identity().unwrap().state,
        PublicIdentityState::Active
    );
    // The observing device also rejects resurrection at a later checkpoint.
    assert!(identity_b
        .adopt_verified_document(remote(joined, 4, 4))
        .is_err());
    let reference_a = identity_a.public_identity().unwrap().reference;
    drop(change);
    drop(identity_a);
    drop(manager_a);
    let reopened = IdentityManager::open(config(root_a.path())).unwrap();
    let mut identity_a = reopened.get(&reference_a).unwrap();
    let EnrollmentProposalKind::Device {
        signing_key,
        agreement_key,
        ..
    } = enrollment.proposal().kind.clone()
    else {
        panic!("device")
    };
    let device = DeviceInput {
        device_id: "device-b".into(),
        signing_key: PublicKeyInput {
            kid: "#new-sign".into(),
            public_key_multibase: signing_key.public_key_multibase,
        },
        agreement_key: PublicKeyInput {
            kid: "#new-ka".into(),
            public_key_multibase: agreement_key.public_key_multibase,
        },
        profiles: profiles(),
    };
    // Both keys and KIDs are absent from the current document; the old device ID is decisive.
    assert!(identity_a
        .prepare_document_change(DocumentChangeRequest {
            changes: vec![DocumentChange::AddDevice { device }],
        })
        .is_err());
}

#[test]
fn old_web_document_does_not_release_uncertain_publication() {
    let root = tempfile::tempdir().unwrap();
    let mut manager = IdentityManager::initialize(config(root.path())).unwrap();
    let mut identity = manager.create(request()).unwrap();
    let initial = identity.public_identity().unwrap().document;
    let mut session = identity
        .prepare_document_change(DocumentChangeRequest {
            changes: vec![DocumentChange::ReplaceServices {
                services: vec![IdentityService {
                    id: "api".into(),
                    service_type: "API".into(),
                    service_endpoint: "https://api.example".into(),
                    service_did: None,
                    profiles: vec![],
                    security_profiles: vec![],
                }],
            }],
        })
        .unwrap();
    let candidate = session.candidate().clone();
    let attempt = session.begin_publication().unwrap();
    assert_eq!(
        session
            .complete(attempt, PublicationResult::Unknown)
            .unwrap(),
        DocumentChangeOutcome::PublicationUncertain
    );
    assert_eq!(
        session.reconcile(remote(initial, 1, 1)).unwrap(),
        DocumentChangeOutcome::PublicationUncertain
    );
    assert!(session.begin_publication().is_err());
    drop(session);
    drop(identity);
    drop(manager);
    let manager = IdentityManager::open(config(root.path())).unwrap();
    let reference = manager.list().unwrap()[0].reference.clone();
    let mut identity = manager.get(&reference).unwrap();
    let mut resumed = identity.resume_document_change().unwrap().unwrap();
    assert_eq!(resumed.candidate(), &candidate);
    assert!(matches!(
        resumed
            .reconcile(remote(candidate.candidate_document, 2, 1))
            .unwrap(),
        DocumentChangeOutcome::Committed { .. }
    ));
}

#[test]
fn web_cannot_create_root_control_or_unknown_method() {
    let root = tempfile::tempdir().unwrap();
    let mut manager = IdentityManager::initialize(config(root.path())).unwrap();
    let mut invalid = request();
    invalid.managed_keys.push(ManagedKeyInput {
        fragment: "root".into(),
        role: ManagedKeyRole::RootControl,
    });
    assert_eq!(
        manager.create(invalid).err(),
        Some(IdentityError::InvalidRequest)
    );
    let mut invalid = request();
    invalid.path_segments.push("..".into());
    assert!(manager.create(invalid).is_err());
    assert!(serde_json::from_str::<CreateIdentityProfile>("\"unknown\"").is_err());
    assert!(manager.list().unwrap().is_empty());
}
