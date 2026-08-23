use super::*;
use crate::facade::{
    DidDocument, IdentityManagerConfig, InjectedStoreKey, RootKeySource,
    VerifiedPublicationEvidence,
};
use crate::host::{
    capability, sealed_enrollment_key_agreement_binding, IdentityStatusPort, ProviderAuthorization,
    SealedEnrollmentKeyAgreementPort, SealedEnrollmentKeyAgreementRequest, SEALED_SECRET_INFO,
};
use crate::{Capabilities, DidCreateSpec, DidProfile, KeyRole, ManagedKeySpec};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

#[test]
fn device_enrollment_scopes_pending_crypto_and_resumes_then_cancels() {
    let (_source_root, source) = source_identity();
    let remote = remote(&source);
    let target_root = tempfile::tempdir().unwrap();
    let mut target = IdentityManager::initialize(config(target_root.path(), [0xc2; 32])).unwrap();

    let session = target
        .begin_device_enrollment(DeviceEnrollmentRequest {
            remote,
            device_id: "new-device".to_owned(),
            device_signing_fragment: "new-device-signing".to_owned(),
            device_agreement_fragment: "new-device-agreement".to_owned(),
            profiles: vec!["anp.core.v1".to_owned()],
            capabilities: EnrollmentCapabilities { did_wba: true },
        })
        .unwrap();
    let reference = session.proposal().identity.clone();
    let signature = session.sign_device_assertion(b"pending assertion").unwrap();
    assert_eq!(signature.len(), 64);
    let shared = session
        .derive_device_shared_secret(
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([0x29; 32])).to_bytes(),
        )
        .unwrap();
    assert!(shared.as_bytes().iter().any(|byte| *byte != 0));

    drop(session);
    let resumed = target.resume_enrollment(&reference).unwrap().unwrap();
    assert_eq!(resumed.proposal().identity, reference);
    resumed.cancel(&mut target).unwrap();
    assert!(target.list().unwrap().is_empty());
}

#[test]
fn pending_device_ecdh_crosses_provider_boundary_only_as_ciphertext() {
    let (_source_root, source) = source_identity();
    let target_root = tempfile::tempdir().unwrap();
    let mut target = IdentityManager::initialize(config(target_root.path(), [0xc4; 32])).unwrap();
    let session = target
        .begin_device_enrollment(DeviceEnrollmentRequest {
            remote: remote(&source),
            device_id: "sealed-device".to_owned(),
            device_signing_fragment: "sealed-signing".to_owned(),
            device_agreement_fragment: "sealed-agreement".to_owned(),
            profiles: vec!["anp.core.v1".to_owned()],
            capabilities: EnrollmentCapabilities { did_wba: true },
        })
        .unwrap();
    let proposal = session.proposal();
    let EnrollmentProposalKind::Device { agreement_key, .. } = &proposal.kind else {
        panic!("device enrollment expected")
    };
    let authority = ProviderAuthorization::new();
    let lease = authority
        .acquire_lease(
            "dsh-awiki".to_owned(),
            [capability::IDENTITY_ECDH_SEALED.to_owned()],
            proposal.identity.store_id.clone(),
            600,
        )
        .unwrap();
    let peer =
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([0x31; 32])).to_bytes();
    let recipient = anp::sealed_handoff::SealedHandoffRecipient::generate();
    let binding = sealed_enrollment_key_agreement_binding(
        &proposal.identity,
        &proposal.enrollment_id,
        &agreement_key.kid,
        &peer,
        recipient.public_key(),
        "enrollment-ecdh-1",
    )
    .unwrap();
    let issued = authority
        .issue_one_time_with_context(&lease, &binding, 60)
        .unwrap();
    let aad =
        crate::host::sealed_operation_aad(&issued.context, &binding, &proposal.identity).unwrap();
    let delivery = session
        .derive_device_shared_secret_sealed(
            &authority,
            SealedEnrollmentKeyAgreementRequest {
                identity: proposal.identity.clone(),
                enrollment_id: proposal.enrollment_id.clone(),
                kid: agreement_key.kid.clone(),
                peer_public: peer,
                recipient_public_key: *recipient.public_key(),
                request_id: "enrollment-ecdh-1".to_owned(),
                token: issued.token,
            },
        )
        .unwrap();
    assert_eq!(delivery.authorization, issued.context);
    assert_eq!(delivery.aad, URL_SAFE_NO_PAD.encode(&aad));
    let plaintext = recipient
        .open(
            &delivery.envelope.to_handoff().unwrap(),
            SEALED_SECRET_INFO,
            &aad,
        )
        .unwrap();
    assert_eq!(plaintext.len(), 32);

    let changed = sealed_enrollment_key_agreement_binding(
        &proposal.identity,
        "different-enrollment",
        &agreement_key.kid,
        &peer,
        recipient.public_key(),
        "enrollment-ecdh-1",
    )
    .unwrap();
    assert_ne!(
        binding.operation_input_digest,
        changed.operation_input_digest
    );
}

#[test]
fn request_signing_enrollment_has_no_pending_device_crypto() {
    let (_source_root, source) = source_identity();
    let target_root = tempfile::tempdir().unwrap();
    let mut target = IdentityManager::initialize(config(target_root.path(), [0xc3; 32])).unwrap();
    let session = target
        .begin_request_signing_enrollment(RequestSigningEnrollmentRequest {
            remote: remote(&source),
            fragment: "daemon-request".to_owned(),
            capabilities: EnrollmentCapabilities { did_wba: true },
        })
        .unwrap();
    assert!(matches!(
        session.proposal().kind,
        EnrollmentProposalKind::RequestSigning { .. }
    ));
    assert_eq!(
        session.sign_device_assertion(b"not allowed").err(),
        Some(IdentityError::CapabilityUnavailable)
    );
    session.cancel(&mut target).unwrap();
}

#[test]
fn convergence_reports_unchanged_for_verified_current_document() {
    let (_root, mut source) = source_identity();
    assert_eq!(
        source.adopt_verified_document(remote(&source)).unwrap(),
        ConvergenceOutcome::Unchanged
    );
}

fn source_identity() -> (tempfile::TempDir, ManagedIdentity) {
    let root = tempfile::tempdir().unwrap();
    let mut manager = IdentityManager::initialize(config(root.path(), [0xc1; 32])).unwrap();
    let identity = manager
        .create(DidCreateSpec {
            profile: DidProfile::E1,
            domain: "example.com".to_owned(),
            port: None,
            path_segments: vec!["facade".to_owned(), "enrollment-source".to_owned()],
            capabilities: Capabilities { did_wba: true },
            managed_keys: vec![
                managed("root", KeyRole::RootControl),
                managed("request", KeyRole::RequestSigning),
            ],
            external_keys: Vec::new(),
            services: Vec::new(),
            agent_description_url: None,
            extensions: Vec::new(),
        })
        .unwrap();
    (root, identity)
}

fn remote(identity: &ManagedIdentity) -> VerifiedRemoteDocument {
    let public = identity.public_identity().unwrap();
    let checkpoint = identity.host_status().unwrap().checkpoint.unwrap();
    VerifiedRemoteDocument {
        document: DidDocument::from_verified(public.document.into_value()),
        evidence: VerifiedPublicationEvidence {
            document_version: checkpoint.document_version,
            registry_version: checkpoint.registry_version,
            document_digest: checkpoint.document_digest,
        },
    }
}

fn config(root: &std::path::Path, bytes: [u8; 32]) -> IdentityManagerConfig {
    IdentityManagerConfig {
        state_root: root.to_owned(),
        root_key: RootKeySource::Injected(InjectedStoreKey::new("enrollment", bytes)),
    }
}

fn managed(fragment: &str, role: KeyRole) -> ManagedKeySpec {
    ManagedKeySpec {
        fragment: fragment.to_owned(),
        role,
    }
}
