use super::*;
use crate::facade::{
    DidDocument, IdentityManagerConfig, InjectedStoreKey, RootKeySource,
    VerifiedPublicationEvidence,
};
use crate::host::IdentityStatusPort;
use crate::{Capabilities, DidCreateSpec, DidProfile, KeyRole, ManagedKeySpec};

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
