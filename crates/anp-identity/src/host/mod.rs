mod convergence;
mod document_change;
mod enrollment;
mod http_signing;
mod key_agreement;
#[cfg(feature = "key-import")]
mod migration;
mod proofs;
mod provider_authorization;
mod root_transfer;
mod sealed_handoff;
mod status;

pub use crate::registry::DocumentCheckpoint;
pub use crate::root_transfer::{
    RootTransferContext, WrappedRootEnvelope, WRAPPED_ROOT_ENVELOPE_TYPE,
    WRAPPED_ROOT_ENVELOPE_VERSION,
};
pub use convergence::{ConvergenceOutcome, ConvergenceWorkflow};
pub use document_change::{DocumentChangeRecoveryPort, HostDocumentChangePhase};
pub use enrollment::{
    DeviceEnrollmentRequest, EnrollmentCapabilities, EnrollmentProposal, EnrollmentProposalKind,
    EnrollmentPublicKey, EnrollmentSession, EnrollmentWorkflow, RequestSigningEnrollmentRequest,
};
pub use http_signing::{
    ExactHttpRequest, HttpHeader, HttpRequestSigningOptions, HttpRequestSigningPort,
    LegacyDidWbaPort, PreparedHttpSignatureAttempt, MAX_HTTP_SIGNING_BODY_BYTES,
};
pub use key_agreement::{KeyAgreementPort, KeyAgreementRequest, ZeroizingSharedSecret};
#[cfg(feature = "key-import")]
pub use migration::{
    DeviceIdentityImportRequest, FullIdentityImportRequest, MigrationKeyPurpose, MigrationPort,
    MigrationPrivateKey, MigrationPrivateKeyEncoding, RequestSigningIdentityImportRequest,
};
pub use proofs::{DocumentProofOptions, DocumentProofRequest, ObjectProofRequest, TypedProofPort};
pub use provider_authorization::{
    capability, recipient_public_key_digest, IssuedAuthorizationContext,
    IssuedOneTimeAuthorization, OneTimeCapabilityToken, OneTimeOperationBinding,
    ProviderAuthorization, ProviderAuthorizationError, ProviderCapabilityLease,
};
#[cfg(feature = "root-export")]
pub use root_transfer::{
    HostExportedRootPrivateKey, RootExportPort, UserConfirmedRootExportRequest,
};
#[cfg(feature = "key-import")]
pub use root_transfer::{
    LegacyRootImportEvidence, LegacyRootImportOutcome, LegacyRootImportRequest, RootImportPort,
    RootPrivateKeyEncoding,
};
pub use root_transfer::{
    PendingRootObjectProofRequest, RootPromotionPort, RootPromotionRequest,
    WrappedRootImportOutcome, WrappedRootImportPort,
};
pub use sealed_handoff::{
    sealed_enrollment_key_agreement_binding, sealed_key_agreement_binding, sealed_operation_aad,
    SealedEnrollmentKeyAgreementPort, SealedEnrollmentKeyAgreementRequest, SealedKeyAgreementPort,
    SealedKeyAgreementRequest, SealedProviderError, SealedSecretDelivery, SealedSecretEnvelope,
    SEALED_SECRET_INFO, SEALED_SECRET_PROTOCOL,
};
#[cfg(feature = "key-import")]
pub use sealed_handoff::{
    sealed_identity_material_import_binding, sealed_root_import_binding,
    PreparedSealedIdentityMaterialImport, PreparedSealedRootImport,
    SealedIdentityMaterialImportOffer, SealedIdentityMaterialImportPreparation,
    SealedIdentityMaterialKeySpec, SealedImportOffer, SealedRootImportPreparation,
};
#[cfg(feature = "root-export")]
pub use sealed_handoff::{
    sealed_root_export_binding, SealedRootExportPort, SealedRootExportRequest,
};
pub use status::{
    HostDocumentCheckpoint, HostRootCapability, IdentityHostStatus, IdentityStatusPort,
};
