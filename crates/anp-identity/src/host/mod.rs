mod convergence;
mod document_change;
mod enrollment;
mod http_signing;
mod key_agreement;
#[cfg(feature = "key-import")]
mod migration;
mod proofs;
mod provider_adoption;
mod provider_authorization;
mod root_transfer;
mod sealed_handoff;
mod status;

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
pub use provider_adoption::{
    adopt_store_root_key_provider, AdoptStoreRootKeyRequest, ProviderAdoptionReport,
    ProviderAdoptionTarget,
};
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
#[cfg(feature = "key-import")]
pub use sealed_handoff::{
    sealed_identity_material_import_binding, sealed_root_import_binding,
    PreparedSealedIdentityMaterialImport, PreparedSealedRootImport,
    SealedIdentityMaterialImportOffer, SealedIdentityMaterialImportPreparation,
    SealedIdentityMaterialKeySpec, SealedImportOffer, SealedRootImportPreparation,
};
pub use sealed_handoff::{
    sealed_key_agreement_binding, sealed_operation_aad, SealedKeyAgreementPort,
    SealedKeyAgreementRequest, SealedProviderError, SealedSecretEnvelope, SEALED_SECRET_INFO,
    SEALED_SECRET_PROTOCOL,
};
#[cfg(feature = "root-export")]
pub use sealed_handoff::{
    sealed_root_export_binding, SealedRootExportPort, SealedRootExportRequest,
};
pub use status::{
    HostDocumentCheckpoint, HostRootCapability, IdentityHostStatus, IdentityStatusPort,
};
