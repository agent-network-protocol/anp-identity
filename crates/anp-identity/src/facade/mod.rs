mod document_change;
mod error;
mod identity;
mod identity_transition;
mod manager;
pub(crate) mod signing;
mod types;

pub use document_change::{
    DeviceInput, DocumentChange, DocumentChangeOutcome, DocumentChangeRequest,
    DocumentChangeSession, IdentityService, PreparedDocumentChange, PublicKeyInput,
    PublicationAttempt, PublicationResult, VerifiedPublicationEvidence, VerifiedRemoteDocument,
};
pub use error::{IdentityError, IdentityResult};
pub use identity::ManagedIdentity;
pub use identity_transition::{
    IdentityTransitionOutcome, IdentityTransitionPublicationAttempt,
    IdentityTransitionPublicationEvidence, IdentityTransitionPublicationResult,
    IdentityTransitionRemoteObservation, IdentityTransitionRequest, IdentityTransitionSession,
    PreparedIdentityTransition,
};
pub use manager::IdentityManager;
pub use signing::{
    KeySelector, OriginProofOptions, OriginProofRequest, SignRequest, Signature, SignedOriginProof,
    SigningPurpose, VerificationOutcome, VerifyRequest,
};
pub use types::{
    CreateIdentityCapabilities, CreateIdentityExtension, CreateIdentityProfile,
    CreateIdentityRequest, DeleteIdentityRequest, DeviceManifestEntryInput, DidDocument,
    ExternalPublicKeyInput, ExternalPublicKeyInputMaterial, IdentityDescriptor,
    IdentityManagerConfig, IdentityRef, InjectedStoreKey, KeyAlgorithm, KeyPurpose,
    ManagedKeyInput, ManagedKeyRole, OkpPublicJwk, PublicCapabilities, PublicIdentity,
    PublicIdentityState, PublicKeyDescriptor, RecoveryReport, RootKeySource, StoreHealth,
    StoreInfo,
};
