mod document_change;
mod error;
mod identity;
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
pub use manager::IdentityManager;
pub use signing::{
    KeySelector, OriginProofOptions, OriginProofRequest, SignRequest, Signature, SignedOriginProof,
    SigningPurpose, VerificationOutcome, VerifyRequest,
};
pub use types::{
    CreateIdentityRequest, DeleteIdentityRequest, DidDocument, IdentityDescriptor,
    IdentityManagerConfig, IdentityRef, InjectedStoreKey, KeyAlgorithm, KeyPurpose,
    PublicCapabilities, PublicIdentity, PublicIdentityState, PublicKeyDescriptor, RecoveryReport,
    RootKeySource, StoreHealth, StoreInfo,
};
