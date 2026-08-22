use thiserror::Error;

use crate::DidError;

pub type IdentityResult<T> = Result<T, IdentityError>;

/// Stable error categories exposed by the application Facade.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdentityError {
    #[error("the identity request is invalid")]
    InvalidRequest,
    #[error("the identity store is not initialized")]
    StoreNotFound,
    #[error("the configured root-key provider is unavailable")]
    ProviderUnavailable,
    #[error("the root key does not match this identity store")]
    RootKeyMismatch,
    #[error("the identity store contains invalid or damaged state")]
    CorruptState,
    #[error("the requested identity does not exist")]
    IdentityNotFound,
    #[error("the requested identity already exists")]
    IdentityAlreadyExists,
    #[error("the requested key does not exist")]
    KeyNotFound,
    #[error("the requested key cannot perform this operation")]
    KeyUnavailable,
    #[error("the requested key is not authorized for this purpose")]
    KeyPurposeViolation,
    #[error("more than one key matches the request")]
    AmbiguousKey,
    #[error("signature verification failed")]
    VerificationFailed,
    #[error("the identity already has a pending document change")]
    PendingDocumentChange,
    #[error("the pending document change does not exist")]
    DocumentChangeNotFound,
    #[error("the document change is not in a valid state for this operation")]
    InvalidDocumentChangeState,
    #[error("the identity store changed concurrently")]
    Conflict,
    #[error("the requested capability is unavailable")]
    CapabilityUnavailable,
    #[error("the operation is not supported")]
    Unsupported,
    #[error("identity storage failed")]
    Storage,
    #[error("identity processing failed")]
    Internal,
}

impl From<DidError> for IdentityError {
    fn from(error: DidError) -> Self {
        match error {
            DidError::InvalidDomain
            | DidError::EmptyPath
            | DidError::InvalidPathSegment
            | DidError::InvalidKidFragment
            | DidError::InvalidManagedRootCount
            | DidError::ExternalRootControl
            | DidError::MissingManagedRequestSigning
            | DidError::ForeignKid
            | DidError::DuplicateKid
            | DidError::InvalidPublicKey
            | DidError::InvalidService
            | DidError::InvalidExtension
            | DidError::InvalidPeerKey
            | DidError::InvalidRootTransfer
            | DidError::RootTransferExpired => Self::InvalidRequest,
            DidError::StoreNotFound => Self::StoreNotFound,
            DidError::ProviderUnavailable => Self::ProviderUnavailable,
            DidError::RootKeyMismatch => Self::RootKeyMismatch,
            DidError::CorruptRecord | DidError::Serialization(_) | DidError::InvalidIdentity => {
                Self::CorruptState
            }
            DidError::SecretNotFound | DidError::KeyNotFound => Self::KeyNotFound,
            DidError::IdentityNotFound => Self::IdentityNotFound,
            DidError::DuplicateIdentity => Self::IdentityAlreadyExists,
            DidError::ExternalKeyOperation
            | DidError::KeyNotUsable
            | DidError::KeyMaterialErased => Self::KeyUnavailable,
            DidError::KeyRoleViolation => Self::KeyPurposeViolation,
            DidError::VerificationFailed => Self::VerificationFailed,
            DidError::PendingRevisionExists | DidError::PendingRootTransferExists => {
                Self::PendingDocumentChange
            }
            DidError::PendingRevisionNotFound => Self::DocumentChangeNotFound,
            DidError::InvalidPublicationState => Self::InvalidDocumentChangeState,
            DidError::Conflict => Self::Conflict,
            DidError::RootCapabilityUnavailable => Self::CapabilityUnavailable,
            DidError::UnsupportedOperation => Self::Unsupported,
            DidError::Io(_) => Self::Storage,
            DidError::Crypto => Self::Internal,
        }
    }
}
