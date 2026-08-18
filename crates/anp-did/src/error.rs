use thiserror::Error;

pub type DidResult<T> = Result<T, DidError>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DidError {
    #[error("only the E1 DID profile is supported")]
    UnsupportedProfile,
    #[error("the DID domain is invalid")]
    InvalidDomain,
    #[error("at least one non-empty DID path segment is required")]
    EmptyPath,
    #[error("the DID path segment is invalid")]
    InvalidPathSegment,
    #[error("the KID fragment is invalid")]
    InvalidKidFragment,
    #[error("exactly one managed root-control key is required")]
    InvalidManagedRootCount,
    #[error("an external root-control key is forbidden")]
    ExternalRootControl,
    #[error("DID-WBA requires at least one managed request-signing key")]
    MissingManagedRequestSigning,
    #[error("a KID belongs to another DID")]
    ForeignKid,
    #[error("a canonical KID is duplicated")]
    DuplicateKid,
    #[error("the public key is invalid or incompatible with its role")]
    InvalidPublicKey,
    #[error("the service definition is invalid")]
    InvalidService,
    #[error("the extension definition is invalid")]
    InvalidExtension,
    #[error("the root-key provider is unavailable")]
    ProviderUnavailable,
    #[error("the root key does not match this store")]
    RootKeyMismatch,
    #[error("the encrypted record is damaged")]
    CorruptRecord,
    #[error("the requested secret does not exist")]
    SecretNotFound,
    #[error("the requested identity does not exist")]
    IdentityNotFound,
    #[error("the DID identity already exists")]
    DuplicateIdentity,
    #[error("the requested KID does not exist")]
    KeyNotFound,
    #[error("the requested KID is external and has no managed private key")]
    ExternalKeyOperation,
    #[error("the key role does not authorize this operation")]
    KeyRoleViolation,
    #[error("the key state does not authorize this operation")]
    KeyNotUsable,
    #[error("the peer public key is invalid")]
    InvalidPeerKey,
    #[error("signature verification failed")]
    VerificationFailed,
    #[error("an identity already has a pending document revision")]
    PendingRevisionExists,
    #[error("the pending document revision does not exist")]
    PendingRevisionNotFound,
    #[error("the document revision is not in a valid publication state for this operation")]
    InvalidPublicationState,
    #[error("the identity document or local identity record is invalid")]
    InvalidIdentity,
    #[error("the store generation changed")]
    Conflict,
    #[error("filesystem operation failed: {0}")]
    Io(String),
    #[error("serialization failed: {0}")]
    Serialization(String),
    #[error("cryptographic operation failed")]
    Crypto,
    #[error("the requested operation is not supported in v1")]
    UnsupportedOperation,
}
