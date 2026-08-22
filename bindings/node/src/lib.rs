use std::path::PathBuf;
use std::sync::Arc;

use anp_identity::{
    DeleteIdentityRequest, DocumentChangeRequest,
    DocumentChangeSession as CoreDocumentChangeSession, IdentityError,
    IdentityManager as CoreIdentityManager, IdentityManagerConfig, IdentityRef, InjectedStoreKey,
    KeySelector, ManagedIdentity as CoreManagedIdentity, OriginProofOptions, OriginProofRequest,
    PublicationAttempt, PublicationResult, RootKeySource, SignRequest, SigningPurpose,
    VerifiedRemoteDocument, VerifyRequest,
};
use napi::bindgen_prelude::Buffer;
use napi::Status;
use napi_derive::napi;
use serde::Serialize;
use serde_json::Value;
use tokio::sync::Mutex;
use zeroize::{Zeroize, Zeroizing};

type Result<T> = napi::Result<T>;

#[napi(object)]
pub struct JsIdentityManagerConfig {
    pub state_root: String,
    pub root_key_kind: String,
    pub key_id: Option<String>,
    pub environment_variable: Option<String>,
    pub root_key: Option<Buffer>,
    pub service: Option<String>,
    pub account: Option<String>,
    pub fallback_to_local_file: Option<bool>,
}

#[napi(object)]
pub struct JsIdentityRef {
    pub store_id: String,
    pub identity_id: String,
    pub did: String,
}

#[napi(object)]
pub struct JsSignRequest {
    pub purpose: String,
    pub domain: Option<String>,
    pub kid: Option<String>,
    pub payload: Buffer,
}

#[napi(object)]
pub struct JsSignature {
    pub kid: String,
    pub algorithm: String,
    pub bytes: Buffer,
}

#[napi(object)]
pub struct JsVerifyRequest {
    pub purpose: String,
    pub domain: Option<String>,
    pub kid: String,
    pub payload: Buffer,
    pub signature: Buffer,
}

#[napi(object)]
pub struct JsOriginProofOptions {
    pub created: Option<i64>,
    pub expires: Option<i64>,
    pub nonce: Option<String>,
}

#[napi(object)]
pub struct JsOriginProofRequest {
    pub method: String,
    pub meta: Value,
    pub body: Value,
    pub kid: Option<String>,
    pub options: Option<JsOriginProofOptions>,
}

#[napi(js_name = "IdentityManager")]
pub struct JsIdentityManager {
    inner: Arc<Mutex<CoreIdentityManager>>,
}

#[napi]
impl JsIdentityManager {
    #[napi(factory)]
    pub async fn initialize(config: JsIdentityManagerConfig) -> Result<Self> {
        let config = manager_config(config)?;
        let manager =
            run_blocking(move || CoreIdentityManager::initialize(config).map_err(map_error))
                .await?;
        Ok(Self::new(manager))
    }

    #[napi(factory)]
    pub async fn open(config: JsIdentityManagerConfig) -> Result<Self> {
        let config = manager_config(config)?;
        let manager =
            run_blocking(move || CoreIdentityManager::open(config).map_err(map_error)).await?;
        Ok(Self::new(manager))
    }

    #[napi]
    pub async fn info(&self) -> Result<Value> {
        self.with_manager(|manager| to_value(manager.info().map_err(map_error)?))
            .await
    }

    #[napi]
    pub async fn list(&self) -> Result<Value> {
        self.with_manager(|manager| to_value(manager.list().map_err(map_error)?))
            .await
    }

    #[napi]
    pub async fn create(&self, request: Value) -> Result<JsManagedIdentity> {
        let request = serde_json::from_value(request).map_err(invalid_json)?;
        self.with_manager(move |manager| {
            manager
                .create(request)
                .map(JsManagedIdentity::new)
                .map_err(map_error)
        })
        .await
    }

    #[napi]
    pub async fn get(&self, identity: JsIdentityRef) -> Result<JsManagedIdentity> {
        let reference = identity.into();
        self.with_manager(move |manager| {
            manager
                .get(&reference)
                .map(JsManagedIdentity::new)
                .map_err(map_error)
        })
        .await
    }

    #[napi]
    pub async fn delete(&self, identity: JsIdentityRef) -> Result<()> {
        let reference = identity.into();
        self.with_manager(move |manager| {
            manager
                .delete(&reference, DeleteIdentityRequest::default())
                .map_err(map_error)
        })
        .await
    }

    #[napi]
    pub async fn recover(&self) -> Result<Value> {
        self.with_manager(|manager| to_value(manager.recover().map_err(map_error)?))
            .await
    }
}

impl JsIdentityManager {
    fn new(manager: CoreIdentityManager) -> Self {
        Self {
            inner: Arc::new(Mutex::new(manager)),
        }
    }

    async fn with_manager<T, F>(&self, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut CoreIdentityManager) -> Result<T> + Send + 'static,
    {
        let inner = Arc::clone(&self.inner);
        run_blocking(move || operation(&mut inner.blocking_lock())).await
    }
}

#[napi(js_name = "ManagedIdentity")]
pub struct JsManagedIdentity {
    inner: Arc<Mutex<CoreManagedIdentity>>,
}

#[napi]
impl JsManagedIdentity {
    #[napi]
    pub async fn reference(&self) -> Result<JsIdentityRef> {
        self.with_identity(|identity| Ok(identity.reference().into()))
            .await
    }

    #[napi]
    pub async fn public_identity(&self) -> Result<Value> {
        self.with_identity(|identity| to_value(identity.public_identity().map_err(map_error)?))
            .await
    }

    #[napi]
    pub async fn sign(&self, request: JsSignRequest) -> Result<JsSignature> {
        let request = SignRequest {
            purpose: signing_purpose(&request.purpose, request.domain)?,
            key: key_selector(request.kid),
            payload: request.payload.to_vec(),
        };
        self.with_identity(move |identity| {
            let signature = identity.sign(request).map_err(map_error)?;
            Ok(JsSignature {
                kid: signature.kid,
                algorithm: key_algorithm(signature.algorithm),
                bytes: signature.bytes.into(),
            })
        })
        .await
    }

    #[napi]
    pub async fn verify(&self, request: JsVerifyRequest) -> Result<String> {
        let request = VerifyRequest {
            purpose: signing_purpose(&request.purpose, request.domain)?,
            kid: request.kid,
            payload: request.payload.to_vec(),
            signature: request.signature.to_vec(),
        };
        self.with_identity(move |identity| {
            identity
                .verify(request)
                .map(|outcome| match outcome {
                    anp_identity::VerificationOutcome::Valid => "valid".to_owned(),
                    anp_identity::VerificationOutcome::Invalid => "invalid".to_owned(),
                })
                .map_err(map_error)
        })
        .await
    }

    #[napi]
    pub async fn sign_origin_proof(&self, request: JsOriginProofRequest) -> Result<Value> {
        let options = request.options.unwrap_or(JsOriginProofOptions {
            created: None,
            expires: None,
            nonce: None,
        });
        let request = OriginProofRequest {
            method: request.method,
            meta: request.meta,
            body: request.body,
            key: key_selector(request.kid),
            options: OriginProofOptions {
                created: options.created,
                expires: options.expires,
                nonce: options.nonce,
            },
        };
        self.with_identity(move |identity| {
            to_value(identity.sign_origin_proof(request).map_err(map_error)?)
        })
        .await
    }

    #[napi]
    pub async fn prepare_document_change(&self, request: Value) -> Result<JsDocumentChangeSession> {
        let request: DocumentChangeRequest =
            serde_json::from_value(request).map_err(invalid_json)?;
        self.with_identity(move |identity| {
            identity
                .prepare_document_change(request)
                .map(JsDocumentChangeSession::new)
                .map_err(map_error)
        })
        .await
    }

    #[napi]
    pub async fn resume_document_change(&self) -> Result<Option<JsDocumentChangeSession>> {
        self.with_identity(|identity| {
            identity
                .resume_document_change()
                .map(|session| session.map(JsDocumentChangeSession::new))
                .map_err(map_error)
        })
        .await
    }
}

impl JsManagedIdentity {
    fn new(identity: CoreManagedIdentity) -> Self {
        Self {
            inner: Arc::new(Mutex::new(identity)),
        }
    }

    async fn with_identity<T, F>(&self, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut CoreManagedIdentity) -> Result<T> + Send + 'static,
    {
        let inner = Arc::clone(&self.inner);
        run_blocking(move || operation(&mut inner.blocking_lock())).await
    }
}

#[napi(js_name = "DocumentChangeSession")]
pub struct JsDocumentChangeSession {
    inner: Arc<Mutex<CoreDocumentChangeSession>>,
}

#[napi]
impl JsDocumentChangeSession {
    #[napi]
    pub async fn candidate(&self) -> Result<Value> {
        self.with_session(|session| to_value(session.candidate()))
            .await
    }

    #[napi]
    pub async fn begin_publication(&self) -> Result<Value> {
        self.with_session(|session| to_value(session.begin_publication().map_err(map_error)?))
            .await
    }

    #[napi]
    pub async fn complete(&self, attempt: Value, result: Value) -> Result<Value> {
        let attempt: PublicationAttempt = serde_json::from_value(attempt).map_err(invalid_json)?;
        let result: PublicationResult = serde_json::from_value(result).map_err(invalid_json)?;
        self.with_session(move |session| {
            to_value(session.complete(attempt, result).map_err(map_error)?)
        })
        .await
    }

    #[napi]
    pub async fn reconcile(&self, observation: Value) -> Result<Value> {
        let observation: VerifiedRemoteDocument =
            serde_json::from_value(observation).map_err(invalid_json)?;
        self.with_session(move |session| {
            to_value(session.reconcile(observation).map_err(map_error)?)
        })
        .await
    }
}

impl JsDocumentChangeSession {
    fn new(session: CoreDocumentChangeSession) -> Self {
        Self {
            inner: Arc::new(Mutex::new(session)),
        }
    }

    async fn with_session<T, F>(&self, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut CoreDocumentChangeSession) -> Result<T> + Send + 'static,
    {
        let inner = Arc::clone(&self.inner);
        run_blocking(move || operation(&mut inner.blocking_lock())).await
    }
}

impl From<JsIdentityRef> for IdentityRef {
    fn from(value: JsIdentityRef) -> Self {
        Self {
            store_id: value.store_id,
            identity_id: value.identity_id,
            did: value.did,
        }
    }
}

impl From<IdentityRef> for JsIdentityRef {
    fn from(value: IdentityRef) -> Self {
        Self {
            store_id: value.store_id,
            identity_id: value.identity_id,
            did: value.did,
        }
    }
}

fn manager_config(mut config: JsIdentityManagerConfig) -> Result<IdentityManagerConfig> {
    let root_key = match config.root_key_kind.as_str() {
        "injected" => {
            let key_id = required(config.key_id, "keyId")?;
            let root_key = required(config.root_key.take(), "rootKey")?;
            RootKeySource::Injected(InjectedStoreKey::new(key_id, *consume_root_key(root_key)?))
        }
        "environment" => RootKeySource::Environment {
            key_id: required(config.key_id, "keyId")?,
            variable: required(config.environment_variable, "environmentVariable")?,
        },
        "local_private_file" => RootKeySource::LocalPrivateFile,
        "keyring" => RootKeySource::Keyring {
            service: required(config.service, "service")?,
            account: required(config.account, "account")?,
            fallback_to_local_file: config.fallback_to_local_file.unwrap_or(false),
        },
        _ => return Err(js_error("invalid_request", "unknown root key provider")),
    };
    Ok(IdentityManagerConfig {
        state_root: PathBuf::from(config.state_root),
        root_key,
    })
}

fn signing_purpose(purpose: &str, domain: Option<String>) -> Result<SigningPurpose> {
    match purpose {
        "authentication" => Ok(SigningPurpose::Authentication),
        "device_assertion" => Ok(SigningPurpose::DeviceAssertion),
        "application_assertion" => Ok(SigningPurpose::ApplicationAssertion {
            domain: required(domain, "domain")?,
        }),
        _ => Err(js_error("invalid_request", "unknown signing purpose")),
    }
}

fn key_selector(kid: Option<String>) -> KeySelector {
    kid.map(KeySelector::Kid).unwrap_or(KeySelector::Default)
}

fn key_algorithm(algorithm: anp_identity::KeyAlgorithm) -> String {
    match algorithm {
        anp_identity::KeyAlgorithm::Ed25519 => "ed25519".to_owned(),
        anp_identity::KeyAlgorithm::X25519 => "x25519".to_owned(),
    }
}

fn to_value(value: impl Serialize) -> Result<Value> {
    serde_json::to_value(value).map_err(|_| js_error("internal", "response serialization failed"))
}

fn required<T>(value: Option<T>, field: &str) -> Result<T> {
    value.ok_or_else(|| js_error("invalid_request", &format!("{field} is required")))
}

fn invalid_json(_: serde_json::Error) -> napi::Error {
    js_error("invalid_request", "request shape is invalid")
}

fn consume_root_key(mut buffer: Buffer) -> Result<Zeroizing<[u8; 32]>> {
    if buffer.len() != 32 {
        buffer.as_mut().zeroize();
        return Err(js_error(
            "invalid_request",
            "root key must contain exactly 32 bytes",
        ));
    }
    let mut output = Zeroizing::new([0_u8; 32]);
    output.copy_from_slice(&buffer);
    buffer.as_mut().zeroize();
    Ok(output)
}

async fn run_blocking<T, F>(operation: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|_| js_error("internal", "blocking operation failed"))?
}

fn js_error(code: &str, message: &str) -> napi::Error {
    napi::Error::new(
        Status::GenericFailure,
        format!("ANP_IDENTITY_CODE:{code}:{message}"),
    )
}

fn map_error(error: IdentityError) -> napi::Error {
    let code = match error {
        IdentityError::InvalidRequest => "invalid_request",
        IdentityError::StoreNotFound => "store_not_found",
        IdentityError::ProviderUnavailable => "provider_unavailable",
        IdentityError::RootKeyMismatch => "root_key_mismatch",
        IdentityError::CorruptState => "corrupt_state",
        IdentityError::IdentityNotFound => "identity_not_found",
        IdentityError::IdentityAlreadyExists => "identity_already_exists",
        IdentityError::KeyNotFound => "key_not_found",
        IdentityError::KeyUnavailable => "key_unavailable",
        IdentityError::KeyPurposeViolation => "key_purpose_violation",
        IdentityError::AmbiguousKey => "ambiguous_key",
        IdentityError::VerificationFailed => "verification_failed",
        IdentityError::PendingDocumentChange => "pending_document_change",
        IdentityError::DocumentChangeNotFound => "document_change_not_found",
        IdentityError::InvalidDocumentChangeState => "invalid_document_change_state",
        IdentityError::Conflict => "conflict",
        IdentityError::CapabilityUnavailable => "capability_unavailable",
        IdentityError::Unsupported => "unsupported_operation",
        IdentityError::Storage => "storage",
        IdentityError::Internal => "internal",
        _ => "internal",
    };
    js_error(code, &error.to_string())
}
