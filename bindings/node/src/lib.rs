use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;

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

#[napi(object)]
pub struct JsProviderLeaseRequest {
    pub consumer: String,
    pub capabilities: Vec<String>,
    pub ttl_seconds: i64,
}

#[napi(object)]
pub struct JsHttpHeader {
    pub name: String,
    pub value: String,
}

#[napi(object)]
pub struct JsExactHttpSigningRequest {
    pub identity: JsIdentityRef,
    pub kid: Option<String>,
    pub url: String,
    pub method: String,
    pub headers: Vec<JsHttpHeader>,
    pub body: Option<Buffer>,
    pub nonce: Option<String>,
    pub created: Option<i64>,
    pub expires: Option<i64>,
    pub covered_components: Option<Vec<String>>,
}

#[napi(object)]
pub struct JsSealedKeyAgreementRequest {
    pub identity: JsIdentityRef,
    pub kid: String,
    pub peer_public: Buffer,
    pub recipient_public_key: Buffer,
    pub request_id: String,
}

#[napi(object)]
pub struct JsSealedRootExportRequest {
    pub identity: JsIdentityRef,
    pub kid: String,
    pub recipient_public_key: Buffer,
    pub request_id: String,
    pub user_presence_confirmed: bool,
}

#[napi(object)]
pub struct JsSealedRootImportPreparation {
    pub identity: JsIdentityRef,
    pub evidence: Value,
    pub encoding: String,
    pub request_id: String,
}

#[napi(object)]
pub struct JsSealedIdentityImportPreparation {
    pub remote: Value,
    pub did_wba: bool,
    pub keys: Value,
    pub request_id: String,
}

#[napi(object)]
pub struct JsSealedProviderAdoptionPreparation {
    pub state_root: String,
    pub target: Value,
    pub request_id: String,
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

#[napi(js_name = "IdentityProvider")]
pub struct JsIdentityProvider {
    manager: Arc<Mutex<CoreIdentityManager>>,
    authorization: Arc<anp_identity::host::ProviderAuthorization>,
}

#[napi]
impl JsIdentityProvider {
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
    pub async fn acquire_lease(&self, request: JsProviderLeaseRequest) -> Result<JsProviderLease> {
        let manager = Arc::clone(&self.manager);
        let authorization = Arc::clone(&self.authorization);
        let store_id = run_blocking(move || {
            manager
                .blocking_lock()
                .info()
                .map(|info| info.store_id)
                .map_err(map_error)
        })
        .await?;
        let lease = self
            .authorization
            .acquire_lease(
                request.consumer,
                request.capabilities,
                store_id,
                request.ttl_seconds,
            )
            .map_err(map_authorization_error)?;
        Ok(JsProviderLease {
            manager: Arc::clone(&self.manager),
            authorization,
            lease: Arc::new(StdMutex::new(Some(lease))),
        })
    }
}

impl JsIdentityProvider {
    fn new(manager: CoreIdentityManager) -> Self {
        Self {
            manager: Arc::new(Mutex::new(manager)),
            authorization: Arc::new(anp_identity::host::ProviderAuthorization::new()),
        }
    }
}

#[napi(js_name = "ProviderLease")]
pub struct JsProviderLease {
    manager: Arc<Mutex<CoreIdentityManager>>,
    authorization: Arc<anp_identity::host::ProviderAuthorization>,
    lease: Arc<StdMutex<Option<anp_identity::host::ProviderCapabilityLease>>>,
}

#[napi]
impl JsProviderLease {
    #[napi]
    pub fn dispose(&self) -> Result<()> {
        let mut slot = self
            .lease
            .lock()
            .map_err(|_| js_error("internal", "provider lease state failed"))?;
        let lease = slot
            .take()
            .ok_or_else(|| js_error("provider_disposed", "provider lease is disposed"))?;
        self.authorization
            .dispose_lease(&lease)
            .map_err(map_authorization_error)
    }

    #[napi]
    pub async fn list(&self) -> Result<Value> {
        self.with_authorized(anp_identity::host::capability::IDENTITY_READ, |manager| {
            to_value(manager.list().map_err(map_error)?)
        })
        .await
    }

    #[napi]
    pub async fn public_identity(&self, identity: JsIdentityRef) -> Result<Value> {
        let reference = identity.into();
        self.with_authorized(
            anp_identity::host::capability::IDENTITY_READ,
            move |manager| {
                to_value(
                    manager
                        .get(&reference)
                        .and_then(|identity| identity.public_identity())
                        .map_err(map_error)?,
                )
            },
        )
        .await
    }

    #[napi]
    pub async fn create(&self, request: Value) -> Result<Value> {
        let request = serde_json::from_value(request).map_err(invalid_json)?;
        self.with_authorized(
            anp_identity::host::capability::IDENTITY_CREATE,
            move |manager| {
                let identity = manager.create(request).map_err(map_error)?;
                to_value(identity.public_identity().map_err(map_error)?)
            },
        )
        .await
    }

    #[napi]
    pub async fn sign(
        &self,
        identity: JsIdentityRef,
        request: JsSignRequest,
    ) -> Result<JsSignature> {
        let reference = identity.into();
        let request = SignRequest {
            purpose: signing_purpose(&request.purpose, request.domain)?,
            key: key_selector(request.kid),
            payload: request.payload.to_vec(),
        };
        self.with_authorized(
            anp_identity::host::capability::IDENTITY_SIGN,
            move |manager| {
                let signature = manager
                    .get(&reference)
                    .and_then(|identity| identity.sign(request))
                    .map_err(map_error)?;
                Ok(JsSignature {
                    kid: signature.kid,
                    algorithm: key_algorithm(signature.algorithm),
                    bytes: signature.bytes.into(),
                })
            },
        )
        .await
    }

    #[napi]
    pub async fn sign_origin_proof(
        &self,
        identity: JsIdentityRef,
        request: JsOriginProofRequest,
    ) -> Result<Value> {
        let reference = identity.into();
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
        self.with_authorized(
            anp_identity::host::capability::IDENTITY_SIGN,
            move |manager| {
                to_value(
                    manager
                        .get(&reference)
                        .and_then(|identity| identity.sign_origin_proof(request))
                        .map_err(map_error)?,
                )
            },
        )
        .await
    }

    #[napi]
    pub async fn prepare_http_signature(
        &self,
        request: JsExactHttpSigningRequest,
    ) -> Result<Value> {
        use anp_identity::host::HttpRequestSigningPort as _;

        let reference = request.identity.into();
        let exact = anp_identity::host::ExactHttpRequest {
            key: key_selector(request.kid),
            url: request.url,
            method: request.method,
            headers: request
                .headers
                .into_iter()
                .map(|header| anp_identity::host::HttpHeader {
                    name: header.name,
                    value: header.value,
                })
                .collect(),
            body: request.body.map(|body| body.to_vec()),
            options: anp_identity::host::HttpRequestSigningOptions {
                nonce: request.nonce,
                created: request.created,
                expires: request.expires,
                covered_components: request.covered_components,
            },
        };
        self.with_authorized(
            anp_identity::host::capability::IDENTITY_HTTP_SIGNATURE,
            move |manager| {
                to_value(
                    manager
                        .get(&reference)
                        .and_then(|identity| identity.prepare_http_signature(exact))
                        .map_err(map_error)?,
                )
            },
        )
        .await
    }

    #[napi]
    pub async fn ecdh_sealed(&self, request: JsSealedKeyAgreementRequest) -> Result<Value> {
        use anp_identity::host::SealedKeyAgreementPort as _;

        let identity: IdentityRef = request.identity.into();
        let peer_public = fixed_public_key(request.peer_public, "peerPublic")?;
        let recipient_public_key =
            fixed_public_key(request.recipient_public_key, "recipientPublicKey")?;
        let binding = anp_identity::host::sealed_key_agreement_binding(
            &identity,
            &request.kid,
            &peer_public,
            &recipient_public_key,
            &request.request_id,
        )
        .map_err(map_sealed_error)?;
        let token = self.issue_one_time(&binding)?;
        let authorization = Arc::clone(&self.authorization);
        self.with_manager(move |manager| {
            let managed = manager.get(&identity).map_err(map_error)?;
            to_value(
                managed
                    .derive_shared_secret_sealed(
                        &authorization,
                        anp_identity::host::SealedKeyAgreementRequest {
                            identity,
                            kid: request.kid,
                            peer_public,
                            recipient_public_key,
                            request_id: request.request_id,
                            token,
                        },
                    )
                    .map_err(map_sealed_error)?,
            )
        })
        .await
    }

    #[napi]
    pub async fn export_root_key_sealed(
        &self,
        request: JsSealedRootExportRequest,
    ) -> Result<Value> {
        use anp_identity::host::SealedRootExportPort as _;

        let identity: IdentityRef = request.identity.into();
        let recipient_public_key =
            fixed_public_key(request.recipient_public_key, "recipientPublicKey")?;
        let binding = anp_identity::host::sealed_root_export_binding(
            &identity,
            &request.kid,
            &recipient_public_key,
            &request.request_id,
            request.user_presence_confirmed,
        )
        .map_err(map_sealed_error)?;
        let token = self.issue_one_time(&binding)?;
        let authorization = Arc::clone(&self.authorization);
        self.with_manager(move |manager| {
            let managed = manager.get(&identity).map_err(map_error)?;
            to_value(
                managed
                    .export_root_key_sealed(
                        &authorization,
                        anp_identity::host::SealedRootExportRequest {
                            identity,
                            kid: request.kid,
                            recipient_public_key,
                            request_id: request.request_id,
                            user_presence_confirmed: request.user_presence_confirmed,
                            token,
                        },
                    )
                    .map_err(map_sealed_error)?,
            )
        })
        .await
    }

    #[napi]
    pub async fn prepare_legacy_root_import(
        &self,
        request: JsSealedRootImportPreparation,
    ) -> Result<JsPreparedRootImport> {
        let identity: IdentityRef = request.identity.into();
        let preparation = anp_identity::host::SealedRootImportPreparation {
            identity: identity.clone(),
            evidence: serde_json::from_value(request.evidence).map_err(invalid_json)?,
            encoding: match request.encoding.as_str() {
                "raw32" => anp_identity::host::RootPrivateKeyEncoding::Raw32,
                "pkcs8_der" => anp_identity::host::RootPrivateKeyEncoding::Pkcs8Der,
                _ => return Err(js_error("invalid_request", "unknown root key encoding")),
            },
            request_id: request.request_id,
        };
        let (prepared, offer) = self.with_lease(|lease| {
            anp_identity::host::PreparedSealedRootImport::prepare(
                &self.authorization,
                lease,
                preparation,
                60,
            )
            .map_err(map_sealed_error)
        })?;
        Ok(JsPreparedRootImport {
            manager: Arc::clone(&self.manager),
            authorization: Arc::clone(&self.authorization),
            identity,
            prepared: Arc::new(StdMutex::new(Some(prepared))),
            offer: Arc::new(StdMutex::new(Some(root_import_offer(offer)?))),
        })
    }

    #[napi]
    pub async fn prepare_identity_material_import(
        &self,
        request: JsSealedIdentityImportPreparation,
    ) -> Result<JsPreparedIdentityMaterialImport> {
        let preparation = anp_identity::host::SealedIdentityMaterialImportPreparation {
            remote: serde_json::from_value(request.remote).map_err(invalid_json)?,
            did_wba: request.did_wba,
            keys: serde_json::from_value(request.keys).map_err(invalid_json)?,
            request_id: request.request_id,
        };
        let manager = Arc::clone(&self.manager);
        let authorization = Arc::clone(&self.authorization);
        let lease = Arc::clone(&self.lease);
        let (prepared, offer) = run_blocking(move || {
            let lease = lease
                .lock()
                .map_err(|_| js_error("internal", "provider lease state failed"))?;
            let lease = lease
                .as_ref()
                .ok_or_else(|| js_error("provider_disposed", "provider lease is disposed"))?;
            anp_identity::host::PreparedSealedIdentityMaterialImport::prepare(
                &manager.blocking_lock(),
                &authorization,
                lease,
                preparation,
                60,
            )
            .map_err(map_sealed_error)
        })
        .await?;
        Ok(JsPreparedIdentityMaterialImport {
            manager: Arc::clone(&self.manager),
            authorization: Arc::clone(&self.authorization),
            prepared: Arc::new(StdMutex::new(Some(prepared))),
            offer: Arc::new(StdMutex::new(Some(identity_import_offer(offer)?))),
        })
    }

    #[napi]
    pub async fn prepare_provider_adoption(
        &self,
        request: JsSealedProviderAdoptionPreparation,
    ) -> Result<JsPreparedProviderAdoption> {
        let preparation = anp_identity::host::SealedProviderAdoptionPreparation {
            state_root: PathBuf::from(request.state_root),
            target: serde_json::from_value(request.target).map_err(invalid_json)?,
            request_id: request.request_id,
        };
        let authorization = Arc::clone(&self.authorization);
        let lease = Arc::clone(&self.lease);
        let (prepared, offer) = run_blocking(move || {
            let lease = lease
                .lock()
                .map_err(|_| js_error("internal", "provider lease state failed"))?;
            let lease = lease
                .as_ref()
                .ok_or_else(|| js_error("provider_disposed", "provider lease is disposed"))?;
            anp_identity::host::PreparedSealedProviderAdoption::prepare(
                &authorization,
                lease,
                preparation,
                60,
            )
            .map_err(map_sealed_error)
        })
        .await?;
        Ok(JsPreparedProviderAdoption {
            authorization: Arc::clone(&self.authorization),
            prepared: Arc::new(StdMutex::new(Some(prepared))),
            offer: Arc::new(StdMutex::new(Some(provider_adoption_offer(offer)?))),
        })
    }
}

#[napi(js_name = "PreparedRootImport")]
pub struct JsPreparedRootImport {
    manager: Arc<Mutex<CoreIdentityManager>>,
    authorization: Arc<anp_identity::host::ProviderAuthorization>,
    identity: IdentityRef,
    prepared: Arc<StdMutex<Option<anp_identity::host::PreparedSealedRootImport>>>,
    offer: Arc<StdMutex<Option<Value>>>,
}

#[napi]
impl JsPreparedRootImport {
    #[napi]
    pub fn offer(&self) -> Result<Value> {
        take_once(&self.offer, "sealed import offer was already read")
    }

    #[napi]
    pub async fn complete(&self, token: String, envelope: Value) -> Result<String> {
        let prepared = take_once(&self.prepared, "sealed root import was already completed")?;
        let envelope = serde_json::from_value(envelope).map_err(invalid_json)?;
        let manager = Arc::clone(&self.manager);
        let authorization = Arc::clone(&self.authorization);
        let identity = self.identity.clone();
        run_blocking(move || {
            let managed = manager.blocking_lock().get(&identity).map_err(map_error)?;
            let mut managed = managed;
            prepared
                .complete(
                    &mut managed,
                    &authorization,
                    anp_identity::host::OneTimeCapabilityToken::from_encoded(token),
                    &envelope,
                )
                .map(|outcome| match outcome {
                    anp_identity::host::LegacyRootImportOutcome::Pending => "pending".to_owned(),
                    anp_identity::host::LegacyRootImportOutcome::Active => "active".to_owned(),
                })
                .map_err(map_sealed_error)
        })
        .await
    }
}

#[napi(js_name = "PreparedIdentityMaterialImport")]
pub struct JsPreparedIdentityMaterialImport {
    manager: Arc<Mutex<CoreIdentityManager>>,
    authorization: Arc<anp_identity::host::ProviderAuthorization>,
    prepared: Arc<StdMutex<Option<anp_identity::host::PreparedSealedIdentityMaterialImport>>>,
    offer: Arc<StdMutex<Option<Value>>>,
}

#[napi]
impl JsPreparedIdentityMaterialImport {
    #[napi]
    pub fn offer(&self) -> Result<Value> {
        take_once(&self.offer, "sealed import offer was already read")
    }

    #[napi]
    pub async fn complete(&self, token: String, envelopes: Value) -> Result<Value> {
        let prepared = take_once(
            &self.prepared,
            "sealed identity import was already completed",
        )?;
        let envelopes: Vec<anp_identity::host::SealedSecretEnvelope> =
            serde_json::from_value(envelopes).map_err(invalid_json)?;
        let manager = Arc::clone(&self.manager);
        let authorization = Arc::clone(&self.authorization);
        run_blocking(move || {
            let identity = prepared
                .complete(
                    &mut manager.blocking_lock(),
                    &authorization,
                    anp_identity::host::OneTimeCapabilityToken::from_encoded(token),
                    &envelopes,
                )
                .map_err(map_sealed_error)?;
            to_value(identity.public_identity().map_err(map_error)?)
        })
        .await
    }
}

#[napi(js_name = "PreparedProviderAdoption")]
pub struct JsPreparedProviderAdoption {
    authorization: Arc<anp_identity::host::ProviderAuthorization>,
    prepared: Arc<StdMutex<Option<anp_identity::host::PreparedSealedProviderAdoption>>>,
    offer: Arc<StdMutex<Option<Value>>>,
}

#[napi]
impl JsPreparedProviderAdoption {
    #[napi]
    pub fn offer(&self) -> Result<Value> {
        take_once(&self.offer, "sealed adoption offer was already read")
    }

    #[napi]
    pub async fn complete(&self, token: String, envelope: Value) -> Result<Value> {
        let prepared = take_once(&self.prepared, "sealed adoption was already completed")?;
        let envelope = serde_json::from_value(envelope).map_err(invalid_json)?;
        let authorization = Arc::clone(&self.authorization);
        run_blocking(move || {
            to_value(
                prepared
                    .complete(
                        &authorization,
                        anp_identity::host::OneTimeCapabilityToken::from_encoded(token),
                        &envelope,
                    )
                    .map_err(map_sealed_error)?,
            )
        })
        .await
    }
}

impl JsProviderLease {
    fn with_lease<T>(
        &self,
        operation: impl FnOnce(&anp_identity::host::ProviderCapabilityLease) -> Result<T>,
    ) -> Result<T> {
        let slot = self
            .lease
            .lock()
            .map_err(|_| js_error("internal", "provider lease state failed"))?;
        let lease = slot
            .as_ref()
            .ok_or_else(|| js_error("provider_disposed", "provider lease is disposed"))?;
        operation(lease)
    }

    fn issue_one_time(
        &self,
        binding: &anp_identity::host::OneTimeOperationBinding,
    ) -> Result<anp_identity::host::OneTimeCapabilityToken> {
        self.with_lease(|lease| {
            self.authorization
                .issue_one_time(lease, binding, 60)
                .map_err(map_authorization_error)
        })
    }

    async fn with_authorized<T, F>(&self, capability: &'static str, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut CoreIdentityManager) -> Result<T> + Send + 'static,
    {
        self.with_lease(|lease| {
            self.authorization
                .authorize(lease, capability)
                .map_err(map_authorization_error)
        })?;
        self.with_manager(operation).await
    }

    async fn with_manager<T, F>(&self, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut CoreIdentityManager) -> Result<T> + Send + 'static,
    {
        let manager = Arc::clone(&self.manager);
        run_blocking(move || operation(&mut manager.blocking_lock())).await
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

fn take_once<T>(slot: &StdMutex<Option<T>>, message: &str) -> Result<T> {
    slot.lock()
        .map_err(|_| js_error("internal", "one-time operation state failed"))?
        .take()
        .ok_or_else(|| js_error("token_consumed", message))
}

fn root_import_offer(offer: anp_identity::host::SealedImportOffer) -> Result<Value> {
    Ok(serde_json::json!({
        "recipient_public_key": offer.recipient_public_key,
        "request_id": offer.request_id,
        "token": offer.token.into_encoded(),
        "authorization": to_value(offer.authorization)?,
        "aad_b64u": offer.aad_b64u,
    }))
}

fn identity_import_offer(
    offer: anp_identity::host::SealedIdentityMaterialImportOffer,
) -> Result<Value> {
    Ok(serde_json::json!({
        "target": offer.target,
        "recipient_public_key": offer.recipient_public_key,
        "request_id": offer.request_id,
        "token": offer.token.into_encoded(),
        "authorization": to_value(offer.authorization)?,
        "item_aad_b64u": offer.item_aad_b64u,
    }))
}

fn provider_adoption_offer(
    offer: anp_identity::host::SealedProviderAdoptionOffer,
) -> Result<Value> {
    Ok(serde_json::json!({
        "store_id": offer.store_id,
        "root_key_fingerprint": offer.root_key_fingerprint,
        "recipient_public_key": offer.recipient_public_key,
        "request_id": offer.request_id,
        "token": offer.token.into_encoded(),
        "authorization": to_value(offer.authorization)?,
        "aad_b64u": offer.aad_b64u,
    }))
}

fn fixed_public_key(buffer: Buffer, field: &str) -> Result<[u8; 32]> {
    buffer
        .as_ref()
        .try_into()
        .map_err(|_| js_error("invalid_request", &format!("{field} must contain 32 bytes")))
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

fn map_authorization_error(error: anp_identity::host::ProviderAuthorizationError) -> napi::Error {
    let code = match error {
        anp_identity::host::ProviderAuthorizationError::CapabilityDenied => "capability_denied",
        anp_identity::host::ProviderAuthorizationError::LeaseInvalid => "provider_disposed",
        anp_identity::host::ProviderAuthorizationError::TokenExpired => "token_expired",
        anp_identity::host::ProviderAuthorizationError::TokenConsumed => "token_consumed",
        anp_identity::host::ProviderAuthorizationError::TokenInvalid => "token_invalid",
        anp_identity::host::ProviderAuthorizationError::Internal => "internal",
    };
    js_error(code, &error.to_string())
}

fn map_sealed_error(error: anp_identity::host::SealedProviderError) -> napi::Error {
    let code = match error {
        anp_identity::host::SealedProviderError::Authorization => "capability_denied",
        anp_identity::host::SealedProviderError::IdentityBinding
        | anp_identity::host::SealedProviderError::InvalidRequest => "invalid_request",
        anp_identity::host::SealedProviderError::Identity => "identity_unavailable",
        anp_identity::host::SealedProviderError::EnvelopeInvalid => "sealed_envelope_invalid",
    };
    js_error(code, &error.to_string())
}
