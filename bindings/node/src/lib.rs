use std::collections::BTreeMap;
use std::sync::Arc;

use anp_identity::{
    Capabilities, DeviceAddSpec, DeviceManifestEntrySpec, DeviceManifestSpec, DeviceMutationSpec,
    DevicePublicKeySpec, DidCreateSpec, DidError, DidExtensionSpec, DidIdentity as CoreDidIdentity,
    DidProfile, DidStore as CoreDidStore, DocumentUpdateSpec, ExternalPublicKeyMaterial,
    ExternalPublicKeySpec, HttpSignatureOptions, KeyMetadata, KeyRole, ManagedKeySpec,
    PublicOkpJwk, PublicationState, RequestSigningRotation, RootKeyProviderKind, ServiceSpec,
    StoreManifest,
};
use napi::bindgen_prelude::Buffer;
use napi::Status;
use napi_derive::napi;
use serde_json::Value;
use tokio::sync::Mutex;
use zeroize::{Zeroize, Zeroizing};

type Result<T> = napi::Result<T>;

#[napi(object)]
pub struct JsCapabilities {
    pub did_wba: bool,
}

#[napi(object)]
pub struct JsManagedKeySpec {
    pub fragment: String,
    pub role: String,
}

#[napi(object)]
pub struct JsExternalPublicKeyMaterial {
    pub format: String,
    pub value: Option<String>,
    pub public_key_jwk: Option<Value>,
}

#[napi(object)]
pub struct JsExternalPublicKeySpec {
    pub kid: String,
    pub role: String,
    pub material: JsExternalPublicKeyMaterial,
}

#[napi(object)]
pub struct JsServiceSpec {
    pub id: String,
    pub service_type: String,
    pub service_endpoint: String,
    pub profiles: Vec<String>,
    pub security_profiles: Vec<String>,
}

#[napi(object)]
pub struct JsDeviceManifestEntrySpec {
    pub device_id: String,
    pub signing_key_id: String,
    #[napi(js_name = "e2eeKeyId")]
    pub e2ee_key_id: String,
    pub profiles: Vec<String>,
}

#[napi(object)]
pub struct JsDeviceManifestSpec {
    pub devices: Vec<JsDeviceManifestEntrySpec>,
}

#[napi(object)]
pub struct JsDidExtensionSpec {
    pub extension_type: String,
    pub device_manifest: Option<JsDeviceManifestSpec>,
}

#[napi(object)]
pub struct JsDidCreateSpec {
    pub profile: String,
    pub domain: String,
    pub port: Option<u16>,
    pub path_segments: Vec<String>,
    pub capabilities: JsCapabilities,
    pub managed_keys: Vec<JsManagedKeySpec>,
    pub external_keys: Vec<JsExternalPublicKeySpec>,
    pub services: Vec<JsServiceSpec>,
    pub agent_description_url: Option<String>,
    pub extensions: Vec<JsDidExtensionSpec>,
}

#[napi(object)]
pub struct JsIdentitySummary {
    pub identity_id: String,
    pub did: String,
    pub state: String,
    pub root_capability: String,
    pub created_at: String,
}

#[napi(object)]
pub struct JsDocumentCheckpoint {
    pub document_version: i64,
    pub registry_version: i64,
    pub document_digest: String,
}

#[napi(object)]
pub struct JsKeyMetadata {
    pub kid: String,
    pub role: String,
    pub origin: String,
    pub state: String,
    pub material_erased: bool,
    pub version: u32,
    pub public_key_multibase: String,
    pub created_at: String,
}

#[napi(object)]
pub struct JsRootKeyProviderBinding {
    pub kind: String,
    pub key_id: String,
    pub account: Option<String>,
}

#[napi(object)]
pub struct JsStoreManifest {
    pub schema_version: u32,
    pub store_id: String,
    pub generation: i64,
    pub provider: JsRootKeyProviderBinding,
    pub root_key_fingerprint: String,
    pub created_at: String,
    pub rekey_generation: i64,
}

#[napi(object)]
pub struct JsIdentitySnapshot {
    pub identity_id: String,
    pub did: String,
    pub state: String,
    pub revision: i64,
    pub root_capability: String,
    pub root_key_fingerprint: String,
    pub checkpoint: Option<JsDocumentCheckpoint>,
    pub document: Value,
    pub capabilities: JsCapabilities,
    pub keys: Vec<JsKeyMetadata>,
}

#[napi(object)]
pub struct JsRequestSigningRotation {
    pub old_kid: String,
    pub new_fragment: String,
}

#[napi(object)]
pub struct JsDevicePublicKeySpec {
    pub kid: String,
    pub public_key_multibase: String,
}

#[napi(object)]
pub struct JsDeviceAddSpec {
    pub device_id: String,
    pub signing_key: JsDevicePublicKeySpec,
    #[napi(js_name = "e2eeKey")]
    pub e2ee_key: JsDevicePublicKeySpec,
    pub profiles: Vec<String>,
}

#[napi(object)]
pub struct JsDeviceMutationSpec {
    pub operation: String,
    pub device: Option<JsDeviceAddSpec>,
    pub device_id: Option<String>,
}

#[napi(object)]
pub struct JsDocumentUpdateSpec {
    pub request_signing_rotation: Option<JsRequestSigningRotation>,
    pub device_mutations: Option<Vec<JsDeviceMutationSpec>>,
    pub services: Option<Vec<JsServiceSpec>>,
}

#[napi(object)]
pub struct JsPreparedUpdate {
    pub revision_id: String,
    pub candidate_document: Value,
    pub candidate_digest: String,
}

#[napi(object)]
pub struct JsPendingRevisionSummary {
    pub revision_id: String,
    pub parent_revision: i64,
    pub candidate_digest: String,
    pub candidate_kids: Vec<String>,
    pub state: String,
    pub generation: i64,
    pub created_at: String,
}

#[napi(object)]
pub struct JsHeader {
    pub name: String,
    pub value: String,
}

#[napi(object)]
pub struct JsHttpSignatureOptions {
    pub nonce: Option<String>,
    pub created: Option<i64>,
    pub expires: Option<i64>,
    pub covered_components: Option<Vec<String>>,
}

#[napi(js_name = "DidStore")]
pub struct JsDidStore {
    inner: Arc<Mutex<CoreDidStore>>,
}

#[napi]
impl JsDidStore {
    #[napi(factory)]
    pub async fn initialize_injected(
        root: String,
        key_id: String,
        root_key: Buffer,
    ) -> Result<Self> {
        let root_key = consume_root_key(root_key)?;
        let store = run_blocking(move || {
            CoreDidStore::initialize_injected(root, key_id, *root_key).map_err(map_error)
        })
        .await?;
        Ok(Self {
            inner: Arc::new(Mutex::new(store)),
        })
    }

    #[napi(factory)]
    pub async fn open_injected(root: String, key_id: String, root_key: Buffer) -> Result<Self> {
        let root_key = consume_root_key(root_key)?;
        let store = run_blocking(move || {
            CoreDidStore::open_injected(root, key_id, *root_key).map_err(map_error)
        })
        .await?;
        Ok(Self {
            inner: Arc::new(Mutex::new(store)),
        })
    }

    #[napi(factory)]
    pub async fn initialize_env(root: String, key_id: String, env_var: String) -> Result<Self> {
        let store = run_blocking(move || {
            CoreDidStore::initialize_env(root, key_id, &env_var).map_err(map_error)
        })
        .await?;
        Ok(Self {
            inner: Arc::new(Mutex::new(store)),
        })
    }

    #[napi(factory)]
    pub async fn open_env(root: String, key_id: String, env_var: String) -> Result<Self> {
        let store =
            run_blocking(move || CoreDidStore::open_env(root, key_id, &env_var).map_err(map_error))
                .await?;
        Ok(Self {
            inner: Arc::new(Mutex::new(store)),
        })
    }

    #[napi(factory)]
    pub async fn initialize_local_file(root: String) -> Result<Self> {
        let store =
            run_blocking(move || CoreDidStore::initialize_local_file(root).map_err(map_error))
                .await?;
        Ok(Self {
            inner: Arc::new(Mutex::new(store)),
        })
    }

    #[napi(factory)]
    pub async fn open_local_file(root: String) -> Result<Self> {
        let store =
            run_blocking(move || CoreDidStore::open_local_file(root).map_err(map_error)).await?;
        Ok(Self {
            inner: Arc::new(Mutex::new(store)),
        })
    }

    #[napi(factory)]
    pub async fn initialize_keyring(
        root: String,
        service: String,
        account: String,
        fallback_to_local_file: bool,
    ) -> Result<Self> {
        let store = run_blocking(move || {
            CoreDidStore::initialize_keyring(root, service, account, fallback_to_local_file)
                .map_err(map_error)
        })
        .await?;
        Ok(Self {
            inner: Arc::new(Mutex::new(store)),
        })
    }

    #[napi(factory)]
    pub async fn open_keyring(root: String, service: String, account: String) -> Result<Self> {
        let store = run_blocking(move || {
            CoreDidStore::open_keyring(root, service, account).map_err(map_error)
        })
        .await?;
        Ok(Self {
            inner: Arc::new(Mutex::new(store)),
        })
    }

    #[napi]
    pub async fn generation(&self) -> Result<i64> {
        i64::try_from(self.inner.lock().await.generation()).map_err(|_| overflow_error())
    }

    #[napi]
    pub async fn manifest(&self) -> Result<JsStoreManifest> {
        store_manifest(self.inner.lock().await.manifest())
    }

    #[napi]
    pub async fn reload(&self) -> Result<()> {
        self.with_store(|store| store.reload().map_err(map_error))
            .await
    }

    #[napi]
    pub async fn list_identities(&self) -> Result<Vec<JsIdentitySummary>> {
        self.with_store(|store| {
            store
                .list_identities()
                .map(|values| values.into_iter().map(identity_summary).collect())
                .map_err(map_error)
        })
        .await
    }

    #[napi]
    pub async fn create_identity(&self, spec: JsDidCreateSpec) -> Result<JsDidIdentity> {
        let spec = did_create_spec(spec)?;
        let identity = self
            .with_store(move |store| store.create_identity(spec).map_err(map_error))
            .await?;
        Ok(JsDidIdentity::new(identity))
    }

    #[napi]
    pub async fn open_identity(&self, did: String) -> Result<JsDidIdentity> {
        let identity = self
            .with_store(move |store| store.open_identity(&did).map_err(map_error))
            .await?;
        Ok(JsDidIdentity::new(identity))
    }
}

impl JsDidStore {
    async fn with_store<T, F>(&self, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut CoreDidStore) -> Result<T> + Send + 'static,
    {
        let inner = Arc::clone(&self.inner);
        run_blocking(move || operation(&mut inner.blocking_lock())).await
    }
}

#[napi(js_name = "DidIdentity")]
pub struct JsDidIdentity {
    inner: Arc<Mutex<CoreDidIdentity>>,
}

impl JsDidIdentity {
    fn new(identity: CoreDidIdentity) -> Self {
        Self {
            inner: Arc::new(Mutex::new(identity)),
        }
    }

    async fn with_identity<T, F>(&self, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut CoreDidIdentity) -> Result<T> + Send + 'static,
    {
        let inner = Arc::clone(&self.inner);
        run_blocking(move || operation(&mut inner.blocking_lock())).await
    }
}

#[napi]
impl JsDidIdentity {
    #[napi]
    pub async fn reload(&self) -> Result<()> {
        self.with_identity(|identity| identity.reload().map_err(map_error))
            .await
    }

    #[napi]
    pub async fn snapshot(&self) -> Result<JsIdentitySnapshot> {
        let identity = self.inner.lock().await;
        Ok(JsIdentitySnapshot {
            identity_id: identity.identity_id().to_string(),
            did: identity.did().to_string(),
            state: identity_state(identity.state()),
            revision: i64::try_from(identity.revision()).map_err(|_| overflow_error())?,
            root_capability: root_capability(identity.root_capability()),
            root_key_fingerprint: identity.root_key_fingerprint().to_string(),
            checkpoint: identity
                .checkpoint()
                .map(|checkpoint| -> Result<JsDocumentCheckpoint> {
                    Ok(JsDocumentCheckpoint {
                        document_version: i64::try_from(checkpoint.document_version)
                            .map_err(|_| overflow_error())?,
                        registry_version: i64::try_from(checkpoint.registry_version)
                            .map_err(|_| overflow_error())?,
                        document_digest: checkpoint.document_digest.clone(),
                    })
                })
                .transpose()?,
            document: identity.document().clone(),
            capabilities: JsCapabilities {
                did_wba: identity.capabilities().did_wba,
            },
            keys: identity.keys().iter().cloned().map(key_metadata).collect(),
        })
    }

    #[napi]
    pub async fn pending_revision(&self) -> Result<Option<JsPendingRevisionSummary>> {
        let identity = self.inner.lock().await;
        identity
            .pending_revision()
            .map(|pending| {
                Ok(JsPendingRevisionSummary {
                    revision_id: pending.revision_id,
                    parent_revision: i64::try_from(pending.parent_revision)
                        .map_err(|_| overflow_error())?,
                    candidate_digest: pending.candidate_digest,
                    candidate_kids: pending.candidate_kids,
                    state: publication_state(pending.state),
                    generation: i64::try_from(pending.generation).map_err(|_| overflow_error())?,
                    created_at: pending.created_at,
                })
            })
            .transpose()
    }

    #[napi]
    pub async fn sign(&self, kid: String, message: Buffer) -> Result<Buffer> {
        let message = message.to_vec();
        self.with_identity(move |identity| {
            identity
                .sign(&kid, &message)
                .map(Buffer::from)
                .map_err(map_error)
        })
        .await
    }

    #[napi]
    pub async fn verify(&self, kid: String, message: Buffer, signature: Buffer) -> Result<bool> {
        let message = message.to_vec();
        let signature = signature.to_vec();
        self.with_identity(
            move |identity| match identity.verify(&kid, &message, &signature) {
                Ok(()) => Ok(true),
                Err(DidError::VerificationFailed) => Ok(false),
                Err(error) => Err(map_error(error)),
            },
        )
        .await
    }

    #[napi]
    pub async fn ecdh(&self, kid: String, peer_public: Buffer) -> Result<Buffer> {
        let peer_public = peer_public.to_vec();
        self.with_identity(move |identity| {
            identity
                .ecdh(&kid, &peer_public)
                .map(|secret| Buffer::from(secret.as_bytes().to_vec()))
                .map_err(map_error)
        })
        .await
    }

    #[napi]
    pub async fn public_key_bytes(&self, kid: String) -> Result<Buffer> {
        self.inner
            .lock()
            .await
            .public_key_bytes(&kid)
            .map(Buffer::from)
            .map_err(map_error)
    }

    #[napi]
    pub async fn legacy_did_wba_header(
        &self,
        kid: String,
        service_domain: String,
        version: String,
    ) -> Result<String> {
        self.with_identity(move |identity| {
            identity
                .legacy_did_wba_header(&kid, &service_domain, &version)
                .map_err(map_error)
        })
        .await
    }

    #[napi]
    pub async fn http_signature_headers(
        &self,
        kid: String,
        request_url: String,
        request_method: String,
        headers: Option<Vec<JsHeader>>,
        body: Option<Buffer>,
        options: Option<JsHttpSignatureOptions>,
    ) -> Result<Vec<JsHeader>> {
        let headers = headers.map(|headers| {
            headers
                .into_iter()
                .map(|header| (header.name, header.value))
                .collect::<BTreeMap<_, _>>()
        });
        let body = body.map(|body| body.to_vec());
        self.with_identity(move |identity| {
            identity
                .http_signature_headers_with_options(
                    &kid,
                    &request_url,
                    &request_method,
                    headers.as_ref(),
                    body.as_deref(),
                    options
                        .map(|options| HttpSignatureOptions {
                            keyid: None,
                            nonce: options.nonce,
                            created: options.created,
                            expires: options.expires,
                            covered_components: options.covered_components,
                        })
                        .unwrap_or_default(),
                )
                .map(|headers| {
                    headers
                        .into_iter()
                        .map(|(name, value)| JsHeader { name, value })
                        .collect()
                })
                .map_err(map_error)
        })
        .await
    }

    #[napi]
    pub async fn prepare_update(&self, spec: JsDocumentUpdateSpec) -> Result<JsPreparedUpdate> {
        let spec = document_update_spec(spec)?;
        let prepared = self
            .with_identity(move |identity| identity.prepare_update(spec).map_err(map_error))
            .await?;
        Ok(JsPreparedUpdate {
            revision_id: prepared.revision_id,
            candidate_document: prepared.candidate_document,
            candidate_digest: prepared.candidate_digest,
        })
    }

    #[napi]
    pub async fn begin_publication(&self, revision_id: String) -> Result<()> {
        self.with_identity(move |identity| {
            identity.begin_publication(&revision_id).map_err(map_error)
        })
        .await
    }

    #[napi]
    pub async fn mark_publication_uncertain(&self, revision_id: String) -> Result<()> {
        self.with_identity(move |identity| {
            identity
                .mark_publication_uncertain(&revision_id)
                .map_err(map_error)
        })
        .await
    }

    #[napi]
    pub async fn mark_published(&self, revision_id: String) -> Result<()> {
        self.with_identity(move |identity| identity.mark_published(&revision_id).map_err(map_error))
            .await
    }

    #[napi]
    pub async fn commit_update(&self, revision_id: String) -> Result<()> {
        self.with_identity(move |identity| identity.commit_update(&revision_id).map_err(map_error))
            .await
    }

    #[napi]
    pub async fn abort_update(&self, revision_id: String) -> Result<()> {
        self.with_identity(move |identity| identity.abort_update(&revision_id).map_err(map_error))
            .await
    }

    #[napi]
    pub async fn reconcile_update(
        &self,
        revision_id: String,
        observed_remote_document: Value,
    ) -> Result<String> {
        self.with_identity(move |identity| {
            identity
                .reconcile_update(&revision_id, &observed_remote_document)
                .map(|outcome| match outcome {
                    anp_identity::ReconcileOutcome::RemoteOld => "remote_old".to_string(),
                    anp_identity::ReconcileOutcome::Committed => "committed".to_string(),
                })
                .map_err(map_error)
        })
        .await
    }

    #[napi]
    pub async fn end_retirement(&self, kid: String) -> Result<()> {
        self.with_identity(move |identity| identity.end_retirement(&kid).map_err(map_error))
            .await
    }

    #[napi]
    pub async fn delete_revoked_key(&self, kid: String) -> Result<()> {
        self.with_identity(move |identity| identity.delete_revoked_key(&kid).map_err(map_error))
            .await
    }
}

fn did_create_spec(spec: JsDidCreateSpec) -> Result<DidCreateSpec> {
    if spec.profile != "e1" {
        return Err(js_error("unsupported_profile", "only E1 is supported"));
    }
    Ok(DidCreateSpec {
        profile: DidProfile::E1,
        domain: spec.domain,
        port: spec.port,
        path_segments: spec.path_segments,
        capabilities: Capabilities {
            did_wba: spec.capabilities.did_wba,
        },
        managed_keys: spec
            .managed_keys
            .into_iter()
            .map(|key| {
                Ok(ManagedKeySpec {
                    fragment: key.fragment,
                    role: key_role(&key.role)?,
                })
            })
            .collect::<Result<Vec<_>>>()?,
        external_keys: spec
            .external_keys
            .into_iter()
            .map(external_key)
            .collect::<Result<Vec<_>>>()?,
        services: spec.services.into_iter().map(service_spec).collect(),
        agent_description_url: spec.agent_description_url,
        extensions: spec
            .extensions
            .into_iter()
            .map(extension_spec)
            .collect::<Result<Vec<_>>>()?,
    })
}

fn external_key(key: JsExternalPublicKeySpec) -> Result<ExternalPublicKeySpec> {
    let material = match key.material.format.as_str() {
        "multibase" => ExternalPublicKeyMaterial::Multibase {
            value: key
                .material
                .value
                .ok_or_else(|| js_error("invalid_public_key", "multibase value is required"))?,
        },
        "jwk" => {
            let value = key
                .material
                .public_key_jwk
                .ok_or_else(|| js_error("invalid_public_key", "publicKeyJwk JSON is required"))?;
            ExternalPublicKeyMaterial::Jwk {
                public_key_jwk: serde_json::from_value::<PublicOkpJwk>(value).map_err(|_| {
                    js_error(
                        "invalid_public_key",
                        "publicKeyJwk must contain public OKP fields only",
                    )
                })?,
            }
        }
        _ => {
            return Err(js_error(
                "invalid_public_key",
                "key format must be multibase or jwk",
            ));
        }
    };
    Ok(ExternalPublicKeySpec {
        kid: key.kid,
        role: key_role(&key.role)?,
        material,
    })
}

fn extension_spec(extension: JsDidExtensionSpec) -> Result<DidExtensionSpec> {
    match extension.extension_type.as_str() {
        "device_manifest" => {
            let manifest = extension
                .device_manifest
                .ok_or_else(|| js_error("invalid_extension", "deviceManifest value is required"))?;
            Ok(DidExtensionSpec::DeviceManifest(DeviceManifestSpec {
                devices: manifest
                    .devices
                    .into_iter()
                    .map(|device| DeviceManifestEntrySpec {
                        device_id: device.device_id,
                        signing_key_id: device.signing_key_id,
                        e2ee_key_id: device.e2ee_key_id,
                        profiles: device.profiles,
                    })
                    .collect(),
            }))
        }
        _ => Err(js_error("invalid_extension", "unknown typed extension")),
    }
}

fn document_update_spec(spec: JsDocumentUpdateSpec) -> Result<DocumentUpdateSpec> {
    Ok(DocumentUpdateSpec {
        request_signing_rotation: spec.request_signing_rotation.map(|rotation| {
            RequestSigningRotation {
                old_kid: rotation.old_kid,
                new_fragment: rotation.new_fragment,
            }
        }),
        device_mutations: spec
            .device_mutations
            .unwrap_or_default()
            .into_iter()
            .map(device_mutation_spec)
            .collect::<Result<Vec<_>>>()?,
        services: spec
            .services
            .map(|services| services.into_iter().map(service_spec).collect()),
    })
}

fn device_mutation_spec(spec: JsDeviceMutationSpec) -> Result<DeviceMutationSpec> {
    match spec.operation.as_str() {
        "add" => {
            let device = spec
                .device
                .ok_or_else(|| js_error("invalid_extension", "device add value is required"))?;
            Ok(DeviceMutationSpec::Add {
                device: DeviceAddSpec {
                    device_id: device.device_id,
                    signing_key: DevicePublicKeySpec {
                        kid: device.signing_key.kid,
                        public_key_multibase: device.signing_key.public_key_multibase,
                    },
                    e2ee_key: DevicePublicKeySpec {
                        kid: device.e2ee_key.kid,
                        public_key_multibase: device.e2ee_key.public_key_multibase,
                    },
                    profiles: device.profiles,
                },
            })
        }
        "remove" => Ok(DeviceMutationSpec::Remove {
            device_id: spec
                .device_id
                .ok_or_else(|| js_error("invalid_extension", "device remove id is required"))?,
        }),
        _ => Err(js_error("invalid_extension", "unknown device mutation")),
    }
}

fn service_spec(service: JsServiceSpec) -> ServiceSpec {
    ServiceSpec {
        id: service.id,
        service_type: service.service_type,
        service_endpoint: service.service_endpoint,
        profiles: service.profiles,
        security_profiles: service.security_profiles,
    }
}

fn key_role(value: &str) -> Result<KeyRole> {
    match value {
        "root_control" => Ok(KeyRole::RootControl),
        "device_signing" => Ok(KeyRole::DeviceSigning),
        "request_signing" => Ok(KeyRole::RequestSigning),
        "e2ee_signing" => Ok(KeyRole::E2eeSigning),
        "e2ee_agreement" => Ok(KeyRole::E2eeAgreement),
        _ => Err(js_error("invalid_key_role", "unknown E1 key role")),
    }
}

fn identity_summary(summary: anp_identity::IdentitySummary) -> JsIdentitySummary {
    JsIdentitySummary {
        identity_id: summary.identity_id,
        did: summary.did,
        state: identity_state(summary.state),
        root_capability: root_capability(summary.root_capability),
        created_at: summary.created_at,
    }
}

fn key_metadata(metadata: KeyMetadata) -> JsKeyMetadata {
    JsKeyMetadata {
        kid: metadata.kid,
        role: key_role_name(metadata.role),
        origin: match metadata.origin {
            anp_identity::KeyOrigin::Managed => "managed".to_string(),
            anp_identity::KeyOrigin::External => "external".to_string(),
        },
        state: match metadata.state {
            anp_identity::KeyState::Pending => "pending".to_string(),
            anp_identity::KeyState::Active => "active".to_string(),
            anp_identity::KeyState::Retired => "retired".to_string(),
            anp_identity::KeyState::Revoked => "revoked".to_string(),
        },
        material_erased: metadata.material_erased,
        version: metadata.version,
        public_key_multibase: metadata.public_key_multibase,
        created_at: metadata.created_at,
    }
}

fn store_manifest(manifest: &StoreManifest) -> Result<JsStoreManifest> {
    Ok(JsStoreManifest {
        schema_version: manifest.schema_version,
        store_id: manifest.store_id.clone(),
        generation: i64::try_from(manifest.generation).map_err(|_| overflow_error())?,
        provider: JsRootKeyProviderBinding {
            kind: match manifest.provider.kind {
                RootKeyProviderKind::OsKeyring => "os_keyring",
                RootKeyProviderKind::Injected => "injected",
                RootKeyProviderKind::LocalPrivateFile => "local_private_file",
            }
            .to_string(),
            key_id: manifest.provider.key_id.clone(),
            account: manifest.provider.account.clone(),
        },
        root_key_fingerprint: manifest.root_key_fingerprint.clone(),
        created_at: manifest.created_at.clone(),
        rekey_generation: i64::try_from(manifest.rekey_generation).map_err(|_| overflow_error())?,
    })
}

fn key_role_name(role: KeyRole) -> String {
    match role {
        KeyRole::RootControl => "root_control",
        KeyRole::DeviceSigning => "device_signing",
        KeyRole::RequestSigning => "request_signing",
        KeyRole::E2eeSigning => "e2ee_signing",
        KeyRole::E2eeAgreement => "e2ee_agreement",
    }
    .to_string()
}

fn identity_state(state: anp_identity::IdentityState) -> String {
    match state {
        anp_identity::IdentityState::Creating => "creating",
        anp_identity::IdentityState::Enrolling => "enrolling",
        anp_identity::IdentityState::Active => "active",
        anp_identity::IdentityState::Revoked => "revoked",
    }
    .to_string()
}

fn root_capability(state: anp_identity::RootCapabilityState) -> String {
    match state {
        anp_identity::RootCapabilityState::Absent => "absent",
        anp_identity::RootCapabilityState::Pending => "pending",
        anp_identity::RootCapabilityState::Active => "active",
    }
    .to_string()
}

fn publication_state(state: PublicationState) -> String {
    match state {
        PublicationState::Prepared => "prepared",
        PublicationState::PublicationInFlight => "publication_in_flight",
        PublicationState::PublicationUncertain => "publication_uncertain",
        PublicationState::Published => "published",
    }
    .to_string()
}

fn consume_root_key(mut buffer: Buffer) -> Result<Zeroizing<[u8; 32]>> {
    if buffer.len() != 32 {
        buffer.as_mut().zeroize();
        return Err(js_error(
            "invalid_root_key",
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

fn overflow_error() -> napi::Error {
    js_error(
        "integer_overflow",
        "integer cannot be represented by Node binding",
    )
}

fn js_error(code: &str, message: &str) -> napi::Error {
    napi::Error::new(
        Status::GenericFailure,
        format!("ANP_IDENTITY_CODE:{code}:{message}"),
    )
}

fn map_error(error: DidError) -> napi::Error {
    let code = match &error {
        DidError::InvalidDomain => "invalid_domain",
        DidError::EmptyPath => "empty_path",
        DidError::InvalidPathSegment => "invalid_path_segment",
        DidError::InvalidKidFragment => "invalid_kid_fragment",
        DidError::InvalidManagedRootCount => "invalid_managed_root_count",
        DidError::ExternalRootControl => "external_root_control",
        DidError::MissingManagedRequestSigning => "missing_managed_request_signing",
        DidError::ForeignKid => "foreign_kid",
        DidError::DuplicateKid => "duplicate_kid",
        DidError::InvalidPublicKey => "invalid_public_key",
        DidError::InvalidService => "invalid_service",
        DidError::InvalidExtension => "invalid_extension",
        DidError::StoreNotFound => "store_not_found",
        DidError::ProviderUnavailable => "provider_unavailable",
        DidError::RootKeyMismatch => "root_key_mismatch",
        DidError::CorruptRecord => "corrupt_record",
        DidError::SecretNotFound => "secret_not_found",
        DidError::IdentityNotFound => "identity_not_found",
        DidError::DuplicateIdentity => "duplicate_identity",
        DidError::KeyNotFound => "key_not_found",
        DidError::ExternalKeyOperation => "external_key_operation",
        DidError::KeyRoleViolation => "key_role_violation",
        DidError::KeyNotUsable => "key_not_usable",
        DidError::KeyMaterialErased => "key_material_erased",
        DidError::InvalidPeerKey => "invalid_peer_key",
        DidError::VerificationFailed => "verification_failed",
        DidError::PendingRevisionExists => "pending_revision_exists",
        DidError::PendingRevisionNotFound => "pending_revision_not_found",
        DidError::InvalidPublicationState => "invalid_publication_state",
        DidError::InvalidIdentity => "invalid_identity",
        DidError::Conflict => "conflict",
        DidError::Io(_) => "io",
        DidError::Serialization(_) => "serialization",
        DidError::Crypto => "crypto",
        DidError::UnsupportedOperation => "unsupported_operation",
    };
    js_error(code, &error.to_string())
}
