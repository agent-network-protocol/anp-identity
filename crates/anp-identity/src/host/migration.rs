use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::convergence::evidence;
use crate::facade::{IdentityManager, IdentityResult, ManagedIdentity, VerifiedRemoteDocument};
use crate::{
    Capabilities, DeviceIdentityImportSpec, IdentityImportSpec, ImportedPrivateKey, KeyRole,
    PrivateKeyEncoding, RequestSigningIdentityImportSpec,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MigrationPrivateKeyEncoding {
    Raw32,
    Pkcs8Der,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MigrationKeyPurpose {
    RootControl,
    Authentication,
    DeviceAssertion,
    ApplicationAssertion,
    KeyAgreement,
}

pub struct MigrationPrivateKey {
    pub kid: String,
    pub purpose: MigrationKeyPurpose,
    pub encoding: MigrationPrivateKeyEncoding,
    pub secret: Zeroizing<Vec<u8>>,
}

pub struct FullIdentityImportRequest {
    pub remote: VerifiedRemoteDocument,
    pub did_wba: bool,
    pub private_keys: Vec<MigrationPrivateKey>,
}

pub struct DeviceIdentityImportRequest {
    pub remote: VerifiedRemoteDocument,
    pub did_wba: bool,
    pub signing_key: MigrationPrivateKey,
    pub agreement_key: MigrationPrivateKey,
}

pub struct RequestSigningIdentityImportRequest {
    pub remote: VerifiedRemoteDocument,
    pub did_wba: bool,
    pub signing_key: MigrationPrivateKey,
}

pub trait MigrationPort {
    fn import_full_identity(
        &mut self,
        request: FullIdentityImportRequest,
    ) -> IdentityResult<ManagedIdentity>;

    fn import_device_identity(
        &mut self,
        request: DeviceIdentityImportRequest,
    ) -> IdentityResult<ManagedIdentity>;

    fn import_request_signing_identity(
        &mut self,
        request: RequestSigningIdentityImportRequest,
    ) -> IdentityResult<ManagedIdentity>;
}

impl MigrationPort for IdentityManager {
    fn import_full_identity(
        &mut self,
        request: FullIdentityImportRequest,
    ) -> IdentityResult<ManagedIdentity> {
        let engine = self.engine_mut().import_identity(IdentityImportSpec {
            verified_document: request.remote.document.into_value(),
            evidence: evidence(request.remote.evidence),
            capabilities: Capabilities {
                did_wba: request.did_wba,
            },
            private_keys: request.private_keys.into_iter().map(Into::into).collect(),
        })?;
        Ok(self.wrap(engine))
    }

    fn import_device_identity(
        &mut self,
        request: DeviceIdentityImportRequest,
    ) -> IdentityResult<ManagedIdentity> {
        let engine = self
            .engine_mut()
            .import_device_identity(DeviceIdentityImportSpec {
                verified_document: request.remote.document.into_value(),
                evidence: evidence(request.remote.evidence),
                capabilities: Capabilities {
                    did_wba: request.did_wba,
                },
                signing_key: request.signing_key.into(),
                e2ee_key: request.agreement_key.into(),
            })?;
        Ok(self.wrap(engine))
    }

    fn import_request_signing_identity(
        &mut self,
        request: RequestSigningIdentityImportRequest,
    ) -> IdentityResult<ManagedIdentity> {
        let engine = self.engine_mut().import_request_signing_identity(
            RequestSigningIdentityImportSpec {
                verified_document: request.remote.document.into_value(),
                evidence: evidence(request.remote.evidence),
                capabilities: Capabilities {
                    did_wba: request.did_wba,
                },
                private_key: request.signing_key.into(),
            },
        )?;
        Ok(self.wrap(engine))
    }
}

impl IdentityManager {
    pub(crate) fn import_full_identity_with_id(
        &mut self,
        identity_id: String,
        request: FullIdentityImportRequest,
    ) -> IdentityResult<ManagedIdentity> {
        let engine = self.engine_mut().import_identity_with_id(
            IdentityImportSpec {
                verified_document: request.remote.document.into_value(),
                evidence: evidence(request.remote.evidence),
                capabilities: Capabilities {
                    did_wba: request.did_wba,
                },
                private_keys: request.private_keys.into_iter().map(Into::into).collect(),
            },
            identity_id,
        )?;
        Ok(self.wrap(engine))
    }
}

impl From<MigrationPrivateKey> for ImportedPrivateKey {
    fn from(value: MigrationPrivateKey) -> Self {
        ImportedPrivateKey::new(
            value.kid,
            match value.purpose {
                MigrationKeyPurpose::RootControl => KeyRole::RootControl,
                MigrationKeyPurpose::Authentication => KeyRole::RequestSigning,
                MigrationKeyPurpose::DeviceAssertion => KeyRole::DeviceSigning,
                MigrationKeyPurpose::ApplicationAssertion => KeyRole::E2eeSigning,
                MigrationKeyPurpose::KeyAgreement => KeyRole::E2eeAgreement,
            },
            match value.encoding {
                MigrationPrivateKeyEncoding::Raw32 => PrivateKeyEncoding::Raw32,
                MigrationPrivateKeyEncoding::Pkcs8Der => PrivateKeyEncoding::Pkcs8Der,
            },
            value.secret,
        )
    }
}
