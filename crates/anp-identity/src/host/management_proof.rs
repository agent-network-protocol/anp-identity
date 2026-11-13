//! Restricted AWiki control-plane proofs using the existing device transcript.
use crate::facade::oauth::nonce;
use crate::facade::signing::select_key;
use crate::{IdentityError, IdentityResult, KeyRole, KeySelector, ManagedIdentity};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ManagementProofRequest {
    pub key: KeySelector,
    pub method: String,
    pub params: Value,
    #[serde(default)]
    pub audience: Option<String>,
}
impl ManagedIdentity {
    pub fn sign_management_proof(&self, request: ManagementProofRequest) -> IdentityResult<Value> {
        let purpose = match request.method.as_str() {
            "agent_client_prepare" => "awiki.agent-client.prepare.v2",
            "agent_client_activate" => "awiki.agent-client.activate.v2",
            "agent_client_status" => "awiki.agent-client.status.v2",
            "agent_client_resolve" => "awiki.agent-client.resolve.v2",
            "agent_client_pap_callback_register" => "awiki.agent-client.pap_callback_register.v2",
            "agent_client_pap_callback_claim" => "awiki.agent-client.pap_callback_claim.v2",
            "device_oauth_keys_update" => "awiki.device.oauth-keys.update.v1",
            "device_document_update" => "awiki.device.document.update.v1",
            _ => return Err(IdentityError::InvalidRequest),
        };
        let mut params = request
            .params
            .as_object()
            .cloned()
            .ok_or(IdentityError::InvalidRequest)?;
        params.remove("authorizing_device_proof");
        if serde_json::to_vec(&params)
            .map_err(|_| IdentityError::InvalidRequest)?
            .len()
            > 512 * 1024
        {
            return Err(IdentityError::InvalidRequest);
        }
        let engine = self.lock_engine()?;
        let _guard = engine.runtime().acquire_write()?;
        engine.require_operational()?;
        let metadata = select_key(&engine, &request.key, KeyRole::DeviceSigning)?;
        if let Some(action) = request.method.strip_prefix("agent_client_") {
            let action = match action {
                "pap_callback_register" => "pap-callback-register",
                "pap_callback_claim" => "pap-callback-claim",
                other => other,
            };
            if params.get("target_did").and_then(Value::as_str) != Some(engine.did())
                || params.get("http_path").and_then(Value::as_str)
                    != Some(format!("/user-service/v1/agent-clients/device/{action}").as_str())
            {
                return Err(IdentityError::InvalidRequest);
            }
        }
        let web = crate::DidProfile::for_did(engine.did())? == crate::DidProfile::Web;
        if web != request.audience.is_some() {
            return Err(IdentityError::InvalidRequest);
        }
        if let Some(audience) = &request.audience {
            validate_management_audience(audience)?;
        }
        let now = chrono::Utc::now();
        let created_at = now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let expires_at = (now + chrono::Duration::seconds(60))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let nonce = nonce();
        let mut transcript = json!({"type":"awiki-device-signature-v1","purpose":purpose,"method":request.method,"key_id":metadata.kid,"created_at":created_at,"expires_at":expires_at,"nonce":nonce,"params":params});
        if let Some(audience) = request.audience {
            transcript["audience"] = json!(audience);
        }
        let input = serde_json_canonicalizer::to_vec(&transcript)
            .map_err(|_| IdentityError::InvalidRequest)?;
        let signature = engine.sign_prepared(metadata, &input)?;
        engine.require_operational()?;
        Ok(
            json!({"type":"awiki-device-signature-v1","key_id":metadata.kid,"created_at":created_at,"expires_at":expires_at,"nonce":nonce,"signature":URL_SAFE_NO_PAD.encode(signature)}),
        )
    }
}
#[cfg(test)]
mod tests;

/// Business projection from AWiki's ordinary Web registration contract.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WebRegistrationProofRequest {
    pub key: KeySelector,
    pub business_projection: Value,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WebProjection {
    contract: String,
    audience: String,
    registration_operation_id: String,
    full_handle: String,
    did: String,
    bootstrap_device: BootstrapDevice,
    document_hash: String,
    account: RegistrationAccount,
    profile: RegistrationProfile,
    invite_code_hash: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapDevice {
    device_id: String,
    signing_key_id: String,
    e2ee_key_id: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrationAccount {
    phone: Option<String>,
    email: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrationProfile {
    name: Option<String>,
    avatar: Option<String>,
    role: Option<String>,
    endpoint_url: Option<String>,
    description: Option<String>,
    is_public: bool,
    is_agent: bool,
}
impl ManagedIdentity {
    pub fn sign_web_registration_proof(
        &self,
        request: WebRegistrationProofRequest,
    ) -> IdentityResult<Value> {
        use sha2::{Digest, Sha256};
        let bytes = serde_json::to_vec(&request.business_projection)
            .map_err(|_| IdentityError::InvalidRequest)?;
        if bytes.len() > 512 * 1024 {
            return Err(IdentityError::InvalidRequest);
        }
        let projection: WebProjection = serde_json::from_value(request.business_projection)
            .map_err(|_| IdentityError::InvalidRequest)?;
        if projection.contract != "awiki.register.web.v1"
            || projection.registration_operation_id.is_empty()
            || projection.registration_operation_id.len() > 128
            || projection.full_handle.is_empty()
            || projection.full_handle.len() > 253
        {
            return Err(IdentityError::InvalidRequest);
        }
        validate_management_audience(&projection.audience)?;
        let engine = self.lock_engine()?;
        let _guard = engine.runtime().acquire_write()?;
        engine.require_operational()?;
        if crate::DidProfile::for_did(engine.did())? != crate::DidProfile::Web
            || engine.revision() != 1
            || engine.record().pending_revision.is_some()
            || projection.did != engine.did()
            || projection.document_hash != crate::document::document_digest(engine.document())?
        {
            return Err(IdentityError::InvalidRequest);
        }
        let metadata = select_key(&engine, &request.key, KeyRole::DeviceSigning)?;
        let manifest = anp::authentication::parse_device_manifest(engine.document())
            .map_err(|_| IdentityError::InvalidRequest)?
            .ok_or(IdentityError::InvalidRequest)?;
        if manifest.devices.len() != 1 {
            return Err(IdentityError::InvalidRequest);
        }
        let device = &manifest.devices[0];
        if projection.bootstrap_device.device_id != device.device_id
            || projection.bootstrap_device.signing_key_id != metadata.kid
            || device.signing_key_id != metadata.kid
            || projection.bootstrap_device.e2ee_key_id != device.e2ee_key_id
        {
            return Err(IdentityError::KeyPurposeViolation);
        }
        let agreement =
            anp::authentication::find_verification_method(engine.document(), &device.e2ee_key_id)
                .ok_or(IdentityError::InvalidRequest)?;
        let signing =
            anp::authentication::find_verification_method(engine.document(), &metadata.kid)
                .ok_or(IdentityError::InvalidRequest)?;
        let mut base = engine.document().clone();
        let object = base.as_object_mut().ok_or(IdentityError::InvalidRequest)?;
        for field in [
            "verificationMethod",
            "authentication",
            "assertionMethod",
            "keyAgreement",
            "deviceManifest",
        ] {
            object.remove(field);
        }
        let rebuilt =
            anp::authentication::build_web_did_document(&base, device, &signing, &agreement)
                .map_err(|_| IdentityError::InvalidRequest)?;
        if rebuilt != *engine.document() {
            return Err(IdentityError::InvalidRequest);
        }
        let canonical = serde_json_canonicalizer::to_vec(&projection)
            .map_err(|_| IdentityError::InvalidRequest)?;
        let request_hash = Sha256::digest(&canonical)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let now = chrono::Utc::now();
        let created_at = now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let expires_at = (now + chrono::Duration::seconds(60))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let nonce = nonce();
        let transcript = json!({"type":"awiki-device-signature-v1","purpose":"awiki.identity.register.web.v1","method":"register","audience":projection.audience,"operation_id":projection.registration_operation_id,"request_hash":request_hash,"key_id":metadata.kid,"created_at":created_at,"expires_at":expires_at,"nonce":nonce});
        let input = serde_json_canonicalizer::to_vec(&transcript)
            .map_err(|_| IdentityError::InvalidRequest)?;
        let signature = engine.sign_prepared(metadata, &input)?;
        engine.require_operational()?;
        Ok(
            json!({"type":"awiki-device-signature-v1","key_id":metadata.kid,"created_at":created_at,"expires_at":expires_at,"nonce":nonce,"signature":URL_SAFE_NO_PAD.encode(signature)}),
        )
    }
}

fn validate_management_audience(value: &str) -> IdentityResult<()> {
    if value.is_empty()
        || value.len() > 256
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(IdentityError::InvalidRequest);
    }
    Ok(())
}
