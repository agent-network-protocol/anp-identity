use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use sha2::{Digest, Sha256};

pub(super) fn require_presence(confirmed: bool) -> IdentityResult<()> {
    if confirmed {
        Ok(())
    } else {
        Err(IdentityError::CapabilityUnavailable)
    }
}
pub(super) fn current_record(
    engine: &crate::DidIdentity,
    expected: u64,
) -> IdentityResult<IdentityRecord> {
    let record = read_identity(engine.runtime().root(), engine.identity_id())?;
    if record.generation != expected || engine.record().generation != expected {
        return Err(IdentityError::Conflict);
    }
    Ok(record)
}
pub(super) fn active_root<'a>(
    record: &'a IdentityRecord,
    kid: &str,
) -> IdentityResult<&'a crate::KeyMetadata> {
    if record.state != IdentityState::Active
        || record.root_capability != RootCapabilityState::Active
        || record.pending_revision.is_some()
    {
        return Err(IdentityError::CapabilityUnavailable);
    }
    let mut roots = record
        .keys
        .iter()
        .filter(|key| key.role == KeyRole::RootControl);
    let root = roots.next().ok_or(IdentityError::CapabilityUnavailable)?;
    if roots.next().is_some()
        || root.kid != kid
        || root.origin != KeyOrigin::Managed
        || root.state != KeyState::Active
        || root.material_erased
    {
        return Err(IdentityError::CapabilityUnavailable);
    }
    let method = anp::authentication::find_verification_method(&record.document, kid)
        .ok_or(IdentityError::CapabilityUnavailable)?;
    let public = anp::authentication::extract_public_key(&method)
        .map_err(|_| IdentityError::InvalidRequest)?;
    if !matches!(public, anp::PublicKeyMaterial::Ed25519(_))
        || crate::document::public_key_multibase(&public)? != root.public_key_multibase
    {
        return Err(IdentityError::RootKeyMismatch);
    }
    Ok(root)
}
pub(super) fn validate_binding(
    binding: &PinRecoveryBinding,
    document: &Value,
) -> IdentityResult<()> {
    for value in [
        &binding.operation_id,
        &binding.account_user_id,
        &binding.target_id,
        &binding.handle,
        &binding.did,
        &binding.domain,
        &binding.binding_generation,
        &binding.recovery_id,
        &binding.slot_id,
        &binding.op_jkt,
        &binding.root_kid,
        &binding.root_public_key_multibase,
        &binding.config_hash,
        &binding.audience,
    ] {
        if value.trim().is_empty() || value.trim() != value {
            return Err(IdentityError::InvalidRequest);
        }
    }
    if !uuid(&binding.operation_id)
        || !uuid(&binding.recovery_id)
        || !slot_id(&binding.slot_id)
        || !hash32(&binding.op_jkt)
        || !hash32(&binding.config_hash)
        || binding
            .encrypted_package_hash
            .as_ref()
            .is_some_and(|value| !hash32(value))
        || binding.account_user_id.chars().count() > 255
        || binding.target_id.chars().count() > 128
        || binding.handle.chars().count() > 320
        || binding.did.chars().count() > 640
        || binding.root_kid.chars().count() > 768
        || !https_uri(&binding.audience)
    {
        return Err(IdentityError::InvalidRequest);
    }
    let generation = &binding.binding_generation;
    if binding.backup_epoch == 0
        || generation.len() > 255
        || !generation.bytes().all(|byte| byte.is_ascii_digit())
        || generation.starts_with('0')
        || !binding
            .audience
            .starts_with(&format!("https://{}/", binding.domain))
        || document["id"] != binding.did
    {
        return Err(IdentityError::InvalidRequest);
    }
    if method_root_fingerprint(document)?.is_none() {
        return Err(IdentityError::Unsupported);
    }
    let method = anp::authentication::find_verification_method(document, &binding.root_kid)
        .ok_or(IdentityError::RootKeyMismatch)?;
    let public = anp::authentication::extract_public_key(&method)
        .map_err(|_| IdentityError::RootKeyMismatch)?;
    if !matches!(public, anp::PublicKeyMaterial::Ed25519(_))
        || crate::document::public_key_multibase(&public)? != binding.root_public_key_multibase
        || document["proof"]["verificationMethod"] != binding.root_kid
    {
        return Err(IdentityError::RootKeyMismatch);
    }
    Ok(())
}
pub(super) fn validate_root_der(
    der: &[u8],
    document: &Value,
    binding: &PinRecoveryBinding,
) -> IdentityResult<crate::secret::SecretBytes> {
    let material = crate::key_import::parse_private_key(
        KeyRole::RootControl,
        crate::PrivateKeyEncoding::Pkcs8Der,
        der,
    )?;
    if crate::document::public_key_multibase(&material.public_key())?
        != binding.root_public_key_multibase
    {
        return Err(IdentityError::RootKeyMismatch);
    }
    validate_binding(binding, document)?;
    let raw = crate::key_import::raw_private_key(material, KeyRole::RootControl)?;
    Ok(crate::secret::SecretBytes::new(raw.to_vec()))
}
pub(super) fn public_jwk(multibase: &str) -> IdentityResult<Value> {
    let method = json!({"type":"Multikey", "publicKeyMultibase":multibase});
    match anp::authentication::extract_public_key(&method)
        .map_err(|_| IdentityError::InvalidRequest)?
    {
        anp::PublicKeyMaterial::Ed25519(key) => {
            Ok(json!({"kty":"OKP", "crv":"Ed25519", "x":URL_SAFE_NO_PAD.encode(key.as_bytes())}))
        }
        anp::PublicKeyMaterial::X25519(key) => {
            Ok(json!({"kty":"OKP", "crv":"X25519", "x":URL_SAFE_NO_PAD.encode(key)}))
        }
        _ => Err(IdentityError::Unsupported),
    }
}
pub(super) fn device_proposal(record: &IdentityRecord) -> IdentityResult<Value> {
    let local = record
        .local_authorization
        .as_ref()
        .ok_or(IdentityError::CorruptState)?;
    let pin = record
        .pin_recovery
        .as_ref()
        .ok_or(IdentityError::CorruptState)?;
    let key = |kid: &str| -> IdentityResult<Value> {
        let key = record
            .keys
            .iter()
            .find(|key| key.kid == kid)
            .ok_or(IdentityError::KeyNotFound)?;
        public_jwk(&key.public_key_multibase)
    };
    Ok(
        json!({"device_id":local.device_id, "device_label":pin.device_label, "signing_kid":local.signing_kid,
        "signing_public_jwk":key(&local.signing_kid)?, "agreement_kid":local.e2ee_kid,
        "agreement_public_jwk":key(&local.e2ee_kid)?, "profiles":local.profiles}),
    )
}
pub(super) fn without_proof(document: &Value) -> IdentityResult<Value> {
    let mut document = document.clone();
    document
        .as_object_mut()
        .ok_or(IdentityError::InvalidRequest)?
        .remove("proof");
    Ok(document)
}
pub(super) fn candidate_document(record: &IdentityRecord, base: &Value) -> IdentityResult<Value> {
    let local = record
        .local_authorization
        .as_ref()
        .ok_or(IdentityError::CorruptState)?;
    let mut candidate = without_proof(base)?;
    for (kid, kind) in [
        (&local.signing_kid, "Multikey"),
        (&local.e2ee_kid, "X25519KeyAgreementKey2019"),
    ] {
        if anp::authentication::find_verification_method(base, kid).is_some() {
            return Err(IdentityError::InvalidRequest);
        }
        let key = record
            .keys
            .iter()
            .find(|key| key.kid == *kid)
            .ok_or(IdentityError::KeyNotFound)?;
        append_array(
            &mut candidate,
            "verificationMethod",
            json!({"id":kid,"type":kind,"controller":record.did,"publicKeyMultibase":key.public_key_multibase}),
        )?;
    }
    append_array(&mut candidate, "authentication", json!(local.signing_kid))?;
    append_array(&mut candidate, "assertionMethod", json!(local.signing_kid))?;
    append_array(&mut candidate, "keyAgreement", json!(local.e2ee_kid))?;
    if candidate.get("deviceManifest").is_none() {
        candidate["deviceManifest"] =
            json!({"type":anp::authentication::DEVICE_MANIFEST_TYPE,"devices":[]});
    }
    let devices = candidate["deviceManifest"]["devices"]
        .as_array_mut()
        .ok_or(IdentityError::InvalidRequest)?;
    if devices
        .iter()
        .any(|device| device["device_id"] == local.device_id)
    {
        return Err(IdentityError::InvalidRequest);
    }
    devices.push(json!({"device_id":local.device_id,"signing_key_id":local.signing_kid,"e2ee_key_id":local.e2ee_kid,"profiles":local.profiles}));
    anp::authentication::validate_device_manifest(&candidate)
        .map_err(|_| IdentityError::InvalidRequest)?;
    Ok(candidate)
}
fn append_array(document: &mut Value, key: &str, value: Value) -> IdentityResult<()> {
    document
        .as_object_mut()
        .ok_or(IdentityError::InvalidRequest)?
        .entry(key)
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or(IdentityError::InvalidRequest)?
        .push(value);
    Ok(())
}
fn canonical(value: &Value) -> IdentityResult<Vec<u8>> {
    serde_json_canonicalizer::to_vec(value).map_err(|_| IdentityError::InvalidRequest)
}
pub(super) fn hash_json(value: &Value) -> IdentityResult<String> {
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(canonical(value)?)))
}
pub(super) fn string<'a>(value: &'a Value, key: &str) -> IdentityResult<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(IdentityError::InvalidRequest)
}
pub(super) fn unique_receipts(value: &Value) -> IdentityResult<usize> {
    let ids = value.as_array().ok_or(IdentityError::InvalidRequest)?;
    if ids.len() > 3 {
        return Err(IdentityError::InvalidRequest);
    }
    let mut seen = std::collections::BTreeSet::new();
    for id in ids {
        let id = id
            .as_str()
            .filter(|id| uuid(id))
            .ok_or(IdentityError::InvalidRequest)?;
        if !seen.insert(id) {
            return Err(IdentityError::InvalidRequest);
        }
    }
    Ok(ids.len())
}
pub(super) fn validate_challenge(
    challenge: &PinRecoveryChallenge,
    binding: &PinRecoveryBinding,
    checkpoint: &crate::DocumentCheckpoint,
    purpose: &str,
) -> IdentityResult<()> {
    let payload_keys = [
        "protocol",
        "purpose",
        "aud",
        "operation_id",
        "challenge_id",
        "nonce",
        "iat",
        "exp",
        "account_user_id",
        "recovery_id",
        "backup_epoch",
        "slot_id",
        "did",
        "root_kid",
        "root_jkt",
        "op_jkt",
        "binding_generation",
        "document_version",
        "registry_version",
        "document_digest",
        "intent_hash",
    ];
    let intent_keys = [
        "kind",
        "operation_id",
        "recovery_id",
        "backup_epoch",
        "slot_id",
        "expected_active_epoch",
        "backup_hash",
        "config_hash",
        "registration_version",
        "registered_receipt_ids",
        "verified_receipt_ids",
        "new_device_proposal_hash",
        "candidate_document_digest",
        "binding_generation",
    ];
    for (value, keys) in [
        (&challenge.payload, payload_keys.as_slice()),
        (&challenge.intent, intent_keys.as_slice()),
    ] {
        let object = value.as_object().ok_or(IdentityError::InvalidRequest)?;
        if object.len() != keys.len() || keys.iter().any(|key| !object.contains_key(*key)) {
            return Err(IdentityError::InvalidRequest);
        }
        validate_common_schema(value)?;
        for (key, expected) in [
            ("operation_id", json!(binding.operation_id)),
            ("recovery_id", json!(binding.recovery_id)),
            ("backup_epoch", json!(binding.backup_epoch)),
            ("slot_id", json!(binding.slot_id)),
            ("binding_generation", json!(binding.binding_generation)),
        ] {
            if value[key] != expected {
                return Err(IdentityError::InvalidRequest);
            }
        }
    }
    validate_payload_schema(&challenge.payload)?;
    validate_intent_schema(&challenge.intent)?;
    let payload = &challenge.payload;
    let now = Utc::now().timestamp();
    let iat = payload["iat"]
        .as_i64()
        .ok_or(IdentityError::InvalidRequest)?;
    let exp = payload["exp"]
        .as_i64()
        .ok_or(IdentityError::InvalidRequest)?;
    if iat < 0 || iat > now + 30 || exp <= now || exp <= iat || exp - iat > 300 {
        return Err(IdentityError::InvalidRequest);
    }
    for (key, expected) in [
        ("protocol", json!("awiki.pin-recovery.v1")),
        ("purpose", json!(purpose)),
        ("aud", json!(binding.audience)),
        ("account_user_id", json!(binding.account_user_id)),
        ("did", json!(binding.did)),
        ("root_kid", json!(binding.root_kid)),
        (
            "root_jkt",
            json!(hash_json(&public_jwk(&binding.root_public_key_multibase)?)?),
        ),
        ("op_jkt", json!(binding.op_jkt)),
        ("document_version", json!(checkpoint.document_version)),
        ("registry_version", json!(checkpoint.registry_version)),
        (
            "document_digest",
            json!(checkpoint
                .document_digest
                .strip_prefix("sha256:")
                .ok_or(IdentityError::InvalidRequest)?),
        ),
        ("intent_hash", json!(hash_json(&challenge.intent)?)),
    ] {
        if payload[key] != expected {
            return Err(IdentityError::InvalidRequest);
        }
    }
    if challenge.intent["config_hash"] != binding.config_hash {
        return Err(IdentityError::InvalidRequest);
    }
    unique_receipts(&challenge.intent["registered_receipt_ids"])?;
    unique_receipts(&challenge.intent["verified_receipt_ids"])?;
    Ok(())
}
// These checks mirror RootChallengePayload/Intent in Realm Docs/02. They run
// before binding comparison or signing, including fields nullable in one phase.
pub(super) fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}
pub(super) fn hash32(value: &str) -> bool {
    value.len() == 43
        && URL_SAFE_NO_PAD
            .decode(value)
            .is_ok_and(|bytes| bytes.len() == 32)
}
fn slot_id(value: &str) -> bool {
    value.strip_prefix("rs_").is_some_and(hash32)
}
fn registration_version(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
pub(super) fn generation(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && !value.starts_with('0')
        && value.bytes().all(|byte| byte.is_ascii_digit())
}
fn https_uri(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("https://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() {
        return false;
    }
    let bytes = rest.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 3;
            continue;
        }
        if !byte.is_ascii_alphanumeric() && !b"-._~:/?#[]@!$&'()*+,;=".contains(&byte) {
            return false;
        }
        index += 1;
    }
    true
}
fn validate_common_schema(value: &Value) -> IdentityResult<()> {
    if !uuid(string(value, "operation_id")?)
        || !uuid(string(value, "recovery_id")?)
        || !slot_id(string(value, "slot_id")?)
        || !generation(string(value, "binding_generation")?)
        || value["backup_epoch"]
            .as_u64()
            .is_none_or(|epoch| epoch == 0)
    {
        return Err(IdentityError::InvalidRequest);
    }
    Ok(())
}
fn validate_payload_schema(value: &Value) -> IdentityResult<()> {
    if value["protocol"] != "awiki.pin-recovery.v1"
        || !matches!(
            string(value, "purpose")?,
            "awiki.pin-recovery.authorize.v1"
                | "awiki.pin-recovery.backup-commit.v1"
                | "awiki.pin-recovery.disable-commit.v1"
                | "awiki.pin-recovery.device-commit.v1"
        )
        || !https_uri(string(value, "aud")?)
        || !uuid(string(value, "challenge_id")?)
        || value["iat"].as_u64().is_none()
        || value["exp"].as_u64().is_none()
        || value["document_version"]
            .as_u64()
            .is_none_or(|version| version == 0)
        || value["registry_version"]
            .as_u64()
            .is_none_or(|version| version == 0)
    {
        return Err(IdentityError::InvalidRequest);
    }
    for (key, max) in [("account_user_id", 255), ("did", 640), ("root_kid", 768)] {
        if string(value, key)?.chars().count() > max {
            return Err(IdentityError::InvalidRequest);
        }
    }
    for key in [
        "nonce",
        "root_jkt",
        "op_jkt",
        "document_digest",
        "intent_hash",
    ] {
        if !hash32(string(value, key)?) {
            return Err(IdentityError::InvalidRequest);
        }
    }
    Ok(())
}
fn validate_intent_schema(value: &Value) -> IdentityResult<()> {
    if !matches!(
        string(value, "kind")?,
        "enable" | "recover" | "change_pin" | "disable"
    ) || !hash32(string(value, "config_hash")?)
        || (!value["expected_active_epoch"].is_null()
            && value["expected_active_epoch"]
                .as_u64()
                .is_none_or(|epoch| epoch == 0))
        || (!value["registration_version"].is_null()
            && !registration_version(string(value, "registration_version")?))
    {
        return Err(IdentityError::InvalidRequest);
    }
    for key in [
        "backup_hash",
        "new_device_proposal_hash",
        "candidate_document_digest",
    ] {
        if !value[key].is_null() && !hash32(string(value, key)?) {
            return Err(IdentityError::InvalidRequest);
        }
    }
    unique_receipts(&value["registered_receipt_ids"])?;
    unique_receipts(&value["verified_receipt_ids"])?;
    Ok(())
}

pub(super) fn sign_jws(
    engine: &crate::DidIdentity,
    key: &crate::KeyMetadata,
    payload: &Value,
    typ: &str,
) -> IdentityResult<String> {
    if key.origin != KeyOrigin::Managed || key.material_erased {
        return Err(IdentityError::KeyUnavailable);
    }
    let protected =
        URL_SAFE_NO_PAD.encode(canonical(&json!({"alg":"EdDSA","typ":typ,"kid":key.kid}))?);
    let payload = URL_SAFE_NO_PAD.encode(canonical(payload)?);
    let input = format!("{protected}.{payload}");
    let signature = engine.sign_prepared(key, input.as_bytes())?;
    Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
}
