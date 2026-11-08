use super::*;
#[test]
fn legacy_v1_ciphertext_remains_readable_and_new_records_bind_algorithm() {
    let root_key = RootKey::from_bytes([83; 32]);
    let reference = SecretRef {
        identity_id: "legacy".into(),
        key_id: "did:wba:example:e1_test#request".into(),
        role: KeyRole::RequestSigning,
        version: 1,
    };
    let plaintext = SecretBytes::new(vec![11; 32]);
    let mut legacy = seal_record(&root_key, reference.clone(), &plaintext).unwrap();
    legacy.schema_version = 1;
    legacy.algorithm = None;
    let aad = aad_for_ref(1, &reference);
    let key = derive_record_key(&root_key, &aad).unwrap();
    let nonce = [13u8; 12];
    let ciphertext = ChaCha20Poly1305::new_from_slice(key.as_slice())
        .unwrap()
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: plaintext.expose(),
                aad: &aad,
            },
        )
        .unwrap();
    legacy.nonce_b64u = URL_SAFE_NO_PAD.encode(nonce);
    legacy.aad_b64u = URL_SAFE_NO_PAD.encode(aad);
    legacy.ciphertext_b64u = URL_SAFE_NO_PAD.encode(ciphertext);
    assert_eq!(
        open_record(&root_key, &legacy).unwrap().expose(),
        plaintext.expose()
    );
    let mut current = seal_record(&root_key, reference, &plaintext).unwrap();
    assert_eq!(current.schema_version, 2);
    assert_eq!(current.algorithm, Some(crate::KeyAlgorithm::Ed25519));
    current.algorithm = Some(crate::KeyAlgorithm::P256);
    assert!(matches!(
        open_record(&root_key, &current),
        Err(DidError::CorruptRecord)
    ));
    legacy.secret_ref.role = KeyRole::OAuthAuthentication;
    assert!(matches!(
        open_record(&root_key, &legacy),
        Err(DidError::CorruptRecord)
    ));
}
