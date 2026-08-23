use anp::authentication::find_verification_method;
use anp_identity::host::{KeyAgreementPort, KeyAgreementRequest};
use anp_identity::{
    CreateIdentityCapabilities, CreateIdentityProfile, CreateIdentityRequest, IdentityManager,
    IdentityManagerConfig, InjectedStoreKey, KeySelector, ManagedIdentity, ManagedKeyInput,
    ManagedKeyRole, RootKeySource,
};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

fn main() {
    let alice_root = tempfile::tempdir().expect("Alice store directory");
    let bob_root = tempfile::tempdir().expect("Bob store directory");
    let mut alice_manager = IdentityManager::initialize(IdentityManagerConfig {
        state_root: alice_root.path().to_path_buf(),
        root_key: RootKeySource::Injected(InjectedStoreKey::new("example", [41_u8; 32])),
    })
    .expect("Alice store");
    let mut bob_manager = IdentityManager::initialize(IdentityManagerConfig {
        state_root: bob_root.path().to_path_buf(),
        root_key: RootKeySource::Injected(InjectedStoreKey::new("example", [42_u8; 32])),
    })
    .expect("Bob store");
    let alice = alice_manager
        .create(identity_spec("alice"))
        .expect("Alice identity");
    let bob = bob_manager
        .create(identity_spec("bob"))
        .expect("Bob identity");

    let alice_public = agreement_public(&alice);
    let bob_public = agreement_public(&bob);
    let alice_shared = alice
        .derive_shared_secret(KeyAgreementRequest {
            key: KeySelector::Kid("#agreement".to_owned()),
            peer_public: bob_public,
        })
        .expect("Alice ECDH");
    let bob_shared = bob
        .derive_shared_secret(KeyAgreementRequest {
            key: KeySelector::Kid("#agreement".to_owned()),
            peer_public: alice_public,
        })
        .expect("Bob ECDH");

    let context = format!(
        "anp-identity:e2ee-example:v1:{}:{}",
        alice.reference().did,
        bob.reference().did
    );
    let alice_session = derive_session_key(alice_shared.as_bytes(), context.as_bytes());
    let bob_session = derive_session_key(bob_shared.as_bytes(), context.as_bytes());
    assert_eq!(&*alice_session, &*bob_session);

    let cipher = ChaCha20Poly1305::new_from_slice(&*alice_session).expect("session key length");
    let mut nonce_bytes = [0_u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(&nonce, b"hello from Alice".as_slice())
        .expect("encrypt");
    let plaintext = ChaCha20Poly1305::new_from_slice(&*bob_session)
        .expect("session key length")
        .decrypt(&nonce, ciphertext.as_slice())
        .expect("decrypt");
    assert_eq!(plaintext, b"hello from Alice");
    println!("ECDH + caller-owned HKDF/session encryption round trip succeeded");
}

fn derive_session_key(shared: &[u8; 32], context: &[u8]) -> Zeroizing<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(None, shared);
    let mut output = Zeroizing::new([0_u8; 32]);
    hkdf.expand(context, output.as_mut())
        .expect("fixed-size HKDF output");
    output
}

fn agreement_public(identity: &ManagedIdentity) -> [u8; 32] {
    let public = identity.public_identity().expect("public identity");
    let kid = public
        .active_keys
        .iter()
        .find(|key| {
            key.purposes
                .contains(&anp_identity::KeyPurpose::KeyAgreement)
        })
        .expect("agreement metadata")
        .kid
        .clone();
    let method = find_verification_method(public.document.as_value(), &kid).expect("agreement VM");
    match anp::authentication::extract_public_key(&method).expect("agreement public key") {
        anp::PublicKeyMaterial::X25519(bytes) => bytes,
        _ => panic!("agreement key must be X25519"),
    }
}

fn identity_spec(name: &str) -> CreateIdentityRequest {
    CreateIdentityRequest {
        profile: CreateIdentityProfile::E1,
        domain: "example.com".to_string(),
        port: None,
        path_segments: vec!["agents".to_string(), name.to_string()],
        capabilities: CreateIdentityCapabilities::default(),
        managed_keys: vec![
            ManagedKeyInput {
                fragment: "root".to_string(),
                role: ManagedKeyRole::RootControl,
            },
            ManagedKeyInput {
                fragment: "agreement".to_string(),
                role: ManagedKeyRole::E2eeAgreement,
            },
        ],
        external_keys: Vec::new(),
        services: Vec::new(),
        agent_description_url: None,
        extensions: Vec::new(),
    }
}
