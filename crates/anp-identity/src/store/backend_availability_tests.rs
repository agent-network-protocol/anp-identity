use super::*;
use crate::platform::{FileRootKeyProvider, InjectedRootKeyProvider, MemoryRootKeyProvider};
use crate::RootKeyProviderKind;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

fn keyring_runtime(root: &Path) -> StoreRuntime {
    let provider = MemoryRootKeyProvider::new(RootKeyProviderKind::OsKeyring, "isolated", [7; 32]);
    StoreRuntime::initialize(root, ProviderInitialization::Required(&provider)).unwrap()
}

#[test]
fn backend_unavailable_blocks_before_private_work() {
    let root = tempfile::tempdir().unwrap();
    let mut runtime = keyring_runtime(root.path());
    runtime.backend_probe = Some(Arc::new(|| Err(DidError::ProviderUnavailable)));
    let entered = AtomicBool::new(false);
    let result = runtime.with_private_access(|| {
        entered.store(true, Ordering::SeqCst);
        Ok(())
    });
    assert!(matches!(result, Err(DidError::ProviderUnavailable)));
    assert!(!entered.load(Ordering::SeqCst));
}

#[test]
fn backend_lock_during_private_work_withholds_result() {
    let root = tempfile::tempdir().unwrap();
    let mut runtime = keyring_runtime(root.path());
    let available = Arc::new(AtomicBool::new(true));
    let probe = Arc::clone(&available);
    runtime.backend_probe = Some(Arc::new(move || {
        if probe.load(Ordering::SeqCst) {
            Ok(RootKey::from_bytes([7; 32]))
        } else {
            Err(DidError::ProviderUnavailable)
        }
    }));
    let result = runtime.with_private_access(|| {
        available.store(false, Ordering::SeqCst);
        Ok([42u8; 64])
    });
    assert!(matches!(result, Err(DidError::ProviderUnavailable)));
    available.store(true, Ordering::SeqCst);
    assert!(runtime.with_private_access(|| Ok(())).is_ok());
}

#[test]
fn backend_fingerprint_change_is_rejected_before_and_after_work() {
    let root = tempfile::tempdir().unwrap();
    let mut runtime = keyring_runtime(root.path());
    runtime.backend_probe = Some(Arc::new(|| Ok(RootKey::from_bytes([8; 32]))));
    assert!(matches!(
        runtime.assert_backend_available(),
        Err(DidError::RootKeyMismatch)
    ));
    let reads = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&reads);
    runtime.backend_probe = Some(Arc::new(move || {
        Ok(RootKey::from_bytes(
            if count.fetch_add(1, Ordering::SeqCst) == 0 {
                [7; 32]
            } else {
                [8; 32]
            },
        ))
    }));
    assert!(matches!(
        runtime.with_private_access(|| Ok(())),
        Err(DidError::RootKeyMismatch)
    ));
    assert_eq!(reads.load(Ordering::SeqCst), 2);
}

#[test]
fn injected_and_local_file_keep_their_existing_open_store_semantics() {
    let injected_root = tempfile::tempdir().unwrap();
    let provider = InjectedRootKeyProvider::new("injected", [11; 32]);
    let runtime = StoreRuntime::initialize(
        injected_root.path(),
        ProviderInitialization::Required(&provider),
    )
    .unwrap();
    assert!(runtime.with_private_access(|| Ok(())).is_ok());
    let file_root = tempfile::tempdir().unwrap();
    let path = crate::platform::default_file_root_key_path(file_root.path());
    let provider = FileRootKeyProvider::new("local", &path);
    let runtime = StoreRuntime::initialize(
        file_root.path(),
        ProviderInitialization::Required(&provider),
    )
    .unwrap();
    std::fs::remove_file(path).unwrap();
    assert!(runtime.with_private_access(|| Ok(())).is_ok());
}
