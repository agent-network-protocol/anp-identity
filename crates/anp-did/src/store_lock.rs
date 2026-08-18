use std::fs::File;
use std::path::{Path, PathBuf};

use fs2::FileExt;

use crate::fs_util::open_private_lock_file;
use crate::{DidError, DidResult};

#[derive(Debug, Clone)]
pub(crate) struct StoreLock {
    store_root: PathBuf,
    lock_path: PathBuf,
}

impl StoreLock {
    pub(crate) fn new(store_root: impl Into<PathBuf>) -> Self {
        let store_root = store_root.into();
        let lock_path = store_root.join(".anp-did.lock");
        Self {
            store_root,
            lock_path,
        }
    }

    pub(crate) fn acquire_exclusive(&self) -> DidResult<StoreWriteGuard> {
        let file = open_private_lock_file(&self.lock_path)?;
        file.lock_exclusive()
            .map_err(|error| DidError::Io(error.to_string()))?;
        Ok(StoreWriteGuard {
            file,
            store_root: self.store_root.clone(),
        })
    }
}

pub(crate) struct StoreWriteGuard {
    file: File,
    store_root: PathBuf,
}

impl StoreWriteGuard {
    pub(crate) fn require_store(&self, store_root: &Path) -> DidResult<()> {
        if self.store_root != store_root {
            return Err(DidError::Conflict);
        }
        Ok(())
    }
}

impl Drop for StoreWriteGuard {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::time::{Duration, Instant};

    use super::*;

    const CHILD_ROOT_ENV: &str = "ANP_DID_LOCK_TEST_ROOT";

    #[test]
    fn store_lock_serializes_threads() {
        let root = tempfile::tempdir().unwrap();
        let lock = StoreLock::new(root.path());
        let first = lock.acquire_exclusive().unwrap();
        let second_lock = lock.clone();
        let handle = std::thread::spawn(move || second_lock.acquire_exclusive().unwrap());
        std::thread::sleep(Duration::from_millis(100));
        assert!(!handle.is_finished());
        drop(first);
        drop(handle.join().unwrap());
    }

    #[test]
    fn store_lock_serializes_processes() {
        let root = tempfile::tempdir().unwrap();
        let ready = root.path().join("child-ready");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "store_lock::tests::store_lock_child_holds_exclusive_lock",
                "--nocapture",
            ])
            .env(CHILD_ROOT_ENV, root.path())
            .spawn()
            .unwrap();
        for _ in 0..100 {
            if ready.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(ready.exists(), "child did not acquire the store lock");

        let start = Instant::now();
        let guard = StoreLock::new(root.path()).acquire_exclusive().unwrap();
        assert!(start.elapsed() >= Duration::from_millis(250));
        drop(guard);
        assert!(child.wait().unwrap().success());
    }

    #[test]
    #[ignore]
    fn store_lock_child_holds_exclusive_lock() {
        let Some(root) = std::env::var_os(CHILD_ROOT_ENV) else {
            return;
        };
        let root = PathBuf::from(root);
        let _guard = StoreLock::new(&root).acquire_exclusive().unwrap();
        std::fs::write(root.join("child-ready"), b"ready").unwrap();
        std::thread::sleep(Duration::from_millis(400));
    }
}
