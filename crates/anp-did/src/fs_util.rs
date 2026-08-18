use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::{DidError, DidResult};

static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(crate) fn ensure_private_dir(path: &Path) -> DidResult<()> {
    fs::create_dir_all(path).map_err(io_error)?;
    set_private_dir_mode(path)
}

pub(crate) fn open_private_lock_file(path: &Path) -> DidResult<fs::File> {
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    let file = open_lock_file(path)?;
    set_private_file_mode(path)?;
    Ok(file)
}

pub(crate) fn write_atomic_private(path: &Path, bytes: &[u8]) -> DidResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| DidError::Io("target has no parent directory".to_string()))?;
    ensure_private_dir(parent)?;
    let temporary = temporary_path(path);
    let result = (|| {
        let mut file = create_private_file(&temporary)?;
        file.write_all(bytes).map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
        drop(file);
        fs::rename(&temporary, path).map_err(io_error)?;
        set_private_file_mode(path)?;
        sync_directory(parent);
        Ok(())
    })();
    let _ = fs::remove_file(&temporary);
    result
}

pub(crate) fn write_private_if_absent(path: &Path, bytes: &[u8]) -> DidResult<bool> {
    if path.exists() {
        return Ok(false);
    }
    write_atomic_private(path, bytes)?;
    Ok(true)
}

pub(crate) fn set_private_file_mode(path: &Path) -> DidResult<()> {
    set_private_file_mode_impl(path)
}

fn temporary_path(path: &Path) -> PathBuf {
    let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("record");
    path.with_file_name(format!(".{name}.{}.{}.tmp", std::process::id(), sequence))
}

fn sync_directory(path: &Path) {
    if let Ok(directory) = fs::File::open(path) {
        let _ = directory.sync_all();
    }
}

fn io_error(error: std::io::Error) -> DidError {
    DidError::Io(error.to_string())
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> DidResult<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(io_error)
}

#[cfg(not(unix))]
fn create_private_file(path: &Path) -> DidResult<fs::File> {
    fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(io_error)
}

#[cfg(unix)]
fn open_lock_file(path: &Path) -> DidResult<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .map_err(io_error)
}

#[cfg(not(unix))]
fn open_lock_file(path: &Path) -> DidResult<fs::File> {
    fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)
        .map_err(io_error)
}

#[cfg(unix)]
fn set_private_dir_mode(path: &Path) -> DidResult<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(io_error)
}

#[cfg(not(unix))]
fn set_private_dir_mode(_path: &Path) -> DidResult<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_mode_impl(path: &Path) -> DidResult<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(io_error)
}

#[cfg(not(unix))]
fn set_private_file_mode_impl(_path: &Path) -> DidResult<()> {
    Ok(())
}
