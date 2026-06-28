//! Host key loading and generation (ADR 0015, 0018).
//!
//! When the user supplies `-h/--host-key` files we load them (OpenSSH format,
//! encrypted or not). When none are supplied we auto-generate and persist a
//! single ed25519 key at `~/.sshdt/host_ed25519` (Windows: `%USERPROFILE%`),
//! so a client's `known_hosts` entry stays stable across restarts.

use std::path::{Path, PathBuf};

use russh::keys::key::safe_rng;
use russh::keys::ssh_key::{Algorithm, HashAlg, LineEnding};
use russh::keys::{PrivateKey, load_secret_key};

use crate::{Error, Result};

/// The default host key path: `~/.sshdt/host_ed25519`.
pub fn default_host_key_path() -> Result<PathBuf> {
    let home = dirs::home_dir()
        .ok_or_else(|| Error::HostKeyGenerate("could not determine the home directory".into()))?;
    Ok(home.join(".sshdt").join("host_ed25519"))
}

/// Load the configured host key files, or generate + persist a default
/// ed25519 key when none are configured.
///
/// Each loaded/generated key's fingerprint is emitted via `tracing` so the CLI
/// can print it on startup.
pub fn load_or_generate(paths: &[PathBuf], passphrase: Option<&str>) -> Result<Vec<PrivateKey>> {
    if paths.is_empty() {
        let path = default_host_key_path()?;
        return Ok(vec![load_or_generate_one(&path, passphrase)?]);
    }

    // Each configured path is loaded if present, otherwise generated and
    // persisted there (matching the default-path behaviour; ADR 0015).
    let mut keys = Vec::with_capacity(paths.len());
    for path in paths {
        keys.push(load_or_generate_one(path, passphrase)?);
    }
    Ok(keys)
}

fn load_or_generate_one(path: &Path, passphrase: Option<&str>) -> Result<PrivateKey> {
    if path.exists() {
        let key = load_secret_key(path, passphrase).map_err(|source| Error::HostKeyLoad {
            path: path.to_path_buf(),
            source,
        })?;
        log_fingerprint(path, &key);
        Ok(key)
    } else {
        generate_and_persist(path)
    }
}

fn generate_and_persist(path: &Path) -> Result<PrivateKey> {
    let mut rng = safe_rng();
    let key = PrivateKey::random(&mut rng, Algorithm::Ed25519)
        .map_err(|e| Error::HostKeyGenerate(e.to_string()))?;

    if let Some(dir) = path.parent()
        && !dir.as_os_str().is_empty()
    {
        std::fs::create_dir_all(dir)?;
        set_dir_private(dir);
    }

    // `write_openssh_file` writes an unencrypted OpenSSH key and sets 0600 on
    // Unix itself; a plain key keeps first-run friction (and `known_hosts`)
    // simple, which is the documented default (ADR 0015).
    key.write_openssh_file(path, LineEnding::LF)
        .map_err(|e| Error::HostKeyGenerate(e.to_string()))?;

    tracing::info!(path = %path.display(), "generated new ed25519 host key");
    log_fingerprint(path, &key);
    Ok(key)
}

fn log_fingerprint(path: &Path, key: &PrivateKey) {
    tracing::info!(
        path = %path.display(),
        algorithm = key.algorithm().as_str(),
        fingerprint = %key.fingerprint(HashAlg::Sha256),
        "loaded host key",
    );
}

#[cfg(unix)]
fn set_dir_private(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn set_dir_private(_dir: &Path) {
    // Best-effort only; Windows ACL hardening is out of scope for v1.
}
