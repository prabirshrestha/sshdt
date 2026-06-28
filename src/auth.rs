//! Authentication: declarative built-ins plus a programmatic
//! [`Authenticator`] hook (ADR 0013).
//!
//! The built-ins cover the CLI's needs — **anonymous** (`none`, accepted only
//! when nothing else is configured), **password**, and **publickey** (matched
//! against `authorized_keys` files and inline keys). Embedders can install an
//! [`Authenticator`] for custom logic; it sees the same requests and its
//! decision supersedes the built-ins.

use std::path::Path;

use russh::keys::ssh_key::HashAlg;

pub use russh::keys::PublicKey;

use crate::config::Config;
use crate::util::BoxFuture;
use crate::{Error, Result};

/// The method a client is attempting.
#[derive(Clone)]
#[non_exhaustive]
pub enum AuthMethod {
    /// The `none` method (anonymous).
    None,
    /// A password attempt.
    Password(String),
    /// A public-key attempt.
    PublicKey(PublicKey),
}

impl std::fmt::Debug for AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthMethod::None => f.write_str("None"),
            // Never print the password.
            AuthMethod::Password(_) => f.write_str("Password(***)"),
            AuthMethod::PublicKey(k) => {
                write!(f, "PublicKey({})", k.fingerprint(HashAlg::Sha256))
            }
        }
    }
}

/// A single authentication request handed to an [`Authenticator`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AuthRequest {
    /// The username the client offered (cosmetic under anonymous auth).
    pub user: String,
    /// The method being attempted.
    pub method: AuthMethod,
}

/// The outcome of an authentication attempt.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AuthResult {
    /// Authentication succeeded; the session may proceed.
    Accept,
    /// Authentication failed; the client may try another method.
    Reject,
    /// This method succeeded but more are required (multi-factor); the client
    /// must continue authenticating.
    Partial,
}

/// A programmatic authentication hook (builder-only; ADR 0013).
///
/// Implementations decide each [`AuthRequest`] asynchronously, enabling DB
/// lookups, per-user key stores, or multi-factor flows via [`AuthResult::Partial`].
pub trait Authenticator: Send + Sync {
    /// Decide a single authentication request.
    fn authenticate<'a>(&'a self, request: &'a AuthRequest) -> BoxFuture<'a, AuthResult>;
}

/// The resolved declarative auth derived from [`Config`].
pub(crate) struct AuthConfig {
    /// Whether anonymous (`none`) auth is accepted.
    pub anonymous: bool,
    /// The configured password, if any.
    pub password: Option<String>,
    /// The union of authorized public keys (files + inline).
    pub authorized_keys: Vec<PublicKey>,
}

impl AuthConfig {
    /// Build the auth config from a [`Config`], reading any `authorized_keys`
    /// files and parsing inline keys.
    pub fn from_config(cfg: &Config) -> Result<Self> {
        let mut authorized_keys = Vec::new();
        for path in &cfg.authorized_keys {
            load_authorized_keys_file(path, &mut authorized_keys)?;
        }
        for line in &cfg.authorized_key_lines {
            authorized_keys.push(parse_public_key_line(line)?);
        }
        Ok(Self {
            anonymous: !cfg.has_explicit_auth(),
            password: cfg.password.clone(),
            authorized_keys,
        })
    }

    /// The set of SSH methods to advertise to clients.
    pub fn method_set(&self, has_hook: bool) -> russh::MethodSet {
        use russh::{MethodKind, MethodSet};

        let mut kinds = Vec::new();
        if has_hook {
            // A custom authenticator may accept any method; advertise them all
            // and let the hook decide.
            kinds.push(MethodKind::None);
            kinds.push(MethodKind::PublicKey);
            kinds.push(MethodKind::Password);
        } else {
            if self.anonymous {
                kinds.push(MethodKind::None);
            }
            if !self.authorized_keys.is_empty() {
                kinds.push(MethodKind::PublicKey);
            }
            if self.password.is_some() {
                kinds.push(MethodKind::Password);
            }
        }
        if kinds.is_empty() {
            kinds.push(MethodKind::None);
        }
        MethodSet::from(&kinds[..])
    }

    /// Check a password attempt against the configured password.
    pub fn check_password(&self, password: &str) -> bool {
        match &self.password {
            Some(expected) => constant_time_eq(expected.as_bytes(), password.as_bytes()),
            None => false,
        }
    }

    /// Check whether an offered public key is authorized.
    pub fn check_publickey(&self, key: &PublicKey) -> bool {
        self.authorized_keys
            .iter()
            .any(|k| k.key_data() == key.key_data())
    }
}

/// Read an `authorized_keys` file, appending each valid key. Invalid lines are
/// warned about and skipped (forward-compat).
fn load_authorized_keys_file(path: &Path, out: &mut Vec<PublicKey>) -> Result<()> {
    let content = std::fs::read_to_string(path).map_err(|source| Error::AuthorizedKeys {
        path: path.to_path_buf(),
        source,
    })?;
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match PublicKey::from_openssh(line) {
            Ok(key) => out.push(key),
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "skipping invalid authorized_keys entry");
            }
        }
    }
    Ok(())
}

/// Parse a single inline public-key line (`"ssh-ed25519 AAAA... comment"`).
fn parse_public_key_line(line: &str) -> Result<PublicKey> {
    PublicKey::from_openssh(line.trim())
        .map_err(|e| Error::PublicKey(format!("could not parse inline public key: {e}")))
}

/// A best-effort constant-time byte comparison, to avoid leaking password
/// length/content through timing. Not security-critical for an anonymous-by-
/// default server, but cheap to do right.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
