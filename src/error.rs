//! The library's typed error (ADR 0008). Embedders can match on variants; the
//! CLI wraps these in `anyhow`.

use std::net::SocketAddr;
use std::path::PathBuf;

/// Convenience alias used throughout the library.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Everything that can go wrong inside `sshdt`.
///
/// Marked `#[non_exhaustive]` so new variants can be added without a breaking
/// change.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A generic I/O failure.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// The address could not be bound.
    #[error("failed to bind {addr}: {source}")]
    Bind {
        /// The address we tried to bind.
        addr: SocketAddr,
        /// The underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// A host key file could not be loaded.
    #[error("failed to load host key {path}: {source}")]
    HostKeyLoad {
        /// The host key path.
        path: PathBuf,
        /// The underlying key error.
        #[source]
        source: russh::keys::Error,
    },

    /// A host key could not be generated or persisted.
    #[error("failed to generate host key: {0}")]
    HostKeyGenerate(String),

    /// No usable host key was available after loading/generation.
    #[error("no host key available")]
    NoHostKey,

    /// An `authorized_keys` file could not be read.
    #[error("failed to read authorized_keys {path}: {source}")]
    AuthorizedKeys {
        /// The file path.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// A public key string could not be parsed.
    #[error("invalid public key: {0}")]
    PublicKey(String),

    /// A configuration value was invalid.
    #[error("invalid configuration: {0}")]
    Config(String),

    /// The configuration file could not be parsed.
    #[error("failed to parse config file {path}: {message}")]
    ConfigFile {
        /// The config file path.
        path: PathBuf,
        /// A human-readable description.
        message: String,
    },

    /// An error from the underlying `russh` engine.
    #[error("ssh error: {0}")]
    Ssh(#[from] russh::Error),

    /// An error from `russh`'s key handling.
    #[error("key error: {0}")]
    Key(#[from] russh::keys::Error),
}
