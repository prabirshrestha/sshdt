//! The declarative, serializable [`Config`] (ADR 0010, 0019).
//!
//! `Config` holds everything that can be expressed as data: bind address, host
//! key sources, auth settings, the session command, the SFTP root, the
//! forwarding policy and the operational limits. Programmatic hooks (a custom
//! [`Authenticator`](crate::Authenticator), command resolver or session
//! handler) are *not* part of `Config` — they live on the
//! [`ServerBuilder`](crate::ServerBuilder) because closures and trait objects
//! cannot be serialized.

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

/// Default TCP port (`sshd` uses 22; we stay out of the privileged range).
pub const DEFAULT_PORT: u16 = 2222;
/// Default bind address — loopback only (ADR 0018).
pub const DEFAULT_BIND: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
/// Default authentication grace period, in seconds (ADR 0018).
pub const DEFAULT_LOGIN_GRACE_SECS: u64 = 60;
/// Default cap on concurrent unauthenticated connections (ADR 0018).
pub const DEFAULT_MAX_STARTUPS: u32 = 32;

/// The declarative configuration for a [`Server`](crate::Server).
///
/// Construct it directly, load it from a file, or — more ergonomically — use
/// [`Server::builder`](crate::Server::builder). Every field has a documented
/// default; [`Config::default`] yields a safe loopback server with anonymous
/// auth and an auto-generated host key.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "config", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "config", serde(default, rename_all = "kebab-case"))]
#[non_exhaustive]
pub struct Config {
    /// Address to bind. Defaults to `127.0.0.1` (ADR 0018).
    pub bind: IpAddr,

    /// Port to listen on. Defaults to [`DEFAULT_PORT`].
    pub port: u16,

    /// Host key files (OpenSSH format, encrypted or not). When empty, a single
    /// ed25519 key is auto-generated and persisted at `~/.sshdt/host_ed25519`
    /// (ADR 0015, 0018). Repeatable to offer multiple algorithms.
    pub host_keys: Vec<PathBuf>,

    /// Passphrase for an encrypted host key. Prefer the
    /// `SSHDT_HOST_KEY_PASSPHRASE` environment variable in the CLI.
    pub host_key_passphrase: Option<String>,

    /// When `Some`, enables password authentication with this password.
    pub password: Option<String>,

    /// `authorized_keys` files to accept for public-key auth (repeatable).
    pub authorized_keys: Vec<PathBuf>,

    /// Inline authorized public keys, each an OpenSSH one-line string such as
    /// `"ssh-ed25519 AAAA... comment"` (repeatable).
    pub authorized_key_lines: Vec<String>,

    /// Whether anonymous (`none`) authentication is allowed when no password
    /// or public key is configured. Defaults to `true`; an sshd-style
    /// authentication directive disables this fallback.
    pub allow_anonymous: bool,

    /// The interactive session command line (e.g. `"rmux new-session -A"`).
    /// When `None`, an OS-aware default is used: `$SHELL` (else `/bin/sh`) on
    /// Unix; `pwsh` → `powershell` → `cmd` on Windows (ADR 0011).
    pub shell: Option<String>,

    /// When `Some`, jails SFTP/scp to this directory; otherwise the full
    /// filesystem is served as the launching OS user (ADR 0016).
    pub sftp_root: Option<PathBuf>,

    /// Whether `direct-tcpip` forwarding (`ssh -L`) is permitted (ADR 0014).
    /// On by default, matching OpenSSH.
    pub allow_tcp_forwarding: bool,

    /// Authentication grace period in seconds (ADR 0018).
    pub login_grace_secs: u64,

    /// Cap on concurrent unauthenticated connections (ADR 0018).
    pub max_startups: u32,

    /// Client environment variables accepted via `env` requests — an allowlist,
    /// matching `sshd`'s `AcceptEnv` (ADR 0017). Entries ending in `*` are
    /// treated as prefixes (e.g. `LC_*`).
    pub accept_env: Vec<String>,

    /// Optional pre-authentication banner sent to the client.
    pub banner: Option<String>,

    /// When `true`, accept the OS user that launched sshdt (auto-detected at
    /// startup) as an allowed username. Off by default, because the username is
    /// otherwise cosmetic: sshdt is **single-user** — every session runs as the
    /// launching user regardless of the username. For real multi-user
    /// (per-account sessions) run OpenSSH `sshd` instead.
    pub require_current_user: bool,

    /// Explicit allowlist of accepted SSH usernames. **Empty means any username
    /// is accepted** (the default — usernames are cosmetic). Any non-empty list
    /// (here or via [`require_current_user`](Self::require_current_user))
    /// restricts auth to an exact, case-sensitive match against these names.
    pub allow_users: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: DEFAULT_BIND,
            port: DEFAULT_PORT,
            host_keys: Vec::new(),
            host_key_passphrase: None,
            password: None,
            authorized_keys: Vec::new(),
            authorized_key_lines: Vec::new(),
            allow_anonymous: true,
            shell: None,
            sftp_root: None,
            allow_tcp_forwarding: true,
            login_grace_secs: DEFAULT_LOGIN_GRACE_SECS,
            max_startups: DEFAULT_MAX_STARTUPS,
            accept_env: default_accept_env(),
            banner: None,
            require_current_user: false,
            allow_users: Vec::new(),
        }
    }
}

/// The default `AcceptEnv` allowlist (ADR 0017): `TERM`, `LANG`, and `LC_*`.
pub fn default_accept_env() -> Vec<String> {
    vec!["TERM".into(), "LANG".into(), "LC_*".into()]
}

impl Config {
    /// Load a [`Config`] from a file, detecting the format by extension: `.toml`
    /// is parsed as TOML, anything else as `sshd_config` directives (ADR 0019).
    #[cfg(feature = "config")]
    pub fn load_file(path: &std::path::Path) -> crate::Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| crate::Error::ConfigFile {
            path: path.to_path_buf(),
            message: e.to_string(),
        })?;
        let with_path = |e: crate::Error| match e {
            crate::Error::ConfigFile { message, .. } => crate::Error::ConfigFile {
                path: path.to_path_buf(),
                message,
            },
            other => other,
        };
        if path.extension().and_then(|s| s.to_str()) == Some("toml") {
            Self::from_toml(&content).map_err(with_path)
        } else {
            crate::sshd_config::parse_for_user(&content, dirs::home_dir().as_deref())
                .map_err(with_path)
        }
    }

    /// Parse a [`Config`] from a TOML string.
    #[cfg(feature = "config")]
    pub fn from_toml(s: &str) -> crate::Result<Self> {
        toml::from_str(s).map_err(|e| crate::Error::ConfigFile {
            path: PathBuf::from("<toml>"),
            message: e.to_string(),
        })
    }

    /// Serialize this [`Config`] to a TOML string.
    #[cfg(feature = "config")]
    pub fn to_toml(&self) -> crate::Result<String> {
        toml::to_string_pretty(self).map_err(|e| crate::Error::Config(e.to_string()))
    }

    /// Returns whether any explicit authentication method is configured.
    ///
    /// When this and [`allow_anonymous`](Self::allow_anonymous) are both false,
    /// the server rejects all built-in authentication (ADR 0013).
    pub fn has_explicit_auth(&self) -> bool {
        self.password.is_some()
            || !self.authorized_keys.is_empty()
            || !self.authorized_key_lines.is_empty()
    }
}
