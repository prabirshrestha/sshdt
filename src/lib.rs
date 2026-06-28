//! `sshdt` — a tiny, faithful, standard SSH server (library + CLI).
//!
//! `sshdt` is a small SSH **server** built on [`russh`] that any normal `ssh`
//! client — and IDE-over-SSH tools like VS Code Remote-SSH and Zed Remote — can
//! connect to. It speaks `exec`, an interactive shell/PTY, SFTP, and
//! `direct-tcpip` (`ssh -L`) forwarding, and it runs real processes as the OS
//! user that launched it.
//!
//! The library has **no global state**: every [`Server`] owns its host keys,
//! auth, command runner and bind address, so many can run in one process. The
//! library only *emits* `tracing` events; installing a subscriber is the
//! binary's job.
//!
//! # Quick start
//!
//! ```no_run
//! # async fn run() -> sshdt::Result<()> {
//! let handle = sshdt::Server::builder()
//!     .port(2222)
//!     .serve_build()
//!     .await?;
//! println!("listening on {}", handle.local_addr());
//! handle.join().await;
//! # Ok(())
//! # }
//! ```
//!
//! [`russh`]: https://docs.rs/russh

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod auth;
mod config;
mod error;
mod forward;
mod handler;
mod hostkey;
mod server;
mod session;
mod sftp;
mod util;

#[cfg(feature = "config")]
pub mod sshd_config;

pub use auth::{AuthMethod, AuthRequest, AuthResult, Authenticator, PublicKey};
pub use config::{
    Config, DEFAULT_BIND, DEFAULT_LOGIN_GRACE_SECS, DEFAULT_MAX_STARTUPS, DEFAULT_PORT,
};
pub use error::{Error, Result};
pub use forward::{ForwardDecision, ForwardRequest, Forwarder};
pub use hostkey::default_host_key_path;
pub use server::{Server, ServerBuilder, ServerHandle};
pub use session::{
    ChannelIo, CommandResolver, PtyRequest, ResizeStream, SessionCommand, SessionHandler,
    SessionRequest,
};
pub use util::BoxFuture;

impl ServerBuilder {
    /// Convenience: [`build`](ServerBuilder::build) then
    /// [`serve`](Server::serve).
    pub async fn serve_build(self) -> Result<ServerHandle> {
        self.build()?.serve().await
    }
}
