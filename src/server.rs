//! The [`Server`] instance, its fluent [`ServerBuilder`], and the
//! [`ServerHandle`] returned by [`Server::serve`] (ADR 0003, 0010, 0018).
//!
//! Everything a server needs is owned by the instance — there is no global or
//! static state, so many `Server`s can run in one process.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, oneshot};

use crate::auth::{AuthConfig, Authenticator};
use crate::config::Config;
use crate::forward::Forwarder;
use crate::handler::ConnectionHandler;
use crate::session::{CommandResolver, DefaultResolver, SessionHandler};
use crate::{Error, Result, hostkey};

/// The resolved, shared per-server state handed to each connection handler.
pub(crate) struct ServerInner {
    pub(crate) auth: AuthConfig,
    pub(crate) authenticator: Option<Arc<dyn Authenticator>>,
    pub(crate) command_resolver: Arc<dyn CommandResolver>,
    pub(crate) session_handler: Option<Arc<dyn SessionHandler>>,
    pub(crate) forwarder: Option<Arc<dyn Forwarder>>,
    pub(crate) allow_tcp_forwarding: bool,
    pub(crate) sftp_root: Option<PathBuf>,
    pub(crate) accept_env: Vec<String>,
    pub(crate) banner: Option<String>,
    /// The allowlist of accepted SSH usernames. **Empty accepts any username**
    /// (the default — the username is cosmetic, since every session runs as the
    /// launching OS user regardless); non-empty restricts to an exact match.
    pub(crate) allowed_users: Vec<String>,
}

/// A configured, ready-to-run SSH server instance.
pub struct Server {
    inner: Arc<ServerInner>,
    russh_config: Arc<russh::server::Config>,
    bind: SocketAddr,
    max_startups: u32,
    login_grace: Duration,
}

impl Server {
    /// Start a fluent builder.
    pub fn builder() -> ServerBuilder {
        ServerBuilder::new()
    }

    /// Build a server from a declarative [`Config`] (ADR 0010). Programmatic
    /// hooks can still be layered via [`Server::builder`] +
    /// [`ServerBuilder::from_config`].
    pub fn from_config(config: Config) -> Result<Self> {
        ServerBuilder::from_config(config).build()
    }

    /// The socket address this server will bind.
    pub fn bind_addr(&self) -> SocketAddr {
        self.bind
    }

    /// Bind and start serving, returning a [`ServerHandle`] for shutdown.
    pub async fn serve(self) -> Result<ServerHandle> {
        let listener = TcpListener::bind(self.bind)
            .await
            .map_err(|source| Error::Bind {
                addr: self.bind,
                source,
            })?;
        let local_addr = listener.local_addr().map_err(|source| Error::Bind {
            addr: self.bind,
            source,
        })?;
        tracing::info!(%local_addr, "sshdt listening");

        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        let inner = self.inner;
        let russh_config = self.russh_config;
        let semaphore = Arc::new(Semaphore::new(self.max_startups.max(1) as usize));
        let grace = self.login_grace;

        let join = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        tracing::debug!("accept loop shutting down");
                        break;
                    }
                    accept = listener.accept() => {
                        let (stream, peer) = match accept {
                            Ok(pair) => pair,
                            Err(error) => {
                                tracing::warn!(%error, "accept failed");
                                continue;
                            }
                        };
                        let _ = stream.set_nodelay(true);
                        tokio::spawn(handle_connection(
                            russh_config.clone(),
                            stream,
                            peer,
                            inner.clone(),
                            semaphore.clone(),
                            grace,
                        ));
                    }
                }
            }
        });

        Ok(ServerHandle {
            local_addr,
            shutdown: Some(shutdown_tx),
            join,
        })
    }

    /// Serve a single, already-established byte stream to completion.
    ///
    /// This is the seam ADR 0001 calls out (a `TcpStream` today, a tunnel
    /// stream later) and is what the in-process Tier-1 tests drive over
    /// `tokio::io::duplex()`. It applies no login-grace or startup limit; those
    /// are properties of the accept loop.
    pub async fn serve_connection<S>(&self, stream: S) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let handler =
            ConnectionHandler::new(self.inner.clone(), Arc::new(AtomicBool::new(false)), None);
        let session = russh::server::run_stream(self.russh_config.clone(), stream, handler).await?;
        session.await?;
        Ok(())
    }
}

/// Handle one accepted connection: enforce the startup cap and login grace.
async fn handle_connection(
    config: Arc<russh::server::Config>,
    stream: TcpStream,
    peer: SocketAddr,
    inner: Arc<ServerInner>,
    semaphore: Arc<Semaphore>,
    grace: Duration,
) {
    // Cap concurrent *unauthenticated* connections: hold the permit until the
    // handler drops it on auth success (or the connection ends).
    let permit = match semaphore.acquire_owned().await {
        Ok(permit) => permit,
        Err(_) => return, // semaphore closed
    };

    tracing::debug!(%peer, "connection accepted");

    let authed = Arc::new(AtomicBool::new(false));
    let handler = ConnectionHandler::new(inner, authed.clone(), Some(permit));

    let session = match russh::server::run_stream(config, stream, handler).await {
        Ok(session) => session,
        Err(error) => {
            tracing::debug!(%peer, %error, "ssh handshake failed");
            return;
        }
    };

    let mut session = Box::pin(session);
    match tokio::time::timeout(grace, &mut session).await {
        Ok(result) => match result {
            Ok(()) => tracing::debug!(%peer, "connection closed"),
            Err(error) => tracing::debug!(%peer, %error, "connection closed with error"),
        },
        Err(_) => {
            if authed.load(Ordering::SeqCst) {
                // Authenticated in time; let the session run to completion.
                let _ = session.await;
                tracing::debug!(%peer, "authenticated connection closed");
            } else {
                tracing::debug!(%peer, "login grace expired before authentication");
                // Dropping the session future closes the connection.
            }
        }
    }
}

/// A handle to a running [`Server`]: shut it down or await it.
pub struct ServerHandle {
    local_addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    join: tokio::task::JoinHandle<()>,
}

impl ServerHandle {
    /// The actual bound address (useful when binding an ephemeral `:0` port).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Signal the accept loop to stop and wait for it to finish. In-flight
    /// connections are not forcibly killed; they end on their own.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        let _ = self.join.await;
    }

    /// Await the accept loop (runs until [`ServerHandle::shutdown`] or an
    /// unrecoverable accept error).
    pub async fn join(self) {
        let _ = self.join.await;
    }
}

/// A fluent builder for a [`Server`] (ADR 0010).
pub struct ServerBuilder {
    config: Config,
    authenticator: Option<Arc<dyn Authenticator>>,
    command_resolver: Option<Arc<dyn CommandResolver>>,
    session_handler: Option<Arc<dyn SessionHandler>>,
    forwarder: Option<Arc<dyn Forwarder>>,
}

impl ServerBuilder {
    /// A builder with default configuration.
    pub fn new() -> Self {
        Self::from_config(Config::default())
    }

    /// A builder seeded from a declarative [`Config`]; hooks can be layered on
    /// afterwards (ADR 0010, 0012, 0013).
    pub fn from_config(config: Config) -> Self {
        Self {
            config,
            authenticator: None,
            command_resolver: None,
            session_handler: None,
            forwarder: None,
        }
    }

    /// Replace the entire [`Config`].
    pub fn config(mut self, config: Config) -> Self {
        self.config = config;
        self
    }

    /// Set the bind address.
    pub fn bind(mut self, addr: std::net::IpAddr) -> Self {
        self.config.bind = addr;
        self
    }

    /// Set the listen port.
    pub fn port(mut self, port: u16) -> Self {
        self.config.port = port;
        self
    }

    /// Add a host key file (repeatable).
    pub fn host_key(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.host_keys.push(path.into());
        self
    }

    /// Set the passphrase for an encrypted host key.
    pub fn host_key_passphrase(mut self, passphrase: impl Into<String>) -> Self {
        self.config.host_key_passphrase = Some(passphrase.into());
        self
    }

    /// Enable password authentication.
    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.config.password = Some(password.into());
        self
    }

    /// Add an `authorized_keys` file (repeatable).
    pub fn authorized_keys(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.authorized_keys.push(path.into());
        self
    }

    /// Add an inline authorized public key (repeatable).
    pub fn pubkey(mut self, key_line: impl Into<String>) -> Self {
        self.config.authorized_key_lines.push(key_line.into());
        self
    }

    /// Set the interactive session command line.
    pub fn shell(mut self, command_line: impl Into<String>) -> Self {
        self.config.shell = Some(command_line.into());
        self
    }

    /// Jail SFTP/scp to a directory.
    pub fn sftp_root(mut self, dir: impl Into<PathBuf>) -> Self {
        self.config.sftp_root = Some(dir.into());
        self
    }

    /// Enable or disable `direct-tcpip` forwarding.
    pub fn allow_tcp_forwarding(mut self, allow: bool) -> Self {
        self.config.allow_tcp_forwarding = allow;
        self
    }

    /// Set the login grace period.
    pub fn login_grace(mut self, grace: Duration) -> Self {
        self.config.login_grace_secs = grace.as_secs();
        self
    }

    /// Set the cap on concurrent unauthenticated connections.
    pub fn max_startups(mut self, n: u32) -> Self {
        self.config.max_startups = n;
        self
    }

    /// Replace the `AcceptEnv` allowlist.
    pub fn accept_env(mut self, patterns: Vec<String>) -> Self {
        self.config.accept_env = patterns;
        self
    }

    /// Set a pre-authentication banner.
    pub fn banner(mut self, banner: impl Into<String>) -> Self {
        self.config.banner = Some(banner.into());
        self
    }

    /// Add the OS user that launched sshdt (auto-detected at
    /// [`build`](ServerBuilder::build)) to the accepted-username allowlist;
    /// every other SSH username is then rejected. Off by default — the username
    /// is otherwise cosmetic, since sshdt is single-user and runs every session
    /// as the launching user regardless. Composes with [`allow_user`](Self::allow_user).
    pub fn require_current_user(mut self, require: bool) -> Self {
        self.config.require_current_user = require;
        self
    }

    /// Add an explicit SSH username to the accepted-username allowlist
    /// (repeatable). Any non-empty allowlist restricts auth to an exact,
    /// case-sensitive match. Use this to validate against a username you supply
    /// rather than the auto-detected launching user.
    pub fn allow_user(mut self, user: impl Into<String>) -> Self {
        self.config.allow_users.push(user.into());
        self
    }

    /// Install a custom [`Authenticator`] (supersedes built-ins; ADR 0013).
    pub fn authenticator(mut self, authenticator: Arc<dyn Authenticator>) -> Self {
        self.authenticator = Some(authenticator);
        self
    }

    /// Install a custom [`CommandResolver`] (ADR 0012).
    pub fn command_resolver(mut self, resolver: Arc<dyn CommandResolver>) -> Self {
        self.command_resolver = Some(resolver);
        self
    }

    /// Install a custom [`SessionHandler`] escape hatch (ADR 0012).
    pub fn session_handler(mut self, handler: Arc<dyn SessionHandler>) -> Self {
        self.session_handler = Some(handler);
        self
    }

    /// Install a custom [`Forwarder`] policy (ADR 0014).
    pub fn forwarder(mut self, forwarder: Arc<dyn Forwarder>) -> Self {
        self.forwarder = Some(forwarder);
        self
    }

    /// Borrow the current configuration.
    pub fn current_config(&self) -> &Config {
        &self.config
    }

    /// Validate, load host keys, and produce a ready [`Server`].
    pub fn build(self) -> Result<Server> {
        let config = self.config;

        let passphrase = config
            .host_key_passphrase
            .clone()
            .or_else(|| std::env::var("SSHDT_HOST_KEY_PASSPHRASE").ok());
        let keys = hostkey::load_or_generate(&config.host_keys, passphrase.as_deref())?;
        if keys.is_empty() {
            return Err(Error::NoHostKey);
        }

        let auth = AuthConfig::from_config(&config)?;
        let methods = auth.method_set(self.authenticator.is_some());

        let russh_config = russh::server::Config {
            methods,
            keys,
            // IDE control channels are long-lived; don't drop idle connections.
            inactivity_timeout: None,
            // Keep this small: it delays the rejection of the client's initial
            // `none` probe, so a large value slows *every* connection (and IDE
            // clients open several). 250ms still mildly throttles real
            // brute-force password attempts.
            auth_rejection_time: Duration::from_millis(250),
            nodelay: true,
            // IDE control channels are long-lived and legitimately idle, so we
            // don't use an inactivity timeout. Instead, send keepalives and drop
            // a connection only after several go unanswered — this reaps dead /
            // abandoned connections (e.g. an IDE that vanished without a clean
            // close) without disconnecting a live-but-idle session.
            keepalive_interval: Some(Duration::from_secs(30)),
            keepalive_max: 3,
            ..Default::default()
        };

        let command_resolver: Arc<dyn CommandResolver> = self
            .command_resolver
            .unwrap_or_else(|| Arc::new(DefaultResolver::new(config.shell.as_deref())));

        let login_grace = if config.login_grace_secs == 0 {
            Duration::from_secs(u64::MAX / 2)
        } else {
            Duration::from_secs(config.login_grace_secs)
        };

        // Resolve the username allowlist now, while we still have the launching
        // process's environment. `--strict-user` adds the current OS user to any
        // explicit `allow_users`. An empty result accepts any username.
        let mut allowed_users = config.allow_users.clone();
        if config.require_current_user {
            match crate::util::current_os_user() {
                Some(user) => allowed_users.push(user),
                None if allowed_users.is_empty() => {
                    return Err(Error::Config(
                        "strict-user mode is enabled but the current OS user could not be \
                         determined (USER/LOGNAME/USERNAME are unset); pass --allow-user instead"
                            .into(),
                    ));
                }
                None => tracing::warn!(
                    "could not determine the current OS user; restricting to the explicit allow-user list only"
                ),
            }
        }
        if !allowed_users.is_empty() {
            tracing::debug!(?allowed_users, "restricting accepted usernames");
        }

        let inner = Arc::new(ServerInner {
            auth,
            authenticator: self.authenticator,
            command_resolver,
            session_handler: self.session_handler,
            forwarder: self.forwarder,
            allow_tcp_forwarding: config.allow_tcp_forwarding,
            sftp_root: config.sftp_root.clone(),
            accept_env: config.accept_env.clone(),
            banner: config.banner.clone(),
            allowed_users,
        });

        Ok(Server {
            inner,
            russh_config: Arc::new(russh_config),
            bind: SocketAddr::new(config.bind, config.port),
            max_startups: config.max_startups,
            login_grace,
        })
    }
}

impl Default for ServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}
