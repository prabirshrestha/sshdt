//! The per-connection `russh` [`Handler`]: auth, channel multiplexing, and
//! dispatch to the session runner, SFTP and forwarding.
//!
//! One `ConnectionHandler` is created per accepted connection. `russh` drives
//! its methods serially, so the per-channel state map needs no locking.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use russh::keys::ssh_key::PublicKey;
use russh::server::{Auth, Handler, Msg, Session};
use russh::{Channel, ChannelId, Pty};
use tokio::sync::OwnedSemaphorePermit;
use tokio::sync::mpsc;

use crate::auth::{AuthMethod, AuthRequest, AuthResult};
use crate::forward::{ForwardDecision, ForwardRequest};
use crate::server::ServerInner;
use crate::session::{self, PtyRequest, SessionRequest};

/// The per-connection handler.
pub(crate) struct ConnectionHandler {
    inner: Arc<ServerInner>,
    channels: HashMap<ChannelId, ChannelState>,
    /// Set true once any auth method succeeds (read by the accept loop's
    /// login-grace timer).
    authed: Arc<AtomicBool>,
    /// The startup-cap permit, dropped on auth success to free the slot.
    startup_permit: Option<OwnedSemaphorePermit>,
}

/// Per-channel accumulated state, built up by `pty/env` requests before the
/// session starts.
#[derive(Default)]
struct ChannelState {
    /// The owned channel, taken when the session (or SFTP) starts.
    channel: Option<Channel<Msg>>,
    /// A PTY request, if the client allocated one.
    pty: Option<PtyRequest>,
    /// Allowlisted client environment.
    env: Vec<(String, String)>,
    /// Resize sender into the running session (set once started).
    resize: Option<mpsc::UnboundedSender<(u16, u16)>>,
    /// Whether this channel is running the SFTP subsystem.
    sftp: bool,
}

/// Which kind of session a `shell`/`exec` request starts.
enum SessionKindReq {
    Shell,
    Exec(String),
}

impl ConnectionHandler {
    pub(crate) fn new(
        inner: Arc<ServerInner>,
        authed: Arc<AtomicBool>,
        startup_permit: Option<OwnedSemaphorePermit>,
    ) -> Self {
        Self {
            inner,
            channels: HashMap::new(),
            authed,
            startup_permit,
        }
    }

    /// Mark the connection authenticated: free the startup slot and stop the
    /// login-grace timer. The SSH username is cosmetic (sessions run as the OS
    /// user that launched sshdt), so it is logged but not otherwise retained.
    fn mark_authenticated(&mut self, user: &str) {
        tracing::debug!(user, "authenticated");
        self.authed.store(true, Ordering::SeqCst);
        self.startup_permit = None;
    }

    /// A rejection that keeps the configured methods available so the client
    /// can try another. (A bare `Auth::reject()` carries
    /// `proceed_with_methods: None`, which makes russh *remove* the attempted
    /// method — leaving the client nothing to retry and forcing a disconnect.)
    fn reject(&self) -> Auth {
        Auth::Reject {
            proceed_with_methods: Some(
                self.inner
                    .auth
                    .method_set(self.inner.authenticator.is_some()),
            ),
            partial_success: false,
        }
    }

    /// Whether `user` is allowed by the username allowlist. An empty allowlist
    /// (the default) permits every username — it is cosmetic, since the session
    /// runs as the launching OS user regardless. Otherwise the match is exact.
    fn user_allowed(&self, user: &str) -> bool {
        let allowed = &self.inner.allowed_users;
        allowed.is_empty() || allowed.iter().any(|name| name == user)
    }

    /// Decide an authentication attempt: a custom [`Authenticator`] supersedes
    /// the declarative built-ins.
    async fn decide(&self, user: &str, method: AuthMethod) -> Auth {
        if !self.user_allowed(user) {
            tracing::debug!(
                user,
                "rejecting auth: username not permitted by strict-user policy"
            );
            return self.reject();
        }
        if let Some(hook) = &self.inner.authenticator {
            let request = AuthRequest {
                user: user.to_string(),
                method,
            };
            return match hook.authenticate(&request).await {
                AuthResult::Accept => Auth::Accept,
                AuthResult::Partial => Auth::Reject {
                    proceed_with_methods: Some(self.inner.auth.method_set(true)),
                    partial_success: true,
                },
                AuthResult::Reject => self.reject(),
            };
        }

        let ok = match &method {
            AuthMethod::None => self.inner.auth.anonymous,
            AuthMethod::Password(p) => self.inner.auth.check_password(p),
            AuthMethod::PublicKey(k) => self.inner.auth.check_publickey(k),
        };
        if ok { Auth::Accept } else { self.reject() }
    }

    /// Start a shell/exec session on a channel by spawning the generic runner.
    fn start_session(
        &mut self,
        id: ChannelId,
        kind: SessionKindReq,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        let Some(state) = self.channels.get_mut(&id) else {
            session.channel_failure(id)?;
            return Ok(());
        };
        let Some(channel) = state.channel.take() else {
            session.channel_failure(id)?;
            return Ok(());
        };
        let pty = state.pty.clone();
        let env = std::mem::take(&mut state.env);
        let (resize_tx, resize_rx) = mpsc::unbounded_channel();
        state.resize = Some(resize_tx);

        let request = match kind {
            SessionKindReq::Shell => SessionRequest::Shell { pty },
            SessionKindReq::Exec(command) => SessionRequest::Exec { command, pty },
        };
        let command = self.inner.command_resolver.resolve(&request);

        session.channel_success(id)?;

        tokio::spawn(session::run_session(
            channel,
            request,
            command,
            env,
            resize_rx,
            self.inner.session_handler.clone(),
        ));
        Ok(())
    }
}

impl Handler for ConnectionHandler {
    type Error = russh::Error;

    async fn authentication_banner(&mut self) -> Result<Option<String>, Self::Error> {
        Ok(self.inner.banner.clone())
    }

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        let auth = self.decide(user, AuthMethod::None).await;
        if matches!(auth, Auth::Accept) {
            self.mark_authenticated(user);
        }
        Ok(auth)
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        let auth = self
            .decide(user, AuthMethod::Password(password.to_string()))
            .await;
        if matches!(auth, Auth::Accept) {
            self.mark_authenticated(user);
        }
        Ok(auth)
    }

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        // With a custom authenticator we can't pre-judge; let the signed
        // attempt through to `auth_publickey`. Otherwise reject a disallowed
        // username or an unlisted key early to save a signature round-trip.
        if !self.user_allowed(user) {
            Ok(self.reject())
        } else if self.inner.authenticator.is_some() || self.inner.auth.check_publickey(public_key)
        {
            Ok(Auth::Accept)
        } else {
            Ok(self.reject())
        }
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        let auth = self
            .decide(user, AuthMethod::PublicKey(public_key.clone()))
            .await;
        if matches!(auth, Auth::Accept) {
            self.mark_authenticated(user);
        }
        Ok(auth)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let id = channel.id();
        tracing::debug!(?id, "session channel opened");
        self.channels.insert(
            id,
            ChannelState {
                channel: Some(channel),
                ..Default::default()
            },
        );
        Ok(true)
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let pty = PtyRequest {
            term: term.to_string(),
            cols: col_width as u16,
            rows: row_height as u16,
            pixel_width: pix_width as u16,
            pixel_height: pix_height as u16,
        };
        if let Some(state) = self.channels.get_mut(&channel) {
            state.pty = Some(pty);
        }
        session.channel_success(channel)?;
        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if env_allowed(variable_name, &self.inner.accept_env) {
            if let Some(state) = self.channels.get_mut(&channel) {
                state
                    .env
                    .push((variable_name.to_string(), variable_value.to_string()));
            }
            session.channel_success(channel)?;
        } else {
            tracing::trace!(
                name = variable_name,
                "rejecting env request (not in AcceptEnv)"
            );
            session.channel_failure(channel)?;
        }
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(state) = self.channels.get(&channel)
            && let Some(resize) = &state.resize
        {
            let _ = resize.send((col_width as u16, row_height as u16));
        }
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.start_session(channel, SessionKindReq::Shell, session)
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data).into_owned();
        tracing::debug!(?channel, %command, "exec request");
        self.start_session(channel, SessionKindReq::Exec(command), session)
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name == "sftp" {
            let taken = self.channels.get_mut(&channel).and_then(|s| {
                s.sftp = true;
                s.channel.take()
            });
            match taken {
                Some(ch) => {
                    session.channel_success(channel)?;
                    crate::sftp::spawn(ch, self.inner.sftp_root.clone());
                }
                None => session.channel_failure(channel)?,
            }
        } else {
            session.channel_failure(channel)?;
        }
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        if !self.inner.allow_tcp_forwarding {
            tracing::debug!("direct-tcpip denied (forwarding disabled)");
            return Ok(false);
        }
        let request = ForwardRequest {
            host: host_to_connect.to_string(),
            port: port_to_connect as u16,
            originator_host: originator_address.to_string(),
            originator_port: originator_port as u16,
        };
        if let Some(forwarder) = &self.inner.forwarder
            && forwarder.authorize(&request) == ForwardDecision::Deny
        {
            tracing::debug!(host = %request.host, port = request.port, "direct-tcpip denied by policy");
            return Ok(false);
        }
        tokio::spawn(crate::forward::run_direct_tcpip(
            channel,
            request.host,
            request.port,
        ));
        Ok(true)
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // The SFTP subsystem has no process to report an exit status, but real
        // `scp` (which runs over SFTP) treats a missing exit-status as failure.
        // When the client signals EOF, the transfer is complete, so report a
        // clean exit and close the channel.
        if self.channels.get(&channel).is_some_and(|s| s.sftp) {
            let _ = session.exit_status_request(channel, 0);
            let _ = session.eof(channel);
            let _ = session.close(channel);
        }
        // For session (process) channels, the runner observes stdin EOF via the
        // channel itself; nothing extra to do here.
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Drop per-channel state; the spawned session task owns its channel
        // halves independently and winds down on its own.
        tracing::debug!(?channel, "channel closed");
        self.channels.remove(&channel);
        Ok(())
    }
}

/// Whether a client env var is allowed by the `AcceptEnv` allowlist. A trailing
/// `*` is a prefix match (e.g. `LC_*`).
fn env_allowed(name: &str, allowlist: &[String]) -> bool {
    allowlist
        .iter()
        .any(|pattern| match pattern.strip_suffix('*') {
            Some(prefix) => name.starts_with(prefix),
            None => name == pattern,
        })
}

#[cfg(test)]
mod tests {
    use super::env_allowed;

    #[test]
    fn accept_env_matches_exact_and_prefix() {
        let allow = vec!["TERM".to_string(), "LANG".to_string(), "LC_*".to_string()];
        assert!(env_allowed("TERM", &allow));
        assert!(env_allowed("LANG", &allow));
        assert!(env_allowed("LC_ALL", &allow));
        assert!(env_allowed("LC_CTYPE", &allow));
        assert!(!env_allowed("PATH", &allow));
        assert!(!env_allowed("LD_PRELOAD", &allow));
    }
}
