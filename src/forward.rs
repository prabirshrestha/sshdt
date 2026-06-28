//! `direct-tcpip` local forwarding (`ssh -L`) and the [`Forwarder`] policy hook
//! (ADR 0014).
//!
//! Forwarding is on by default (OpenSSH parity). The server dials the client's
//! requested target and pumps bytes both ways over the channel.

use russh::Channel;
use russh::server::Msg;
use tokio::net::TcpStream;

/// A client's forwarding request (`ssh -L` target).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ForwardRequest {
    /// The host the client wants the server to connect to.
    pub host: String,
    /// The port the client wants the server to connect to.
    pub port: u16,
    /// The originating host on the client side.
    pub originator_host: String,
    /// The originating port on the client side.
    pub originator_port: u16,
}

/// The policy decision for a forwarding request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ForwardDecision {
    /// Permit the forward.
    Allow,
    /// Reject the forward.
    Deny,
}

/// A forwarding policy hook (builder-only; ADR 0014).
///
/// Implementations can allow, deny, or allowlist `host:port` targets. Combined
/// with the `--no-forward` switch (which denies everything) and the auth layer,
/// this bounds who can use the server as a relay.
pub trait Forwarder: Send + Sync {
    /// Decide whether a forward is permitted.
    fn authorize(&self, request: &ForwardRequest) -> ForwardDecision;
}

/// Run a `direct-tcpip` forward: connect to `host:port` and pump bytes between
/// the TCP stream and the SSH channel until either side closes.
pub(crate) async fn run_direct_tcpip(channel: Channel<Msg>, host: String, port: u16) {
    let target = format!("{host}:{port}");
    let tcp = match TcpStream::connect(&target).await {
        Ok(stream) => stream,
        Err(error) => {
            tracing::debug!(%target, %error, "direct-tcpip connect failed");
            let _ = channel.eof().await;
            let _ = channel.close().await;
            return;
        }
    };

    let mut channel_stream = channel.into_stream();
    let mut tcp = tcp;
    match tokio::io::copy_bidirectional(&mut channel_stream, &mut tcp).await {
        Ok((to_target, to_client)) => {
            tracing::trace!(%target, to_target, to_client, "direct-tcpip closed");
        }
        Err(error) => tracing::debug!(%target, %error, "direct-tcpip stream error"),
    }
}
