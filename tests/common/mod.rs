//! Shared helpers for the in-process test suite.
//!
//! Each test builds a real [`sshdt::Server`], serves one end of a
//! `tokio::io::duplex()` pipe via [`Server::serve_connection`], and drives a
//! real `russh` client over the other end — exercising the full SSH stack
//! without touching the network.

#![allow(dead_code)]

use std::sync::Arc;

use russh::client;
use russh::keys::PrivateKey;
use russh::keys::key::safe_rng;
use russh::keys::ssh_key::Algorithm;
use sshdt::{Server, ServerBuilder};
use tempfile::TempDir;

/// A minimal client handler that trusts any host key.
pub struct TrustingClient;

impl client::Handler for TrustingClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// A builder seeded with a throwaway host key under a temp dir, so tests never
/// touch the real `~/.sshdt/`. Keep the returned [`TempDir`] alive for the test.
pub fn builder() -> (TempDir, ServerBuilder) {
    let dir = tempfile::tempdir().expect("tempdir");
    let host_key = dir.path().join("host_ed25519");
    let builder = Server::builder().host_key(host_key);
    (dir, builder)
}

/// Generate a fresh ed25519 keypair for client-auth tests.
pub fn gen_keypair() -> PrivateKey {
    PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519).expect("keygen")
}

/// The OpenSSH one-line public-key string for an authorized_keys entry.
pub fn public_line(key: &PrivateKey) -> String {
    key.public_key().to_openssh().expect("to_openssh")
}

/// Serve `server` over one end of a fresh duplex pipe and return a connected,
/// **unauthenticated** client handle for the other end.
pub async fn connect(server: Server) -> client::Handle<TrustingClient> {
    connect_arc(Arc::new(server)).await
}

/// Like [`connect`], but keeps the [`Server`] shared so it can accept several
/// independent connections (each call serves a fresh duplex stream).
pub async fn connect_arc(server: Arc<Server>) -> client::Handle<TrustingClient> {
    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    tokio::spawn(async move {
        let _ = server.serve_connection(server_io).await;
    });
    let config = Arc::new(client::Config::default());
    client::connect_stream(config, client_io, TrustingClient)
        .await
        .expect("client connect")
}

/// stdout, stderr and exit code collected from a session channel.
#[derive(Default, Debug)]
pub struct Output {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub code: Option<u32>,
}

impl Output {
    pub fn stdout_str(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
    pub fn stderr_str(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

/// Drain a channel to EOF, separating stdout/stderr and capturing exit status.
pub async fn collect(channel: &mut russh::Channel<client::Msg>) -> Output {
    use russh::ChannelMsg;
    let mut out = Output::default();
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { data } => out.stdout.extend_from_slice(&data),
            ChannelMsg::ExtendedData { data, ext: 1 } => out.stderr.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status } => out.code = Some(exit_status),
            ChannelMsg::Eof | ChannelMsg::Close => {}
            _ => {}
        }
    }
    out
}

/// Run `command` via `exec` on a fresh channel and collect its output.
pub async fn exec(handle: &client::Handle<TrustingClient>, command: &str) -> Output {
    let mut channel = handle.channel_open_session().await.expect("open session");
    channel.exec(true, command).await.expect("exec");
    collect(&mut channel).await
}
