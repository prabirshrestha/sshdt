//! Multiplexer session **persistence across reconnect** (rmux), gated on `rmux`
//! + `ssh` being installed (Unix only).
//!
//! This exercises the full interactive PTY path end to end: `ssh -tt` lands in an
//! rmux session running on a server-side PTY (via `rmux-pty`), exactly like the
//! well-worn `ssh -t host rmux` pattern. rmux's own daemon keeps the session
//! alive when the SSH connection drops, so a reconnect lands back in the *same*
//! session.
//!
//! To stay robust we never parse the multiplexer's full-screen TUI output.
//! Instead the session's inner shell records its PID to a file the moment the
//! session is created; we then prove the session survived a disconnect and a
//! fresh `ssh -tt` reattaches to it (the SSH process stays alive, the daemon
//! still has the session, and the recorded PID is unchanged).

#![cfg(unix)]

use std::process::Stdio;
use std::time::Duration;

use sshdt::Server;
use tempfile::TempDir;
use tokio::process::{Child, Command};

fn have(bin: &str) -> bool {
    std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {bin}"))
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

async fn start(shell: String) -> (TempDir, sshdt::ServerHandle, u16) {
    let dir = tempfile::tempdir().unwrap();
    let handle = Server::builder()
        .bind("127.0.0.1".parse().unwrap())
        .port(0)
        .host_key(dir.path().join("host_key"))
        .shell(shell)
        .serve_build()
        .await
        .unwrap();
    let port = handle.local_addr().port();
    (dir, handle, port)
}

/// Spawn `ssh -tt` with a held-open stdin pipe so the client stays attached
/// (forcing remote PTY allocation) until we kill it.
fn ssh_attach(dir: &TempDir, port: u16) -> Child {
    let known = dir.path().join("known_hosts");
    Command::new("ssh")
        .arg("-tt")
        .args(["-o", "StrictHostKeyChecking=no"])
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", known.display()))
        .args(["-o", "LogLevel=ERROR"])
        .args(["-p", &port.to_string()])
        .arg("me@127.0.0.1")
        // `ssh -tt` forwards $TERM to the remote PTY; a multiplexer refuses to
        // start under an empty/"dumb" terminal (common on headless CI), so pin a
        // real one.
        .env("TERM", "xterm-256color")
        .stdin(Stdio::piped()) // kept open (we never take it) → ssh stays alive
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn ssh -tt")
}

async fn poll_file(path: &std::path::Path, tries: u32) -> Option<String> {
    for _ in 0..tries {
        if let Ok(s) = std::fs::read_to_string(path)
            && !s.trim().is_empty()
        {
            return Some(s.trim().to_string());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    None
}

async fn persistence(mux: &str) {
    if !have("ssh") {
        eprintln!("skipping: ssh not installed");
        return;
    }
    if !have(mux) {
        eprintln!("skipping: {mux} not installed");
        return;
    }

    // Isolate from the user's default multiplexer server: use a dedicated
    // socket (in a short path — AF_UNIX caps the length) so the test neither
    // depends on nor pollutes the shared default server.
    let sock = format!("/tmp/sshdt-{mux}-{}.sock", std::process::id());
    let session = format!("sshdt_{mux}_{}", std::process::id());
    let mux_cmd = |args: &[&str]| {
        let _ = std::process::Command::new(mux)
            .arg("-S")
            .arg(&sock)
            .args(args)
            .output();
    };
    mux_cmd(&["kill-session", "-t", &session]); // clean slate

    let dir0 = tempfile::tempdir().unwrap();
    let pidfile = dir0.path().join("inner.pid");

    // The session's inner program records its shell PID once (on creation),
    // then execs an interactive shell. Reattaches do not re-run it.
    let inner = format!("sh -c \"echo $$ > {}; exec sh\"", pidfile.display());
    let shell = format!("{mux} -S {sock} new-session -A -s {session} {inner}");

    let (dir, _handle, port) = start(shell).await;

    // --- Connection 1: create + attach ---
    let mut ssh1 = ssh_attach(&dir, port);
    let pid1 = poll_file(&pidfile, 40).await; // up to ~10s (CI runners are slow)
    assert!(
        pid1.is_some(),
        "{mux}: session never recorded an inner shell PID (did it start on the PTY?)"
    );
    let pid1 = pid1.unwrap();

    // Disconnect; the multiplexer daemon keeps the session detached.
    let _ = ssh1.kill().await;
    tokio::time::sleep(Duration::from_millis(1200)).await;

    // Session must still exist after the client left.
    let alive = std::process::Command::new(mux)
        .args(["-S", &sock, "has-session", "-t", &session])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(alive, "{mux}: session did not persist after disconnect");

    // --- Connection 2: reattach ---
    let mut ssh2 = ssh_attach(&dir, port);
    tokio::time::sleep(Duration::from_millis(2500)).await;
    // A broken reconnect/PTY would make `ssh -tt` exit immediately; a healthy
    // reattach keeps it running (held open by its stdin pipe).
    assert!(
        ssh2.try_wait().ok().flatten().is_none(),
        "{mux}: reconnected ssh -tt exited instead of reattaching"
    );

    // The session is the same one (inner PID unchanged — not recreated).
    let pid2 = std::fs::read_to_string(&pidfile)
        .unwrap_or_default()
        .trim()
        .to_string();
    assert_eq!(
        pid1, pid2,
        "{mux}: inner shell changed across reconnect (pid1={pid1}, pid2={pid2})"
    );

    let _ = ssh2.kill().await;
    mux_cmd(&["kill-server"]);
    let _ = std::fs::remove_file(&sock);
}

#[tokio::test(flavor = "multi_thread")]
async fn rmux_session_persists_across_reconnect() {
    persistence("rmux").await;
}
