//! Integration against the real OpenSSH client suite (`ssh`, `sftp`,
//! `scp`), gated on those binaries being present so the core suite stays green
//! without them. Each test binds a real ephemeral `127.0.0.1` port.
//!
//! Unix-only: the exec/shell assertions and helper commands are POSIX.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Stdio;

use russh::keys::PrivateKey;
use russh::keys::key::safe_rng;
use russh::keys::ssh_key::{Algorithm, LineEnding};
use sshdt::{Server, ServerBuilder, ServerHandle};
use tempfile::TempDir;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

/// Whether the system `ssh` client is available.
fn have_ssh() -> bool {
    std::process::Command::new("ssh")
        .arg("-V")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Whether a binary is on `PATH`.
fn have_bin(bin: &str) -> bool {
    std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {bin}"))
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

macro_rules! require_ssh {
    () => {
        if !have_ssh() {
            eprintln!("skipping: system `ssh` not found");
            return;
        }
    };
}

/// Start a server on an ephemeral loopback port with a throwaway host key.
async fn start(
    configure: impl FnOnce(ServerBuilder) -> ServerBuilder,
) -> (TempDir, ServerHandle, u16) {
    let dir = tempfile::tempdir().unwrap();
    let builder = Server::builder()
        .bind("127.0.0.1".parse().unwrap())
        .port(0)
        .host_key(dir.path().join("host_key"));
    let handle = configure(builder).serve_build().await.unwrap();
    let port = handle.local_addr().port();
    (dir, handle, port)
}

/// Standard `ssh`/`sftp`/`scp` options for a test server, with a per-dir
/// `known_hosts` (cross-platform; avoids `/dev/null`). `port_flag` is `-p` for
/// `ssh` or `-P` for `sftp`/`scp`.
fn common_opts(dir: &TempDir, port: u16, port_flag: &str) -> Vec<String> {
    let known = dir.path().join("known_hosts");
    vec![
        "-o".into(),
        "StrictHostKeyChecking=no".into(),
        "-o".into(),
        format!("UserKnownHostsFile={}", known.display()),
        "-o".into(),
        "LogLevel=ERROR".into(),
        port_flag.into(),
        port.to_string(),
    ]
}

/// Generate a client keypair; returns (private key path, public key line).
fn client_key(dir: &Path) -> (PathBuf, String) {
    let key = PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519).unwrap();
    let priv_path = dir.join("id_client");
    key.write_openssh_file(&priv_path, LineEnding::LF).unwrap();
    let line = key.public_key().to_openssh().unwrap();
    (priv_path, line)
}

#[tokio::test]
async fn ssh_exec_exit_codes() {
    require_ssh!();
    let (dir, _h, port) = start(|b| b).await;
    let opts = common_opts(&dir, port, "-p");

    let out = Command::new("ssh")
        .args(&opts)
        .arg("me@127.0.0.1")
        .arg("echo hi")
        .output()
        .await
        .unwrap();
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "hi");

    let out = Command::new("ssh")
        .args(&opts)
        .arg("me@127.0.0.1")
        .arg("exit 3")
        .output()
        .await
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
}

#[tokio::test]
async fn ssh_pipe_bootstrap() {
    require_ssh!();
    // Exactly how VS Code / Zed bootstrap their server: pipe a script into a
    // remote shell over an exec channel.
    let (dir, _h, port) = start(|b| b).await;
    let opts = common_opts(&dir, port, "-p");

    let mut child = Command::new("ssh")
        .args(&opts)
        .arg("me@127.0.0.1")
        .arg("sh -s")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"echo bootstrapped-$((3*4))\n")
        .await
        .unwrap();
    let out = child.wait_with_output().await.unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "bootstrapped-12"
    );
}

#[tokio::test]
async fn sftp_and_scp_roundtrip_including_large_file() {
    require_ssh!();
    let (dir, _h, port) = start(|b| b).await;
    let work = dir.path().join("work");
    std::fs::create_dir(&work).unwrap();

    // A small text file and a >= 10 MB binary file.
    let small = work.join("small.txt");
    std::fs::write(&small, b"byte-for-byte\n").unwrap();
    let big = work.join("big.bin");
    let big_data: Vec<u8> = (0..11_000_000u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 11) as u8)
        .collect();
    std::fs::write(&big, &big_data).unwrap();

    // --- sftp batch put/get round-trip ---
    let remote_small = work.join("small-remote.txt");
    let fetched_small = work.join("small-fetched.txt");
    let remote_big = work.join("big-remote.bin");
    let fetched_big = work.join("big-fetched.bin");
    let batch = work.join("batch.txt");
    std::fs::write(
        &batch,
        format!(
            "put {} {}\nget {} {}\nput {} {}\nget {} {}\n",
            small.display(),
            remote_small.display(),
            remote_small.display(),
            fetched_small.display(),
            big.display(),
            remote_big.display(),
            remote_big.display(),
            fetched_big.display(),
        ),
    )
    .unwrap();

    let opts = common_opts(&dir, port, "-P");
    let status = Command::new("sftp")
        .arg("-b")
        .arg(&batch)
        .args(&opts)
        .arg("me@127.0.0.1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .unwrap();
    assert!(status.success(), "sftp batch exited {status:?}");
    assert_eq!(std::fs::read(&fetched_small).unwrap(), b"byte-for-byte\n");
    assert_eq!(std::fs::read(&fetched_big).unwrap(), big_data, "11MB sftp");

    // --- scp upload + download round-trip ---
    let scp_remote = work.join("big-scp.bin");
    let scp_fetched = work.join("big-scp-fetched.bin");
    let up = Command::new("scp")
        .args(&opts)
        .arg(&big)
        .arg(format!("me@127.0.0.1:{}", scp_remote.display()))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .unwrap();
    assert!(up.success(), "scp upload exited {up:?}");
    let down = Command::new("scp")
        .args(&opts)
        .arg(format!("me@127.0.0.1:{}", scp_remote.display()))
        .arg(&scp_fetched)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .unwrap();
    assert!(down.success(), "scp download exited {down:?}");
    assert_eq!(std::fs::read(&scp_fetched).unwrap(), big_data, "11MB scp");
}

#[tokio::test]
async fn ssh_publickey_auth() {
    require_ssh!();
    let keydir = tempfile::tempdir().unwrap();
    let (priv_path, pub_line) = client_key(keydir.path());

    let pub_line2 = pub_line.clone();
    let (dir, _h, port) = start(move |b| b.pubkey(pub_line2)).await;
    let opts = common_opts(&dir, port, "-p");

    let out = Command::new("ssh")
        .args(&opts)
        .arg("-o")
        .arg("IdentitiesOnly=yes")
        .arg("-o")
        .arg("PreferredAuthentications=publickey")
        .arg("-i")
        .arg(&priv_path)
        .arg("me@127.0.0.1")
        .arg("echo key-auth-ok")
        .output()
        .await
        .unwrap();
    assert!(out.status.success(), "key auth failed: {out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "key-auth-ok");
}

#[tokio::test]
async fn ssh_password_auth() {
    require_ssh!();
    if !have_bin("sshpass") {
        eprintln!("skipping: sshpass not installed");
        return;
    }
    let (dir, _h, port) = start(|b| b.password("s3cret-pw")).await;
    let opts = common_opts(&dir, port, "-p");

    let out = Command::new("sshpass")
        .arg("-p")
        .arg("s3cret-pw")
        .arg("ssh")
        .args(&opts)
        .arg("-o")
        .arg("PreferredAuthentications=password")
        .arg("-o")
        .arg("PubkeyAuthentication=no")
        .arg("me@127.0.0.1")
        .arg("echo pw-auth-ok")
        .output()
        .await
        .unwrap();
    assert!(out.status.success(), "password auth failed: {out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "pw-auth-ok");
}

#[tokio::test]
async fn ssh_local_forward() {
    require_ssh!();
    // An in-test echo server to forward to.
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = echo.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = sock.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });

    let (dir, _h, port) = start(|b| b).await;
    let opts = common_opts(&dir, port, "-p");

    // Pick a local forward port.
    let fwd = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };

    // `ssh -L fwd:127.0.0.1:echo -N` in the background; sleep keeps it alive.
    let mut ssh = Command::new("ssh")
        .args(&opts)
        .arg("-N")
        .arg("-L")
        .arg(format!("{fwd}:127.0.0.1:{echo_port}"))
        .arg("me@127.0.0.1")
        .spawn()
        .unwrap();
    // Give the forward time to establish.
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut conn = tokio::net::TcpStream::connect(("127.0.0.1", fwd))
        .await
        .expect("connect through forward");
    conn.write_all(b"through-the-tunnel").await.unwrap();
    let mut buf = vec![0u8; b"through-the-tunnel".len()];
    conn.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"through-the-tunnel");

    let _ = ssh.kill().await;
}
