//! SFTP round-trip + ops + jail escape, and `direct-tcpip` forwarding.

mod common;

use common::{builder, connect};
use russh::ChannelMsg;
use russh_sftp::client::SftpSession;

/// Authenticate and open an SFTP session over a fresh channel.
async fn sftp(handle: &russh::client::Handle<common::TrustingClient>) -> SftpSession {
    let channel = handle.channel_open_session().await.unwrap();
    channel.request_subsystem(true, "sftp").await.unwrap();
    SftpSession::new(channel.into_stream()).await.unwrap()
}

#[tokio::test]
async fn sftp_write_read_roundtrip_and_ops() {
    let work = tempfile::tempdir().unwrap();
    let (_dir, b) = builder();
    let mut handle = connect(b.build().unwrap()).await;
    assert!(handle.authenticate_none("u").await.unwrap().success());
    let fs = sftp(&handle).await;

    let file = work.path().join("hello.txt");
    let file_s = file.to_string_lossy().to_string();
    let payload = b"sftp round-trip\n";

    // write -> read
    fs.write(&file_s, payload).await.unwrap();
    assert_eq!(fs.read(&file_s).await.unwrap(), payload);

    // metadata
    let meta = fs.metadata(&file_s).await.unwrap();
    assert_eq!(meta.size, Some(payload.len() as u64));

    // mkdir + readdir
    let sub = work.path().join("sub");
    fs.create_dir(sub.to_string_lossy().to_string())
        .await
        .unwrap();
    let names: Vec<String> = fs
        .read_dir(work.path().to_string_lossy().to_string())
        .await
        .unwrap()
        .map(|entry| entry.file_name())
        .collect();
    assert!(names.iter().any(|n| n == "hello.txt"));
    assert!(names.iter().any(|n| n == "sub"));

    // rename
    let renamed = work.path().join("renamed.txt");
    let renamed_s = renamed.to_string_lossy().to_string();
    fs.rename(&file_s, &renamed_s).await.unwrap();
    assert_eq!(fs.read(&renamed_s).await.unwrap(), payload);
    assert!(fs.read(&file_s).await.is_err());

    // remove
    fs.remove_file(&renamed_s).await.unwrap();
    assert!(fs.metadata(&renamed_s).await.is_err());
}

#[tokio::test]
async fn sftp_jail_rejects_path_escape() {
    let jail = tempfile::tempdir().unwrap();
    std::fs::write(jail.path().join("inside.txt"), b"ok").unwrap();
    // A secret living outside the jail.
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("secret.txt"), b"top secret").unwrap();

    let (_dir, b) = builder();
    let server = b.sftp_root(jail.path()).build().unwrap();
    let mut handle = connect(server).await;
    assert!(handle.authenticate_none("u").await.unwrap().success());
    let fs = sftp(&handle).await;

    // In-jail access works (the client sees the root as "/").
    assert_eq!(fs.read("/inside.txt").await.unwrap(), b"ok");

    // `..` traversal out of the jail is rejected.
    assert!(fs.read("/../secret.txt").await.is_err());
    assert!(fs.read("/../../etc/passwd").await.is_err());

    // An absolute-looking escape is also contained.
    let escape = format!("/..{}/secret.txt", outside.path().to_string_lossy());
    assert!(fs.read(escape).await.is_err());
}

#[tokio::test]
async fn direct_tcpip_round_trips_bytes() {
    // In-test echo server.
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = echo.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = sock.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });

    let (_dir, b) = builder();
    let mut handle = connect(b.build().unwrap()).await;
    assert!(handle.authenticate_none("u").await.unwrap().success());

    let mut channel = handle
        .channel_open_direct_tcpip("127.0.0.1", echo_addr.port() as u32, "127.0.0.1", 0)
        .await
        .unwrap();
    channel.data(&b"ping-pong"[..]).await.unwrap();

    let mut got = Vec::new();
    while got.len() < b"ping-pong".len() {
        match channel.wait().await {
            Some(ChannelMsg::Data { data }) => got.extend_from_slice(&data),
            Some(ChannelMsg::Eof | ChannelMsg::Close) | None => break,
            Some(_) => {}
        }
    }
    assert_eq!(got, b"ping-pong");
}

#[tokio::test]
async fn direct_tcpip_denied_when_forwarding_disabled() {
    let (_dir, b) = builder();
    let server = b.allow_tcp_forwarding(false).build().unwrap();
    let mut handle = connect(server).await;
    assert!(handle.authenticate_none("u").await.unwrap().success());

    // Server rejects the channel open, so the client call errors.
    let result = handle
        .channel_open_direct_tcpip("127.0.0.1", 9, "127.0.0.1", 0)
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn sftp_large_file_roundtrip() {
    let work = tempfile::tempdir().unwrap();
    let (_dir, b) = builder();
    let mut handle = connect(b.build().unwrap()).await;
    assert!(handle.authenticate_none("u").await.unwrap().success());
    let fs = sftp(&handle).await;

    // 5 MB of pseudo-random-ish data.
    let data: Vec<u8> = (0..5_000_000u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    let path = work.path().join("big.bin").to_string_lossy().to_string();

    fs.write(&path, &data).await.unwrap();
    let got = fs.read(&path).await.unwrap();
    assert_eq!(got.len(), data.len(), "length mismatch");
    assert!(got == data, "content mismatch");
}
