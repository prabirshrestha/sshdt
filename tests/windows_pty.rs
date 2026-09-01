//! Windows ConPTY sessions.

#![cfg(windows)]

mod common;

use std::time::Duration;

use common::{builder, collect, connect};
use russh::ChannelMsg;

#[tokio::test]
async fn direct_powershell_pty_exec_starts_and_exits() {
    let (_dir, b) = builder();
    let mut handle = connect(b.shell("powershell.exe").build().unwrap()).await;
    assert!(handle.authenticate_none("u").await.unwrap().success());

    let mut channel = handle.channel_open_session().await.unwrap();
    channel
        .request_pty(true, "xterm-256color", 120, 30, 0, 0, &[])
        .await
        .unwrap();
    channel
        .exec(true, "Write-Output SSHDT_DIRECT_POWERSHELL_OK")
        .await
        .unwrap();

    let out = tokio::time::timeout(Duration::from_secs(20), collect(&mut channel))
        .await
        .expect("PowerShell PTY command timed out");
    let stdout = out.stdout_str();
    assert!(
        stdout.contains("SSHDT_DIRECT_POWERSHELL_OK"),
        "expected PowerShell output, got {stdout:?}"
    );
    assert!(
        !stdout.contains("ServicePointManager"),
        "PowerShell failed during .NET initialization: {stdout:?}"
    );
    assert_eq!(out.code, Some(0));
}

#[tokio::test]
async fn direct_interactive_powershell_accepts_input() {
    let (_dir, b) = builder();
    let mut handle = connect(b.shell("powershell.exe").build().unwrap()).await;
    assert!(handle.authenticate_none("u").await.unwrap().success());

    let mut channel = handle.channel_open_session().await.unwrap();
    channel
        .request_pty(true, "xterm-256color", 120, 30, 0, 0, &[])
        .await
        .unwrap();
    channel.request_shell(true).await.unwrap();

    let mut startup = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), async {
        while !String::from_utf8_lossy(&startup).contains("PS ") {
            match channel.wait().await {
                Some(ChannelMsg::Data { data }) => startup.extend_from_slice(&data),
                Some(ChannelMsg::ExitStatus { exit_status }) => {
                    panic!("PowerShell exited during startup with status {exit_status}")
                }
                Some(_) => {}
                None => panic!("PowerShell channel closed during startup"),
            }
        }
    })
    .await
    .expect("PowerShell prompt timed out");

    let startup = String::from_utf8_lossy(&startup);
    assert!(
        !startup.contains("ServicePointManager"),
        "PowerShell failed during .NET initialization: {startup:?}"
    );
    channel
        .data(&b"Write-Output SSHDT_INTERACTIVE_POWERSHELL_OK\r"[..])
        .await
        .unwrap();
    channel.data(&b"exit\r"[..]).await.unwrap();

    let out = tokio::time::timeout(Duration::from_secs(20), collect(&mut channel))
        .await
        .expect("interactive PowerShell did not exit");
    assert!(
        out.stdout_str().contains("SSHDT_INTERACTIVE_POWERSHELL_OK"),
        "expected interactive PowerShell output, got {:?}",
        out.stdout_str()
    );
    assert_eq!(out.code, Some(0));
}
