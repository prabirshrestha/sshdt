//! Interactive PTY sessions via the `rmux-pty` runner.
//!
//! Unix-only: these drive a POSIX shell (`/bin/sh`) and assert on `stty`.

#![cfg(unix)]

mod common;

use common::{builder, collect, connect};

#[tokio::test]
async fn pty_exec_runs_on_a_terminal() {
    let (_dir, b) = builder();
    let mut handle = connect(b.build().unwrap()).await;
    assert!(handle.authenticate_none("u").await.unwrap().success());

    let mut channel = handle.channel_open_session().await.unwrap();
    channel
        .request_pty(true, "xterm-256color", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    channel.exec(true, "echo ptyhello").await.unwrap();

    let out = collect(&mut channel).await;
    assert!(
        out.stdout_str().contains("ptyhello"),
        "expected ptyhello, got {:?}",
        out.stdout_str()
    );
    assert_eq!(out.code, Some(0));
}

#[tokio::test]
async fn pty_interactive_shell_echoes_and_exits() {
    let (_dir, b) = builder();
    let mut handle = connect(b.shell("/bin/sh").build().unwrap()).await;
    assert!(handle.authenticate_none("u").await.unwrap().success());

    let mut channel = handle.channel_open_session().await.unwrap();
    channel
        .request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    channel.request_shell(true).await.unwrap();

    // Run a command on the interactive shell, then exit so the session ends.
    channel.data(&b"echo shellmark\n"[..]).await.unwrap();
    channel.data(&b"exit\n"[..]).await.unwrap();

    let out = collect(&mut channel).await;
    assert!(
        out.stdout_str().contains("shellmark"),
        "expected shellmark in {:?}",
        out.stdout_str()
    );
}

#[tokio::test]
async fn pty_window_change_resizes_the_terminal() {
    let (_dir, b) = builder();
    let mut handle = connect(b.shell("/bin/sh").build().unwrap()).await;
    assert!(handle.authenticate_none("u").await.unwrap().success());

    let mut channel = handle.channel_open_session().await.unwrap();
    channel
        .request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    channel.request_shell(true).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;

    // Client resizes its terminal (SIGWINCH equivalent): 120 cols x 40 rows.
    channel.window_change(120, 40, 0, 0).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;

    // The PTY should report the new geometry. `stty size` prints "rows cols".
    channel.data(&b"stty size\n"[..]).await.unwrap();
    channel.data(&b"exit\n"[..]).await.unwrap();

    let out = collect(&mut channel).await;
    assert!(
        out.stdout_str().contains("40 120"),
        "expected resized geometry '40 120' in {:?}",
        out.stdout_str()
    );
}
