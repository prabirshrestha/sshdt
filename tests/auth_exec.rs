//! Authentication matrix + exec semantics, in-process over a duplex.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{builder, connect, gen_keypair, public_line};
// The exec/command tests assume a POSIX shell, so they are Unix-only; `exec`
// would otherwise be an unused import on Windows.
#[cfg(unix)]
use common::exec;
use russh::keys::PrivateKeyWithHashAlg;
use sshdt::{Config, Server};

#[derive(Default)]
struct ChannelLifecycle {
    stderr: Vec<u8>,
    exit_status: Option<u32>,
    eof_count: usize,
    close_count: usize,
}

async fn collect_channel_lifecycle(
    channel: &mut russh::Channel<russh::client::Msg>,
) -> ChannelLifecycle {
    use russh::ChannelMsg;

    tokio::time::timeout(Duration::from_secs(5), async {
        let mut lifecycle = ChannelLifecycle::default();
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::ExtendedData { data, ext: 1 } => {
                    lifecycle.stderr.extend_from_slice(&data);
                }
                ChannelMsg::ExitStatus { exit_status } => {
                    lifecycle.exit_status = Some(exit_status);
                }
                ChannelMsg::Eof => {
                    assert!(
                        lifecycle.exit_status.is_some(),
                        "EOF arrived before exit-status"
                    );
                    lifecycle.eof_count += 1;
                }
                ChannelMsg::Close => lifecycle.close_count += 1,
                _ => {}
            }
        }
        lifecycle
    })
    .await
    .expect("timed out waiting for channel close")
}

#[tokio::test]
async fn anonymous_auth_accepts_by_default() {
    let (_dir, b) = builder();
    let server = b.build().unwrap();
    let mut handle = connect(server).await;
    assert!(handle.authenticate_none("anyone").await.unwrap().success());
}

#[tokio::test]
async fn explicit_authentication_disable_rejects_anonymous() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("sshdt_config");
    std::fs::write(
        &config_path,
        format!(
            "HostKey {}\nPasswordAuthentication no\nPubkeyAuthentication no\n",
            dir.path().join("host_ed25519").display()
        ),
    )
    .unwrap();
    let server = Server::from_config(Config::load_file(&config_path).unwrap()).unwrap();
    let mut handle = connect(server).await;
    assert!(!handle.authenticate_none("anyone").await.unwrap().success());
}

#[tokio::test]
async fn password_auth_accept_and_reject() {
    let (_dir, b) = builder();
    let server = b.password("hunter2").build().unwrap();
    let mut handle = connect(server).await;
    // Wrong password rejected.
    assert!(
        !handle
            .authenticate_password("u", "nope")
            .await
            .unwrap()
            .success()
    );
    // Right password accepted.
    assert!(
        handle
            .authenticate_password("u", "hunter2")
            .await
            .unwrap()
            .success()
    );
}

#[tokio::test]
async fn password_server_rejects_anonymous() {
    let (_dir, b) = builder();
    let server = b.password("pw").build().unwrap();
    let mut handle = connect(server).await;
    assert!(!handle.authenticate_none("u").await.unwrap().success());
}

#[tokio::test]
async fn pubkey_auth_inline_accept_and_reject() {
    let authorized = gen_keypair();
    let (_dir, b) = builder();
    let server = b.pubkey(public_line(&authorized)).build().unwrap();
    let mut handle = connect(server).await;

    // An unlisted key is rejected.
    let stranger = gen_keypair();
    let stranger_key = PrivateKeyWithHashAlg::new(Arc::new(stranger), None);
    assert!(
        !handle
            .authenticate_publickey("u", stranger_key)
            .await
            .unwrap()
            .success()
    );

    // The authorized key is accepted.
    let key = PrivateKeyWithHashAlg::new(Arc::new(authorized), None);
    assert!(
        handle
            .authenticate_publickey("u", key)
            .await
            .unwrap()
            .success()
    );
}

#[tokio::test]
async fn pubkey_auth_from_file() {
    let authorized = gen_keypair();
    let (_dir, b) = builder();
    let ak_path = _dir.path().join("authorized_keys");
    std::fs::write(&ak_path, format!("{}\n", public_line(&authorized))).unwrap();

    let server = b.authorized_keys(&ak_path).build().unwrap();
    let mut handle = connect(server).await;
    let key = PrivateKeyWithHashAlg::new(Arc::new(authorized), None);
    assert!(
        handle
            .authenticate_publickey("u", key)
            .await
            .unwrap()
            .success()
    );
}

/// The launching OS user's login name, by the same rule the server uses.
fn launching_user() -> Option<String> {
    ["USER", "LOGNAME", "USERNAME"]
        .into_iter()
        .find_map(|var| std::env::var(var).ok().filter(|v| !v.is_empty()))
}

#[tokio::test]
async fn strict_user_accepts_only_the_launching_user() {
    let Some(me) = launching_user() else {
        // No OS user discoverable in this environment; nothing to assert.
        return;
    };
    let (_dir, b) = builder();
    let mut handle = connect(b.require_current_user(true).build().unwrap()).await;

    // A foreign username is rejected even though anonymous auth is enabled.
    assert!(
        !handle
            .authenticate_none("not-the-owner")
            .await
            .unwrap()
            .success()
    );
    // The launching OS user is accepted.
    assert!(handle.authenticate_none(&me).await.unwrap().success());
}

#[tokio::test]
async fn allow_user_matches_exact_username_including_spaces() {
    // An explicit allowlist (no env detection needed). Exact, case-sensitive
    // match — and a username containing spaces is handled as one whole string.
    let (_dir, b) = builder();
    let mut handle = connect(b.allow_user("John Doe").build().unwrap()).await;

    // Partial / wrong-case / different names are rejected.
    assert!(!handle.authenticate_none("John").await.unwrap().success());
    assert!(
        !handle
            .authenticate_none("john doe")
            .await
            .unwrap()
            .success()
    );
    assert!(!handle.authenticate_none("Jane").await.unwrap().success());
    // The exact name, spaces and all, is accepted.
    assert!(
        handle
            .authenticate_none("John Doe")
            .await
            .unwrap()
            .success()
    );
}

#[tokio::test]
async fn allow_user_accepts_any_of_several() {
    let (_dir, b) = builder();
    let server = b.allow_user("alice").allow_user("bob").build().unwrap();
    let mut handle = connect(server).await;
    assert!(!handle.authenticate_none("carol").await.unwrap().success());
    assert!(handle.authenticate_none("bob").await.unwrap().success());
}

// The exec/command tests below run real commands through a shell, which is
// POSIX-specific (Windows' default shell is PowerShell). They are Unix-only;
// the auth tests above stay cross-platform.
#[cfg(unix)]
#[tokio::test]
async fn exec_echo_stdout_and_exit_zero() {
    let (_dir, b) = builder();
    let mut handle = connect(b.build().unwrap()).await;
    assert!(handle.authenticate_none("u").await.unwrap().success());

    let out = exec(&handle, "echo hi").await;
    assert_eq!(out.stdout_str(), "hi\n");
    assert_eq!(out.code, Some(0));
}

#[cfg(unix)]
#[tokio::test]
async fn exec_propagates_nonzero_exit_code() {
    let (_dir, b) = builder();
    let mut handle = connect(b.build().unwrap()).await;
    assert!(handle.authenticate_none("u").await.unwrap().success());

    let out = exec(&handle, "exit 7").await;
    assert_eq!(out.code, Some(7));
}

#[cfg(unix)]
#[tokio::test]
async fn exec_stderr_goes_to_extended_data() {
    let (_dir, b) = builder();
    let mut handle = connect(b.build().unwrap()).await;
    assert!(handle.authenticate_none("u").await.unwrap().success());

    let out = exec(&handle, "echo oops 1>&2").await;
    assert_eq!(out.stderr_str(), "oops\n");
    assert_eq!(out.stdout_str(), "");
    assert_eq!(out.code, Some(0));
}

#[cfg(unix)]
#[tokio::test]
async fn exec_sends_one_eof_after_exit_status() {
    let (_dir, b) = builder();
    let mut handle = connect(b.build().unwrap()).await;
    assert!(handle.authenticate_none("u").await.unwrap().success());

    let mut channel = handle.channel_open_session().await.unwrap();
    channel
        .exec(true, "printf stdout; printf stderr >&2")
        .await
        .unwrap();

    let lifecycle = collect_channel_lifecycle(&mut channel).await;

    assert_eq!(lifecycle.exit_status, Some(0));
    assert_eq!(lifecycle.eof_count, 1);
    assert_eq!(lifecycle.close_count, 1);
}

#[tokio::test]
async fn exec_spawn_failure_sends_one_eof_after_exit_status() {
    use sshdt::{CommandResolver, SessionCommand, SessionRequest};

    struct MissingCommand(String);

    impl CommandResolver for MissingCommand {
        fn resolve(&self, _request: &SessionRequest) -> SessionCommand {
            SessionCommand::new(&self.0)
        }
    }

    let (_dir, b) = builder();
    let missing = _dir.path().join("missing-executable");
    let resolver = Arc::new(MissingCommand(missing.to_string_lossy().into_owned()));
    let mut handle = connect(b.command_resolver(resolver).build().unwrap()).await;
    assert!(handle.authenticate_none("u").await.unwrap().success());

    let mut channel = handle.channel_open_session().await.unwrap();
    channel.exec(true, "ignored").await.unwrap();

    let lifecycle = collect_channel_lifecycle(&mut channel).await;
    let stderr = String::from_utf8_lossy(&lifecycle.stderr);

    assert_eq!(lifecycle.exit_status, Some(127));
    assert_eq!(lifecycle.eof_count, 1);
    assert_eq!(lifecycle.close_count, 1);
    assert!(
        stderr.starts_with(&format!("sshdt: failed to run {}: ", missing.display())),
        "unexpected stderr: {stderr}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn exec_cat_is_full_duplex() {
    let (_dir, b) = builder();
    let mut handle = connect(b.build().unwrap()).await;
    assert!(handle.authenticate_none("u").await.unwrap().success());

    let mut channel = handle.channel_open_session().await.unwrap();
    channel.exec(true, "cat").await.unwrap();

    let payload = b"the quick brown fox\n";
    channel.data(&payload[..]).await.unwrap();
    channel.eof().await.unwrap(); // close stdin so cat exits

    let out = common::collect(&mut channel).await;
    assert_eq!(out.stdout, payload);
    assert_eq!(out.code, Some(0));
}

#[cfg(unix)]
#[tokio::test]
async fn multiple_channels_on_one_connection() {
    let (_dir, b) = builder();
    let mut handle = connect(b.build().unwrap()).await;
    assert!(handle.authenticate_none("u").await.unwrap().success());

    // ControlMaster-style: many session channels over one connection.
    for i in 0..5 {
        let out = exec(&handle, &format!("echo n{i}")).await;
        assert_eq!(out.stdout_str(), format!("n{i}\n"));
        assert_eq!(out.code, Some(0));
    }
}

#[cfg(unix)]
#[tokio::test]
async fn multiple_server_instances_in_one_process() {
    use common::connect_arc;
    use std::sync::Arc;

    // Guards "no global state": two independent servers with distinct
    // passwords, each accepting only its own and never the other's.
    let (_d1, b1) = builder();
    let (_d2, b2) = builder();
    let s1 = Arc::new(b1.password("one").build().unwrap());
    let s2 = Arc::new(b2.password("two").build().unwrap());

    // server1 rejects server2's password (fresh connection).
    let mut wrong = connect_arc(s1.clone()).await;
    assert!(
        !wrong
            .authenticate_password("u", "two")
            .await
            .unwrap()
            .success()
    );

    // server1 accepts its own and runs a command.
    let mut h1 = connect_arc(s1.clone()).await;
    assert!(
        h1.authenticate_password("u", "one")
            .await
            .unwrap()
            .success()
    );
    assert_eq!(exec(&h1, "echo a").await.stdout_str(), "a\n");

    // server2 accepts its own and runs a command.
    let mut h2 = connect_arc(s2.clone()).await;
    assert!(
        h2.authenticate_password("u", "two")
            .await
            .unwrap()
            .success()
    );
    assert_eq!(exec(&h2, "echo b").await.stdout_str(), "b\n");
}
