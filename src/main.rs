//! The `sshdt` command-line interface (ADR 0007, 0008).
//!
//! Flags mirror `sshd` where they overlap (`-h` = host key, `-p`, `-E`, `-f`).
//! The library never installs a `tracing` subscriber — that is done here.

use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::Context;
use argh::FromArgs;
use sshdt::{Config, Server};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;

/// sshdt — a tiny, faithful, standard SSH server you can `ssh` into.
#[derive(FromArgs)]
struct Args {
    /// port to listen on [default: 2222]
    #[argh(option, short = 'p')]
    port: Option<u16>,

    /// host key file, generated if missing; repeatable
    /// [default: ~/.sshdt/host_ed25519]
    #[argh(option, short = 'h')]
    host_key: Vec<PathBuf>,

    /// load a config file: sshd_config format, or TOML by .toml extension
    #[argh(option, short = 'f')]
    config: Option<PathBuf>,

    /// append logs to FILE instead of stderr
    #[argh(option, short = 'E')]
    log_file: Option<PathBuf>,

    /// debug logging (sshd-style -d)
    #[argh(switch, short = 'd')]
    debug: bool,

    /// verbose logging (alias for -d)
    #[argh(switch, short = 'v')]
    verbose: bool,

    /// errors-only logging
    #[argh(switch, short = 'q')]
    quiet: bool,

    /// bind address [default: 127.0.0.1]
    #[argh(option, short = 'b')]
    bind: Option<IpAddr>,

    /// passphrase for an encrypted host key [or $SSHDT_HOST_KEY_PASSPHRASE]
    #[argh(option)]
    host_key_passphrase: Option<String>,

    /// enable password authentication with this password
    #[argh(option)]
    password: Option<String>,

    /// authorized_keys file for public-key auth; repeatable
    #[argh(option)]
    authorized_keys: Vec<PathBuf>,

    /// inline authorized public key ("ssh-ed25519 AAAA..."); repeatable
    #[argh(option)]
    pubkey: Vec<String>,

    /// the interactive session command [default: $SHELL, else /bin/sh]
    #[argh(option)]
    shell: Option<String>,

    /// jail SFTP/scp to DIR [default: full filesystem as the OS user]
    #[argh(option)]
    sftp_root: Option<PathBuf>,

    /// accept only the launching OS user's username; reject all others
    #[argh(switch)]
    strict_user: bool,

    /// accept only this SSH username (exact match); repeatable
    #[argh(option)]
    allow_user: Vec<String>,

    /// disable `ssh -L` (direct-tcpip) forwarding
    #[argh(switch)]
    no_forward: bool,

    /// authentication grace period in seconds [default: 60]
    #[argh(option)]
    login_grace: Option<u64>,

    /// max concurrent unauthenticated connections [default: 32]
    #[argh(option)]
    max_startups: Option<u32>,

    /// print version and exit
    #[argh(switch)]
    version: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Args = argh::from_env();

    if args.version {
        println!("sshdt {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    let _log_guard = init_logging(&args)?;

    let config = build_config(&args).context("invalid configuration")?;
    let bind = std::net::SocketAddr::new(config.bind, config.port);

    let server = Server::from_config(config).context("failed to build server")?;
    let handle = server
        .serve()
        .await
        .with_context(|| format!("failed to bind {bind}"))?;

    tracing::info!(addr = %handle.local_addr(), "sshdt is ready — press Ctrl-C to stop");

    tokio::signal::ctrl_c()
        .await
        .context("failed to listen for Ctrl-C")?;
    tracing::info!("shutting down");
    handle.shutdown().await;
    Ok(())
}

/// Build the effective [`Config`]: defaults < config file < flags (ADR 0019).
fn build_config(args: &Args) -> anyhow::Result<Config> {
    let mut config = match &args.config {
        Some(path) => Config::load_file(path)
            .with_context(|| format!("failed to load config file {}", path.display()))?,
        None => Config::default(),
    };

    if let Some(port) = args.port {
        config.port = port;
    }
    if let Some(bind) = args.bind {
        config.bind = bind;
    }
    if !args.host_key.is_empty() {
        config.host_keys = args.host_key.clone();
    }
    if let Some(passphrase) = &args.host_key_passphrase {
        config.host_key_passphrase = Some(passphrase.clone());
    }
    if let Some(password) = &args.password {
        config.password = Some(password.clone());
    }
    // Authorized keys and inline keys are additive on top of any from a file.
    config
        .authorized_keys
        .extend(args.authorized_keys.iter().cloned());
    config
        .authorized_key_lines
        .extend(args.pubkey.iter().cloned());
    if let Some(shell) = &args.shell {
        config.shell = Some(shell.clone());
    }
    if let Some(root) = &args.sftp_root {
        config.sftp_root = Some(root.clone());
    }
    if args.strict_user {
        config.require_current_user = true;
    }
    config.allow_users.extend(args.allow_user.iter().cloned());
    if args.no_forward {
        config.allow_tcp_forwarding = false;
    }
    if let Some(grace) = args.login_grace {
        config.login_grace_secs = grace;
    }
    if let Some(max) = args.max_startups {
        config.max_startups = max;
    }

    Ok(config)
}

/// Install the process-global `tracing` subscriber. When `-E/--log-file` is
/// given, logs are appended to that file (returning the appender's guard, which
/// must be kept alive); otherwise they go to stderr.
fn init_logging(args: &Args) -> anyhow::Result<Option<WorkerGuard>> {
    let level = if args.quiet {
        "error"
    } else if args.debug || args.verbose {
        "debug"
    } else {
        "info"
    };
    // `RUST_LOG` overrides the flag-derived level when set.
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("sshdt={level},warn")));

    if let Some(path) = &args.log_file {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("failed to open log file {}", path.display()))?;
        let (writer, guard) = tracing_appender::non_blocking(file);
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .with_writer(writer)
            .init();
        Ok(Some(guard))
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .init();
        Ok(None)
    }
}
