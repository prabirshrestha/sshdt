//! The `sshdt` command-line interface (ADR 0007, 0008).
//!
//! Flags mirror `sshd` where they overlap (`-h` = host key, `-p`, `-E`, `-f`).
//! The library never installs a `tracing` subscriber — that is done here.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::Context;
use argh::FromArgs;
use sshdt::{Config, Server};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;

mod service;

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

    /// load a config file [default: ~/.ssh/sshdt_config when present]
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

    /// run under Windows launch-at-login process control
    #[argh(switch, hidden_help)]
    service_run: bool,

    /// manage launch at login for the current Windows user
    #[argh(subcommand)]
    command: Option<Command>,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum Command {
    Service(ServiceArgs),
}

/// Manage launch at login for the current Windows user.
#[derive(FromArgs)]
#[argh(subcommand, name = "service")]
struct ServiceArgs {
    #[argh(subcommand)]
    command: ServiceCommand,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum ServiceCommand {
    Install(InstallService),
    Uninstall(UninstallService),
    Status(ServiceStatus),
    Start(StartService),
    Stop(StopService),
    Restart(RestartService),
    Logs(ServiceLogs),
}

/// Install sshdt as a launch-at-login program.
#[derive(FromArgs)]
#[argh(subcommand, name = "install")]
struct InstallService {}

/// Remove sshdt from launch at login.
#[derive(FromArgs)]
#[argh(subcommand, name = "uninstall")]
struct UninstallService {}

/// Show whether sshdt is configured to launch at login.
#[derive(FromArgs)]
#[argh(subcommand, name = "status")]
struct ServiceStatus {}

/// Start the installed sshdt program now.
#[derive(FromArgs)]
#[argh(subcommand, name = "start")]
struct StartService {}

/// Stop the running sshdt program.
#[derive(FromArgs)]
#[argh(subcommand, name = "stop")]
struct StopService {}

/// Restart the installed sshdt program.
#[derive(FromArgs)]
#[argh(subcommand, name = "restart")]
struct RestartService {}

/// Print the sshdt service log.
#[derive(FromArgs)]
#[argh(subcommand, name = "logs")]
struct ServiceLogs {
    /// continue printing new log entries
    #[argh(switch, short = 'f')]
    follow: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Args = argh::from_env();

    if args.version {
        println!("sshdt {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    if args.service_run {
        #[cfg(not(windows))]
        anyhow::bail!("service mode is currently supported only on Windows");

        #[cfg(windows)]
        return run_server(&args, true).await;
    }

    if let Some(Command::Service(service_args)) = &args.command {
        return manage_service(service_args, &args);
    }

    run_server(&args, false).await
}

async fn run_server(args: &Args, _service_mode: bool) -> anyhow::Result<()> {
    #[cfg(windows)]
    let service_mode = _service_mode;
    #[cfg(not(windows))]
    let service_mode = false;
    let service_run = service_mode.then(service::RunGuard::acquire).transpose()?;

    let _log_guard = init_logging(args, service_mode)?;
    let result = async {
        let config = build_config(args).context("invalid configuration")?;
        let bind = std::net::SocketAddr::new(config.bind, config.port);

        let server = Server::from_config(config).context("failed to build server")?;
        let handle = server
            .serve()
            .await
            .with_context(|| format!("failed to bind {bind}"))?;

        if let Some(service_run) = &service_run {
            service_run.mark_ready()?;
        }

        tracing::info!(addr = %handle.local_addr(), "sshdt is ready");

        if let Some(service_run) = &service_run {
            service_run.wait_for_stop().await?;
        } else {
            tokio::signal::ctrl_c()
                .await
                .context("failed to listen for Ctrl-C")?;
        }
        tracing::info!("shutting down");
        handle.shutdown().await;
        Ok(())
    }
    .await;
    if service_mode && let Err(error) = &result {
        tracing::error!(error = %error, "sshdt service stopped with an error");
    }
    result
}

fn manage_service(service_args: &ServiceArgs, args: &Args) -> anyhow::Result<()> {
    match &service_args.command {
        ServiceCommand::Install(_) => {
            service::manage(service::Action::Install, startup_args(args)?)
        }
        ServiceCommand::Uninstall(_) => service::manage(service::Action::Uninstall, Vec::new()),
        ServiceCommand::Status(_) => service::manage(service::Action::Status, Vec::new()),
        ServiceCommand::Start(_) => service::manage(service::Action::Start, Vec::new()),
        ServiceCommand::Stop(_) => service::manage(service::Action::Stop, Vec::new()),
        ServiceCommand::Restart(_) => service::manage(service::Action::Restart, Vec::new()),
        ServiceCommand::Logs(logs) => service::manage(
            service::Action::Logs {
                follow: logs.follow,
            },
            Vec::new(),
        ),
    }
}

/// Rebuild the explicit server options for the launch-at-login command.
/// Paths are made absolute because Windows does not define a stable working
/// directory for programs started from the Run registry key.
fn startup_args(args: &Args) -> anyhow::Result<Vec<String>> {
    let mut result = Vec::new();

    push_option(&mut result, "--port", args.port);
    for path in &args.host_key {
        push_path_option(&mut result, "--host-key", path)?;
    }
    if let Some(path) = &args.config {
        push_path_option(&mut result, "--config", path)?;
    }
    if let Some(path) = &args.log_file {
        push_path_option(&mut result, "--log-file", path)?;
    }
    push_switch(&mut result, "--debug", args.debug);
    push_switch(&mut result, "--verbose", args.verbose);
    push_switch(&mut result, "--quiet", args.quiet);
    push_option(&mut result, "--bind", args.bind);
    push_option(
        &mut result,
        "--host-key-passphrase",
        args.host_key_passphrase.as_deref(),
    );
    push_option(&mut result, "--password", args.password.as_deref());
    for path in &args.authorized_keys {
        push_path_option(&mut result, "--authorized-keys", path)?;
    }
    for key in &args.pubkey {
        push_option(&mut result, "--pubkey", Some(key.as_str()));
    }
    push_option(&mut result, "--shell", args.shell.as_deref());
    if let Some(path) = &args.sftp_root {
        push_path_option(&mut result, "--sftp-root", path)?;
    }
    push_switch(&mut result, "--strict-user", args.strict_user);
    for user in &args.allow_user {
        push_option(&mut result, "--allow-user", Some(user.as_str()));
    }
    push_switch(&mut result, "--no-forward", args.no_forward);
    push_option(&mut result, "--login-grace", args.login_grace);
    push_option(&mut result, "--max-startups", args.max_startups);

    Ok(result)
}

fn push_option<T: ToString>(result: &mut Vec<String>, name: &str, value: Option<T>) {
    if let Some(value) = value {
        result.push(name.to_owned());
        result.push(value.to_string());
    }
}

fn push_switch(result: &mut Vec<String>, name: &str, enabled: bool) {
    if enabled {
        result.push(name.to_owned());
    }
}

fn push_path_option(
    result: &mut Vec<String>,
    name: &str,
    path: &std::path::Path,
) -> anyhow::Result<()> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("failed to resolve the current directory")?
            .join(path)
    };
    result.push(name.to_owned());
    result.push(absolute.to_string_lossy().into_owned());
    Ok(())
}

/// Build the effective [`Config`]: defaults < config file < flags (ADR 0019).
fn build_config(args: &Args) -> anyhow::Result<Config> {
    let home = dirs::home_dir();
    let config_path = select_config_path(args.config.as_deref(), home.as_deref());
    let mut config = match config_path {
        Some(path) => Config::load_file(&path)
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

fn select_config_path(explicit: Option<&Path>, home: Option<&Path>) -> Option<PathBuf> {
    explicit.map(Path::to_path_buf).or_else(|| {
        let path = home?.join(".ssh").join("sshdt_config");
        path.exists().then_some(path)
    })
}

/// Install the process-global `tracing` subscriber. When `-E/--log-file` is
/// given, logs are appended to that file (returning the appender's guard, which
/// must be kept alive); otherwise they go to stderr.
fn init_logging(args: &Args, service_mode: bool) -> anyhow::Result<Option<WorkerGuard>> {
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

    if service_mode && args.log_file.is_none() {
        let directory = service::default_log_directory()?;
        let file = tracing_appender::rolling::RollingFileAppender::builder()
            .rotation(tracing_appender::rolling::Rotation::DAILY)
            .filename_prefix("sshdt")
            .filename_suffix("log")
            .max_log_files(7)
            .build(&directory)
            .with_context(|| {
                format!(
                    "failed to initialize service logs in {}",
                    directory.display()
                )
            })?;
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .with_writer(file)
            .init();
        Ok(None)
    } else if let Some(path) = &args.log_file {
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

#[cfg(test)]
mod tests {
    use super::{Args, Command, ServiceCommand, ServiceLogs, select_config_path, startup_args};
    use argh::FromArgs;

    fn parse(command: &[&str]) -> Args {
        Args::from_args(&["sshdt"], command).expect("arguments should parse")
    }

    #[test]
    fn server_mode_does_not_require_a_subcommand() {
        let args = parse(&["--port", "2200"]);
        assert!(args.command.is_none());
        assert_eq!(args.port, Some(2200));
    }

    #[test]
    fn service_install_preserves_server_options() {
        let args = parse(&[
            "--port",
            "2200",
            "--bind",
            "0.0.0.0",
            "--shell",
            "pwsh -NoLogo",
            "--allow-user",
            "Ada Lovelace",
            "--no-forward",
            "service",
            "install",
        ]);
        assert!(matches!(
            args.command,
            Some(Command::Service(ref service))
                if matches!(service.command, ServiceCommand::Install(_))
        ));
        assert_eq!(
            startup_args(&args).unwrap(),
            [
                "--port",
                "2200",
                "--bind",
                "0.0.0.0",
                "--shell",
                "pwsh -NoLogo",
                "--allow-user",
                "Ada Lovelace",
                "--no-forward",
            ]
        );
    }

    #[test]
    fn service_install_does_not_save_the_implicit_config_path() {
        let args = parse(&["service", "install"]);
        assert!(startup_args(&args).unwrap().is_empty());
    }

    #[test]
    fn selects_implicit_config_only_when_it_exists() {
        let directory = tempfile::tempdir().unwrap();
        assert_eq!(select_config_path(None, Some(directory.path())), None);

        let ssh_directory = directory.path().join(".ssh");
        std::fs::create_dir(&ssh_directory).unwrap();
        let implicit = ssh_directory.join("sshdt_config");
        std::fs::write(&implicit, "Port 2200\n").unwrap();
        assert_eq!(
            select_config_path(None, Some(directory.path())),
            Some(implicit)
        );
    }

    #[test]
    fn explicit_config_path_overrides_the_implicit_path() {
        let directory = tempfile::tempdir().unwrap();
        let explicit = directory.path().join("custom_config");
        assert_eq!(
            select_config_path(Some(&explicit), Some(directory.path())),
            Some(explicit)
        );
    }

    #[test]
    fn service_logs_follow_parses() {
        let args = parse(&["service", "logs", "--follow"]);
        let Some(Command::Service(service)) = args.command else {
            panic!("expected service command");
        };
        assert!(matches!(
            service.command,
            ServiceCommand::Logs(ServiceLogs { follow: true })
        ));
    }

    #[test]
    fn service_commands_parse() {
        for (name, expected) in [
            ("install", "install"),
            ("uninstall", "uninstall"),
            ("status", "status"),
            ("start", "start"),
            ("stop", "stop"),
            ("restart", "restart"),
            ("logs", "logs"),
        ] {
            let args = parse(&["service", name]);
            let Some(Command::Service(service)) = args.command else {
                panic!("expected service command");
            };
            let actual = match service.command {
                ServiceCommand::Install(_) => "install",
                ServiceCommand::Uninstall(_) => "uninstall",
                ServiceCommand::Status(_) => "status",
                ServiceCommand::Start(_) => "start",
                ServiceCommand::Stop(_) => "stop",
                ServiceCommand::Restart(_) => "restart",
                ServiceCommand::Logs(_) => "logs",
            };
            assert_eq!(actual, expected);
        }
    }
}
