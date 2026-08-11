//! Windows Service Control Manager integration for the CLI.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow, bail};
use tokio::sync::oneshot;
use windows_service::define_windows_service;
use windows_service::service::{
    ServiceAccess, ServiceAction as FailureAction, ServiceActionType, ServiceControl,
    ServiceControlAccept, ServiceDependency, ServiceErrorControl, ServiceExitCode,
    ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState,
    ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use super::{Args, ServiceAction, build_config, init_logging};
use sshdt::Server;

const SERVICE_NAME: &str = "sshdt";
const SERVICE_DISPLAY_NAME: &str = "sshdt SSH Server";
const SERVICE_DESCRIPTION: &str = "Tiny SSH server daemon";
const SERVICE_ACCOUNT: &str = r"NT AUTHORITY\LocalService";
const STATE_TIMEOUT: Duration = Duration::from_secs(30);

static SERVICE_ARGS: OnceLock<Args> = OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

pub(super) fn manage(args: &Args, action: &ServiceAction) -> anyhow::Result<()> {
    match action {
        ServiceAction::Install(_) => install(args),
        ServiceAction::Uninstall(_) => uninstall(),
        ServiceAction::Start(_) => start(),
        ServiceAction::Stop(_) => stop(),
        ServiceAction::Restart(_) => restart(),
        ServiceAction::Status(_) => status(),
    }
}

pub(super) fn dispatch(args: Args) -> windows_service::Result<()> {
    assert!(
        SERVICE_ARGS.set(args).is_ok(),
        "Windows service arguments must only be initialized once"
    );
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

fn install(args: &Args) -> anyhow::Result<()> {
    let config = build_config(args).context("invalid service configuration")?;
    if !config.has_explicit_auth() {
        bail!(
            "refusing to install an anonymous Windows service; configure --password, \
             --authorized-keys, or --pubkey first"
        );
    }

    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .context("could not open the Windows Service Control Manager (run as Administrator)")?;

    let executable_path = std::env::current_exe().context("could not locate sshdt.exe")?;
    let service_info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: SERVICE_DISPLAY_NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path,
        launch_arguments: service_launch_arguments(args)?,
        dependencies: vec![ServiceDependency::Service(OsString::from("Tcpip"))],
        account_name: Some(OsString::from(SERVICE_ACCOUNT)),
        account_password: None,
    };

    let service = manager
        .create_service(
            &service_info,
            ServiceAccess::CHANGE_CONFIG | ServiceAccess::DELETE,
        )
        .context(
            "could not install the sshdt service; it may already exist (run as Administrator)",
        )?;

    if let Err(error) = service.set_description(SERVICE_DESCRIPTION) {
        return rollback_install(&service, error);
    }
    let failure_actions = ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(60)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![FailureAction {
            action_type: ServiceActionType::Restart,
            delay: Duration::from_secs(5),
        }]),
    };
    if let Err(error) = service.update_failure_actions(failure_actions) {
        return rollback_install(&service, error);
    }
    if let Err(error) = service.set_failure_actions_on_non_crash_failures(true) {
        return rollback_install(&service, error);
    }

    println!("installed {SERVICE_DISPLAY_NAME} with automatic startup");
    println!("start it with `sshdt service start`");
    Ok(())
}

fn rollback_install(
    service: &windows_service::service::Service,
    error: windows_service::Error,
) -> anyhow::Result<()> {
    match service.delete() {
        Ok(()) => Err(error).context("service installation failed and was rolled back"),
        Err(rollback_error) => Err(anyhow!(
            "service installation failed: {error}; rollback also failed: {rollback_error}"
        )),
    }
}

fn uninstall() -> anyhow::Result<()> {
    let manager = open_manager()?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .context("the sshdt service is not installed or cannot be opened")?;

    let state = service.query_status()?.current_state;
    if state != ServiceState::Stopped {
        if state == ServiceState::StartPending {
            wait_for_state(&service, ServiceState::Running)?;
            service.stop().context("could not stop the sshdt service")?;
        } else if state != ServiceState::StopPending {
            service.stop().context("could not stop the sshdt service")?;
        }
        wait_for_state(&service, ServiceState::Stopped)?;
    }
    service
        .delete()
        .context("could not remove the sshdt service")?;
    drop(service);
    wait_for_deletion(&manager)?;
    println!("removed {SERVICE_DISPLAY_NAME}");
    Ok(())
}

fn start() -> anyhow::Result<()> {
    let manager = open_manager()?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::START,
        )
        .context("the sshdt service is not installed or cannot be opened")?;
    start_service(&service)
}

fn stop() -> anyhow::Result<()> {
    let manager = open_manager()?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP,
        )
        .context("the sshdt service is not installed or cannot be opened")?;
    stop_service(&service)
}

fn restart() -> anyhow::Result<()> {
    let manager = open_manager()?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::START | ServiceAccess::STOP,
        )
        .context("the sshdt service is not installed or cannot be opened")?;
    stop_service(&service)?;
    start_service(&service)
}

fn status() -> anyhow::Result<()> {
    let manager = open_manager()?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::QUERY_CONFIG,
        )
        .context("the sshdt service is not installed or cannot be opened")?;
    let status = service.query_status()?;
    let config = service.query_config()?;

    println!("service: {SERVICE_NAME}");
    println!("state: {}", state_name(status.current_state));
    println!("startup: {}", start_type_name(config.start_type));
    if let Some(process_id) = status.process_id.filter(|process_id| *process_id != 0) {
        println!("process id: {process_id}");
    }
    Ok(())
}

fn open_manager() -> anyhow::Result<ServiceManager> {
    ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("could not open the Windows Service Control Manager")
}

fn start_service(service: &windows_service::service::Service) -> anyhow::Result<()> {
    match service.query_status()?.current_state {
        ServiceState::Running => {
            println!("{SERVICE_DISPLAY_NAME} is already running");
            return Ok(());
        }
        ServiceState::StartPending => {
            wait_for_state(service, ServiceState::Running)?;
            println!("started {SERVICE_DISPLAY_NAME}");
            return Ok(());
        }
        ServiceState::StopPending => wait_for_state(service, ServiceState::Stopped)?,
        ServiceState::Stopped => {}
        state => bail!("cannot start the service while it is {}", state_name(state)),
    }

    service
        .start::<&OsStr>(&[])
        .context("could not start the sshdt service")?;
    wait_for_state(service, ServiceState::Running)?;
    println!("started {SERVICE_DISPLAY_NAME}");
    Ok(())
}

fn stop_service(service: &windows_service::service::Service) -> anyhow::Result<()> {
    match service.query_status()?.current_state {
        ServiceState::Stopped => {
            println!("{SERVICE_DISPLAY_NAME} is already stopped");
            return Ok(());
        }
        ServiceState::StopPending => {}
        ServiceState::StartPending => {
            wait_for_state(service, ServiceState::Running)?;
            service.stop().context("could not stop the sshdt service")?;
        }
        _ => {
            service.stop().context("could not stop the sshdt service")?;
        }
    }
    wait_for_state(service, ServiceState::Stopped)?;
    println!("stopped {SERVICE_DISPLAY_NAME}");
    Ok(())
}

fn wait_for_state(
    service: &windows_service::service::Service,
    expected: ServiceState,
) -> anyhow::Result<()> {
    let started = Instant::now();
    loop {
        let status = service.query_status()?;
        if status.current_state == expected {
            return Ok(());
        }
        if expected == ServiceState::Running && status.current_state == ServiceState::Stopped {
            bail!("the service stopped before reaching the running state");
        }
        if started.elapsed() >= STATE_TIMEOUT {
            bail!(
                "timed out waiting for the service to become {} (currently {})",
                state_name(expected),
                state_name(status.current_state)
            );
        }
        thread::sleep(Duration::from_millis(250));
    }
}

fn wait_for_deletion(manager: &ServiceManager) -> anyhow::Result<()> {
    let started = Instant::now();
    loop {
        if manager
            .open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS)
            .is_err()
        {
            return Ok(());
        }
        if started.elapsed() >= STATE_TIMEOUT {
            bail!("the service is marked for deletion but is still in use");
        }
        thread::sleep(Duration::from_millis(250));
    }
}

fn service_launch_arguments(args: &Args) -> anyhow::Result<Vec<OsString>> {
    let mut result = Vec::new();

    push_value(
        &mut result,
        "--port",
        args.port.map(|value| value.to_string()),
    );
    for path in &args.host_key {
        push_path(&mut result, "--host-key", path)?;
    }
    if let Some(path) = &args.config {
        push_path(&mut result, "--config", path)?;
    }
    if let Some(path) = &args.log_file {
        push_path(&mut result, "--log-file", path)?;
    }
    push_switch(&mut result, "--debug", args.debug);
    push_switch(&mut result, "--verbose", args.verbose);
    push_switch(&mut result, "--quiet", args.quiet);
    push_value(
        &mut result,
        "--bind",
        args.bind.map(|value| value.to_string()),
    );
    push_value(
        &mut result,
        "--host-key-passphrase",
        args.host_key_passphrase.clone(),
    );
    push_value(&mut result, "--password", args.password.clone());
    for path in &args.authorized_keys {
        push_path(&mut result, "--authorized-keys", path)?;
    }
    for value in &args.pubkey {
        push_value(&mut result, "--pubkey", Some(value.clone()));
    }
    push_value(&mut result, "--shell", args.shell.clone());
    if let Some(path) = &args.sftp_root {
        push_path(&mut result, "--sftp-root", path)?;
    }
    push_switch(&mut result, "--strict-user", args.strict_user);
    for value in &args.allow_user {
        push_value(&mut result, "--allow-user", Some(value.clone()));
    }
    push_switch(&mut result, "--no-forward", args.no_forward);
    push_value(
        &mut result,
        "--login-grace",
        args.login_grace.map(|value| value.to_string()),
    );
    push_value(
        &mut result,
        "--max-startups",
        args.max_startups.map(|value| value.to_string()),
    );
    result.push(OsString::from("--windows-service"));
    Ok(result)
}

fn push_value(values: &mut Vec<OsString>, name: &str, value: Option<String>) {
    if let Some(value) = value {
        values.push(OsString::from(name));
        values.push(OsString::from(value));
    }
}

fn push_switch(values: &mut Vec<OsString>, name: &str, enabled: bool) {
    if enabled {
        values.push(OsString::from(name));
    }
}

fn push_path(values: &mut Vec<OsString>, name: &str, path: &Path) -> anyhow::Result<()> {
    values.push(OsString::from(name));
    values.push(absolute_path(path)?.into_os_string());
    Ok(())
}

fn absolute_path(path: &Path) -> anyhow::Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    Ok(std::env::current_dir()
        .context("could not determine the current directory")?
        .join(path))
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(error) = run_service() {
        eprintln!("sshdt service failed: {error:#}");
    }
}

fn run_service() -> anyhow::Result<()> {
    let args = SERVICE_ARGS
        .get()
        .ok_or_else(|| anyhow!("service arguments were not initialized"))?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let shutdown_tx = Arc::new(Mutex::new(Some(shutdown_tx)));
    let event_shutdown_tx = shutdown_tx.clone();
    let event_handler = move |event| match event {
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        ServiceControl::Stop | ServiceControl::Shutdown => {
            if let Ok(mut sender) = event_shutdown_tx.lock()
                && let Some(sender) = sender.take()
            {
                let _ = sender.send(());
            }
            ServiceControlHandlerResult::NoError
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;
    set_service_status(
        &status_handle,
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        ServiceExitCode::NO_ERROR,
        Duration::from_secs(30),
    )?;

    let result = run_service_worker(args, &status_handle, shutdown_rx);
    let exit_code = if result.is_ok() {
        ServiceExitCode::NO_ERROR
    } else {
        ServiceExitCode::ServiceSpecific(1)
    };
    let stopped_result = set_service_status(
        &status_handle,
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        exit_code,
        Duration::ZERO,
    );

    result.and(stopped_result)
}

fn run_service_worker(
    args: &Args,
    status_handle: &ServiceStatusHandle,
    shutdown_rx: oneshot::Receiver<()>,
) -> anyhow::Result<()> {
    set_service_working_directory(args)?;
    let _log_guard = init_logging(args)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("could not create the service runtime")?;

    let result = runtime.block_on(async {
        let config = build_config(args).context("invalid configuration")?;
        let bind = std::net::SocketAddr::new(config.bind, config.port);
        let server = Server::from_config(config).context("failed to build server")?;
        let handle = server
            .serve()
            .await
            .with_context(|| format!("failed to bind {bind}"))?;

        set_service_status(
            status_handle,
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            ServiceExitCode::NO_ERROR,
            Duration::ZERO,
        )?;
        tracing::info!(addr = %handle.local_addr(), "sshdt Windows service is ready");

        let _ = shutdown_rx.await;
        set_service_status(
            status_handle,
            ServiceState::StopPending,
            ServiceControlAccept::empty(),
            ServiceExitCode::NO_ERROR,
            Duration::from_secs(30),
        )?;
        tracing::info!("shutting down Windows service");
        handle.shutdown().await;
        Ok(())
    });
    if let Err(error) = &result {
        tracing::error!(%error, "sshdt Windows service failed");
    }
    result
}

fn set_service_working_directory(args: &Args) -> anyhow::Result<()> {
    let directory = if let Some(config) = &args.config {
        absolute_path(config)?
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| anyhow!("invalid config path {}", config.display()))?
    } else {
        std::env::current_exe()
            .context("could not locate sshdt.exe")?
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| anyhow!("sshdt.exe has no parent directory"))?
    };
    std::env::set_current_dir(&directory).with_context(|| {
        format!(
            "could not use {} as the service directory",
            directory.display()
        )
    })
}

fn set_service_status(
    handle: &ServiceStatusHandle,
    current_state: ServiceState,
    controls_accepted: ServiceControlAccept,
    exit_code: ServiceExitCode,
    wait_hint: Duration,
) -> anyhow::Result<()> {
    handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state,
            controls_accepted,
            exit_code,
            checkpoint: u32::from(matches!(
                current_state,
                ServiceState::StartPending | ServiceState::StopPending
            )),
            wait_hint,
            process_id: None,
        })
        .context("could not report service status")
}

fn state_name(state: ServiceState) -> &'static str {
    match state {
        ServiceState::Stopped => "stopped",
        ServiceState::StartPending => "starting",
        ServiceState::StopPending => "stopping",
        ServiceState::Running => "running",
        ServiceState::ContinuePending => "continuing",
        ServiceState::PausePending => "pausing",
        ServiceState::Paused => "paused",
    }
}

fn start_type_name(start_type: ServiceStartType) -> &'static str {
    match start_type {
        ServiceStartType::AutoStart => "automatic",
        ServiceStartType::OnDemand => "manual",
        ServiceStartType::Disabled => "disabled",
        ServiceStartType::SystemStart => "system",
        ServiceStartType::BootStart => "boot",
    }
}
