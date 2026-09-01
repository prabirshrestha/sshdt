//! Windows launch-at-login and process management for the CLI.

use std::path::PathBuf;

#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Clone, Copy)]
pub(crate) enum Action {
    Enable,
    Disable,
    Status,
    Start,
    Stop,
    Restart,
    Logs { follow: bool },
}

pub(crate) fn manage(action: Action, startup_args: Vec<String>) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        windows::manage(action, &startup_args)
    }

    #[cfg(not(windows))]
    {
        let _ = (action, startup_args);
        anyhow::bail!("service management is currently supported only on Windows")
    }
}

pub(crate) fn default_log_directory() -> anyhow::Result<PathBuf> {
    let home =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("could not find the home directory"))?;
    let directory = home.join(".sshdt").join("logs");
    std::fs::create_dir_all(&directory)?;
    Ok(directory)
}

pub(crate) struct RunGuard {
    #[cfg(windows)]
    inner: windows::RunGuard,
}

impl RunGuard {
    pub(crate) fn acquire() -> anyhow::Result<Self> {
        #[cfg(windows)]
        {
            Ok(Self {
                inner: windows::RunGuard::acquire()?,
            })
        }

        #[cfg(not(windows))]
        {
            anyhow::bail!("service mode is currently supported only on Windows")
        }
    }

    pub(crate) fn mark_ready(&self) -> anyhow::Result<()> {
        #[cfg(windows)]
        {
            self.inner.mark_ready()
        }

        #[cfg(not(windows))]
        {
            Ok(())
        }
    }

    pub(crate) async fn wait_for_stop(&self) -> anyhow::Result<()> {
        #[cfg(windows)]
        {
            self.inner.wait_for_stop().await
        }

        #[cfg(not(windows))]
        {
            Ok(())
        }
    }
}

#[cfg(any(windows, test))]
fn quote_windows_argument(argument: &str) -> String {
    if !argument.is_empty()
        && !argument
            .chars()
            .any(|character| character.is_whitespace() || character == '"')
    {
        return argument.to_owned();
    }

    let mut quoted = String::from("\"");
    let mut backslashes = 0;
    for character in argument.chars() {
        match character {
            '\\' => backslashes += 1,
            '"' => {
                quoted.push_str(&"\\".repeat(backslashes * 2 + 1));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                quoted.push_str(&"\\".repeat(backslashes));
                quoted.push(character);
                backslashes = 0;
            }
        }
    }
    quoted.push_str(&"\\".repeat(backslashes * 2));
    quoted.push('"');
    quoted
}

#[cfg(windows)]
mod windows {
    use std::ffi::OsStr;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::Duration;

    use anyhow::{Context, ensure};
    use windows_registry::CURRENT_USER;
    use windows_result::HRESULT;
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, GetLastError, HANDLE,
        WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_NO_WINDOW, CreateEventW, EVENT_MODIFY_STATE, OpenEventW,
        SYNCHRONIZATION_SYNCHRONIZE, SetEvent, WaitForSingleObject,
    };

    use super::{Action, default_log_directory, quote_windows_argument};

    const APP_NAME: &str = "sshdt";
    const SETTINGS_KEY: &str = r"SOFTWARE\sshdt";
    const ARGS_VALUE: &str = "ServiceArgs";
    const EXECUTABLE_VALUE: &str = "ServiceExecutable";
    const RUN_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    const STARTUP_APPROVED_KEY: &str =
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
    const STARTUP_ENABLED: [u8; 12] = [
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    const FILE_NOT_FOUND: HRESULT = HRESULT::from_win32(2);
    const RUNNING_EVENT_NAME: &str = r"Local\sshdt-service-running";
    const STOP_EVENT_NAME: &str = r"Local\sshdt-service-stop";
    const READY_EVENT_NAME: &str = r"Local\sshdt-service-ready";
    const WAIT_TIMEOUT_MS: u32 = 10_000;

    pub(super) fn manage(action: Action, startup_args: &[String]) -> anyhow::Result<()> {
        match action {
            Action::Enable => {
                enable(startup_args)?;
                println!("enabled sshdt launch at login for the current Windows user");
                println!("run `sshdt service start` to start it now");
            }
            Action::Disable => {
                disable()?;
                println!("disabled sshdt launch at login for the current Windows user");
            }
            Action::Status => {
                println!(
                    "sshdt launch at login is {}; process is {}",
                    if launch_at_login_enabled()? {
                        "enabled"
                    } else {
                        "disabled"
                    },
                    if is_running()? { "running" } else { "stopped" }
                );
            }
            Action::Start => start()?,
            Action::Stop => stop(true)?,
            Action::Restart => {
                stop(false)?;
                start()?;
            }
            Action::Logs { follow } => show_logs(follow)?,
        }
        Ok(())
    }

    fn enable(startup_args: &[String]) -> anyhow::Result<()> {
        let executable = current_executable()?;
        let mut command = launch_app_path(&executable);
        for argument in startup_args {
            command.push(' ');
            command.push_str(&quote_windows_argument(argument));
        }
        command.push_str(" --service-run");

        let settings = CURRENT_USER
            .create(SETTINGS_KEY)
            .context("failed to open sshdt service settings")?;
        settings
            .set_multi_string(
                ARGS_VALUE,
                &startup_args.iter().map(String::as_str).collect::<Vec<_>>(),
            )
            .context("failed to save sshdt service options")?;
        settings
            .set_string(EXECUTABLE_VALUE, executable.to_string_lossy())
            .context("failed to save the sshdt service executable")?;
        CURRENT_USER
            .create(RUN_KEY)
            .and_then(|key| key.set_string(APP_NAME, command))
            .context("failed to enable sshdt launch at login")?;

        match CURRENT_USER.options().write().open(STARTUP_APPROVED_KEY) {
            Ok(key) => key
                .set_bytes(APP_NAME, windows_registry::Type::Bytes, &STARTUP_ENABLED)
                .context("failed to enable sshdt in Windows startup settings")?,
            Err(error) if error.code() == FILE_NOT_FOUND => {}
            Err(error) => return Err(error).context("failed to open Windows startup settings"),
        }
        Ok(())
    }

    fn disable() -> anyhow::Result<()> {
        remove_value(RUN_KEY, APP_NAME, "failed to disable sshdt launch at login")
    }

    fn remove_value(key: &str, value: &str, context: &'static str) -> anyhow::Result<()> {
        match CURRENT_USER
            .options()
            .write()
            .open(key)
            .and_then(|key| key.remove_value(value))
        {
            Ok(()) => Ok(()),
            Err(error) if error.code() == FILE_NOT_FOUND => Ok(()),
            Err(error) => Err(error).context(context),
        }
    }

    fn start() -> anyhow::Result<()> {
        ensure!(
            is_configured()?,
            "sshdt is not configured; run `sshdt service enable` first"
        );
        if is_running()? {
            println!("sshdt is already running");
            return Ok(());
        }

        let mut command = Command::new(saved_executable()?);
        command
            .args(saved_args()?)
            .arg("--service-run")
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = command.spawn().context("failed to start sshdt")?;
        wait_for_ready(&mut child, WAIT_TIMEOUT_MS)
            .context("sshdt did not become ready; run `sshdt service logs` for details")?;
        println!("started sshdt");
        Ok(())
    }

    fn stop(print_status: bool) -> anyhow::Result<()> {
        let Some(event) = stop_event()? else {
            if print_status {
                println!("sshdt is already stopped");
            }
            return Ok(());
        };
        let signaled = unsafe { SetEvent(event.0) };
        ensure!(
            signaled != 0,
            "failed to request sshdt shutdown: {}",
            std::io::Error::last_os_error()
        );
        wait_until_stopped(WAIT_TIMEOUT_MS)?;
        if print_status {
            println!("stopped sshdt");
        }
        Ok(())
    }

    fn stop_event() -> anyhow::Result<Option<OwnedHandle>> {
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        loop {
            if let Some(event) = open_event(STOP_EVENT_NAME, EVENT_MODIFY_STATE)? {
                return Ok(Some(event));
            }
            if !is_running()? || std::time::Instant::now() >= deadline {
                ensure!(
                    !is_running()?,
                    "sshdt is running but cannot accept a stop request"
                );
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn saved_args() -> anyhow::Result<Vec<String>> {
        try_saved_args()?.ok_or_else(|| anyhow::anyhow!("sshdt service options are not configured"))
    }

    fn try_saved_args() -> anyhow::Result<Option<Vec<String>>> {
        match CURRENT_USER
            .open(SETTINGS_KEY)
            .and_then(|key| key.get_multi_string(ARGS_VALUE))
        {
            Ok(args) => Ok(Some(
                args.into_iter()
                    .filter(|argument| !argument.is_empty())
                    .collect(),
            )),
            Err(error) if error.code() == FILE_NOT_FOUND => Ok(None),
            Err(error) => Err(error).context("failed to read configured sshdt service options"),
        }
    }

    fn saved_executable() -> anyhow::Result<PathBuf> {
        CURRENT_USER
            .open(SETTINGS_KEY)
            .and_then(|key| key.get_string(EXECUTABLE_VALUE))
            .map(PathBuf::from)
            .context("failed to read the configured sshdt executable")
    }

    fn has_run_entry() -> anyhow::Result<bool> {
        match CURRENT_USER
            .open(RUN_KEY)
            .and_then(|key| key.get_string(APP_NAME))
        {
            Ok(_) => Ok(true),
            Err(error) if error.code() == FILE_NOT_FOUND => Ok(false),
            Err(error) => Err(error).context("failed to read sshdt launch-at-login state"),
        }
    }

    fn startup_approved() -> anyhow::Result<bool> {
        match CURRENT_USER
            .open(STARTUP_APPROVED_KEY)
            .and_then(|key| key.get_value(APP_NAME))
        {
            Ok(value) => Ok(value.first() == Some(&STARTUP_ENABLED[0])),
            Err(error) if error.code() == FILE_NOT_FOUND => Ok(true),
            Err(error) => Err(error).context("failed to read Windows startup settings"),
        }
    }

    fn launch_at_login_enabled() -> anyhow::Result<bool> {
        Ok(has_run_entry()? && startup_approved()?)
    }

    fn is_configured() -> anyhow::Result<bool> {
        let Some(_) = try_saved_args()? else {
            return Ok(false);
        };
        match CURRENT_USER
            .open(SETTINGS_KEY)
            .and_then(|key| key.get_string(EXECUTABLE_VALUE))
        {
            Ok(_) => Ok(true),
            Err(error) if error.code() == FILE_NOT_FOUND => Ok(false),
            Err(error) => Err(error).context("failed to read sshdt service configuration"),
        }
    }

    fn is_running() -> anyhow::Result<bool> {
        Ok(open_event(RUNNING_EVENT_NAME, SYNCHRONIZATION_SYNCHRONIZE)?.is_some())
    }

    fn wait_until_stopped(timeout_ms: u32) -> anyhow::Result<()> {
        let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms.into());
        while is_running()? {
            ensure!(
                std::time::Instant::now() < deadline,
                "timed out while stopping sshdt"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        Ok(())
    }

    fn wait_for_ready(child: &mut std::process::Child, timeout_ms: u32) -> anyhow::Result<()> {
        let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms.into());
        let mut observed_running = false;
        loop {
            if let Some(ready) = open_event(READY_EVENT_NAME, SYNCHRONIZATION_SYNCHRONIZE)?
                && unsafe { WaitForSingleObject(ready.0, 0) } == WAIT_OBJECT_0
            {
                return Ok(());
            }
            let running = is_running()?;
            observed_running |= running;
            if observed_running && !running {
                anyhow::bail!("sshdt stopped before it became ready");
            }
            if let Some(status) = child
                .try_wait()
                .context("failed to inspect sshdt startup")?
            {
                anyhow::bail!("sshdt exited before it became ready with {status}");
            }
            ensure!(
                std::time::Instant::now() < deadline,
                "timed out waiting for sshdt"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn show_logs(follow: bool) -> anyhow::Result<()> {
        let directory = default_log_directory()?;
        let explicit = configured_log_path()?;
        let mut current: Option<(PathBuf, File)> = None;
        loop {
            let latest = if explicit.as_ref().is_some_and(|path| path.is_file()) {
                explicit.clone()
            } else if explicit.is_some() {
                None
            } else {
                latest_log(&directory)?
            };
            if latest.as_ref() != current.as_ref().map(|(path, _)| path) {
                if let Some(path) = latest {
                    let mut file = File::open(&path)?;
                    if current.is_none() {
                        std::io::copy(&mut file, &mut std::io::stdout())?;
                    }
                    current = Some((path, file));
                } else if !follow {
                    println!(
                        "no sshdt service logs found at {}",
                        explicit.as_ref().unwrap_or(&directory).display()
                    );
                    return Ok(());
                }
            }

            if let Some((_, file)) = &mut current {
                let mut buffer = Vec::new();
                file.read_to_end(&mut buffer)?;
                std::io::stdout().write_all(&buffer)?;
                std::io::stdout().flush()?;
            }
            if !follow {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    fn configured_log_path() -> anyhow::Result<Option<PathBuf>> {
        Ok(try_saved_args()?
            .unwrap_or_default()
            .windows(2)
            .find(|pair| pair[0] == "--log-file")
            .map(|pair| PathBuf::from(&pair[1])))
    }

    fn latest_log(directory: &Path) -> anyhow::Result<Option<PathBuf>> {
        let mut latest = None;
        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            let is_log = path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("sshdt.") && name.ends_with(".log"));
            if !is_log {
                continue;
            }
            let modified = entry.metadata()?.modified()?;
            if latest
                .as_ref()
                .is_none_or(|(_, latest_modified)| modified > *latest_modified)
            {
                latest = Some((path, modified));
            }
        }
        Ok(latest.map(|(path, _)| path))
    }

    fn current_executable() -> anyhow::Result<PathBuf> {
        let executable = std::env::current_exe().context("could not locate sshdt.exe")?;
        Ok(executable.canonicalize().unwrap_or(executable))
    }

    fn wide(value: &str) -> Vec<u16> {
        OsStr::new(value).encode_wide().chain(Some(0)).collect()
    }

    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    fn open_event(name: &str, access: u32) -> anyhow::Result<Option<OwnedHandle>> {
        let name = wide(name);
        let handle = unsafe { OpenEventW(access, 0, name.as_ptr()) };
        optional_handle(handle)
    }

    fn optional_handle(handle: HANDLE) -> anyhow::Result<Option<OwnedHandle>> {
        if !handle.is_null() {
            return Ok(Some(OwnedHandle(handle)));
        }
        let error = unsafe { GetLastError() };
        if error == ERROR_FILE_NOT_FOUND {
            Ok(None)
        } else {
            Err(std::io::Error::from_raw_os_error(error as i32).into())
        }
    }

    pub(super) struct RunGuard {
        _running: OwnedHandle,
        stop: OwnedHandle,
        ready: OwnedHandle,
    }

    impl RunGuard {
        pub(super) fn acquire() -> anyhow::Result<Self> {
            let running_name = wide(RUNNING_EVENT_NAME);
            let running = unsafe { CreateEventW(std::ptr::null(), 1, 1, running_name.as_ptr()) };
            ensure!(
                !running.is_null(),
                "failed to create sshdt running event: {}",
                std::io::Error::last_os_error()
            );
            if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
                unsafe { CloseHandle(running) };
                anyhow::bail!("sshdt is already running");
            }

            Ok(Self {
                _running: OwnedHandle(running),
                stop: create_event(STOP_EVENT_NAME)?,
                ready: create_event(READY_EVENT_NAME)?,
            })
        }

        pub(super) fn mark_ready(&self) -> anyhow::Result<()> {
            let result = unsafe { SetEvent(self.ready.0) };
            ensure!(
                result != 0,
                "failed to publish sshdt readiness: {}",
                std::io::Error::last_os_error()
            );
            Ok(())
        }

        pub(super) async fn wait_for_stop(&self) -> anyhow::Result<()> {
            loop {
                match unsafe { WaitForSingleObject(self.stop.0, 0) } {
                    WAIT_OBJECT_0 => return Ok(()),
                    WAIT_TIMEOUT => tokio::time::sleep(Duration::from_millis(100)).await,
                    _ => anyhow::bail!("failed while waiting for sshdt stop request"),
                }
            }
        }
    }

    fn create_event(name: &str) -> anyhow::Result<OwnedHandle> {
        let name = wide(name);
        let handle = unsafe { CreateEventW(std::ptr::null(), 1, 0, name.as_ptr()) };
        ensure!(
            !handle.is_null(),
            "failed to create sshdt service event: {}",
            std::io::Error::last_os_error()
        );
        Ok(OwnedHandle(handle))
    }

    fn launch_app_path(executable: &Path) -> String {
        let raw = executable.to_string_lossy();
        let clean = raw
            .strip_prefix(r"\\?\UNC\")
            .map(|path| format!(r"\\{path}"))
            .unwrap_or_else(|| raw.strip_prefix(r"\\?\").unwrap_or(&raw).to_owned());
        format!("\"{clean}\"")
    }
}

#[cfg(test)]
mod tests {
    use super::quote_windows_argument;

    #[test]
    fn windows_arguments_are_quoted_for_the_run_key() {
        assert_eq!(quote_windows_argument("--port"), "--port");
        assert_eq!(
            quote_windows_argument(r"C:\Program Files\sshdt config.toml"),
            r#""C:\Program Files\sshdt config.toml""#
        );
        assert_eq!(quote_windows_argument(""), r#""""#);
        assert_eq!(
            quote_windows_argument(r#"say "hello""#),
            r#""say \"hello\"""#
        );
        assert_eq!(
            quote_windows_argument("C:\\trailing slash\\"),
            r#""C:\trailing slash\\""#
        );
    }
}
