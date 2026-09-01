//! Windows launch-at-login and process management for the CLI.

#[cfg(any(windows, test))]
use std::path::Path;
use std::path::PathBuf;

#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Clone, Copy)]
pub(crate) enum Action {
    Enable,
    Disable,
    Uninstall,
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

#[cfg(windows)]
pub(crate) fn saved_startup_args() -> anyhow::Result<Vec<String>> {
    windows::saved_args()
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
fn launch_command(executable: &Path) -> String {
    let raw = executable.to_string_lossy();
    let clean = raw
        .strip_prefix(r"\\?\UNC\")
        .map(|path| format!(r"\\{path}"))
        .unwrap_or_else(|| raw.strip_prefix(r"\\?\").unwrap_or(&raw).to_owned());
    format!("\"{clean}\" --service-run")
}

#[cfg(windows)]
mod windows {
    use std::ffi::{OsStr, c_void};
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
        CloseHandle, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER,
        GetLastError, HANDLE, LocalFree, SetLastError, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
        TokenUser,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_NO_WINDOW, CreateEventW, EVENT_MODIFY_STATE, GetCurrentProcess, OpenEventW,
        OpenProcessToken, SYNCHRONIZATION_SYNCHRONIZE, SetEvent, WaitForSingleObject,
    };

    use super::{Action, default_log_directory, launch_command};

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
            Action::Uninstall => {
                uninstall(&EventNames::current()?)?;
                println!("uninstalled sshdt launch-at-login settings for the current Windows user");
            }
            Action::Status => {
                let names = EventNames::current()?;
                println!(
                    "sshdt launch at login is {}; process is {}",
                    if launch_at_login_enabled()? {
                        "enabled"
                    } else {
                        "disabled"
                    },
                    if is_running(&names)? {
                        "running"
                    } else {
                        "stopped"
                    }
                );
            }
            Action::Start => start(&EventNames::current()?)?,
            Action::Stop => stop(&EventNames::current()?, true)?,
            Action::Restart => {
                let names = EventNames::current()?;
                stop(&names, false)?;
                start(&names)?;
            }
            Action::Logs { follow } => show_logs(follow)?,
        }
        Ok(())
    }

    fn enable(startup_args: &[String]) -> anyhow::Result<()> {
        let executable = current_executable()?;
        let command = launch_command(&executable);

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

    fn uninstall(names: &EventNames) -> anyhow::Result<()> {
        stop(names, false)?;
        disable()?;
        remove_value(
            STARTUP_APPROVED_KEY,
            APP_NAME,
            "failed to remove sshdt from Windows startup settings",
        )?;
        match CURRENT_USER.remove_tree(SETTINGS_KEY) {
            Ok(()) => Ok(()),
            Err(error) if error.code() == FILE_NOT_FOUND => Ok(()),
            Err(error) => Err(error).context("failed to remove sshdt service settings"),
        }
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

    fn start(names: &EventNames) -> anyhow::Result<()> {
        ensure!(
            is_configured()?,
            "sshdt is not configured; run `sshdt service enable` first"
        );
        if is_running(names)? {
            println!("sshdt is already running");
            return Ok(());
        }

        let mut command = Command::new(saved_executable()?);
        command
            .arg("--service-run")
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = command.spawn().context("failed to start sshdt")?;
        if let Err(error) = wait_for_ready(&mut child, names, WAIT_TIMEOUT_MS) {
            cleanup_failed_start(&mut child, names)
                .with_context(|| format!("failed to stop sshdt after startup error: {error:#}"))?;
            return Err(error)
                .context("sshdt did not become ready; run `sshdt service logs` for details");
        }
        println!("started sshdt");
        Ok(())
    }

    fn stop(names: &EventNames, print_status: bool) -> anyhow::Result<()> {
        let Some(event) = stop_event(names)? else {
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
        wait_until_stopped(names, WAIT_TIMEOUT_MS)?;
        if print_status {
            println!("stopped sshdt");
        }
        Ok(())
    }

    fn stop_event(names: &EventNames) -> anyhow::Result<Option<OwnedHandle>> {
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        loop {
            if let Some(event) = open_event(&names.stop, EVENT_MODIFY_STATE)? {
                return Ok(Some(event));
            }
            if !is_running(names)? || std::time::Instant::now() >= deadline {
                ensure!(
                    !is_running(names)?,
                    "sshdt is running but cannot accept a stop request"
                );
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    pub(super) fn saved_args() -> anyhow::Result<Vec<String>> {
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

    fn is_running(names: &EventNames) -> anyhow::Result<bool> {
        Ok(open_event(&names.running, SYNCHRONIZATION_SYNCHRONIZE)?.is_some())
    }

    fn wait_until_stopped(names: &EventNames, timeout_ms: u32) -> anyhow::Result<()> {
        let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms.into());
        while is_running(names)? {
            ensure!(
                std::time::Instant::now() < deadline,
                "timed out while stopping sshdt"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        Ok(())
    }

    fn wait_for_ready(
        child: &mut std::process::Child,
        names: &EventNames,
        timeout_ms: u32,
    ) -> anyhow::Result<()> {
        let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms.into());
        let mut observed_running = false;
        loop {
            if let Some(ready) = open_event(&names.ready, SYNCHRONIZATION_SYNCHRONIZE)?
                && unsafe { WaitForSingleObject(ready.0, 0) } == WAIT_OBJECT_0
            {
                return Ok(());
            }
            let running = is_running(names)?;
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

    fn cleanup_failed_start(
        child: &mut std::process::Child,
        names: &EventNames,
    ) -> anyhow::Result<()> {
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        let mut stop_requested = false;
        loop {
            if child
                .try_wait()
                .context("failed to inspect sshdt during startup cleanup")?
                .is_some()
            {
                return Ok(());
            }
            if !stop_requested {
                match open_event(&names.stop, EVENT_MODIFY_STATE) {
                    Ok(Some(event)) if unsafe { SetEvent(event.0) } != 0 => {
                        stop_requested = true;
                    }
                    Ok(Some(_)) | Err(_) => break,
                    Ok(None) => {}
                }
            }
            if std::time::Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }

        if child
            .try_wait()
            .context("failed to inspect sshdt before forced startup cleanup")?
            .is_none()
        {
            child
                .kill()
                .context("failed to terminate sshdt after startup error")?;
        }
        child
            .wait()
            .context("failed to reap sshdt after startup error")?;
        Ok(())
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

    struct EventNames {
        running: String,
        stop: String,
        ready: String,
    }

    impl EventNames {
        fn current() -> anyhow::Result<Self> {
            Ok(Self::for_sid(&current_user_sid()?))
        }

        fn for_sid(sid: &str) -> Self {
            Self {
                running: format!(r"Global\sshdt-service-{sid}-running"),
                stop: format!(r"Global\sshdt-service-{sid}-stop"),
                ready: format!(r"Global\sshdt-service-{sid}-ready"),
            }
        }
    }

    fn current_user_sid() -> anyhow::Result<String> {
        let mut token = std::ptr::null_mut();
        ensure!(
            unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } != 0,
            "failed to open the current process token: {}",
            std::io::Error::last_os_error()
        );
        let token = OwnedHandle(token);

        let mut length = 0;
        unsafe { GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut length) };
        ensure!(
            unsafe { GetLastError() } == ERROR_INSUFFICIENT_BUFFER,
            "failed to size the current user token: {}",
            std::io::Error::last_os_error()
        );
        let word_size = std::mem::size_of::<usize>();
        let mut buffer = vec![0usize; (length as usize).div_ceil(word_size)];
        ensure!(
            unsafe {
                GetTokenInformation(
                    token.0,
                    TokenUser,
                    buffer.as_mut_ptr().cast(),
                    length,
                    &mut length,
                )
            } != 0,
            "failed to read the current user token: {}",
            std::io::Error::last_os_error()
        );
        let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
        let mut text = std::ptr::null_mut();
        ensure!(
            unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } != 0,
            "failed to format the current user SID: {}",
            std::io::Error::last_os_error()
        );
        let text = OwnedLocal(text.cast());
        let mut length = 0;
        while unsafe { *text.0.cast::<u16>().add(length) } != 0 {
            length += 1;
        }
        Ok(String::from_utf16_lossy(unsafe {
            std::slice::from_raw_parts(text.0.cast::<u16>(), length)
        }))
    }

    struct OwnedLocal(*mut c_void);

    impl Drop for OwnedLocal {
        fn drop(&mut self) {
            unsafe { LocalFree(self.0) };
        }
    }

    struct EventSecurity(PSECURITY_DESCRIPTOR);

    impl EventSecurity {
        fn for_user(sid: &str) -> anyhow::Result<Self> {
            let descriptor = wide(&event_security_descriptor(sid));
            let mut security_descriptor = std::ptr::null_mut();
            ensure!(
                unsafe {
                    ConvertStringSecurityDescriptorToSecurityDescriptorW(
                        descriptor.as_ptr(),
                        SDDL_REVISION_1,
                        &mut security_descriptor,
                        std::ptr::null_mut(),
                    )
                } != 0,
                "failed to create sshdt event security: {}",
                std::io::Error::last_os_error()
            );
            Ok(Self(security_descriptor))
        }

        fn attributes(&self) -> SECURITY_ATTRIBUTES {
            SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: self.0,
                bInheritHandle: 0,
            }
        }
    }

    fn event_security_descriptor(sid: &str) -> String {
        format!(r"D:P(A;;GA;;;SY)(A;;GA;;;{sid})")
    }

    impl Drop for EventSecurity {
        fn drop(&mut self) {
            unsafe { LocalFree(self.0) };
        }
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
            let sid = current_user_sid()?;
            let names = EventNames::for_sid(&sid);
            let security = EventSecurity::for_user(&sid)?;
            let security_attributes = security.attributes();
            let running_name = wide(&names.running);
            unsafe { SetLastError(0) };
            let running =
                unsafe { CreateEventW(&security_attributes, 1, 1, running_name.as_ptr()) };
            let create_error = unsafe { GetLastError() };
            ensure!(
                !running.is_null(),
                "failed to create sshdt running event: {}",
                std::io::Error::from_raw_os_error(create_error as i32)
            );
            let running = OwnedHandle(running);
            if create_error == ERROR_ALREADY_EXISTS {
                anyhow::bail!("sshdt is already running");
            }

            Ok(Self {
                _running: running,
                stop: create_event(&names.stop, &security_attributes)?,
                ready: create_event(&names.ready, &security_attributes)?,
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

    fn create_event(name: &str, security: &SECURITY_ATTRIBUTES) -> anyhow::Result<OwnedHandle> {
        let name = wide(name);
        let handle = unsafe { CreateEventW(security, 1, 0, name.as_ptr()) };
        ensure!(
            !handle.is_null(),
            "failed to create sshdt service event: {}",
            std::io::Error::last_os_error()
        );
        Ok(OwnedHandle(handle))
    }

    #[cfg(test)]
    mod tests {
        use super::{EventNames, event_security_descriptor};

        #[test]
        fn events_are_global_and_scoped_to_the_user_sid() {
            let sid = "S-1-5-21-42";
            let names = EventNames::for_sid(sid);
            assert_eq!(names.running, r"Global\sshdt-service-S-1-5-21-42-running");
            assert_eq!(names.stop, r"Global\sshdt-service-S-1-5-21-42-stop");
            assert_eq!(names.ready, r"Global\sshdt-service-S-1-5-21-42-ready");
        }

        #[test]
        fn event_acl_allows_only_system_and_the_current_user() {
            assert_eq!(
                event_security_descriptor("S-1-5-21-42"),
                "D:P(A;;GA;;;SY)(A;;GA;;;S-1-5-21-42)"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::launch_command;
    use std::path::Path;

    #[test]
    fn windows_run_command_uses_only_the_service_bootstrap() {
        assert_eq!(
            launch_command(Path::new(r"C:\Program Files\sshdt.exe")),
            r#""C:\Program Files\sshdt.exe" --service-run"#
        );
    }
}
