//! Windows launch-at-login management for the CLI.

/// A launch-at-login management action.
#[derive(Clone, Copy)]
pub(crate) enum Action {
    /// Register the current executable for launch at login.
    Install,
    /// Remove the launch-at-login registration.
    Uninstall,
    /// Print the launch-at-login registration state.
    Status,
}

/// Apply a launch-at-login action for the current user.
pub(crate) fn manage(action: Action, startup_args: Vec<String>) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        windows::manage(action, &startup_args)
    }

    #[cfg(not(windows))]
    {
        let _ = (action, startup_args);
        anyhow::bail!("launch-at-login management is currently supported only on Windows")
    }
}

/// Quote one argument according to the Windows CommandLineToArgvW rules.
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
    use std::path::Path;

    use anyhow::Context;
    use windows_registry::CURRENT_USER;
    use windows_result::HRESULT;

    use super::{Action, quote_windows_argument};

    const APP_NAME: &str = "sshdt";
    const RUN_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    const STARTUP_APPROVED_KEY: &str =
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
    const STARTUP_ENABLED: [u8; 12] = [
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    const FILE_NOT_FOUND: HRESULT = HRESULT::from_win32(2);

    pub(super) fn manage(action: Action, startup_args: &[String]) -> anyhow::Result<()> {
        match action {
            Action::Install => {
                install(startup_args)?;
                println!("installed sshdt launch at login for the current Windows user");
                println!("sshdt will start after this user next signs in");
            }
            Action::Uninstall => {
                uninstall()?;
                println!("removed sshdt launch at login for the current Windows user");
            }
            Action::Status => {
                let enabled = is_enabled()?;
                println!(
                    "sshdt launch at login is {} for the current Windows user",
                    if enabled { "enabled" } else { "disabled" }
                );
            }
        }
        Ok(())
    }

    fn install(startup_args: &[String]) -> anyhow::Result<()> {
        let executable = std::env::current_exe().context("could not locate sshdt.exe")?;
        let executable = executable.canonicalize().unwrap_or(executable);
        let mut command = launch_app_path(&executable);
        for argument in startup_args {
            command.push(' ');
            command.push_str(&quote_windows_argument(argument));
        }

        CURRENT_USER
            .create(RUN_KEY)
            .and_then(|key| key.set_string(APP_NAME, command))
            .context("failed to install sshdt launch at login")?;

        match CURRENT_USER.options().write().open(STARTUP_APPROVED_KEY) {
            Ok(key) => key
                .set_bytes(APP_NAME, windows_registry::Type::Bytes, &STARTUP_ENABLED)
                .context("failed to enable sshdt in Windows startup settings")?,
            Err(error) if error.code() == FILE_NOT_FOUND => {}
            Err(error) => {
                return Err(error).context("failed to open Windows startup settings");
            }
        }
        Ok(())
    }

    fn uninstall() -> anyhow::Result<()> {
        match CURRENT_USER
            .options()
            .write()
            .open(RUN_KEY)
            .and_then(|key| key.remove_value(APP_NAME))
        {
            Ok(()) => Ok(()),
            Err(error) if error.code() == FILE_NOT_FOUND => Ok(()),
            Err(error) => Err(error).context("failed to remove sshdt launch at login"),
        }
    }

    fn is_enabled() -> anyhow::Result<bool> {
        let registered = match CURRENT_USER
            .open(RUN_KEY)
            .and_then(|key| key.get_string(APP_NAME))
        {
            Ok(_) => true,
            Err(error) if error.code() == FILE_NOT_FOUND => false,
            Err(error) => {
                return Err(error).context("failed to read sshdt launch-at-login registration");
            }
        };
        if !registered {
            return Ok(false);
        }

        match CURRENT_USER
            .open(STARTUP_APPROVED_KEY)
            .and_then(|key| key.get_value(APP_NAME))
        {
            Ok(value) => Ok(value.len() < 8 || value.iter().rev().take(8).all(|byte| *byte == 0)),
            Err(error) if error.code() == FILE_NOT_FOUND => Ok(true),
            Err(error) => Err(error).context("failed to read Windows startup settings"),
        }
    }

    /// The Run registry key is parsed as a Windows command line. Remove the
    /// verbatim path prefix and quote the executable path so spaces are safe.
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
