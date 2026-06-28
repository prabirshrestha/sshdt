//! Small shared helpers.

use std::future::Future;
use std::pin::Pin;

/// A boxed, `Send` future — used by the object-safe async hook traits
/// ([`Authenticator`](crate::Authenticator), [`SessionHandler`](crate::SessionHandler)).
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The login name of the OS user running this process, read from the
/// environment (`USER`/`LOGNAME` on Unix, `USERNAME` on Windows). This is the
/// single source of truth for "the current user": it both populates `$USER` in
/// sessions and backs the strict-user policy. Returns `None` when none are set.
pub(crate) fn current_os_user() -> Option<String> {
    ["USER", "LOGNAME", "USERNAME"]
        .into_iter()
        .find_map(|var| std::env::var(var).ok().filter(|value| !value.is_empty()))
}

/// Split a command line into a program and its arguments.
///
/// Handles whitespace separation plus single/double quotes and backslash
/// escaping — enough for the shell specs we accept (`"busybox.exe sh"`,
/// `"wsl.exe -d Ubuntu"`, `"rmux new-session -A -s main"`). Returns an empty
/// vec for an all-whitespace input.
pub fn split_command_line(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = input.chars().peekable();
    let mut in_single = false;
    let mut in_double = false;
    let mut has_token = false;

    while let Some(c) = chars.next() {
        match c {
            '\\' if !in_single => {
                if let Some(&next) = chars.peek() {
                    cur.push(next);
                    chars.next();
                    has_token = true;
                }
            }
            '\'' if !in_double => {
                in_single = !in_single;
                has_token = true;
            }
            '"' if !in_single => {
                in_double = !in_double;
                has_token = true;
            }
            c if c.is_whitespace() && !in_single && !in_double => {
                if has_token {
                    out.push(std::mem::take(&mut cur));
                    has_token = false;
                }
            }
            c => {
                cur.push(c);
                has_token = true;
            }
        }
    }
    if has_token {
        out.push(cur);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::split_command_line;

    #[test]
    fn splits_simple() {
        assert_eq!(split_command_line("/bin/sh"), vec!["/bin/sh"]);
        assert_eq!(
            split_command_line("rmux new-session -A -s main"),
            vec!["rmux", "new-session", "-A", "-s", "main"]
        );
    }

    #[test]
    fn handles_quotes() {
        assert_eq!(
            split_command_line(r#"sh -c "echo hi there""#),
            vec!["sh", "-c", "echo hi there"]
        );
        assert_eq!(split_command_line("'a b' c"), vec!["a b", "c"]);
    }

    #[test]
    fn empty_is_empty() {
        assert!(split_command_line("   ").is_empty());
    }
}
