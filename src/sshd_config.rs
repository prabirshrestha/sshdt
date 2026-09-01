//! A pragmatic `sshd_config`-format parser (ADR 0019).
//!
//! We parse the subset of directives that map cleanly onto sshdt's [`Config`].
//! Unknown or unsupported directives are warned about and ignored, so existing
//! `sshd_config` files load without hard failures.
//!
//! Honored directives: `Port`, `ListenAddress`, `HostKey`, `AuthorizedKeysFile`,
//! `AllowTcpForwarding`, `LoginGraceTime`, `MaxStartups`, `AcceptEnv`,
//! `ForceCommand`, `Banner`. `PasswordAuthentication`/`PubkeyAuthentication`
//! are recognized but note that sshdt's auth uses an explicit `--password` and
//! authorized-keys, not OS/PAM auth.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::{Error, Result};

/// Parse an `sshd_config`-format string into a [`Config`], starting from
/// defaults. CLI flags are applied on top of the result by the caller.
pub fn parse(input: &str) -> Result<Config> {
    let mut config = Config::default();
    // AcceptEnv accumulates across directives, replacing the default the first
    // time it appears.
    let mut accept_env_seen = false;
    let mut password_disabled = false;
    let mut pubkey_disabled = false;
    // HostKey / AuthorizedKeysFile replace the default (empty) and accumulate.

    for (lineno, raw) in input.lines().enumerate() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        let (key, value) = match line.split_once(char::is_whitespace) {
            Some((k, v)) => (k, v.trim()),
            None => (line, ""),
        };
        let lower = key.to_ascii_lowercase();
        let ctx = || format!("line {}", lineno + 1);

        match lower.as_str() {
            "port" => {
                config.port = value.parse().map_err(|_| invalid(&ctx(), "Port", value))?;
            }
            "listenaddress" => {
                config.bind = parse_listen_address(value)
                    .ok_or_else(|| invalid(&ctx(), "ListenAddress", value))?;
            }
            "hostkey" => {
                config.host_keys.push(PathBuf::from(value));
            }
            "authorizedkeysfile" => {
                // sshd allows several space-separated paths with tokens; we take
                // them literally (token expansion is out of scope for v1).
                for path in value.split_whitespace() {
                    config.authorized_keys.push(PathBuf::from(path));
                }
            }
            "passwordauthentication" => {
                let enabled = parse_yes_no(value);
                if enabled.is_some() {
                    config.allow_anonymous = false;
                }
                if enabled == Some(false) {
                    password_disabled = true;
                } else if enabled == Some(true) && config.password.is_none() {
                    tracing::warn!(
                        "PasswordAuthentication yes requires a configured password (use --password)"
                    );
                }
            }
            "pubkeyauthentication" => {
                let enabled = parse_yes_no(value);
                if enabled.is_some() {
                    config.allow_anonymous = false;
                }
                pubkey_disabled |= enabled == Some(false);
            }
            "allowtcpforwarding" => {
                // sshd accepts yes/no/local/remote; anything non-"no" allows
                // local forwarding, which is all we implement.
                config.allow_tcp_forwarding = !matches!(value.to_ascii_lowercase().as_str(), "no");
            }
            "logingracetime" => {
                config.login_grace_secs =
                    parse_time(value).ok_or_else(|| invalid(&ctx(), "LoginGraceTime", value))?;
            }
            "maxstartups" => {
                // "start:rate:full" — take the first number.
                let first = value.split(':').next().unwrap_or(value);
                config.max_startups = first
                    .parse()
                    .map_err(|_| invalid(&ctx(), "MaxStartups", value))?;
            }
            "acceptenv" => {
                if !accept_env_seen {
                    config.accept_env.clear();
                    accept_env_seen = true;
                }
                for pattern in value.split_whitespace() {
                    config.accept_env.push(pattern.to_string());
                }
            }
            "forcecommand" => {
                config.shell = Some(value.to_string());
            }
            "banner" => {
                config.banner = Some(read_banner(value));
            }
            "subsystem" => {
                // We always provide the sftp subsystem internally; ignore.
            }
            other => {
                tracing::warn!(
                    directive = other,
                    value,
                    "ignoring unsupported sshd_config directive"
                );
            }
        }
    }

    if password_disabled {
        config.password = None;
    }
    if pubkey_disabled {
        config.authorized_keys.clear();
        config.authorized_key_lines.clear();
    }
    Ok(config)
}

pub(crate) fn parse_for_user(input: &str, home: Option<&Path>) -> Result<Config> {
    let mut config = parse(input)?;
    for path in &mut config.authorized_keys {
        if path.is_relative() {
            let home = home.ok_or_else(|| Error::ConfigFile {
                path: PathBuf::from("<sshd_config>"),
                message: format!(
                    "cannot resolve relative AuthorizedKeysFile {} without a home directory",
                    path.display()
                ),
            })?;
            *path = home.join(&*path);
        }
    }
    Ok(config)
}

/// Strip a trailing `#` comment. Following OpenSSH, a `#` only begins a comment
/// at the start of the line or when preceded by whitespace, so a `#` embedded in
/// a value (e.g. `Banner Welcome#1`) is preserved rather than truncated.
fn strip_comment(line: &str) -> &str {
    let mut prev_ws = true; // start-of-line counts as a token boundary
    for (idx, ch) in line.char_indices() {
        if ch == '#' && prev_ws {
            return &line[..idx];
        }
        prev_ws = ch.is_whitespace();
    }
    line
}

fn invalid(ctx: &str, directive: &str, value: &str) -> Error {
    Error::ConfigFile {
        path: PathBuf::from("<sshd_config>"),
        message: format!("{ctx}: invalid {directive} value {value:?}"),
    }
}

fn parse_yes_no(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "yes" => Some(true),
        "no" => Some(false),
        _ => None,
    }
}

/// `ListenAddress` may be `host`, `host:port`, or `[ipv6]:port`; we only need
/// the address part.
fn parse_listen_address(value: &str) -> Option<IpAddr> {
    let value = value.trim();
    if let Some(rest) = value.strip_prefix('[') {
        // [ipv6]:port
        let addr = rest.split(']').next()?;
        return addr.parse().ok();
    }
    if let Ok(addr) = value.parse::<IpAddr>() {
        return Some(addr);
    }
    // host:port with an IPv4 — take the part before the last ':'.
    if let Some((host, _port)) = value.rsplit_once(':') {
        return host.parse().ok();
    }
    None
}

/// Parse an sshd time value: bare seconds, or with a `s`/`m`/`h` suffix.
fn parse_time(value: &str) -> Option<u64> {
    let value = value.trim();
    if let Ok(secs) = value.parse::<u64>() {
        return Some(secs);
    }
    let (num, mult) = match value.chars().last()? {
        's' | 'S' => (&value[..value.len() - 1], 1),
        'm' | 'M' => (&value[..value.len() - 1], 60),
        'h' | 'H' => (&value[..value.len() - 1], 3600),
        _ => return None,
    };
    num.trim().parse::<u64>().ok().map(|n| n * mult)
}

/// `Banner` names a file whose contents are shown; if it isn't a readable file,
/// fall back to treating the value as the literal banner text.
fn read_banner(value: &str) -> String {
    match std::fs::read_to_string(value) {
        Ok(text) => text,
        Err(_) => value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{parse, parse_for_user, strip_comment};
    use std::path::PathBuf;

    #[test]
    fn parses_core_directives() {
        let cfg = parse(
            "\
            # a comment\n\
            Port 2200\n\
            ListenAddress 0.0.0.0\n\
            AllowTcpForwarding no\n\
            LoginGraceTime 30\n\
            MaxStartups 10:30:60\n\
            AcceptEnv LANG LC_*\n\
            ForceCommand /bin/echo hi\n\
            UnknownDirective whatever\n",
        )
        .unwrap();
        assert_eq!(cfg.port, 2200);
        assert_eq!(cfg.bind.to_string(), "0.0.0.0");
        assert!(!cfg.allow_tcp_forwarding);
        assert_eq!(cfg.login_grace_secs, 30);
        assert_eq!(cfg.max_startups, 10);
        assert_eq!(cfg.accept_env, vec!["LANG", "LC_*"]);
        assert_eq!(cfg.shell.as_deref(), Some("/bin/echo hi"));
    }

    /// A realistic, fully-commented `sshd_config` excerpt: leading-block
    /// comments, blank lines, indented directives, indented comments, and
    /// trailing inline comments all in one file.
    #[test]
    fn parses_realistic_commented_config() {
        let cfg = parse(
            "\
# /etc/ssh/sshd_config — sshdt
#
# This file is heavily commented on purpose.

Port 2022                       # listen high, unprivileged
ListenAddress 0.0.0.0           # all interfaces

# --- host keys (repeatable) ---
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

# --- auth ---
    AuthorizedKeysFile  .ssh/authorized_keys  .ssh/authorized_keys2
PasswordAuthentication no       # keys only

# --- behaviour ---
AllowTcpForwarding yes
LoginGraceTime 45s
MaxStartups 10:30:100
AcceptEnv LANG
AcceptEnv LC_* EDITOR           # second AcceptEnv accumulates
ForceCommand /usr/bin/tmux new -A -s main
Banner /etc/ssh/banner.txt

Subsystem sftp internal-sftp    # ignored: sftp is built in
#FullyCommentedOutDirective value
",
        )
        .unwrap();

        assert_eq!(cfg.port, 2022);
        assert_eq!(cfg.bind.to_string(), "0.0.0.0");
        assert_eq!(
            cfg.host_keys,
            vec![
                PathBuf::from("/etc/ssh/ssh_host_ed25519_key"),
                PathBuf::from("/etc/ssh/ssh_host_rsa_key"),
            ]
        );
        assert_eq!(
            cfg.authorized_keys,
            vec![
                PathBuf::from(".ssh/authorized_keys"),
                PathBuf::from(".ssh/authorized_keys2"),
            ]
        );
        assert!(cfg.allow_tcp_forwarding);
        assert_eq!(cfg.login_grace_secs, 45);
        assert_eq!(cfg.max_startups, 10);
        // First AcceptEnv replaces the default, the second accumulates.
        assert_eq!(cfg.accept_env, vec!["LANG", "LC_*", "EDITOR"]);
        assert_eq!(cfg.shell.as_deref(), Some("/usr/bin/tmux new -A -s main"));
    }

    #[test]
    fn comments_in_every_position() {
        // Full-line, indented, trailing-inline, blank lines, and a
        // comment-only/whitespace file all reduce to the same thing.
        let cfg = parse(
            "\
# full-line comment
   # indented comment

Port 2200   # trailing inline comment
\t# tab-indented comment
",
        )
        .unwrap();
        assert_eq!(cfg.port, 2200);

        // A file of only comments and blanks parses to defaults, not an error.
        let only_comments = parse("# just a comment\n\n   # another\n").unwrap();
        assert_eq!(only_comments.port, crate::DEFAULT_PORT);
        assert_eq!(parse("").unwrap().port, crate::DEFAULT_PORT);
    }

    #[test]
    fn hash_inside_a_value_is_not_a_comment() {
        // `#` is only a comment at a token boundary (start of line or after
        // whitespace), so an embedded `#` survives — matching OpenSSH.
        assert_eq!(strip_comment("Banner Welcome#1"), "Banner Welcome#1");
        assert_eq!(strip_comment("Port 22 # the port"), "Port 22 ");
        assert_eq!(strip_comment("# whole line"), "");
        assert_eq!(strip_comment("   # indented"), "   ");
        assert_eq!(
            strip_comment("ForceCommand echo hi#there"),
            "ForceCommand echo hi#there"
        );

        let cfg = parse("ForceCommand /bin/echo a#b c#d\n").unwrap();
        assert_eq!(cfg.shell.as_deref(), Some("/bin/echo a#b c#d"));
    }

    #[test]
    fn directive_keys_are_case_insensitive() {
        let cfg = parse("PORT 2300\nlistenaddress 127.0.0.2\nLoGiNgRaCeTiMe 1m\n").unwrap();
        assert_eq!(cfg.port, 2300);
        assert_eq!(cfg.bind.to_string(), "127.0.0.2");
        assert_eq!(cfg.login_grace_secs, 60);
    }

    #[test]
    fn time_suffixes() {
        assert_eq!(parse("LoginGraceTime 90\n").unwrap().login_grace_secs, 90);
        assert_eq!(parse("LoginGraceTime 30s\n").unwrap().login_grace_secs, 30);
        assert_eq!(parse("LoginGraceTime 2m\n").unwrap().login_grace_secs, 120);
        assert_eq!(parse("LoginGraceTime 1h\n").unwrap().login_grace_secs, 3600);
    }

    #[test]
    fn listen_address_variants() {
        assert_eq!(
            parse("ListenAddress 10.0.0.1\n").unwrap().bind.to_string(),
            "10.0.0.1"
        );
        // host:port — only the address is taken.
        assert_eq!(
            parse("ListenAddress 10.0.0.1:22\n")
                .unwrap()
                .bind
                .to_string(),
            "10.0.0.1"
        );
        // [ipv6]:port
        assert_eq!(
            parse("ListenAddress [::1]:22\n").unwrap().bind.to_string(),
            "::1"
        );
        assert_eq!(
            parse("ListenAddress ::1\n").unwrap().bind.to_string(),
            "::1"
        );
    }

    #[test]
    fn maxstartups_takes_first_field() {
        assert_eq!(parse("MaxStartups 5\n").unwrap().max_startups, 5);
        assert_eq!(parse("MaxStartups 10:30:60\n").unwrap().max_startups, 10);
    }

    #[test]
    fn allow_tcp_forwarding_variants() {
        assert!(
            !parse("AllowTcpForwarding no\n")
                .unwrap()
                .allow_tcp_forwarding
        );
        assert!(
            parse("AllowTcpForwarding yes\n")
                .unwrap()
                .allow_tcp_forwarding
        );
        // sshd accepts local/remote/all; anything non-"no" enables what we do.
        assert!(
            parse("AllowTcpForwarding local\n")
                .unwrap()
                .allow_tcp_forwarding
        );
    }

    #[test]
    fn auth_toggles() {
        // PasswordAuthentication no clears a configured password (none here, so
        // it is simply a no-op and must not error).
        let cfg = parse("PasswordAuthentication no\n").unwrap();
        assert!(cfg.password.is_none());
        assert!(!cfg.allow_anonymous);
        // PubkeyAuthentication no clears any accumulated key sources.
        let cfg = parse("AuthorizedKeysFile /k\nPubkeyAuthentication no\n").unwrap();
        assert!(cfg.authorized_keys.is_empty());
        assert!(!cfg.allow_anonymous);
        assert!(
            !parse("PasswordAuthentication yes\n")
                .unwrap()
                .allow_anonymous
        );
        assert!(!parse("PubkeyAuthentication yes\n").unwrap().allow_anonymous);
    }

    #[test]
    fn relative_authorized_keys_files_use_the_user_home() {
        let home = if cfg!(windows) {
            PathBuf::from(r"C:\Users\ada")
        } else {
            PathBuf::from("/home/ada")
        };
        let absolute = if cfg!(windows) {
            PathBuf::from(r"C:\ProgramData\sshdt\shared_keys")
        } else {
            PathBuf::from("/etc/ssh/shared_keys")
        };
        let cfg = parse_for_user(
            &format!(
                "AuthorizedKeysFile .ssh/authorized_keys {}\n",
                absolute.display()
            ),
            Some(&home),
        )
        .unwrap();
        assert_eq!(
            cfg.authorized_keys,
            [home.join(".ssh/authorized_keys"), absolute,]
        );
    }

    #[test]
    fn relative_authorized_keys_files_require_a_user_home() {
        let error = parse_for_user("AuthorizedKeysFile .ssh/authorized_keys\n", None).unwrap_err();
        assert!(error.to_string().contains("without a home directory"));
    }

    #[test]
    fn subsystem_and_unknown_directives_are_ignored_not_errors() {
        let cfg = parse("Subsystem sftp internal-sftp\nFooBar baz\nPort 2222\n").unwrap();
        assert_eq!(cfg.port, 2222);
    }

    #[test]
    fn rejects_invalid_values() {
        assert!(parse("Port notanumber\n").is_err());
        assert!(parse("ListenAddress not-an-ip\n").is_err());
        assert!(parse("LoginGraceTime 5y\n").is_err());
        assert!(parse("MaxStartups abc\n").is_err());
    }
}
