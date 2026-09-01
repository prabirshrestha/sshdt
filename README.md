# sshdt

**sshdt** — a *tiny* `sshd` — is a faithful, standard **SSH server** in Rust, a library **and** a CLI in one crate.
You launch it with one command and connect with a **normal `ssh` client** (plus **`sftp`** and
**`scp`**), IDE-over-SSH tools (**VS Code Remote-SSH**, **Zed Remote Development**), and terminal
multiplexers (**rmux**, **tmux** — they're just commands you run). It listens on a local TCP port
like `sshd`.

Built on [`russh`](https://github.com/Eugeny/russh). Dual-licensed **MIT OR Apache-2.0**.

> [!WARNING]
> **Not production-ready. Do not expose sshdt to the public internet.**
> This is a developer tool, not a hardened multi-user `sshd`. It runs every session as the
> OS user that launched it (no per-user accounts, no privilege separation, no PAM), and has
> not had a security audit. Only run it on a **trusted network (e.g. loopback or a private
> LAN)** or, for remote access, **behind a private tunnel** such as
> [Tailscale](https://tailscale.com), a [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/),
> or [Dev tunnels](https://learn.microsoft.com/azure/developer/dev-tunnels/) — never by
> port-forwarding it straight to the internet. It binds to `127.0.0.1` by default for this
> reason; only change `-b`/`ListenAddress` if you understand the exposure.

## Features

- **exec**, interactive **shell/PTY**, **SFTP**, and **`direct-tcpip`** local forwarding (`ssh -L`).
- `exec` is **full-duplex and long-lived** — the channel IDE control servers run over.
- **One generic command runner**: `$SHELL`, `pwsh`, `wsl`, `busybox`, `tmux`, `rmux` are all just
  commands. Drop into a multiplexer with `--shell "rmux new-session -A -s main"`.
- **Auth**: anonymous by default, or `--password`, or public-key (`authorized_keys` files **and**
  inline keys). Any one method succeeding is enough.
- **Host key**: auto-generated + persisted **ed25519** at `~/.sshdt/host_ed25519`
  (Windows `%USERPROFILE%\.sshdt`); `-h` is repeatable.
- **SFTP**: full filesystem as the launching OS user (OpenSSH parity); `--sftp-root` jails it.
- **Cross-platform**: Linux, macOS, Windows (ConPTY via `rmux-pty`).
- **No global state** — run many independent `Server` instances in one process.

## Install / build

```sh
cargo build --release      # binary at target/release/sshdt
cargo install --path .     # or install the CLI
```

Requires the toolchain pinned in `rust-toolchain.toml` (latest stable; edition 2024).

### Windows launch at login

On Windows, sshdt can register itself to start when the current user signs in:

```powershell
sshdt service enable
sshdt service start
sshdt service status
sshdt service restart
sshdt service logs --follow
sshdt service stop
sshdt service disable
sshdt service uninstall
```

Store sshdt server settings in `%USERPROFILE%\.ssh\sshdt_config`, beside the
OpenSSH authorized keys file at `%USERPROFILE%\.ssh\authorized_keys`. For
example:

```text
ListenAddress 0.0.0.0
Port 2222
AuthorizedKeysFile .ssh/authorized_keys
```

Enable launch at login and start the process:

```powershell
sshdt service enable
sshdt service start
```

After you edit the config, run `sshdt service restart` to apply the changes.
Use `127.0.0.1` instead of `0.0.0.0` if only local clients must connect.
As in OpenSSH, a relative `AuthorizedKeysFile` path starts at the current
user's home directory.

`service enable` saves the server options that appear before `service`. Relative
file and directory paths are converted to absolute paths. Run the command again
to replace the saved options. `enable` and `disable` control launch at login.
They do not change the running process. `start`, `stop`, and `restart` control
the process without changing whether it starts at login. `status` reports both
states. A disabled process can still be started manually.

`service uninstall` stops sshdt and removes its launch-at-login entry and saved
service options. It does not delete the sshdt executable, `sshdt_config`, host
keys, or logs.

By default, the service writes daily rotating logs to `%USERPROFILE%\.sshdt\logs`
and keeps up to seven files. `service logs` prints the current log. Add
`--follow` or `-f` to continue printing new entries across log rotation. If
`--log-file` was set during `service enable`, these commands use that file instead.

If `--config` is not set, sshdt automatically loads
`%USERPROFILE%\.ssh\sshdt_config` when that file exists. If it does not exist,
sshdt uses its normal built-in defaults. These include `127.0.0.1:2222`, the
persistent host key at `%USERPROFILE%\.sshdt\host_ed25519`, anonymous
authentication, and the default Windows shell. Use `--no-config` to skip the
automatic config file:

```powershell
sshdt --no-config service enable
```

This uses the current user's Windows `Run` registry entry, like AI Proxy's
**Launch at login** setting. It needs no administrator rights and runs sshdt as
the signed-in user. It is not a Windows Service Control Manager service, and it
does not start before user sign-in. Service management is not supported on
macOS or Linux yet.

## Quick start

```sh
# Anonymous loopback server on port 2222 (auto-generates a host key on first run).
sshdt -p 2222

# Then, from another terminal:
ssh -p 2222 user@127.0.0.1 'echo hi'
sftp -P 2222 user@127.0.0.1      # put/get round-trips
ssh -p 2222 user@127.0.0.1 -L 9000:127.0.0.1:8080            # local forward
```

Password or key auth:

```sh
sshdt -p 2222 --password hunter2
sshdt -p 2222 --authorized-keys ~/.ssh/authorized_keys
sshdt -p 2222 --pubkey "ssh-ed25519 AAAAC3Nza... user@laptop"
```

Choose the session shell/command with `--shell` — it's just a program sshdt runs (default: `$SHELL`,
else `/bin/sh`; Windows: `pwsh` → `powershell` → `cmd`):

```sh
sshdt --shell bash
sshdt --shell zsh
sshdt --shell fish
sshdt --shell pwsh          # or: powershell
sshdt --shell cmd.exe       # Windows
```

Persistent multiplexer session (`--shell` is also how you drop into one; it survives reconnects via
the multiplexer's own daemon):

```sh
sshdt -p 2223 --shell "rmux new-session -A -s main"
ssh -tt -p 2223 user@127.0.0.1        # lands in the session; reconnect to resume
```

## Connecting (ssh, VS Code, Zed)

sshdt is a faithful SSH server, so clients connect the normal way. **VS Code Remote-SSH and Zed Remote
shell out to the *system* `ssh` and read `~/.ssh/config`**, so a `Host` alias is the cleanest setup and
makes all three clients "just work". Use **key auth** for the IDEs.

Start a server that accepts your key (the host key is auto-generated and persisted, so `known_hosts`
stays stable across restarts):

```sh
sshdt -p 2222 --authorized-keys ~/.ssh/id_ed25519.pub
```

Add a `Host` to `~/.ssh/config`:

```sshconfig
Host mybox
    HostName 127.0.0.1        # or the LAN/tunnel address (start sshdt with -b 0.0.0.0)
    Port 2222
    User user                 # cosmetic — sessions run as the OS user that launched sshdt
    IdentityFile ~/.ssh/id_ed25519
```

**Plain ssh / sftp / scp**

```sh
ssh mybox                      # interactive shell
ssh mybox 'uname -a'           # exec
sftp mybox                     # put/get
scp file mybox:/path/          # copy
ssh mybox -L 9000:127.0.0.1:8080   # local forward
```

**VS Code — Remote-SSH** (needs the *Remote-SSH* extension)

```sh
code --remote ssh-remote+mybox /path/to/folder
```
…or `Cmd/Ctrl-Shift-P → Remote-SSH: Connect to Host → mybox`. VS Code installs its server under
`~/.vscode-server` on the remote and runs it over the exec channel — no port forwarding needed.

**Zed — Remote Development**

```sh
zed ssh://mybox/path/to/folder
```
…or in Zed: `Cmd-Shift-P → projects: open remote → Connect New Server`, and in the *"command you use to
SSH into this server"* field type the ssh command — e.g. just `ssh mybox`, or fully explicit:

```
ssh user@127.0.0.1 -p 2222 -i ~/.ssh/id_ed25519
```

> Notes — most "extra" ssh flags people add are workarounds you usually don't need here:
> `-i` only if the key isn't in the default `~/.ssh/`; `-o IdentitiesOnly=yes` is an optional tightening;
> avoid `-o StrictHostKeyChecking=no` for real servers — sshdt's host key is stable, so normal host-key
> verification works. Zed requires an official build (it downloads a version-matched server); custom/dev
> Zed builds whose server isn't published won't finish installing it — that's a Zed limitation, not sshdt.

## Users & identity

sshdt is **single-user**: every session runs as the **OS user that launched sshdt** — there is no
per-user privilege switch, no `setuid`, no PAM, no Windows token logon. Consequently the **SSH username
is cosmetic** by
default — `ssh user@host`, `ssh root@host`, anything authenticates against the configured method(s) and the
session still runs as the launching user (this is why IDE clients and `~/.ssh/config` aliases "just work"
with any `User`). The session's `$USER`/`$HOME` reflect the real launching user.

If you'd rather the server only answer to specific login names, restrict the username:

- **`--strict-user`** — sshdt detects the launching OS user and accepts only that name.
- **`--allow-user <NAME>`** (repeatable) — accept only the name(s) you pass (exact, case-sensitive match;
  a name may contain spaces, e.g. `--allow-user "John Doe"`). Combine with `--strict-user` to also include
  the launching user.

Either way it needs no privilege — it's a least-surprise guardrail, not a security boundary (auth methods
are what actually gate access). With no restriction (the default), any username is accepted.

> **Want real multi-user** (each login runs as its own OS account, isolated)? That requires running as
> root with privilege separation and platform-specific user-switching — out of scope for sshdt. **Run
> OpenSSH `sshd` for that.** For an unprivileged ~80% approximation you can supply a custom
> `CommandResolver` that wraps sessions in `runuser`/`su`.

## CLI

```
sshdt [OPTIONS] [<command>]

  -p, --port <PORT>              Port to listen on                     [default: 2222]
  -h, --host-key <FILE>          Host key file (generated if missing)  [default: ~/.sshdt/host_ed25519]
                                 (repeatable)
  -f, --config <FILE>            Load config [default: ~/.ssh/sshdt_config when present]
      --no-config                Do not load the default ~/.ssh/sshdt_config file
  -E, --log-file <FILE>          Append logs to FILE instead of stderr
  -d, --debug                    Debug logging (-v alias)
  -q, --quiet                    Errors only
  -b, --bind <ADDR>              Bind address                          [default: 127.0.0.1]
      --host-key-passphrase <P>  Passphrase for an encrypted host key  [or $SSHDT_HOST_KEY_PASSPHRASE]
      --password <PW>            Enable password auth                  [default: off]
      --authorized-keys <FILE>   Public-key auth from a file           (repeatable)
      --pubkey <KEY>             Public-key auth from an inline key     (repeatable)
      --shell <CMD>              Interactive session command           [default: $SHELL→/bin/sh;
                                                                        Windows: pwsh→powershell→cmd]
      --sftp-root <DIR>          Jail SFTP/scp to DIR                   [default: full FS as the OS user]
      --strict-user              Accept only the launching OS user's username  [default: off]
      --allow-user <NAME>        Accept only this SSH username (exact); repeatable
      --no-forward               Disable `ssh -L` (direct-tcpip)        [default: allowed]
      --login-grace <SECS>       Auth timeout                           [default: 60]
      --max-startups <N>         Max concurrent unauthenticated conns   [default: 32]
      --version / --help

Commands:
  service enable                 Enable sshdt at login for the current Windows user
  service disable                Disable sshdt at login without stopping it
  service uninstall              Stop sshdt and remove its saved service settings
  service status                 Show launch-at-login and process state
  service start                  Start the configured sshdt process
  service stop                   Stop the running sshdt process
  service restart                Restart the configured sshdt process
  service logs [-f|--follow]     Print or follow the rotating service log
```

Precedence is **flags > explicit `--config` or `~/.ssh/sshdt_config` > defaults**.
Use `--no-config` for flags plus built-in defaults only. It cannot be combined
with `--config`.
`RUST_LOG` overrides the `-d`/`-q` log level.

## Config file (`-f`)

Without `-f`, sshdt loads `~/.ssh/sshdt_config` when it exists. `-f <file>`
selects a different config file. Config files use the **`sshd_config` format**
(or **TOML** when the extension is `.toml`).
Honored `sshd_config` directives (others are warned about and ignored):

| Directive | Maps to |
|---|---|
| `Port` | listen port |
| `ListenAddress` | bind address |
| `HostKey` | host key file (repeatable) |
| `AuthorizedKeysFile` | authorized_keys file(s) |
| `AllowTcpForwarding` | `no` disables `direct-tcpip` |
| `LoginGraceTime` | auth timeout (`30`, `1m`, …) |
| `MaxStartups` | concurrent unauth cap (first field of `a:b:c`) |
| `AcceptEnv` | client env allowlist |
| `ForceCommand` | the session command (`--shell`) |
| `Banner` | pre-auth banner (file contents or literal) |

> `PasswordAuthentication`/`PubkeyAuthentication` are recognized, but sshdt's auth uses an explicit
> `--password` and authorized keys rather than OS/PAM accounts.

## Library

`sshdt` is also a library with **no global state**. The lib only emits `tracing` events; installing
a subscriber is the embedder's job.

```rust
use std::sync::Arc;
use sshdt::{Server, Config};

#[tokio::main]
async fn main() -> sshdt::Result<()> {
    // Fluent builder:
    let handle = Server::builder()
        .bind("127.0.0.1".parse().unwrap())
        .port(2222)
        .password("hunter2")
        .shell("/bin/bash")
        .serve_build()
        .await?;
    println!("listening on {}", handle.local_addr());

    // …or from a declarative, serde-serializable Config:
    let mut config = Config::default();
    config.port = 2200;
    let server = Server::from_config(config)?;
    let _ = server;

    handle.join().await;       // or handle.shutdown().await
    Ok(())
}
```

Programmatic hooks (builder-only, since closures/trait objects don't serialize): `.authenticator(..)`
(Accept/Reject/Partial), `.command_resolver(..)`, `.session_handler(..)`, and `.forwarder(..)`.
For embedders feeding arbitrary byte streams (e.g. a future tunnel relay), `Server::serve_connection`
serves a single `AsyncRead + AsyncWrite` stream.

The serde `Config` lives behind the default `config` feature; build the lean library with
`--no-default-features` to drop serde, the CLI, and the config-file parser.

## Testing

The SSH / SFTP / multiplexer paths are exercised **end to end**:

- **In-process** (always, no network): a `russh` client over `tokio::io::duplex()` — auth matrix,
  exec + exit codes, full-duplex `cat`, SFTP round-trip + ops + jail escape, `direct-tcpip` echo,
  PTY shell + resize, multi-channel, multi-instance.
- **Real OpenSSH** (gated on `ssh`/`sftp`/`scp`): exec exit codes, pipe-over-ssh bootstrap,
  `sftp`/`scp` byte-for-byte round-trips incl. a ≥10 MB file, public-key auth, `ssh -L`.
- **rmux** (gated on `rmux`): `ssh -tt` lands in a multiplexer session that **persists across reconnect**.

```sh
cargo test                       # in-process always; the rest where the binaries exist
cargo clippy --all-targets -- -D warnings
```

CI runs the matrix on **Linux, macOS, and Windows** (the shell / ssh / PTY suites are Unix-only).

## Manual IDE smoke checklist

Add a `Host` to `~/.ssh/config` pointing at `127.0.0.1` and the chosen port, then:

- [ ] **VS Code Remote-SSH**: connect, open a folder, run an integrated terminal, edit + save a file.
- [ ] **Zed Remote Development**: connect, open a folder, run a terminal, edit + save a file.

Both work because sshdt is a faithful SSH server: per-connection channel multiplexing (ControlMaster),
real processes as the OS user, full-duplex long-lived exec, and SFTP.

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.
