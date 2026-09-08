# sshdt

sshdt is an SSH server for Linux, macOS, and Windows. It provides a CLI and a
Rust library built on [`russh`](https://github.com/Eugeny/russh).

It supports remote commands, interactive shells, SFTP, SCP, and local TCP
forwarding with `ssh -L`. You can connect with OpenSSH, VS Code Remote-SSH,
and Zed Remote Development.

> [!WARNING]
> sshdt is a development tool. It is not production-ready and has not had a
> security audit. Every session runs as the OS user who started the server.
> There is no privilege separation or PAM support.
>
> Keep it on loopback, a trusted private network, or behind a private tunnel.
> Do not expose it directly to the public internet. It binds to `127.0.0.1`
> by default. Remote access options include [Tailscale](https://tailscale.com),
> [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/),
> and [Dev tunnels](https://learn.microsoft.com/azure/developer/dev-tunnels/).

## Build and install

From a checkout, use the Rust toolchain pinned in `rust-toolchain.toml`:

```sh
cargo build --release
cargo install --path .
```

The build produces `target/release/sshdt`. The install command adds the CLI
to Cargo's binary directory.

## Quick start

Start a server on `127.0.0.1:2222`:

```sh
sshdt -p 2222
```

By default, sshdt accepts anonymous connections. On first run, it creates an
Ed25519 host key at `~/.sshdt/host_ed25519` and reuses it on later starts.
On Windows, the key is under `%USERPROFILE%\.sshdt`. Use `-h <file>` to
select a host key. You can supply more than one.

Connect from another terminal:

```sh
ssh -p 2222 user@127.0.0.1 'echo hi'
sftp -P 2222 user@127.0.0.1
ssh -p 2222 user@127.0.0.1 -L 9000:127.0.0.1:8080
```

To require a password or public key, start the server with one of these options:

```sh
sshdt -p 2222 --password hunter2
sshdt -p 2222 --authorized-keys ~/.ssh/authorized_keys
sshdt -p 2222 --pubkey "ssh-ed25519 AAAAC3Nza... user@laptop"
```

`--authorized-keys` and `--pubkey` are repeatable. If you configure multiple
authentication methods, any one successful method grants access.

SFTP and SCP can access the files available to the server's OS user. Use
`--sftp-root <dir>` to restrict file transfers to a directory.

### Choose a shell

`--shell` sets the interactive session command. On Unix, the default is
`$SHELL`, then `/bin/sh`. On Windows, sshdt tries `pwsh`, `powershell`, then `cmd`.

```sh
sshdt --shell bash
sshdt --shell zsh
sshdt --shell fish
sshdt --shell pwsh
sshdt --shell cmd.exe
```

You can also start [rmux](https://rmux.io) as the session command:

```sh
sshdt -p 2223 --shell "rmux new-session -A -s main"
ssh -tt -p 2223 user@127.0.0.1
```

The rmux daemon keeps the session alive after you disconnect. Reconnect with
the same SSH command to resume it.

## Connect with SSH or an IDE

Start a server that accepts your public key:

```sh
sshdt -p 2222 --authorized-keys ~/.ssh/id_ed25519.pub
```

Add an alias to `~/.ssh/config`:

```sshconfig
Host mybox
	HostName 127.0.0.1
	Port 2222
	User user
	IdentityFile ~/.ssh/id_ed25519
```

For a remote server, replace `HostName` with its LAN or tunnel address.
The server must listen on a reachable address. The SSH username does not
change the OS account that runs the session.

Use the alias with OpenSSH:

```sh
ssh mybox
ssh mybox 'uname -a'
sftp mybox
scp file mybox:/path/
ssh mybox -L 9000:127.0.0.1:8080
```

VS Code Remote-SSH and Zed use the system SSH client and `~/.ssh/config`.
Use public-key authentication for these clients.

### VS Code Remote-SSH

Install the Remote-SSH extension, then open a remote folder:

```sh
code --remote ssh-remote+mybox /path/to/folder
```

You can also select **Remote-SSH: Connect to Host** in the command palette
and choose `mybox`.

### Zed Remote Development

Open a remote folder:

```sh
zed ssh://mybox/path/to/folder
```

You can also select **projects: open remote** in the command palette,
choose **Connect New Server**, and enter `ssh mybox`.

Zed downloads a server that matches its version. Use an official Zed build.
A custom build needs a matching published server.

## Users and authentication

Every session runs as the OS user who started sshdt. The SSH username does
not select an OS account. The session's `$USER` and `$HOME` refer to the
server's OS user.

By default, sshdt accepts any username. To limit the accepted names:

- Use `--strict-user` to accept only the server's OS username.
- Use `--allow-user <name>` to accept a specific name. Repeat the option for
  more names. Matching is exact and case-sensitive. Names can contain spaces,
  as in `--allow-user "John Doe"`.
- Combine both options to accept the listed names and the server's OS username.

These options restrict login names. They do not isolate sessions or change
permissions. Use OpenSSH `sshd` if each login must run as a separate OS account.

## Windows launch at login

On Windows, sshdt can start when the current user signs in.

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
A relative `AuthorizedKeysFile` path starts at the current user's home directory.

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

sshdt loads `%USERPROFILE%\.ssh\sshdt_config` if it exists.
Use `--config <file>` to select another file or `--no-config` to skip it:

```powershell
sshdt --no-config service enable
```

sshdt uses the current user's Windows `Run` registry entry. It needs no
administrator rights and starts only after sign-in. It is not a Windows
Service Control Manager service. Service management is available only on Windows.

## Managed Dev tunnels

Install the `devtunnel` CLI on both machines. Run `devtunnel user login` under
the account that runs sshdt and under the client account.

Add these settings to `~/.ssh/sshdt_config` on the server:

Use a dedicated tunnel. `devtunnel host` hosts every configured port on that
tunnel. Set your own tunnel ID. sshdt does not derive it from the hostname
or append a region. The CLI can resolve a bare ID such as `sshdt-machine1`.

```text
Port 22
DevTunnelEnable yes
DevTunnelId sshdt-machine1
DevTunnelAutoCreate yes
DevTunnelTimeout 30s
DevTunnelLabel environment=dev
DevTunnelLabel team=platform
Shell pwsh
```

`DevTunnelEnable` and `DevTunnelAutoCreate` default to `no`.
Auto-create adds a missing tunnel and SSH port with protocol `auto`.
It preserves existing access rules. An existing SSH port must use protocol
`auto`, or tunnel setup fails.

To select the executable, set `DevTunnelBin`, such as
`DevTunnelBin C:\tools\devtunnel.exe`. Otherwise, sshdt uses
`SSHDT_DEVTUNNEL_BIN`, then searches `PATH`.

Missing login, CLI, ID, or tunnel does not stop the SSH server. sshdt logs the
reason and retries setup when possible. `DevTunnelTimeout` limits each setup
attempt, not an active connection. Use `sshdt --check` to validate the config.
On Windows, restart the existing launch-at-login process to apply changes.

You can also set tunnel options on the command line:

```sh
sshdt --port 22 --devtunnel-enable --devtunnel-id sshdt-machine1 --devtunnel-auto-create --devtunnel-timeout 30s --devtunnel-label environment=dev --devtunnel-label team=platform
```

Command-line labels replace the labels from the config file.
Labels are optional. Each label must contain 1 to 50 ASCII letters, digits,
underscores, hyphens, or equals signs. You can configure up to 100 unique labels.
sshdt adds missing labels to new and existing tunnels before it starts hosting.
It keeps other remote labels. Removing a label from the config does not remove
it from the tunnel. Use `devtunnel update <tunnel-id> --remove-labels <label>`
to remove a remote label.

Use `--devtunnel-bin /path/to/devtunnel` to override `DevTunnelBin`.
Use `--devtunnel-disable` to override an enabled config. Server options before
`service enable` are saved with the launch-at-login settings.

On the client, install sshdt and add this entry to `~/.ssh/config`.
On Windows, use `%USERPROFILE%\.ssh\config`:

```sshconfig
Host machine1
	User admin
	Port 22
	HostKeyAlias sshdt-machine1
	ProxyCommand sshdt proxy devtunnel sshdt-machine1 --port %p --timeout 5m
```

Connect with `ssh machine1`. Replace the alias, username, and tunnel ID with
your own values. This is the SSH client config, separate from the server's
`sshdt_config`. sshdt does not edit either file for you.

`Port` and `%p` select the remote SSH port. The local port is automatic. To reserve
an exact local port, add `--local-port 32222` to the proxy command. If that port
is busy, the request fails. Different tunnels can use the same remote port.
Concurrent proxies share a connector through a locked local manager. The manager
stops its connector five seconds after the last session closes. `ControlMaster`
is optional and follows your SSH client's settings.

Failed tunnel host and connector processes retry after 30 seconds, 1 minute,
2 minutes, 4 minutes, then every 5 minutes. Five minutes of readiness resets the
delay. Pending proxy requests wait up to 5 minutes by default. Use `--timeout`
to change that limit. A connector that does not announce a local listener within
30 seconds also restarts through this retry schedule.

On Windows, IP interface changes can shorten a pending retry. sshdt waits for
2 seconds without another change and allows at most one early retry every
30 seconds. These events do not reset the retry delay or restart a running
connector. They are change signals, not proof of internet access. Permanent host
setup errors keep their normal delay. Other platforms use timed retries.

Retries can restore new connections. An established SSH session that loses its
connector closes and needs a new SSH connection. A running Dev Tunnels CLI
handles its own relay reconnection. sshdt does not restart healthy tunnels on a
timer or guarantee recovery from a CLI process that stays alive but stops working.

`Shell` selects the server's interactive shell. To request a shell from an SSH
alias, use the standard `RemoteCommand` and `RequestTTY force` options. Those
settings also affect tools that use the alias.

Host and client CLI output goes to separate daily logs under `~/.sshdt/logs`.
Each role keeps seven files. Read or follow them with:

```sh
sshdt service logs --devtunnel --follow
sshdt service logs --devtunnel-client --follow
```

These log commands work on macOS, Linux, and Windows. Windows `service status`
also reports the managed host's tunnel state. Proxy stdout contains only SSH bytes.

## CLI

Show the available options and commands:

```sh
sshdt --help
sshdt service --help
sshdt proxy devtunnel --help
```

Command-line flags override config values. Config values override built-in defaults.
Use `--no-config` for flags plus built-in defaults only. It cannot be combined
with `--config`.
`RUST_LOG` overrides the `-d`/`-q` log level.

## Configuration

Without `-f`, sshdt loads `~/.ssh/sshdt_config` when it exists. `-f <file>`
selects a different file. Config files use the `sshd_config` format.

sshdt supports these directives. It logs a warning for unsupported directives
and ignores them:

| Directive | Maps to |
|---|---|
| `Port` | listen port |
| `ListenAddress` | bind address |
| `HostKey` | host key file (repeatable) |
| `AuthorizedKeysFile` | authorized_keys files |
| `AllowTcpForwarding` | `no` disables `direct-tcpip` |
| `LoginGraceTime` | authentication timeout, such as `30` or `1m` |
| `MaxStartups` | unauthenticated connection limit, first field of `a:b:c` |
| `AcceptEnv` | client env allowlist |
| `Shell` or `ForceCommand` | the session command (`--shell`) |
| `Banner` | pre-auth banner (file contents or literal) |

sshdt also recognizes `PasswordAuthentication` and `PubkeyAuthentication`.
Passwords come from `--password`, and public keys come from the configured
key files or inline keys. sshdt does not authenticate against OS accounts.

Dev tunnel directives are described in [Managed Dev tunnels](#managed-dev-tunnels).

## Library

Each `Server` owns its configuration and state. You can run multiple servers
in one process. The library emits `tracing` events. Your application installs
the subscriber.

```rust
use sshdt::Server;

#[tokio::main]
async fn main() -> sshdt::Result<()> {
	let handle = Server::builder()
		.bind("127.0.0.1".parse().unwrap())
		.port(2222)
		.password("hunter2")
		.shell("/bin/bash")
		.serve_build()
		.await?;

	println!("listening on {}", handle.local_addr());
	handle.join().await;
	Ok(())
}
```

Use `handle.shutdown().await` to stop a server. You can also construct one
with `Server::from_config(config)`.

The builder accepts custom authentication, command resolution, session handling,
and forwarding through `.authenticator(..)`, `.command_resolver(..)`,
`.session_handler(..)`, and `.forwarder(..)`.

`Server::serve_connection` serves a single `AsyncRead + AsyncWrite` stream.
Exec channels support long-running processes and simultaneous input and output.

The default `config` feature enables the config-file parser.
Build with `--no-default-features` to omit the CLI and the config-file parser.

## Tests

```sh
cargo test
cargo clippy --all-targets -- -D warnings
```

The test suite covers authentication, command execution and exit codes,
SFTP operations and directory restrictions, TCP forwarding, PTY resize,
and independent channels and servers.

In-process tests use a `russh` client over `tokio::io::duplex()`.
OpenSSH tests run when `ssh`, `sftp`, and `scp` are available.
The rmux test checks that a session survives reconnection when `rmux` is installed.
CI runs on Linux, macOS, and Windows. Platform-specific tests run on their
supported systems.

For a manual IDE check, connect through a local SSH alias in VS Code Remote-SSH
or Zed. Open a folder, run a terminal, and edit and save a file.

## License

Licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
