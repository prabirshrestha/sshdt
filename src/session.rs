//! The single generic command runner (ADR 0002) and the session-shaping hooks
//! (ADR 0011, 0012, 0017).
//!
//! One mechanism runs *a command* with full-duplex I/O: pipes for non-PTY
//! `exec`/shell (the IDE-critical path), or a PTY (via `rmux-pty`) when the
//! client requested one. `$SHELL`, `pwsh`, `wsl`, `busybox`, `tmux` and `rmux`
//! are all just commands.

use std::sync::Arc;

use russh::ChannelId;
use russh::server::Msg;
use russh::{Channel, ChannelReadHalf, ChannelWriteHalf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::util::{BoxFuture, split_command_line};

/// A pseudo-terminal request from the client.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PtyRequest {
    /// The terminal type (`$TERM`), e.g. `xterm-256color`.
    pub term: String,
    /// Columns (character cells wide).
    pub cols: u16,
    /// Rows (character cells tall).
    pub rows: u16,
    /// Pixel width (0 if unknown).
    pub pixel_width: u16,
    /// Pixel height (0 if unknown).
    pub pixel_height: u16,
}

/// What the client asked a session channel to run (ADR 0012).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SessionRequest {
    /// An interactive shell.
    Shell {
        /// The PTY request, if the client allocated one.
        pty: Option<PtyRequest>,
    },
    /// A one-shot command execution (full-duplex, long-lived).
    Exec {
        /// The command line the client sent.
        command: String,
        /// The PTY request, if the client allocated one (`ssh -t host cmd`).
        pty: Option<PtyRequest>,
    },
}

impl SessionRequest {
    /// The PTY request, if any.
    pub fn pty(&self) -> Option<&PtyRequest> {
        match self {
            SessionRequest::Shell { pty } | SessionRequest::Exec { pty, .. } => pty.as_ref(),
        }
    }
}

/// A resolved command to run for a session.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SessionCommand {
    /// The program to execute.
    pub program: String,
    /// Its arguments.
    pub args: Vec<String>,
    /// Extra environment variables to set on top of the inherited environment.
    pub env: Vec<(String, String)>,
}

impl SessionCommand {
    /// A convenience constructor for a bare program.
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: Vec::new(),
        }
    }
}

/// Maps each [`SessionRequest`] to the [`SessionCommand`] to run (ADR 0012).
///
/// The default implementation runs the configured/OS-default shell for an
/// interactive session, and `<shell> -c <command>` (`/c` for `cmd.exe`) for
/// `exec`.
pub trait CommandResolver: Send + Sync {
    /// Resolve a request to a command.
    fn resolve(&self, request: &SessionRequest) -> SessionCommand;
}

/// The default command resolver: shell selection per ADR 0011 + `shell -c`
/// exec semantics per ADR 0017.
pub(crate) struct DefaultResolver {
    /// The resolved interactive shell command line (program + args).
    pub shell: Vec<String>,
}

impl DefaultResolver {
    pub fn new(shell: Option<&str>) -> Self {
        let shell = match shell {
            Some(s) if !split_command_line(s).is_empty() => split_command_line(s),
            _ => default_shell(),
        };
        Self { shell }
    }

    fn shell_program(&self) -> &str {
        self.shell.first().map(String::as_str).unwrap_or("/bin/sh")
    }
}

impl CommandResolver for DefaultResolver {
    fn resolve(&self, request: &SessionRequest) -> SessionCommand {
        match request {
            SessionRequest::Shell { .. } => {
                let mut iter = self.shell.iter();
                let program = iter.next().cloned().unwrap_or_else(|| "/bin/sh".into());
                SessionCommand {
                    program,
                    args: iter.cloned().collect(),
                    env: Vec::new(),
                }
            }
            SessionRequest::Exec { command, .. } => {
                let shell = self.shell_program();
                let flag = exec_flag(shell);
                SessionCommand {
                    program: shell.to_string(),
                    args: vec![flag.to_string(), command.clone()],
                    env: Vec::new(),
                }
            }
        }
    }
}

/// The command flag a shell uses to run a single command string.
fn exec_flag(shell: &str) -> &'static str {
    let lower = std::path::Path::new(shell)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(shell)
        .to_ascii_lowercase();
    if lower == "cmd" || lower == "cmd.exe" {
        "/C"
    } else {
        // pwsh/powershell accept -c as an alias for -Command; POSIX shells use -c.
        "-c"
    }
}

/// The OS-aware default interactive shell (ADR 0011).
#[cfg(unix)]
fn default_shell() -> Vec<String> {
    match std::env::var("SHELL") {
        Ok(s) if !s.is_empty() => vec![s],
        _ => vec!["/bin/sh".to_string()],
    }
}

/// The OS-aware default interactive shell on Windows: `pwsh` → `powershell` → `cmd`.
#[cfg(windows)]
fn default_shell() -> Vec<String> {
    for candidate in ["pwsh.exe", "powershell.exe", "cmd.exe"] {
        if which_on_path(candidate).is_some() {
            return vec![candidate.to_string()];
        }
    }
    vec!["cmd.exe".to_string()]
}

#[cfg(windows)]
fn which_on_path(program: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(program);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// A stream of terminal resize events (cols, rows) for the
/// [`SessionHandler`] escape hatch.
pub struct ResizeStream {
    rx: mpsc::UnboundedReceiver<(u16, u16)>,
}

impl ResizeStream {
    /// Await the next resize event, or `None` once the session ends.
    pub async fn next(&mut self) -> Option<(u16, u16)> {
        self.rx.recv().await
    }
}

/// The duplex I/O of a session channel, handed to a [`SessionHandler`].
pub struct ChannelIo {
    /// Client → session bytes (stdin).
    stdin: mpsc::Receiver<Vec<u8>>,
    /// Session → client stdout.
    stdout: Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    /// Session → client stderr (SSH extended data type 1).
    stderr: Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
}

impl ChannelIo {
    /// Read the next chunk of client input, or `None` at EOF.
    pub async fn read_stdin(&mut self) -> Option<Vec<u8>> {
        self.stdin.recv().await
    }

    /// Write to the client's stdout.
    pub async fn write_stdout(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.stdout.write_all(data).await?;
        self.stdout.flush().await
    }

    /// Write to the client's stderr.
    pub async fn write_stderr(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.stderr.write_all(data).await?;
        self.stderr.flush().await
    }
}

/// A fully custom in-process session handler (builder-only escape hatch;
/// ADR 0012). When set it supersedes the generic runner.
pub trait SessionHandler: Send + Sync {
    /// Service a session entirely in-process, returning its exit code.
    fn run<'a>(
        &'a self,
        request: SessionRequest,
        io: ChannelIo,
        resize: ResizeStream,
    ) -> BoxFuture<'a, i32>;
}

/// Build the environment overrides to layer on top of the inherited process
/// environment (ADR 0017): ensure `HOME`, `USER`/`LOGNAME`, `SHELL`, and (with
/// a PTY) `TERM`; then the allowlisted client env; then any resolver env.
pub(crate) fn session_env_overrides(
    shell_program: &str,
    pty: Option<&PtyRequest>,
    client_env: &[(String, String)],
    resolver_env: &[(String, String)],
) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut set = |k: &str, v: String| out.push((k.to_string(), v));

    // SHELL reflects the session's shell.
    set("SHELL", shell_program.to_string());

    // Ensure HOME exists.
    if std::env::var_os("HOME").is_none()
        && let Some(home) = dirs::home_dir()
    {
        set("HOME", home.to_string_lossy().into_owned());
    }

    // Ensure USER/LOGNAME exist (best effort from each other / the OS).
    if let Some(user) = crate::util::current_os_user() {
        if std::env::var_os("USER").is_none() {
            set("USER", user.clone());
        }
        if std::env::var_os("LOGNAME").is_none() {
            set("LOGNAME", user);
        }
    }

    // TERM from the PTY request.
    if let Some(pty) = pty
        && !pty.term.is_empty()
    {
        set("TERM", pty.term.clone());
    }

    // Allowlisted client env, then resolver env (later wins).
    out.extend(client_env.iter().cloned());
    out.extend(resolver_env.iter().cloned());
    out
}

/// Run a session: resolve PTY vs pipe and pump I/O until the child exits, then
/// report exit status, EOF and close on the channel.
///
/// This is the body of the generic runner. `command` is already resolved;
/// `pty` is the client's PTY request, if any.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_session(
    channel: Channel<Msg>,
    request: SessionRequest,
    command: SessionCommand,
    client_env: Vec<(String, String)>,
    mut resize_rx: mpsc::UnboundedReceiver<(u16, u16)>,
    session_handler: Option<Arc<dyn SessionHandler>>,
) {
    let id = channel.id();
    let pty = request.pty().cloned();
    let env = session_env_overrides(&command.program, pty.as_ref(), &client_env, &command.env);

    let (read_half, write_half) = channel.split();

    let exit_code = if let Some(handler) = session_handler {
        run_custom_handler(handler, request, read_half, &write_half, resize_rx).await
    } else {
        let mut command = command;
        command.env = env;
        match pty {
            Some(pty) => run_pty(command, pty, read_half, &write_half, &mut resize_rx).await,
            None => run_pipe(command, read_half, &write_half).await,
        }
    };

    finish_channel(id, &write_half, exit_code).await;
}

/// Send the final `exit-status`, `eof` and `close` on the channel.
///
/// This is the sole owner of outbound channel EOF. A russh channel writer's
/// `AsyncWrite::shutdown` also sends channel-wide EOF, so stdout/stderr pumps
/// must only flush and drop their writers.
async fn finish_channel(id: ChannelId, write_half: &ChannelWriteHalf<Msg>, exit_code: u32) {
    if let Err(error) = write_half.exit_status(exit_code).await {
        tracing::debug!(?id, %error, "failed to send exit-status");
    }
    let _ = write_half.eof().await;
    let _ = write_half.close().await;
    tracing::debug!(?id, exit_code, "session finished");
}

/// Drive a custom [`SessionHandler`], bridging the channel halves into a
/// [`ChannelIo`].
async fn run_custom_handler(
    handler: Arc<dyn SessionHandler>,
    request: SessionRequest,
    mut read_half: ChannelReadHalf,
    write_half: &ChannelWriteHalf<Msg>,
    resize_rx: mpsc::UnboundedReceiver<(u16, u16)>,
) -> u32 {
    // Forward client input into an mpsc so ChannelIo can own its stdin without
    // borrowing the read half.
    let (stdin_tx, stdin_rx) = mpsc::channel::<Vec<u8>>(32);
    let forward = async move {
        let mut reader = read_half.make_reader();
        let mut buf = [0u8; 32768];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if stdin_tx.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
            }
        }
    };

    let io = ChannelIo {
        stdin: stdin_rx,
        stdout: Box::new(write_half.make_writer()),
        stderr: Box::new(write_half.make_writer_ext(Some(1))),
    };
    let resize = ResizeStream { rx: resize_rx };

    let (code, ()) = tokio::join!(handler.run(request, io, resize), forward);
    code.max(0) as u32
}

/// Non-PTY session: run the command with piped stdio (the IDE-critical path).
async fn run_pipe(
    command: SessionCommand,
    mut read_half: ChannelReadHalf,
    write_half: &ChannelWriteHalf<Msg>,
) -> u32 {
    use std::process::Stdio;

    let mut cmd = tokio::process::Command::new(&command.program);
    cmd.args(&command.args);
    for (k, v) in &command.env {
        cmd.env(k, v);
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    cmd.process_group(0); // own process group, so signals don't leak to sshdt

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(error) => {
            tracing::warn!(program = %command.program, %error, "failed to spawn command");
            let mut w = write_half.make_writer_ext(Some(1));
            let _ = w
                .write_all(
                    format!("sshdt: failed to run {}: {error}\n", command.program).as_bytes(),
                )
                .await;
            let _ = w.flush().await;
            return 127;
        }
    };

    let mut child_stdin = child.stdin.take().expect("piped stdin");
    let mut child_stdout = child.stdout.take().expect("piped stdout");
    let mut child_stderr = child.stderr.take().expect("piped stderr");

    let mut stdout_writer = write_half.make_writer();
    let mut stderr_writer = write_half.make_writer_ext(Some(1));

    // child stdout/stderr → client (spawned; writers are 'static). Do not call
    // shutdown here: russh maps it to channel-wide EOF, which finish_channel
    // sends exactly once after both streams have drained.
    let stdout_task = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut child_stdout, &mut stdout_writer).await;
        let _ = stdout_writer.flush().await;
    });
    let stderr_task = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut child_stderr, &mut stderr_writer).await;
        let _ = stderr_writer.flush().await;
    });

    // client → child stdin; on client EOF, close stdin so e.g. `cat` exits.
    let stdin_pump = async move {
        let mut reader = read_half.make_reader();
        let _ = tokio::io::copy(&mut reader, &mut child_stdin).await;
        drop(child_stdin);
    };

    let status = tokio::select! {
        status = child.wait() => status,
        _ = stdin_pump => child.wait().await,
    };

    // Drain any remaining output before reporting exit status.
    let _ = stdout_task.await;
    let _ = stderr_task.await;

    exit_code_of(status)
}

/// PTY session: run the command on a pseudo-terminal via `rmux-pty`, pumping
/// I/O through blocking threads (no `unsafe`, identical on Unix and Windows).
async fn run_pty(
    command: SessionCommand,
    pty: PtyRequest,
    mut read_half: ChannelReadHalf,
    write_half: &ChannelWriteHalf<Msg>,
    resize_rx: &mut mpsc::UnboundedReceiver<(u16, u16)>,
) -> u32 {
    use rmux_pty::{ChildCommand, Signal, TerminalSize};

    let mut builder = ChildCommand::new(&command.program);
    for arg in &command.args {
        builder = builder.arg(arg);
    }
    for (k, v) in &command.env {
        builder = builder.env(k, v);
    }
    builder = builder.size(TerminalSize::new(pty.cols.max(1), pty.rows.max(1)));

    let spawned = match builder.spawn() {
        Ok(spawned) => spawned,
        Err(error) => {
            tracing::warn!(program = %command.program, %error, "failed to spawn pty command");
            return 127;
        }
    };

    let (mut master, mut child) = spawned.into_parts();
    // The reader carries the one-shot startup-slave guard so EOF is observed
    // only after the child actually exits.
    let reader_io = match master.try_clone_for_startup_reader() {
        Ok(m) => m.into_io(),
        Err(error) => {
            tracing::warn!(%error, "failed to clone pty for reader");
            return 1;
        }
    };
    let writer_io = match master.try_clone_io() {
        Ok(io) => io,
        Err(error) => {
            tracing::warn!(%error, "failed to clone pty for writer");
            return 1;
        }
    };

    // Blocking reader thread: PTY master → tokio mpsc.
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(64);
    let reader_join = tokio::task::spawn_blocking(move || {
        release_startup_guard(&reader_io);
        let mut buf = [0u8; 32768];
        loop {
            match reader_io.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if out_tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    });

    // Blocking writer thread: std mpsc → PTY master.
    let (in_tx, in_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let writer_join = tokio::task::spawn_blocking(move || {
        while let Ok(chunk) = in_rx.recv() {
            if writer_io.write_all(&chunk).is_err() {
                break;
            }
        }
    });

    let mut reader = read_half.make_reader();
    let mut stdout = write_half.make_writer();
    let mut stdin_buf = [0u8; 32768];
    let mut stdin_open = true;
    let mut poll = tokio::time::interval(std::time::Duration::from_millis(50));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let exit_status = loop {
        tokio::select! {
            // client → PTY stdin
            r = reader.read(&mut stdin_buf), if stdin_open => {
                match r {
                    Ok(0) | Err(_) => stdin_open = false,
                    Ok(n) => { let _ = in_tx.send(stdin_buf[..n].to_vec()); }
                }
            }
            // PTY output → client
            chunk = out_rx.recv() => {
                match chunk {
                    Some(data) => {
                        if stdout.write_all(&data).await.is_err() {
                            // Client is gone; hang up the child.
                            let _ = child.kill(Signal::HUP);
                            break child.wait();
                        }
                        let _ = stdout.flush().await;
                    }
                    // Reader EOF: child closed the slave (it exited).
                    None => break child.wait(),
                }
            }
            // window-change → resize
            Some((cols, rows)) = resize_rx.recv() => {
                let _ = master.resize(TerminalSize::new(cols.max(1), rows.max(1)));
            }
            // Periodic exit poll (primary signal on Windows ConPTY).
            _ = poll.tick() => {
                if let Ok(Some(status)) = child.try_wait() {
                    #[cfg(windows)]
                    child.close_pseudoconsole();
                    break Ok(status);
                }
            }
        }
    };

    // Flush any buffered output, bounded so a stuck reader can't hang us.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while let Some(data) = out_rx.recv().await {
            if stdout.write_all(&data).await.is_err() {
                break;
            }
        }
    })
    .await;
    let _ = stdout.flush().await;

    drop(in_tx); // end the writer thread
    let _ = tokio::time::timeout(std::time::Duration::from_secs(1), reader_join).await;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(1), writer_join).await;

    exit_code_of(exit_status)
}

/// Release the Unix startup-slave guard so the reader observes EOF on child
/// exit (no-op on non-Unix).
#[cfg(unix)]
fn release_startup_guard(io: &rmux_pty::PtyIo) {
    io.release_startup_slave_guard();
}

#[cfg(not(unix))]
fn release_startup_guard(_io: &rmux_pty::PtyIo) {}

/// Map a process exit status to an SSH exit code (128 + signal on Unix). Shared
/// by the pipe and PTY runners, whose `wait()`s differ only in error type.
fn exit_code_of<E: std::fmt::Display>(status: Result<std::process::ExitStatus, E>) -> u32 {
    match status {
        Ok(status) => {
            if let Some(code) = status.code() {
                code as u32
            } else {
                #[cfg(unix)]
                {
                    use std::os::unix::process::ExitStatusExt;
                    status.signal().map(|s| 128 + s as u32).unwrap_or(1)
                }
                #[cfg(not(unix))]
                {
                    1
                }
            }
        }
        Err(error) => {
            tracing::debug!(%error, "child wait failed");
            1
        }
    }
}
