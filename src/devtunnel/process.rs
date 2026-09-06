use anyhow::{Context, Result};
use std::{process::Stdio, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::{Child, ChildStdin, Command},
    sync::mpsc,
};

#[derive(Debug)]
pub enum ProcessEvent {
    Line { stream: &'static str, line: String },
    Exited { success: bool, code: Option<i32> },
}

pub struct OwnedProcess {
    child: Child,
    liveness: Option<ChildStdin>,
    events: mpsc::Receiver<ProcessEvent>,
    exited: bool,
}

pub async fn spawn_owned(argv: &[String]) -> Result<OwnedProcess> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .arg("devtunnel-guardian")
        .args(argv)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    command.process_group(0);
    #[cfg(windows)]
    command.creation_flags(0x08000000);
    let mut child = command
        .spawn()
        .context("start Dev Tunnel process guardian")?;
    let (tx, events) = mpsc::channel(256);
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    tokio::spawn(drain(stdout, "stdout", tx.clone()));
    tokio::spawn(drain(stderr, "stderr", tx));
    let liveness = child.stdin.take();
    Ok(OwnedProcess {
        child,
        liveness,
        events,
        exited: false,
    })
}

async fn drain<R: AsyncRead + Unpin>(
    mut reader: R,
    stream: &'static str,
    tx: mpsc::Sender<ProcessEvent>,
) {
    let mut chunk = [0; 4096];
    let mut line = Vec::new();
    let mut oversized = false;
    loop {
        match reader.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                for byte in &chunk[..n] {
                    if *byte == b'\n' {
                        let text = if oversized {
                            "[oversized output line omitted]".into()
                        } else {
                            String::from_utf8_lossy(&line)
                                .trim_end_matches('\r')
                                .to_string()
                        };
                        if tx
                            .send(ProcessEvent::Line { stream, line: text })
                            .await
                            .is_err()
                        {
                            return;
                        }
                        line.clear();
                        oversized = false;
                    } else if line.len() < 65536 {
                        line.push(*byte);
                    } else {
                        oversized = true;
                    }
                }
            }
        }
    }
    if oversized || !line.is_empty() {
        let text = if oversized {
            "[oversized output line omitted]".into()
        } else {
            String::from_utf8_lossy(&line).into_owned()
        };
        let _ = tx.send(ProcessEvent::Line { stream, line: text }).await;
    }
}

impl OwnedProcess {
    pub async fn next_event(&mut self) -> Option<ProcessEvent> {
        if let Some(event) = self.events.recv().await {
            return Some(event);
        }
        if self.exited {
            return None;
        }
        let status = self.child.wait().await;
        self.exited = true;
        match status {
            Ok(status) => Some(ProcessEvent::Exited {
                success: status.success(),
                code: status.code(),
            }),
            Err(_) => Some(ProcessEvent::Exited {
                success: false,
                code: None,
            }),
        }
    }

    pub fn stop(&mut self) {
        self.liveness.take();
    }

    pub async fn shutdown(&mut self) {
        self.stop();
        let cleanup = async { while self.next_event().await.is_some() {} };
        let _ = tokio::time::timeout(Duration::from_secs(10), cleanup).await;
    }
}

impl Drop for OwnedProcess {
    fn drop(&mut self) {
        self.liveness.take();
    }
}

pub fn guardian(args: Vec<String>) -> Result<()> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        use std::io::Read;
        let mut byte = [0];
        loop {
            match std::io::stdin().read(&mut byte) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        let _ = tx.send(());
    });
    if rx.try_recv().is_ok() {
        return Ok(());
    }
    let code = run_guarded(args, rx)?;
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

#[cfg(unix)]
fn run_guarded(args: Vec<String>, owner: std::sync::mpsc::Receiver<()>) -> Result<i32> {
    let binary = std::env::var_os("SSHDT_DEVTUNNEL_BIN").unwrap_or_else(|| "devtunnel".into());
    run_unix_child(binary, args, owner)
}

#[cfg(unix)]
fn run_unix_child(
    binary: std::ffi::OsString,
    args: Vec<String>,
    owner: std::sync::mpsc::Receiver<()>,
) -> Result<i32> {
    use std::os::unix::process::CommandExt;
    let mut child = std::process::Command::new(binary)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .process_group(0)
        .spawn()
        .context("start devtunnel CLI")?;
    let pid = child.id() as libc::pid_t;
    loop {
        if owner.recv_timeout(Duration::from_millis(50)).is_ok() {
            break;
        }
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result != 0 {
            break;
        }
        if unsafe { info.si_pid() } != 0 {
            break;
        }
    }
    // Keep the leader unreaped until the group is killed so its ID cannot be reused.
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
    let status = child.wait()?;
    Ok(status.code().unwrap_or(1))
}

#[cfg(windows)]
fn run_guarded(args: Vec<String>, owner: std::sync::mpsc::Receiver<()>) -> Result<i32> {
    std::thread::spawn(move || -> Result<i32> {
        use process_wrap::tokio::*;
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async move {
                let binary =
                    std::env::var_os("SSHDT_DEVTUNNEL_BIN").unwrap_or_else(|| "devtunnel".into());
                let mut command = CommandWrap::with_new(binary, |command| {
                    command
                        .args(args)
                        .stdin(Stdio::null())
                        .stdout(Stdio::inherit())
                        .stderr(Stdio::inherit());
                });
                command.wrap(KillOnDrop);
                command.wrap(JobObject);
                let mut child = command.spawn().context("start devtunnel CLI")?;
                loop {
                    if owner.try_recv().is_ok() {
                        child.start_kill()?;
                        return Ok(child.wait().await?.code().unwrap_or(1));
                    }
                    if let Some(status) = child.try_wait()? {
                        let _ = child.start_kill();
                        return Ok(status.code().unwrap_or(1));
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
    })
    .join()
    .map_err(|_| anyhow::anyhow!("Dev Tunnel guardian thread failed"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    #[test]
    fn guardian_kills_descendants_when_owner_disconnects() {
        let directory = tempfile::tempdir().unwrap();
        let pid_path = directory.path().join("descendant.pid");
        let (owner, closed) = std::sync::mpsc::channel();
        let args = vec![
            "-c".into(),
            "sleep 600 & echo $! > \"$1\"; wait".into(),
            "test".into(),
            pid_path.to_string_lossy().into_owned(),
        ];
        let guardian = std::thread::spawn(move || run_unix_child("/bin/sh".into(), args, closed));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let pid: libc::pid_t = loop {
            if let Some(pid) = std::fs::read_to_string(&pid_path)
                .ok()
                .and_then(|text| text.trim().parse().ok())
            {
                break pid;
            }
            assert!(std::time::Instant::now() < deadline, "child did not start");
            std::thread::sleep(Duration::from_millis(10));
        };
        owner.send(()).unwrap();
        guardian.join().unwrap().unwrap();
        while unsafe { libc::kill(pid, 0) } == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "descendant survived owner disconnect"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cancelled_exit_wait_preserves_exit_event() {
        let child = Command::new("/bin/sh")
            .args(["-c", "sleep 0.2"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let (sender, events) = mpsc::channel(1);
        drop(sender);
        let mut process = OwnedProcess {
            child,
            liveness: None,
            events,
            exited: false,
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(10), process.next_event())
                .await
                .is_err()
        );
        assert!(matches!(
            process.next_event().await,
            Some(ProcessEvent::Exited { success: true, .. })
        ));
        assert!(process.next_event().await.is_none());
    }

    #[tokio::test]
    async fn both_streams_drain_when_each_exceeds_pipe_capacity() {
        let (tx, mut rx) = mpsc::channel(256);
        let stdout = "stdout line\n".repeat(10000).into_bytes();
        let stderr = "stderr line\n".repeat(10000).into_bytes();
        let stderr_tx = tx.clone();
        let a = tokio::spawn(async move { drain(&stdout[..], "stdout", tx).await });
        let b = tokio::spawn(async move { drain(&stderr[..], "stderr", stderr_tx).await });
        let mut counts = [0; 2];
        tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(event) = rx.recv().await {
                match event {
                    ProcessEvent::Line {
                        stream: "stdout",
                        line,
                    } => {
                        assert_eq!(line, "stdout line");
                        counts[0] += 1;
                    }
                    ProcessEvent::Line {
                        stream: "stderr",
                        line,
                    } => {
                        assert_eq!(line, "stderr line");
                        counts[1] += 1;
                    }
                    _ => panic!("unexpected output event"),
                }
            }
        })
        .await
        .unwrap();
        a.await.unwrap();
        b.await.unwrap();
        assert_eq!(counts, [10000, 10000]);
    }

    #[tokio::test]
    async fn oversized_lines_are_bounded() {
        let (tx, mut rx) = mpsc::channel(256);
        let oversized = vec![b'x'; 100000];
        let a = tokio::spawn(async move { drain(&oversized[..], "stdout", tx).await });
        let event = rx.recv().await.unwrap();
        assert!(
            matches!(event, ProcessEvent::Line { line, .. } if line == "[oversized output line omitted]")
        );
        a.await.unwrap();
        assert!(rx.recv().await.is_none());
    }
}
