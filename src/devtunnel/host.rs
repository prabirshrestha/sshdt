use super::{
    logs::{Log, state_dir},
    process::{OwnedProcess, ProcessEvent, spawn_owned},
};
use anyhow::{Context, Result, bail};
use fs4::fs_std::FileExt;
use serde_json::{Value, json};
use sshdt::DevTunnelConfig;
use std::fs::{self, OpenOptions};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    sync::oneshot,
    task::JoinHandle,
    time::{Instant, timeout_at},
};

pub struct HostHandle {
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

pub fn start(config: DevTunnelConfig, addr: SocketAddr) -> HostHandle {
    let (stop, mut cancelled) = oneshot::channel();
    let task = tokio::spawn(async move {
        if !config.enabled {
            return;
        }
        let log = match Log::new("host") {
            Ok(log) => log,
            Err(error) => {
                tracing::warn!(%error, "Dev Tunnel skipped because its log cannot be opened");
                return;
            }
        };
        let instance_path =
            state_dir().join(format!("devtunnel-instance-{}.lock", std::process::id()));
        let instance_lock = match OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(instance_path)
        {
            Ok(lock) => lock,
            Err(error) => {
                tracing::warn!(%error, "Dev Tunnel status lock unavailable");
                return;
            }
        };
        if !matches!(instance_lock.try_lock_exclusive(), Ok(true)) {
            tracing::warn!("Dev Tunnel status lock already held");
            return;
        }
        let id = match config.id.as_deref().filter(|id| sshdt::valid_tunnel_id(id)) {
            Some(id) => id,
            None => {
                status(
                    &log,
                    None,
                    "skipped",
                    "DevTunnelId must contain an explicit valid tunnel ID",
                );
                let _ = (&mut cancelled).await;
                return;
            }
        };
        if !addr.ip().is_loopback() && !addr.ip().is_unspecified() {
            status(
                &log,
                Some(id),
                "skipped",
                "SSH listener must accept loopback connections",
            );
            let _ = (&mut cancelled).await;
            return;
        }
        if config.timeout_secs == 0 {
            status(
                &log,
                Some(id),
                "skipped",
                "DevTunnelTimeout must be greater than zero",
            );
            let _ = (&mut cancelled).await;
            return;
        }
        let lock_path = state_dir().join(format!("devtunnel-host-{id}.lock"));
        let lock = match OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(lock_path)
        {
            Ok(lock) => lock,
            Err(error) => {
                status(&log, Some(id), "skipped", &error.to_string());
                let _ = (&mut cancelled).await;
                return;
            }
        };
        if !matches!(lock.try_lock_exclusive(), Ok(true)) {
            status(
                &log,
                Some(id),
                "skipped",
                "another sshdt process already hosts this tunnel",
            );
            let _ = (&mut cancelled).await;
            return;
        }
        {
            use std::io::{Seek, SeekFrom, Write};
            let mut file = &lock;
            let _ = file.set_len(0);
            let _ = file.seek(SeekFrom::Start(0));
            let _ = write!(file, "{}", std::process::id());
        }
        let mut delay = 1;
        loop {
            status(&log, Some(id), "starting", "checking tunnel configuration");
            let attempt = attempt(&config, addr.port(), &log);
            let result = tokio::select! {
                _ = &mut cancelled => break,
                result = attempt => result,
            };
            let mut child = match result {
                Ok(child) => {
                    delay = 1;
                    child
                }
                Err(error) => {
                    let reason = error.to_string();
                    let permanent = [
                        "login required",
                        "DevTunnelAutoCreate",
                        "Tunnel not found",
                        "No such file",
                        "not found",
                        "incompatible protocol",
                    ]
                    .iter()
                    .any(|part| reason.contains(part));
                    status(
                        &log,
                        Some(id),
                        if permanent { "skipped" } else { "retrying" },
                        &reason,
                    );
                    let pause = if permanent { 60 } else { delay };
                    tokio::select! {
                        _ = &mut cancelled => break,
                        _ = tokio::time::sleep(Duration::from_secs(pause)) => {},
                    }
                    delay = (delay * 2).min(60);
                    continue;
                }
            };
            status(&log, Some(id), "connected", "tunnel ready");
            loop {
                tokio::select! {
                    _ = &mut cancelled => {
                        shutdown_logged(&mut child, &log).await;
                        status(&log, Some(id), "stopped", "SSH server stopped");
                        return;
                    }
                    event = child.next_event() => match event {
                        Some(ProcessEvent::Line { stream, line }) => log.write("host", stream, &line),
                        Some(ProcessEvent::Exited { code, .. }) => {
                            status(&log, Some(id), "retrying", &format!("host process exited with code {code:?}"));
                            break;
                        }
                        None => break,
                    }
                }
            }
            shutdown_logged(&mut child, &log).await;
            tokio::select! {
                _ = &mut cancelled => break,
                _ = tokio::time::sleep(Duration::from_secs(delay)) => {},
            }
            delay = (delay * 2).min(60);
        }
        status(&log, config.id.as_deref(), "stopped", "SSH server stopped");
    });
    HostHandle {
        stop: Some(stop),
        task,
    }
}

impl HostHandle {
    pub async fn shutdown(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let _ = (&mut self.task).await;
    }
}

impl Drop for HostHandle {
    fn drop(&mut self) {
        self.stop.take();
    }
}

fn status(log: &Log, id: Option<&str>, state: &str, reason: &str) {
    let reason = super::logs::sanitize(reason);
    log.write("status", state, &reason);
    tracing::info!(tunnel_id = id, tunnel_state = state, %reason, "Dev Tunnel status");
    let value = json!({ "pid": std::process::id(), "id": id, "state": state, "reason": reason });
    let path = state_dir().join(format!("devtunnel-host-{}.json", std::process::id()));
    if let Ok(bytes) = serde_json::to_vec(&value)
        && let Ok(mut temp) = tempfile::NamedTempFile::new_in(state_dir())
    {
        use std::io::Write;
        if temp.write_all(&bytes).is_ok() {
            let _ = temp.persist(path);
        }
    }
}

struct Output {
    success: bool,
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

async fn command(args: &[&str], deadline: Instant, log: &Log, json_output: bool) -> Result<Output> {
    let args = args.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    let mut child = spawn_owned(&args).await?;
    let result = timeout_at(deadline, async {
        let mut stdout = String::new();
        let mut stderr = String::new();
        while let Some(event) = child.next_event().await {
            match event {
                ProcessEvent::Line { stream, line } => {
                    if !json_output || stream != "stdout" {
                        log.write(&args[0], stream, &line);
                    }
                    let target = if stream == "stdout" {
                        &mut stdout
                    } else {
                        &mut stderr
                    };
                    if target.len() + line.len() > 1024 * 1024 {
                        bail!("Dev Tunnel command output exceeds limit");
                    }
                    target.push_str(&line);
                    target.push('\n');
                }
                ProcessEvent::Exited { success, code } => {
                    return Ok(Output {
                        success,
                        code,
                        stdout,
                        stderr,
                    });
                }
            }
        }
        bail!("Dev Tunnel command ended without exit status")
    })
    .await;
    shutdown_logged(&mut child, log).await;
    result.context("Dev Tunnel setup timed out")?
}

fn not_found(output: &Output) -> bool {
    output.code == Some(2)
        && format!("{}{}", output.stdout, output.stderr)
            .to_ascii_lowercase()
            .contains("tunnel not found")
}

fn failure(output: &Output) -> String {
    let combined = format!("{} {}", output.stderr, output.stdout);
    let lower = combined.to_ascii_lowercase();
    if lower.contains("login")
        || lower.contains("not logged")
        || lower.contains("unauthorized")
        || lower.contains("authentication")
    {
        "login required; run devtunnel user login under the SSH server account".into()
    } else {
        format!(
            "Dev Tunnel CLI failed with code {:?}: {}",
            output.code,
            super::logs::sanitize(&combined)
        )
    }
}

fn tunnel(value: &Value) -> &Value {
    value.get("tunnel").unwrap_or(value)
}
fn has_port(value: &Value, port: u16) -> bool {
    tunnel(value)
        .get("ports")
        .and_then(Value::as_array)
        .is_some_and(|ports| {
            ports.iter().any(|p| {
                p.get("portNumber").and_then(Value::as_u64) == Some(u64::from(port))
                    && p.get("protocol").and_then(Value::as_str) == Some("auto")
            })
        })
}

async fn attempt(config: &DevTunnelConfig, port: u16, log: &Log) -> Result<OwnedProcess> {
    let id = config.id.as_deref().unwrap();
    let deadline = Instant::now() + Duration::from_secs(config.timeout_secs);
    let user = command(&["user", "show", "--json"], deadline, log, true).await?;
    if !user.success {
        bail!("{}", failure(&user));
    }
    let account: Value =
        serde_json::from_str(&user.stdout).context("invalid Dev Tunnel login response")?;
    if account.get("status").and_then(Value::as_str) != Some("Logged in") {
        bail!("login required; run devtunnel user login under the SSH server account");
    }
    let mut shown = command(&["show", id, "--json"], deadline, log, true).await?;
    if !shown.success {
        if !not_found(&shown) || !config.auto_create {
            bail!("{}", failure(&shown));
        }
        let created = command(&["create", id, "--json"], deadline, log, true).await?;
        if !created.success {
            log.write(
                "create",
                "result",
                "creation failed; checking for a concurrent creator",
            );
        }
        shown = command(&["show", id, "--json"], deadline, log, true).await?;
    }
    if !shown.success {
        bail!("{}", failure(&shown));
    }
    let mut value: Value =
        serde_json::from_str(&shown.stdout).context("invalid Dev Tunnel details")?;
    if !has_port(&value, port) {
        if tunnel(&value)
            .get("ports")
            .and_then(Value::as_array)
            .is_some_and(|ports| {
                ports
                    .iter()
                    .any(|p| p.get("portNumber").and_then(Value::as_u64) == Some(u64::from(port)))
            })
        {
            bail!(
                "tunnel port {port} has an incompatible protocol; update it explicitly with devtunnel"
            );
        }
        if !config.auto_create {
            bail!(
                "tunnel {id} lacks port {port} with protocol auto; DevTunnelAutoCreate is disabled"
            );
        }
        let number = port.to_string();
        let created = command(
            &[
                "port",
                "create",
                id,
                "-p",
                &number,
                "--protocol",
                "auto",
                "--json",
            ],
            deadline,
            log,
            true,
        )
        .await?;
        if !created.success {
            log.write(
                "port create",
                "result",
                "port creation failed; checking current configuration",
            );
        }
        shown = command(&["show", id, "--json"], deadline, log, true).await?;
        if !shown.success {
            bail!("{}", failure(&shown));
        }
        value = serde_json::from_str(&shown.stdout).context("invalid Dev Tunnel port details")?;
        if !has_port(&value, port) {
            bail!("tunnel port {port} is missing or has an incompatible protocol");
        }
    }
    let mut child = spawn_owned(&["host".into(), id.into()]).await?;
    let ready = timeout_at(deadline, async {
        while let Some(event) = child.next_event().await {
            match event {
                ProcessEvent::Line { stream, line } => {
                    log.write("host", stream, &line);
                    if line.contains("Ready to accept connections for tunnel:") {
                        return Ok(());
                    }
                }
                ProcessEvent::Exited { code, .. } => {
                    bail!("Dev Tunnel host exited before readiness with code {code:?}")
                }
            }
        }
        bail!("Dev Tunnel host ended before readiness")
    })
    .await
    .context("Dev Tunnel host startup timed out")?;
    ready?;
    Ok(child)
}

pub fn print_status() -> Result<()> {
    let dir = state_dir();
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("devtunnel-host-") || !name.ends_with(".json") {
            continue;
        }
        let value: Value = match fs::read(entry.path())
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        {
            Some(value) => value,
            None => continue,
        };
        let Some(pid) = value["pid"].as_u64() else {
            continue;
        };
        let lock = match OpenOptions::new()
            .read(true)
            .write(true)
            .open(dir.join(format!("devtunnel-instance-{pid}.lock")))
        {
            Ok(lock) => lock,
            Err(_) => continue,
        };
        if matches!(lock.try_lock_exclusive(), Ok(false)) {
            println!(
                "Dev Tunnel {}: {} ({})",
                value["id"].as_str().unwrap_or("not configured"),
                value["state"].as_str().unwrap_or("unknown"),
                value["reason"].as_str().unwrap_or("")
            );
        }
    }
    Ok(())
}

async fn shutdown_logged(child: &mut OwnedProcess, log: &Log) {
    child.stop();
    let _ = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(event) = child.next_event().await {
            match event {
                ProcessEvent::Line { stream, line } => log.write("shutdown", stream, &line),
                ProcessEvent::Exited { code, .. } => {
                    log.write("shutdown", "exit", &format!("code {code:?}"))
                }
            }
        }
    })
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn port_checks_require_exact_number_and_protocol() {
        let data = json!({"tunnel":{"ports":[{"portNumber":2222,"protocol":"auto"}]}});
        assert!(has_port(&data, 2222));
        assert!(!has_port(&data, 2223));
        assert!(!has_port(
            &json!({"ports":[{"portNumber":2222,"protocol":"https"}]}),
            2222
        ));
    }
    #[test]
    fn creation_requires_a_confirmed_missing_tunnel() {
        let mut output = Output {
            success: false,
            code: Some(2),
            stdout: String::new(),
            stderr: "Tunnel not found: test".into(),
        };
        assert!(not_found(&output));
        output.stderr = "Network unavailable".into();
        assert!(!not_found(&output));
        output.stderr = "Tunnel not found: test".into();
        output.code = Some(1);
        assert!(!not_found(&output));
    }
}
