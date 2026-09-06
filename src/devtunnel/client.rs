use super::{
    ipc,
    logs::Log,
    process::{self, ProcessEvent},
};
use anyhow::{Context, Result, bail, ensure};
use fs4::{FileExt, TryLockError};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    net::{Ipv4Addr, SocketAddr},
    process::Stdio,
    sync::{Arc, Weak},
    time::Duration,
};
use tokio::{
    io::{AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
    sync::{Mutex, mpsc, watch},
    task::JoinSet,
    time::{Instant, sleep, timeout},
};

pub struct ProxyRequest {
    pub tunnel: String,
    pub remote_port: u16,
    pub local_port: Option<u16>,
    pub timeout: Duration,
}

pub async fn proxy(request: ProxyRequest) -> Result<()> {
    sshdt::validate_tunnel_id(&request.tunnel).map_err(anyhow::Error::msg)?;
    ensure!(
        request.remote_port != 0 && request.local_port != Some(0),
        "port must be between 1 and 65535"
    );
    ensure!(!request.timeout.is_zero(), "timeout must be positive");
    let log = Log::new("client")?;
    let stream = timeout(request.timeout, acquire(&request))
        .await
        .context("Dev Tunnel connection timed out")??;
    log.write("proxy", "status", "SSH stream opened");
    stdio(stream).await
}

async fn stdio(mut stream: TcpStream) -> Result<()> {
    let (mut reader, mut writer) = stream.split();
    let (input_tx, mut input_rx) = mpsc::channel(4);
    std::thread::spawn(move || {
        use std::io::Read;
        let mut input = std::io::stdin().lock();
        loop {
            let mut buffer = vec![0; 16384];
            match input.read(&mut buffer) {
                Ok(0) => break,
                Ok(length) => {
                    buffer.truncate(length);
                    if input_tx.blocking_send(Ok(buffer)).is_err() {
                        break;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    let _ = input_tx.blocking_send(Err(error));
                    break;
                }
            }
        }
    });
    let upload = async {
        while let Some(bytes) = input_rx.recv().await {
            writer.write_all(&bytes?).await?;
        }
        writer.shutdown().await
    };
    let download = async {
        let mut output = tokio::io::stdout();
        tokio::io::copy(&mut reader, &mut output).await?;
        output.flush().await
    };
    tokio::pin!(upload, download);
    tokio::select! {
        result = &mut upload => { result?; download.await?; }
        result = &mut download => { result?; }
    }

    Ok(())
}

async fn acquire(request: &ProxyRequest) -> Result<TcpStream> {
    let path = ipc::directory()?.join(format!("{}.json", request.tunnel));
    let mut next_spawn = Instant::now();
    loop {
        if let Ok(lock) = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path.with_extension("lock"))
            && broker_lock_held(&lock)?
            && let Ok(bytes) = ipc::read_endpoint(&path)
            && let Ok(endpoint) = serde_json::from_slice::<ipc::Endpoint>(&bytes)
            && let Ok(Ok(mut stream)) = timeout(
                Duration::from_millis(300),
                TcpStream::connect((Ipv4Addr::LOCALHOST, endpoint.port)),
            )
            .await
        {
            let hello = ipc::Request {
                version: ipc::VERSION,
                token: endpoint.token,
                remote_port: request.remote_port,
                local_port: request.local_port,
            };
            if ipc::send(&mut stream, &hello).await.is_ok()
                && let Ok(response) = broker_response(&mut stream, &lock).await
            {
                ensure!(
                    response.version == ipc::VERSION,
                    "incompatible sshdt tunnel manager; close existing sessions before retrying"
                );
                if let Some(error) = response.error {
                    bail!("{error}");
                }
                return Ok(stream);
            }
        }
        if Instant::now() >= next_spawn {
            let mut command = std::process::Command::new(std::env::current_exe()?);
            command
                .args(["devtunnel-broker", &request.tunnel])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            #[cfg(unix)]
            {
                use std::os::unix::process::CommandExt;
                unsafe {
                    command.pre_exec(|| {
                        if libc::setsid() < 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
            }
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                command.creation_flags(0x08000000);
            }
            let mut child = command.spawn().context("cannot start tunnel manager")?;
            std::thread::spawn(move || {
                let _ = child.wait();
            });
            next_spawn = Instant::now() + Duration::from_secs(1);
        }
        sleep(Duration::from_millis(50)).await;
    }
}

fn broker_lock_held(lock: &std::fs::File) -> Result<bool> {
    match FileExt::try_lock(lock) {
        Ok(()) => {
            FileExt::unlock(lock)?;
            Ok(false)
        }
        Err(TryLockError::WouldBlock) => Ok(true),
        Err(TryLockError::Error(error)) => Err(error.into()),
    }
}

async fn broker_response(stream: &mut TcpStream, lock: &std::fs::File) -> Result<ipc::Response> {
    let response = ipc::receive(stream);
    tokio::pin!(response);
    let mut check = tokio::time::interval(Duration::from_millis(100));
    loop {
        tokio::select! {
            response = &mut response => return response,
            _ = check.tick() => ensure!(broker_lock_held(lock)?, "tunnel manager stopped"),
        }
    }
}

#[derive(Clone, Default)]
struct Forwarding {
    ports: BTreeMap<u16, SocketAddr>,
    error: Option<String>,
    generation: u64,
}

struct Relay {
    remote_port: u16,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

type Relays = Arc<Mutex<BTreeMap<u16, Weak<Relay>>>>;

struct LeaseState {
    count: usize,
    idle_until: Instant,
    stopping: bool,
}

impl Default for LeaseState {
    fn default() -> Self {
        Self {
            count: 0,
            idle_until: Instant::now() + Duration::from_secs(5),
            stopping: false,
        }
    }
}

type Leases = Arc<std::sync::Mutex<LeaseState>>;

struct Lease(Leases);
impl Lease {
    fn acquire(leases: &Leases) -> Option<Self> {
        let mut state = leases.lock().unwrap();
        if state.stopping {
            return None;
        }
        state.count += 1;
        Some(Self(leases.clone()))
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        let mut state = self.0.lock().unwrap();
        state.count -= 1;
        if state.count == 0 {
            state.idle_until = Instant::now() + Duration::from_secs(5);
        }
    }
}

fn begin_idle_shutdown(leases: &Leases) -> bool {
    let mut state = leases.lock().unwrap();
    if state.count == 0 && Instant::now() >= state.idle_until {
        state.stopping = true;
    }
    state.stopping
}

pub async fn broker(tunnel: String) -> Result<()> {
    sshdt::validate_tunnel_id(&tunnel).map_err(anyhow::Error::msg)?;
    let directory = ipc::directory()?;
    let lock_path = directory.join(format!("{tunnel}.lock"));
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)?;
    ipc::secure(&lock_path)?;
    match FileExt::try_lock(&lock) {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => return Ok(()),
        Err(TryLockError::Error(error)) => return Err(error.into()),
    }
    let log = Log::new("client")?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let token: String = rand::random::<[u8; 32]>()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let endpoint = ipc::Endpoint {
        port: listener.local_addr()?.port(),
        token: token.clone(),
    };
    let endpoint_path = directory.join(format!("{tunnel}.json"));
    let mut temporary = tempfile::NamedTempFile::new_in(&directory)?;
    ipc::secure(temporary.path())?;
    std::io::Write::write_all(&mut temporary, &serde_json::to_vec(&endpoint)?)?;
    temporary.as_file().sync_all()?;
    temporary.persist(&endpoint_path)?;
    let (forward_tx, forward_rx) = watch::channel(Forwarding::default());
    let mut connector: Option<process::OwnedProcess> = None;
    let mut announcements = BTreeMap::new();
    let mut listeners = std::collections::BTreeSet::new();
    let (start_tx, mut start_rx) = mpsc::channel(32);
    let mut requested = std::collections::BTreeSet::new();
    let mut retry_at = Instant::now();
    let mut retry_delay = Duration::from_millis(100);
    let mut restarting = false;
    let relays = Relays::default();
    let mut sessions = JoinSet::new();
    let leases = Leases::default();
    let mut idle_check = tokio::time::interval(Duration::from_millis(100));
    log.write("broker", "status", "tunnel manager started");
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                if sessions.len() >= 256 { continue; }
                let leases = leases.clone();
                let token = token.clone();
                let state = forward_rx.clone();
                let relays = relays.clone();
                let start = start_tx.clone();
                sessions.spawn(async move { let _ = serve(stream, &token, state, relays, start, leases).await; });
            }
            Some(port) = start_rx.recv() => {
                requested.insert(port);
            }
            _ = tokio::time::sleep_until(retry_at), if connector.is_none() && !requested.is_empty() => {
                if connector.is_none() {
                    match process::spawn_owned(&["connect".into(), tunnel.clone()], None).await {
                        Ok(process) => connector = Some(process),
                        Err(_) => { forward_tx.send_modify(|state| state.error = Some("cannot start devtunnel; check installation and login".into())); break; }
                    }
                }
            }
            event = async { connector.as_mut().unwrap().next_event().await }, if connector.is_some() => {
                match event {
                    Some(ProcessEvent::Line { stream, line }) => {
                        log.write("connect", stream, &line);
                        if startup_forwarding_failure(&line) && !restarting {
                            log.write("connect", "status", "CLI forwarding startup failed; restarting connector");
                            restarting = true;
                            connector.as_mut().unwrap().stop();
                            announcements.clear();
                            listeners.clear();
                            forward_tx.send_modify(|state| { state.ports.clear(); state.generation += 1; });
                        }
                        if !restarting {
                            if let Some((remote, local)) = forwarding_line(&line) { announcements.insert(local, remote); }
                            if let Some(local) = listening_line(&line) { listeners.insert(local); }
                        }
                    }
                    _ if restarting => {
                        connector = None;
                        restarting = false;
                        retry_at = Instant::now() + retry_delay;
                        retry_delay = (retry_delay * 2).min(Duration::from_secs(8));
                    }
                    _ => {
                        forward_tx.send_modify(|state| { state.ports.clear(); state.error = Some("devtunnel connector exited; check login and client logs".into()); });
                        break;
                    }
                }
            }
            _ = sessions.join_next(), if !sessions.is_empty() => {}
            _ = idle_check.tick() => {
                if begin_idle_shutdown(&leases) { break; }
                if !restarting {
                    for (local, remote) in &announcements {
                        if listeners.contains(local) {
                            forward_tx.send_modify(|state| {
                                let selected = state.ports.entry(*remote).or_insert(*local);
                                if local.is_ipv4() { *selected = *local; }
                            });
                        }
                    }
                }
            },
        }
    }
    drop(listener);
    let _ = fs::remove_file(endpoint_path);
    let _ = timeout(Duration::from_secs(1), async {
        while sessions.join_next().await.is_some() {}
    })
    .await;
    sessions.abort_all();
    while sessions.join_next().await.is_some() {}
    relays.lock().await.clear();
    if let Some(mut connector) = connector {
        connector.shutdown().await;
    }
    log.write("broker", "status", "tunnel manager stopped");
    drop(lock);
    Ok(())
}

async fn serve(
    mut stream: TcpStream,
    token: &str,
    mut state: watch::Receiver<Forwarding>,
    relays: Relays,
    start: mpsc::Sender<u16>,
    leases: Leases,
) -> Result<()> {
    let request: ipc::Request =
        timeout(Duration::from_secs(5), ipc::receive(&mut stream)).await??;
    ensure!(
        same_token(&request.token, token),
        "invalid tunnel manager capability"
    );
    let Some(_lease) = Lease::acquire(&leases) else {
        return Ok(());
    };
    let mut relay = None;
    let open = async {
        ensure!(
            request.version == ipc::VERSION,
            "incompatible sshdt tunnel manager"
        );
        ensure!(
            request.remote_port != 0 && request.local_port != Some(0),
            "invalid port"
        );
        if let Some(port) = request.local_port {
            relay = Some(ensure_relay(&relays, port, request.remote_port, state.clone()).await?);
        }
        start
            .send(request.remote_port)
            .await
            .context("tunnel manager stopped")?;
        loop {
            let snapshot = state.borrow().clone();
            if let Some(error) = snapshot.error {
                bail!("{error}");
            }
            if let Some(address) = snapshot.ports.get(&request.remote_port) {
                let destination = request
                    .local_port
                    .map(|port| SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
                    .unwrap_or(*address);
                let connect = async {
                    let mut destination = TcpStream::connect(destination).await?;
                    let prefix = read_ssh_banner(&mut destination).await?;
                    Ok::<_, std::io::Error>((destination, prefix))
                };
                let result = tokio::select! {
                    result = connect => Some(result),
                    _ = async {
                        loop {
                            if state.borrow().error.is_some() || state.borrow().generation != snapshot.generation { break; }
                            if state.changed().await.is_err() { break; }
                        }
                    } => None,
                };
                if let Some(Ok((destination, prefix))) = result
                    && state.borrow().generation == snapshot.generation
                {
                    return Ok((destination, prefix, snapshot.generation));
                }
                sleep(Duration::from_millis(100)).await;
                continue;
            }
            state.changed().await.context("tunnel manager stopped")?;
        }
    };
    let mut probe = [0; 1];
    let result = tokio::select! {
        result = open => result,
        result = stream.peek(&mut probe) => { result?; return Ok(()); }
    };
    let response = ipc::Response {
        version: ipc::VERSION,
        error: result.as_ref().err().map(ToString::to_string),
    };
    ipc::send(&mut stream, &response).await?;
    let (mut destination, prefix, generation) = result?;
    stream.write_all(&prefix).await?;
    tokio::select! {
        result = copy_bidirectional(&mut stream, &mut destination) => { result?; }
        _ = async {
            loop {
                if state.borrow().error.is_some() || state.borrow().generation != generation { break; }
                if state.changed().await.is_err() { break; }
            }
        } => bail!("devtunnel connector stopped"),
    }
    Ok(())
}

async fn ensure_relay(
    relays: &Relays,
    port: u16,
    remote_port: u16,
    state: watch::Receiver<Forwarding>,
) -> Result<Arc<Relay>> {
    let mut relays = relays.lock().await;
    relays.retain(|_, relay| relay.strong_count() > 0);
    if let Some(relay) = relays.get(&port).and_then(Weak::upgrade) {
        ensure!(
            relay.remote_port == remote_port,
            "local port {port} already routes to a different destination"
        );
        return Ok(relay);
    }
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
        .await
        .with_context(|| format!("local port {port} is unavailable"))?;
    let relay = Arc::new(spawn_relay(listener, remote_port, state));
    relays.insert(port, Arc::downgrade(&relay));
    Ok(relay)
}

fn spawn_relay(
    listener: TcpListener,
    remote_port: u16,
    state: watch::Receiver<Forwarding>,
) -> Relay {
    let task = tokio::spawn(async move {
        let mut streams = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((mut incoming, _)) = accepted else { break; };
                    let address = state.borrow().ports.get(&remote_port).copied();
                    if let Some(address) = address {
                        streams.spawn(async move {
                            if let Ok(mut destination) = TcpStream::connect(address).await { let _ = copy_bidirectional(&mut incoming, &mut destination).await; }
                        });
                    }
                }
                _ = streams.join_next(), if !streams.is_empty() => {}
            }
        }
    });
    Relay { remote_port, task }
}

fn startup_forwarding_failure(line: &str) -> bool {
    line.contains("System.InvalidOperationException: Port ")
        && line.contains(" is not being forwarded.")
}

async fn read_ssh_banner(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut prefix = Vec::new();
    let mut start = 0;
    for _ in 0..8192 {
        let byte = stream.read_u8().await?;
        prefix.push(byte);
        if byte == b'\n' {
            let line = &prefix[start..];
            if (line.starts_with(b"SSH-2.0-") || line.starts_with(b"SSH-1.99-"))
                && line.len() <= 255
            {
                return Ok(prefix);
            }
            start = prefix.len();
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "invalid SSH identification",
    ))
}

fn same_token(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |difference, (a, b)| difference | (a ^ b))
            == 0
}

fn listening_line(line: &str) -> Option<SocketAddr> {
    let line = line.trim().strip_prefix("SSH: ").unwrap_or(line.trim());
    let local = line
        .strip_prefix("PortForwardingService listening on ")
        .or_else(|| line.strip_prefix("PortForwardingService also listening on "))?;
    let local = local.strip_suffix('.')?;
    let address: SocketAddr = local.parse().ok().or_else(|| {
        let (ip, port) = local.rsplit_once(':')?;
        Some(SocketAddr::new(ip.parse().ok()?, port.parse().ok()?))
    })?;
    (address.ip().is_loopback() && address.port() != 0).then_some(address)
}

fn forwarding_line(line: &str) -> Option<(u16, SocketAddr)> {
    let line = line.trim().strip_prefix("SSH: ").unwrap_or(line.trim());
    let (local, remote) = line
        .strip_prefix("Forwarding from ")?
        .split_once(" to host port ")?;
    let local: SocketAddr = local.parse().ok()?;
    let remote: u16 = remote.strip_suffix('.').unwrap_or(remote).parse().ok()?;
    (local.ip().is_loopback() && local.port() != 0 && remote != 0).then_some((remote, local))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwarding_parser_requires_loopback_and_valid_ports() {
        assert_eq!(
            forwarding_line("SSH: Forwarding from 127.0.0.1:2223 to host port 2222."),
            Some((2222, "127.0.0.1:2223".parse().unwrap()))
        );
        assert_eq!(
            forwarding_line("Forwarding from [::1]:2300 to host port 2222."),
            Some((2222, "[::1]:2300".parse().unwrap()))
        );
        for text in [
            "Forwarding from 1.2.3.4:2223 to host port 2222.",
            "Forwarding from 127.0.0.1:0 to host port 2222.",
            "Forwarding from 127.0.0.1:2223 to host port 0.",
            "Forwarding from 127.0.0.1:2223 to host port 2222. evil",
        ] {
            assert_eq!(forwarding_line(text), None);
        }
    }

    #[tokio::test]
    async fn exact_port_conflicts_and_same_destination_reuses_listener() {
        let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = occupied.local_addr().unwrap().port();
        let (_, state) = watch::channel(Forwarding::default());
        let relays = Relays::default();
        assert!(
            ensure_relay(&relays, port, 2222, state.clone())
                .await
                .is_err()
        );
        let relay = Arc::new(spawn_relay(occupied, 2222, state.clone()));
        relays.lock().await.insert(port, Arc::downgrade(&relay));
        ensure_relay(&relays, port, 2222, state.clone())
            .await
            .unwrap();
        ensure_relay(&relays, port, 2222, state.clone())
            .await
            .unwrap();
        assert!(ensure_relay(&relays, port, 2223, state).await.is_err());
    }
    #[test]
    fn listening_parser_requires_explicit_readiness() {
        assert_eq!(
            listening_line("SSH: Forwarding from 127.0.0.1:2223 to host port 2222."),
            None
        );
        assert_eq!(
            listening_line("SSH: PortForwardingService listening on 127.0.0.1:2223."),
            Some("127.0.0.1:2223".parse().unwrap())
        );
        assert_eq!(
            listening_line("SSH: PortForwardingService also listening on ::1:2223."),
            Some("[::1]:2223".parse().unwrap())
        );
        assert_eq!(
            listening_line("SSH: PortForwardingService listening on 1.2.3.4:2223."),
            None
        );
    }

    #[test]
    fn lock_child() {
        let Some(path) = std::env::var_os("SSHDT_TEST_BROKER_LOCK") else {
            return;
        };
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        assert!(matches!(
            FileExt::try_lock(&file),
            Err(TryLockError::WouldBlock)
        ));
    }

    #[test]
    fn stable_lock_excludes_another_process() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("broker.lock");
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        FileExt::try_lock(&file).unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "devtunnel::client::tests::lock_child",
                "--nocapture",
            ])
            .env("SSHDT_TEST_BROKER_LOCK", &path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        drop(file);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        FileExt::try_lock(&file).unwrap();
    }

    async fn session(
        state: watch::Receiver<Forwarding>,
        relays: Relays,
        start: mpsc::Sender<u16>,
        version: u32,
        token: &str,
    ) -> (TcpStream, tokio::task::JoinHandle<Result<()>>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let task = tokio::spawn(async move {
            serve(
                server,
                "capability",
                state,
                relays,
                start,
                Leases::default(),
            )
            .await
        });
        ipc::send(
            &mut client,
            &ipc::Request {
                version,
                token: token.into(),
                remote_port: 2222,
                local_port: None,
            },
        )
        .await
        .unwrap();
        (client, task)
    }

    #[tokio::test]
    async fn canceled_pending_lease_does_not_cancel_another_stream() {
        use tokio::io::AsyncReadExt;
        let (state_tx, state) = watch::channel(Forwarding::default());
        let (start, mut starts) = mpsc::channel(8);
        let relays = Relays::default();
        let (canceled, canceled_task) = session(
            state.clone(),
            relays.clone(),
            start.clone(),
            ipc::VERSION,
            "capability",
        )
        .await;
        let (mut live, live_task) = session(state, relays, start, ipc::VERSION, "capability").await;
        starts.recv().await.unwrap();
        starts.recv().await.unwrap();
        drop(canceled);
        timeout(Duration::from_secs(1), canceled_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        state_tx.send_modify(|state| {
            state.ports.insert(2222, target.local_addr().unwrap());
        });
        let (mut destination, _) = target.accept().await.unwrap();
        destination.write_all(b"SSH-2.0-test\r\n").await.unwrap();
        let reply: ipc::Response = ipc::receive(&mut live).await.unwrap();
        assert!(reply.error.is_none());
        live.write_all(b"request").await.unwrap();
        live.shutdown().await.unwrap();
        let mut bytes = Vec::new();
        destination.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"request");
        destination.write_all(b"response after EOF").await.unwrap();
        destination.shutdown().await.unwrap();
        bytes.clear();
        live.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"SSH-2.0-test\r\nresponse after EOF");
        live_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn invalid_capability_and_version_never_start_connector() {
        let (_, state) = watch::channel(Forwarding::default());
        let (start, mut starts) = mpsc::channel(8);
        let (mut denied, task) = session(
            state.clone(),
            Relays::default(),
            start.clone(),
            ipc::VERSION,
            "wrong",
        )
        .await;
        assert!(task.await.unwrap().is_err());
        assert!(ipc::receive::<ipc::Response>(&mut denied).await.is_err());
        let (mut incompatible, task) = session(
            state,
            Relays::default(),
            start,
            ipc::VERSION + 1,
            "capability",
        )
        .await;
        let response: ipc::Response = ipc::receive(&mut incompatible).await.unwrap();
        assert!(response.error.unwrap().contains("incompatible"));
        assert!(task.await.unwrap().is_err());
        assert!(starts.try_recv().is_err());
    }
    #[test]
    fn stdio_child() {
        let Ok(address) = std::env::var("SSHDT_TEST_STDIO_ENDPOINT") else {
            return;
        };
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            stdio(TcpStream::connect(address).await.unwrap())
                .await
                .unwrap();
        });
    }

    #[test]
    fn remote_eof_exits_process_with_stdin_still_open() {
        use std::io::Write;
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "devtunnel::client::tests::stdio_child",
                "--nocapture",
            ])
            .env(
                "SSHDT_TEST_STDIO_ENDPOINT",
                listener.local_addr().unwrap().to_string(),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let _input = child.stdin.take().unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        stream.write_all(b"SSH-test").unwrap();
        stream.shutdown(std::net::Shutdown::Both).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("proxy process stayed alive after remote EOF");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    #[tokio::test(start_paused = true)]
    async fn idle_shutdown_and_new_leases_are_serialized() {
        let leases = Leases::default();
        let first = Lease::acquire(&leases).unwrap();
        tokio::time::advance(Duration::from_secs(10)).await;
        assert!(!begin_idle_shutdown(&leases));
        drop(first);
        tokio::time::advance(Duration::from_secs(4)).await;
        let second = Lease::acquire(&leases).unwrap();
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(!begin_idle_shutdown(&leases));
        drop(second);
        tokio::time::advance(Duration::from_secs(5)).await;
        assert!(begin_idle_shutdown(&leases));
        assert!(Lease::acquire(&leases).is_none());
    }

    #[tokio::test]
    async fn connector_failure_reaches_pending_proxy_as_an_error() {
        let (sender, state) = watch::channel(Forwarding::default());
        let (start, mut starts) = mpsc::channel(8);
        let (mut stream, task) =
            session(state, Relays::default(), start, ipc::VERSION, "capability").await;
        starts.recv().await.unwrap();
        sender.send_modify(|state| state.error = Some("connector exited".into()));
        let response: ipc::Response = ipc::receive(&mut stream).await.unwrap();
        assert_eq!(response.error.as_deref(), Some("connector exited"));
        assert!(task.await.unwrap().is_err());
    }
    #[tokio::test]
    async fn readiness_retries_and_preserves_the_actual_stream() {
        use tokio::io::AsyncReadExt;
        let (sender, state) = watch::channel(Forwarding::default());
        let (start, mut starts) = mpsc::channel(8);
        let (mut stream, task) =
            session(state, Relays::default(), start, ipc::VERSION, "capability").await;
        starts.recv().await.unwrap();
        let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        sender.send_modify(|state| {
            state.ports.insert(2222, target.local_addr().unwrap());
        });
        let (failed, _) = target.accept().await.unwrap();
        drop(failed);
        let (mut destination, _) = timeout(Duration::from_secs(2), target.accept())
            .await
            .unwrap()
            .unwrap();
        let mut byte = [0];
        assert!(
            timeout(Duration::from_millis(50), stream.peek(&mut byte))
                .await
                .is_err()
        );
        destination
            .write_all(b"notice\r\nSSH-2.0-ready\r\n")
            .await
            .unwrap();
        let response: ipc::Response = ipc::receive(&mut stream).await.unwrap();
        assert!(response.error.is_none());
        let mut prefix = vec![0; b"notice\r\nSSH-2.0-ready\r\n".len()];
        stream.read_exact(&mut prefix).await.unwrap();
        assert_eq!(prefix, b"notice\r\nSSH-2.0-ready\r\n");
        stream.write_all(b"client bytes").await.unwrap();
        let mut payload = [0; 12];
        destination.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"client bytes");
        drop(stream);
        drop(destination);
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
    #[tokio::test]
    async fn slow_banner_uses_request_deadline() {
        let (sender, state) = watch::channel(Forwarding::default());
        let (start, mut starts) = mpsc::channel(8);
        let (mut stream, task) =
            session(state, Relays::default(), start, ipc::VERSION, "capability").await;
        starts.recv().await.unwrap();
        let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        sender.send_modify(|state| {
            state.ports.insert(2222, target.local_addr().unwrap());
        });
        let (mut destination, _) = target.accept().await.unwrap();
        sleep(Duration::from_millis(2200)).await;
        let _ = destination.write_all(b"SSH-2.0-slow\r\n").await;
        let response = timeout(
            Duration::from_millis(500),
            ipc::receive::<ipc::Response>(&mut stream),
        )
        .await;
        task.abort();
        assert!(
            response.is_ok(),
            "slow valid banner was discarded before caller deadline"
        );
    }

    #[tokio::test]
    async fn dropping_last_relay_request_releases_port() {
        let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = occupied.local_addr().unwrap().port();
        let (_, state) = watch::channel(Forwarding::default());
        let relays = Relays::default();
        let relay = Arc::new(spawn_relay(occupied, 2222, state.clone()));
        relays.lock().await.insert(port, Arc::downgrade(&relay));
        let request = ensure_relay(&relays, port, 2222, state).await.unwrap();
        drop(relay);
        assert!(
            TcpListener::bind((Ipv4Addr::LOCALHOST, port))
                .await
                .is_err()
        );
        drop(request);
        tokio::task::yield_now().await;
        assert!(
            TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await.is_ok(),
            "relay port survives its final request"
        );
    }

    #[tokio::test]
    async fn canceled_fixed_port_request_releases_listener() {
        let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = occupied.local_addr().unwrap().port();
        let (_sender, state) = watch::channel(Forwarding::default());
        let relays = Relays::default();
        let relay = Arc::new(spawn_relay(occupied, 2222, state.clone()));
        relays.lock().await.insert(port, Arc::downgrade(&relay));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let (start, mut starts) = mpsc::channel(8);
        let task = tokio::spawn(serve(
            server,
            "capability",
            state,
            relays,
            start,
            Leases::default(),
        ));
        ipc::send(
            &mut client,
            &ipc::Request {
                version: ipc::VERSION,
                token: "capability".into(),
                remote_port: 2222,
                local_port: Some(port),
            },
        )
        .await
        .unwrap();
        starts.recv().await.unwrap();
        drop(relay);
        assert!(
            TcpListener::bind((Ipv4Addr::LOCALHOST, port))
                .await
                .is_err()
        );
        drop(client);
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        timeout(Duration::from_secs(1), async {
            loop {
                if TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await.is_ok() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("canceled request retained its relay listener");
    }
    #[tokio::test]
    async fn broker_owner_loss_interrupts_silent_response() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("broker.lock");
        let owner = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        FileExt::try_lock(&owner).unwrap();
        let probe = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert!(broker_lock_held(&probe).unwrap());
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let mut stream = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (_silent, _) = listener.accept().await.unwrap();
        let response = broker_response(&mut stream, &probe);
        tokio::pin!(response);
        assert!(
            timeout(Duration::from_millis(150), &mut response)
                .await
                .is_err()
        );
        drop(owner);
        assert!(
            timeout(Duration::from_secs(1), response)
                .await
                .unwrap()
                .is_err()
        );
        assert!(!broker_lock_held(&probe).unwrap());
    }
}
