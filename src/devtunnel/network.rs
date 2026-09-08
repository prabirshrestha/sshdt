use std::time::Duration;
use tokio::{sync::watch, time::Instant};

const SETTLE_TIME: Duration = Duration::from_secs(2);
const EARLY_RETRY_INTERVAL: Duration = Duration::from_secs(30);

pub(super) struct NetworkChanges {
    events: Option<watch::Receiver<Instant>>,
    pending: Option<Instant>,
    next_allowed: Instant,
    #[cfg(windows)]
    _registration: Option<windows::Registration>,
}

impl NetworkChanges {
    pub fn new() -> Self {
        let mut watcher = Self {
            events: None,
            pending: None,
            next_allowed: Instant::now(),
            #[cfg(windows)]
            _registration: None,
        };
        #[cfg(windows)]
        match windows::Registration::new() {
            Ok((registration, events)) => {
                watcher.events = Some(events);
                watcher._registration = Some(registration);
            }
            Err(error) => {
                tracing::warn!(%error, "Network change watcher unavailable; using timed retries")
            }
        }
        watcher.begin_wait();
        watcher
    }

    pub fn begin_wait(&mut self) {
        self.pending = None;
        if let Some(events) = &mut self.events {
            events.borrow_and_update();
        }
    }

    pub async fn wait_until(&mut self, deadline: Instant) -> bool {
        loop {
            let early_at = self
                .pending
                .map(|at| (at + SETTLE_TIME).max(self.next_allowed));
            let wake_at = early_at.unwrap_or(deadline).min(deadline);
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(deadline) => return false,
                event = async {
                    match &mut self.events {
                        Some(events) => {
                            events.changed().await.ok()?;
                            Some(*events.borrow_and_update())
                        }
                        None => std::future::pending().await,
                    }
                } => match event {
                    Some(at) => self.pending = Some(at),
                    None => self.events = None,
                },
                _ = tokio::time::sleep_until(wake_at), if early_at.is_some() => {
                    self.pending = None;
                    self.next_allowed = Instant::now() + EARLY_RETRY_INTERVAL;
                    return true;
                }
            }
        }
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::{ffi::c_void, io, ptr};
    use windows_sys::Win32::{
        Foundation::HANDLE,
        NetworkManagement::IpHelper::{
            CancelMibChangeNotify2, MIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE,
            NotifyIpInterfaceChange,
        },
        Networking::WinSock::AF_UNSPEC,
    };

    pub(super) struct Registration {
        // Windows permits cancellation from another thread. The value is an opaque handle.
        handle: usize,
        context: Option<Box<watch::Sender<Instant>>>,
    }

    impl Registration {
        pub fn new() -> io::Result<(Self, watch::Receiver<Instant>)> {
            let (sender, receiver) = watch::channel(Instant::now());
            let context = Box::new(sender);
            let mut handle = ptr::null_mut();
            // The boxed context stays at this address until callbacks have been cancelled.
            let error = unsafe {
                NotifyIpInterfaceChange(
                    AF_UNSPEC,
                    Some(changed),
                    (&*context as *const watch::Sender<Instant>).cast(),
                    false,
                    &mut handle,
                )
            };
            if error != 0 {
                return Err(io::Error::from_raw_os_error(error as i32));
            }
            Ok((
                Self {
                    handle: handle as usize,
                    context: Some(context),
                },
                receiver,
            ))
        }
    }

    unsafe extern "system" fn changed(
        context: *const c_void,
        _row: *const MIB_IPINTERFACE_ROW,
        _notification: MIB_NOTIFICATION_TYPE,
    ) {
        // Registration owns the context and cancellation waits for callbacks to finish.
        let _ = std::panic::catch_unwind(|| {
            let sender = unsafe { &*context.cast::<watch::Sender<Instant>>() };
            let _ = sender.send(Instant::now());
        });
    }

    impl Drop for Registration {
        fn drop(&mut self) {
            // This runs outside the callback, as required by CancelMibChangeNotify2.
            let error = unsafe { CancelMibChangeNotify2(self.handle as HANDLE) };
            if error != 0 {
                if let Some(context) = self.context.take() {
                    Box::leak(context);
                }
                tracing::warn!(
                    error,
                    "Cannot cancel network watcher; retaining callback context"
                );
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn registration_can_be_cancelled_from_another_thread() {
            let (registration, _events) = Registration::new().unwrap();
            std::thread::spawn(move || drop(registration))
                .join()
                .unwrap();
        }

        #[tokio::test(start_paused = true)]
        async fn registered_callback_wakes_retry_after_settling() {
            let (registration, events) = Registration::new().unwrap();
            let mut watcher = NetworkChanges {
                events: Some(events),
                pending: None,
                next_allowed: Instant::now(),
                _registration: Some(registration),
            };
            watcher.begin_wait();
            let context = watcher
                ._registration
                .as_ref()
                .unwrap()
                .context
                .as_deref()
                .unwrap() as *const watch::Sender<Instant>;
            let started = Instant::now();
            let wait = watcher.wait_until(started + Duration::from_secs(60));
            tokio::pin!(wait);
            assert!(futures_util::poll!(&mut wait).is_pending());
            // Registration remains owned by the pending wait until the callback returns.
            unsafe {
                changed(context.cast(), ptr::null(), 0);
            }
            assert!(wait.await);
            assert_eq!(started.elapsed(), SETTLE_TIME);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::task::Poll;

    fn watcher() -> (watch::Sender<Instant>, NetworkChanges) {
        let (sender, receiver) = watch::channel(Instant::now());
        let watcher = NetworkChanges {
            events: Some(receiver),
            pending: None,
            next_allowed: Instant::now(),
            #[cfg(windows)]
            _registration: None,
        };
        (sender, watcher)
    }

    #[tokio::test(start_paused = true)]
    async fn fresh_changes_debounce_without_extending_the_retry_deadline() {
        let (events, mut watcher) = watcher();
        watcher.begin_wait();
        let started = Instant::now();
        events.send(Instant::now()).unwrap();
        let wait = watcher.wait_until(started + Duration::from_secs(60));
        tokio::pin!(wait);
        assert!(matches!(futures_util::poll!(&mut wait), Poll::Pending));
        tokio::time::advance(Duration::from_secs(1)).await;
        events.send(Instant::now()).unwrap();
        assert!(matches!(futures_util::poll!(&mut wait), Poll::Pending));
        assert!(wait.await);
        assert_eq!(started.elapsed(), Duration::from_secs(3));
    }

    #[tokio::test(start_paused = true)]
    async fn changes_during_failed_startup_are_kept_for_the_retry_wait() {
        let (events, mut watcher) = watcher();
        watcher.begin_wait();
        let started = Instant::now();
        tokio::time::advance(Duration::from_secs(10)).await;
        events.send(Instant::now()).unwrap();
        tokio::time::advance(Duration::from_secs(10)).await;
        assert!(watcher.wait_until(started + Duration::from_secs(60)).await);
        assert_eq!(started.elapsed(), Duration::from_secs(20));
    }

    #[tokio::test(start_paused = true)]
    async fn stale_changes_and_closed_sources_keep_the_retry_deadline() {
        let (events, mut watcher) = watcher();
        events.send(Instant::now()).unwrap();
        watcher.begin_wait();
        let started = Instant::now();
        assert!(!watcher.wait_until(started + Duration::from_secs(60)).await);
        assert_eq!(started.elapsed(), Duration::from_secs(60));
        drop(events);
        assert!(!watcher.wait_until(started + Duration::from_secs(120)).await);
        assert_eq!(started.elapsed(), Duration::from_secs(120));
    }

    #[tokio::test(start_paused = true)]
    async fn event_bursts_cannot_postpone_the_retry_deadline() {
        let (events, mut watcher) = watcher();
        watcher.begin_wait();
        let started = Instant::now();
        events.send(Instant::now()).unwrap();
        assert!(!watcher.wait_until(started + Duration::from_secs(1)).await);
        assert_eq!(started.elapsed(), Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_keeps_debounce_and_cooldown_state() {
        let (events, mut watcher) = watcher();
        watcher.begin_wait();
        let started = Instant::now();
        events.send(Instant::now()).unwrap();
        {
            let wait = watcher.wait_until(started + Duration::from_secs(60));
            tokio::pin!(wait);
            assert!(matches!(futures_util::poll!(&mut wait), Poll::Pending));
        }
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(watcher.wait_until(started + Duration::from_secs(60)).await);
        assert_eq!(started.elapsed(), Duration::from_secs(2));
        watcher.begin_wait();
        events.send(Instant::now()).unwrap();
        assert!(watcher.wait_until(started + Duration::from_secs(60)).await);
        assert_eq!(started.elapsed(), Duration::from_secs(32));
    }

    #[tokio::test(start_paused = true)]
    async fn beginning_another_wait_discards_a_cancelled_pending_change() {
        let (events, mut watcher) = watcher();
        watcher.begin_wait();
        let started = Instant::now();
        events.send(Instant::now()).unwrap();
        {
            let wait = watcher.wait_until(started + Duration::from_secs(60));
            tokio::pin!(wait);
            assert!(matches!(futures_util::poll!(&mut wait), Poll::Pending));
        }
        watcher.begin_wait();
        assert!(!watcher.wait_until(started + Duration::from_secs(60)).await);
        assert_eq!(started.elapsed(), Duration::from_secs(60));
    }

    #[cfg(not(windows))]
    #[tokio::test(start_paused = true)]
    async fn unsupported_platform_uses_only_the_timer() {
        let mut watcher = NetworkChanges::new();
        let started = Instant::now();
        assert!(!watcher.wait_until(started + Duration::from_secs(60)).await);
        assert_eq!(started.elapsed(), Duration::from_secs(60));
    }
}
