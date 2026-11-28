use std::time::Duration;
use tokio::time::Instant;

// The devtunnel CLI can stay alive after a failed relay reconnect, so its exit is not
// the only sign of a dead tunnel.
pub(super) struct RelayWatch {
    grace: Duration,
    deadline: Option<Instant>,
}

impl RelayWatch {
    pub fn new(grace: Duration) -> Self {
        Self {
            grace,
            deadline: None,
        }
    }

    pub fn observe(&mut self, line: &str) {
        if line.contains("Connection to host tunnel relay closed") {
            self.deadline
                .get_or_insert_with(|| Instant::now() + self.grace);
        } else if line.contains("Connection to host tunnel relay restored")
            || line.contains("Ready to accept connections for tunnel:")
        {
            self.deadline = None;
        }
    }

    pub async fn lost(&self) {
        match self.deadline {
            Some(deadline) => tokio::time::sleep_until(deadline).await,
            None => std::future::pending().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLOSED: &str = "Connection to host tunnel relay closed. Connection lost.. Reconnecting.";
    const GRACE: Duration = Duration::from_secs(30);

    async fn lost_within(watch: &RelayWatch, wait: Duration) -> bool {
        tokio::time::timeout(wait, watch.lost()).await.is_ok()
    }

    #[tokio::test(start_paused = true)]
    async fn connected_relay_is_never_lost() {
        let mut watch = RelayWatch::new(GRACE);
        watch.observe("Hosting port: 22");
        assert!(!lost_within(&watch, GRACE * 10).await);
    }

    #[tokio::test(start_paused = true)]
    async fn unrestored_relay_is_lost_after_the_grace_period() {
        let mut watch = RelayWatch::new(GRACE);
        watch.observe(CLOSED);
        watch.observe("Refreshing tunnel.");
        assert!(!lost_within(&watch, GRACE - Duration::from_secs(1)).await);
        assert!(lost_within(&watch, Duration::from_secs(2)).await);
    }

    #[tokio::test(start_paused = true)]
    async fn restored_or_ready_relay_is_not_lost() {
        for recovered in [
            "Connection to host tunnel relay restored.",
            "Ready to accept connections for tunnel: sshdt-machine1.usw2",
        ] {
            let mut watch = RelayWatch::new(GRACE);
            watch.observe(CLOSED);
            watch.observe(recovered);
            assert!(!lost_within(&watch, GRACE * 10).await);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn repeated_close_keeps_the_first_deadline() {
        let mut watch = RelayWatch::new(GRACE);
        watch.observe(CLOSED);
        tokio::time::advance(GRACE - Duration::from_secs(1)).await;
        watch.observe(CLOSED);
        assert!(lost_within(&watch, Duration::from_secs(2)).await);
    }
}
