use std::time::Duration;
use tokio::time::Instant;

pub(super) struct Retry {
    delay: Duration,
    ready_since: Option<Instant>,
}

impl Default for Retry {
    fn default() -> Self {
        Self {
            delay: Duration::from_secs(30),
            ready_since: None,
        }
    }
}

impl Retry {
    pub fn ready(&mut self) {
        self.ready_since.get_or_insert_with(Instant::now);
    }

    pub fn failed(&mut self) -> Duration {
        if self
            .ready_since
            .take()
            .is_some_and(|since| since.elapsed() >= Duration::from_secs(300))
        {
            self.delay = Duration::from_secs(30);
        }
        let delay = self.delay;
        self.delay = (delay * 2).min(Duration::from_secs(300));
        delay
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn repeated_failures_back_off_and_brief_readiness_does_not_reset() {
        let mut retry = Retry::default();
        for seconds in [30, 60, 120, 240, 300, 300] {
            retry.ready();
            tokio::time::advance(Duration::from_secs(1)).await;
            assert_eq!(retry.failed(), Duration::from_secs(seconds));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn only_continuous_stable_readiness_resets_backoff() {
        let mut retry = Retry::default();
        assert_eq!(retry.failed(), Duration::from_secs(30));
        tokio::time::advance(Duration::from_secs(120)).await;
        assert_eq!(retry.failed(), Duration::from_secs(60));
        retry.ready();
        tokio::time::advance(Duration::from_secs(299)).await;
        assert_eq!(retry.failed(), Duration::from_secs(120));
        retry.ready();
        tokio::time::advance(Duration::from_secs(300)).await;
        retry.ready();
        assert_eq!(retry.failed(), Duration::from_secs(30));
        assert_eq!(retry.failed(), Duration::from_secs(60));
    }
}
