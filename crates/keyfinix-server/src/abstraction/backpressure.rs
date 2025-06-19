use std::{
    future::Future,
    num::NonZeroU32,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};

use futures::future::FutureExt;

use tokio::sync::{Semaphore, SemaphorePermit};

#[derive(Clone)]
/// A backpressure mechanism that limits the number of concurrent operations
pub struct Backpressure {
    hard_limit: NonZeroU32,

    inner: Arc<BackpressureInner>,
}

struct BackpressureInner {
    soft: Semaphore,
    in_use: AtomicU32,
}

struct BackPressureDropHelper(Arc<BackpressureInner>);

impl Drop for BackPressureDropHelper {
    fn drop(&mut self) {
        self.0.in_use.fetch_sub(1, Ordering::Relaxed);
    }
}

#[ouroboros::self_referencing]
pub struct BackPressureGuard {
    backpressure: BackPressureDropHelper,

    #[borrows(backpressure)]
    #[covariant]
    permit: SemaphorePermit<'this>,
}

impl BackPressureGuard {
    async fn create(bp: Arc<BackpressureInner>) -> Self {
        BackPressureGuardAsyncSendBuilder {
            backpressure: BackPressureDropHelper(bp),
            permit_builder: |bp| bp.0.soft.acquire().map(|r| r.unwrap()).boxed(),
        }
        .build()
        .await
    }
}

impl Backpressure {
    /// Create a new backpressure mechanism
    ///
    /// # Arguments
    ///
    /// * `soft_limit` - The soft limit of the backpressure mechanism, requests will be queued if this limit is reached
    /// * `hard_limit` - The hard limit of the backpressure mechanism, requests will be rejected if this limit is reached
    #[must_use]
    pub fn new(soft_limit: NonZeroU32, hard_limit: NonZeroU32) -> Self {
        Self {
            hard_limit,
            inner: Arc::new(BackpressureInner {
                soft: Semaphore::new(soft_limit.get() as usize),
                in_use: AtomicU32::new(0),
            }),
        }
    }

    /// Check if the backpressure mechanism is fresh state
    pub fn fresh(&mut self) -> bool {
        self.inner.in_use.load(Ordering::SeqCst) == 0
    }

    /// Get a backpressure guard, returns None if the hard limit is reached
    #[must_use]
    pub fn acquire(&self) -> Option<impl Future<Output = BackPressureGuard> + Send + use<>> {
        let in_use = self
            .inner
            .in_use
            .fetch_add(1, Ordering::SeqCst)
            .saturating_add(1);

        if in_use > self.hard_limit.get() {
            self.inner.in_use.fetch_sub(1, Ordering::Relaxed);
            return None;
        }

        Some(BackPressureGuard::create(self.inner.clone()))
    }
}
