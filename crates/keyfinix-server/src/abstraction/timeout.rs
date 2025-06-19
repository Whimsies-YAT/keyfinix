use std::{
    future::Future,
    pin::Pin,
    sync::{atomic::AtomicU32, Arc},
    task::ready,
    time::Duration,
};

#[derive(Clone)]
/// A handle to reset the API timeout
pub struct ResettableTimeoutHandle {
    renewal_millis: Arc<AtomicU32>,
}

/// A future that can be reset with a new timeout
pub struct ResettableTimeout<F: Future> {
    renewal_handle: ResettableTimeoutHandle,
    inner: F,
    sleep: tokio::time::Sleep,
}

impl<F: Future> ResettableTimeout<F> {
    /// Create a new `ResettableTimeout`
    pub fn new(inner: F, duration: Duration, handle: ResettableTimeoutHandle) -> Self {
        Self {
            renewal_handle: handle,
            inner,
            sleep: tokio::time::sleep(duration),
        }
    }
}

impl ResettableTimeoutHandle {
    /// Create a new `ResettableTimeoutHandle`
    #[must_use]
    pub fn new(duration: Duration) -> Self {
        Self {
            #[allow(clippy::cast_possible_truncation)]
            renewal_millis: Arc::new(AtomicU32::new(duration.as_millis() as u32)),
        }
    }
}

impl ResettableTimeoutHandle {
    /// Renew the timeout by adding the given duration to the current timeout in milliseconds
    pub fn renew(&self, millis: u32) {
        self.renewal_millis
            .store(millis, std::sync::atomic::Ordering::Relaxed);
    }

    fn take(&self) -> u32 {
        self.renewal_millis
            .swap(0, std::sync::atomic::Ordering::Relaxed)
    }
}

impl<F: Future> Future for ResettableTimeout<F> {
    type Output = Option<F::Output>;
    fn poll(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<F::Output>> {
        #[allow(unsafe_code)]
        unsafe {
            let this = Pin::get_unchecked_mut(self);

            match Pin::new_unchecked(&mut this.sleep).poll(cx) {
                // notified, try to see if we have renewal available
                std::task::Poll::Ready(()) => {
                    let renewal = this.renewal_handle.take();
                    if renewal != 0 {
                        let new_deadline =
                            this.sleep.deadline() + Duration::from_millis(u64::from(renewal));
                        Pin::new_unchecked(&mut this.sleep).reset(new_deadline);

                        // poll the sleep again to make it aware of the new deadline
                        ready!(Pin::new_unchecked(&mut this.sleep).poll(cx));
                    } else {
                        return std::task::Poll::Ready(None);
                    }
                }
                std::task::Poll::Pending => {}
            }

            // poll the inner future
            Pin::new_unchecked(&mut this.inner).poll(cx).map(Some)
        }
    }
}
