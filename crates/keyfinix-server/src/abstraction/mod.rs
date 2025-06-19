use std::{
    future::Future,
    ops::Deref,
    sync::{Arc, atomic::AtomicBool},
};

use sea_orm::DatabaseConnection;
use tokio::sync::RwLock;
use tracing::{Instrument, info_span, warn, warn_span};

/// Reusable metrics
pub mod metrics;
/// Stream utilities
pub mod stream;

/// An async backpressure mechanism
pub mod backpressure;

/// Sharded data structures
pub mod sharded;

/// Timeout utilities
pub mod timeout;

/// Shutdown utilities
pub mod shutdown;

/// Time utilities
pub mod time;

#[macro_export]
#[cfg(feature = "large-scale")]
/// Select between a smaller and larger value based on the targeted deployment scale
macro_rules! select_by_scale {
    ($norm:expr => $more:expr) => {
        $more
    };
}

#[macro_export]
#[cfg(not(feature = "large-scale"))]
/// Select between a smaller and larger value based on the targeted deployment scale
macro_rules! select_by_scale {
    ($norm:expr => $more:expr) => {
        $norm
    };
}

/// A finally block that runs when the object is dropped
pub struct Finally<T, F: FnOnce(Option<T>)> {
    inner: Option<F>,
    _phantom: std::marker::PhantomData<T>,
}

impl<T, F: FnOnce(Option<T>)> Finally<T, F> {
    /// Create a new finally block
    pub fn new(inner: F) -> Self {
        Self {
            inner: Some(inner),
            _phantom: std::marker::PhantomData,
        }
    }

    /// Trigger the finally block early
    pub fn trigger(&mut self, value: Option<T>) {
        if let Some(f) = self.inner.take() {
            f(value);
        }
    }
}

impl<T, F: FnOnce(Option<T>)> Drop for Finally<T, F> {
    fn drop(&mut self) {
        if let Some(f) = self.inner.take() {
            f(None);
        }
    }
}

/// A backoff strategy
pub trait Backoff {
    /// Return the duration to wait before the next try, or None if the operation should be aborted
    fn next_try(&self, count: u32) -> Option<std::time::Duration>;
}

/// Something that can be health checked
pub trait HealthCheck {
    /// The error type
    type Error: std::error::Error + Send + Sync;
    /// Perform a health check
    fn health_check(&self) -> impl Future<Output = Result<bool, Self::Error>> + Send;
}

impl HealthCheck for DatabaseConnection {
    type Error = sea_orm::error::DbErr;
    fn health_check(&self) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        let conn = self.clone();
        async move {
            match conn.ping().await {
                Ok(()) => Ok(true),
                Err(e) => {
                    warn!("Database connection unhealthy: {}", e);
                    Ok(false)
                }
            }
        }
    }
}

/// A resource that need to be manually renewed
pub trait KeepAlivable: Send {
    /// The value type of the resource
    type Value: HealthCheck + Send + Sync;
    /// The error type that occurs during resource initialization
    type Error: Backoff + Send + std::error::Error + From<<Self::Value as HealthCheck>::Error>;

    /// The name of the resource
    fn name(&self) -> &str;
    /// The interval between health checks
    fn health_check_interval(&self) -> std::time::Duration;
    /// Initialize the resource
    fn initialize(&self) -> impl Future<Output = Result<Self::Value, Self::Error>> + Send;
}

/// A keepalive loop for a resource
pub struct KeepAlive<T: KeepAlivable> {
    proto: T,
    health_flag: Option<Arc<AtomicBool>>,
    resource: Arc<RwLock<T::Value>>,
}

impl<T: KeepAlivable + Clone> Clone for KeepAlive<T> {
    fn clone(&self) -> Self {
        Self {
            proto: self.proto.clone(),
            health_flag: self.health_flag.clone(),
            resource: self.resource.clone(),
        }
    }
}

impl<T: KeepAlivable + 'static> KeepAlive<T> {
    /// Get the prototype   
    pub fn proto(&self) -> &T {
        &self.proto
    }
    /// Create a new keepalive instance
    pub async fn new(proto: T, health_flag: Option<Arc<AtomicBool>>) -> Result<Self, T::Error> {
        let resource = Arc::new(RwLock::new(
            proto
                .initialize()
                .instrument(info_span!("keepalive_initialization", name = %proto.name()))
                .await?,
        ));

        Ok(Self {
            proto,
            health_flag,
            resource,
        })
    }
    /// Get an instance of the resource
    pub async fn get(&self) -> impl Deref<Target = T::Value> + '_ {
        self.resource.read().await
    }
    /// Start the keepalive loop
    pub async fn keepalive_loop(&self) -> Result<(), T::Error> {
        let name = self.proto.name().to_string();
        let interval = self.proto.health_check_interval();
        loop {
            if let Err(e) = self.resource.read().await.health_check().await {
                if let Some(flag) = self.health_flag.as_ref() {
                    flag.store(false, std::sync::atomic::Ordering::SeqCst);
                }
                warn_span!("Resource unhealthy", name  = %self.proto.name(), err = ?e).in_scope(
                    || {
                        warn!("Resource unhealthy");
                    },
                );

                let mut resource = self.resource.write().await;

                let mut failures = 0;
                loop {
                    match self
                        .proto
                        .initialize()
                        .instrument(
                            info_span!("Resource reinitialization", name = %self.proto.name()),
                        )
                        .await
                    {
                        Ok(new_resource) => {
                            *resource = new_resource;
                            break;
                        }
                        Err(err) => {
                            failures += 1;
                            if let Some(duration) = err.next_try(failures) {
                                tokio::time::sleep(duration).await;
                            } else {
                                warn_span!("Resource initialization failed", name = %name)
                                    .in_scope(|| {
                                        warn!("Resource initialization failed");
                                    });
                                break;
                            }
                        }
                    }
                }
            } else if let Some(flag) = self.health_flag.as_ref() {
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
            }

            tokio::time::sleep(interval).await;
        }
    }
}
