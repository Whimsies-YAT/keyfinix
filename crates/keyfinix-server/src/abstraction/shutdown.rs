use std::{
    collections::HashMap,
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicU32, AtomicUsize},
    },
};

use futures::future::BoxFuture;
use tokio::sync::{Mutex, RwLock, oneshot};
use tracing::{event, instrument};

/// The level of shutdown
pub type ShutdownLevel = u32;

/// No warning
pub const SHUTDOWN_LEVEL_NONE: u32 = 0;
/// The first warning
pub const SHUTDOWN_LEVEL_ONE: u32 = 1;
/// The second warning
pub const SHUTDOWN_LEVEL_TWO: u32 = 2;
/// The last warning before the final shutdown
pub const SHUTDOWN_LEVEL_LAST_WARNING: u32 = SHUTDOWN_LEVEL_TWO;
/// The final shutdown for internal tracking, handler will not be notified
const SHUTDOWN_LEVEL_FORCED: u32 = u32::MAX;

/// Something that can handle shutdown signals
pub trait ShutdownHandler: Send + Sync {
    /// The name of the handler for tracing and logging purposes
    fn name(&self) -> &'static str;

    /// Return after the shutdown is complete, we will call this shortly after the handler is added
    fn wait(&self) -> BoxFuture<'static, Result<(), Box<dyn std::error::Error + Send + Sync>>>;

    /// Signal the handler to shutdown, you must minimize blocking operations here
    fn signal(&self, level: ShutdownLevel) -> BoxFuture<'_, ()>;
}

/// A handler that listens for Ctrl-C and sends a shutdown signal
pub async fn ctrlc_handler(shutdown: Arc<ShutdownManager>) {
    loop {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to listen for Ctrl-C");
        shutdown.trigger().await;
    }
}

#[cfg(target_family = "unix")]
/// A handler that listens for SIGTERM and sends a shutdown signal
pub fn sigterm_handler(shutdown: Arc<ShutdownManager>) -> impl Future<Output = ()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut term = signal(SignalKind::terminate()).expect("Failed to listen for SIGTERM");

    async move {
        loop {
            term.recv().await;
            shutdown.trigger().await;
        }
    }
}

/// A manager for graceful shutdown
pub struct ShutdownManager {
    errors: Arc<Mutex<HashMap<String, Box<dyn std::error::Error + Send + Sync>>>>,
    shutdown_rx: Mutex<Option<oneshot::Receiver<()>>>,
    // This has multiple ways to trigger so we need to lock it properly
    shutdown_tx: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    pending: Arc<AtomicUsize>,
    current_level: AtomicU32,
    handlers: RwLock<Vec<Arc<dyn ShutdownHandler>>>,
}

impl Default for ShutdownManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ShutdownManager {
    /// Create a new shutdown manager
    pub fn new() -> Self {
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        Self {
            errors: Arc::new(Mutex::new(HashMap::new())),
            shutdown_rx: Mutex::new(Some(shutdown_rx)),
            shutdown_tx: Arc::new(Mutex::new(Some(shutdown_tx))),
            // Start with 1 to account for the self trigger (whether there is a shutdown request or not)
            pending: Arc::new(AtomicUsize::new(1)),
            current_level: AtomicU32::new(0),
            handlers: RwLock::new(Vec::new()),
        }
    }

    /// Add a shutdown handler
    pub async fn add_handler(&self, handler: Arc<dyn ShutdownHandler>) {
        self.pending
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let waiter = handler.wait();
        let pending = Arc::clone(&self.pending);
        let name = handler.name();
        let done = Arc::clone(&self.shutdown_tx);
        let errors = Arc::clone(&self.errors);
        self.handlers.write().await.push(handler);

        tokio::spawn(async move {
            if let Err(e) = waiter.await {
                event!(
                    tracing::Level::ERROR,
                    handler = name,
                    error = %e,
                    "Error while waiting for graceful shutdown handler"
                );

                errors.lock().await.insert(name.to_string(), e);
            }
            let original_pending = pending.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            event!(
                tracing::Level::DEBUG,
                handler = name,
                pending = original_pending - 1,
                "Received confirmation from graceful shutdown handler"
            );
            if original_pending == 1 {
                event!(
                    tracing::Level::INFO,
                    last_handler = name,
                    "All graceful shutdown handlers completed successfully"
                );
                done.lock().await.take().map(|tx| tx.send(()));
            }
        });
    }

    /// The number of pending handlers
    pub fn pending(&self) -> usize {
        self.pending.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The current level of shutdown
    pub fn current_level(&self) -> u32 {
        self.current_level.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Add an error to the shutdown manager
    pub async fn force_trigger(&self) {
        let span = tracing::span!(tracing::Level::DEBUG, "shutdown_force_trigger");
        let _guard = span.enter();
        event!(
            tracing::Level::WARN,
            level = SHUTDOWN_LEVEL_FORCED,
            pending = self.pending(),
            "Forcing shutdown"
        );

        self.current_level
            .store(SHUTDOWN_LEVEL_FORCED, std::sync::atomic::Ordering::SeqCst);
        self.shutdown_tx.lock().await.take().map(|tx| tx.send(()));
    }

    #[instrument(name = "shutdown_trigger", skip(self))]
    /// Trigger a shutdown, incrementing the level
    pub async fn trigger(&self) {
        if self
            .current_level
            .compare_exchange(
                SHUTDOWN_LEVEL_LAST_WARNING,
                SHUTDOWN_LEVEL_FORCED,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            )
            .is_ok()
        {
            self.force_trigger().await;
            return;
        }

        let level = self
            .current_level
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        event!(
            tracing::Level::INFO,
            level = level,
            pending = self.pending(),
            "Shutdown triggered"
        );

        // This is the self trigger
        if level == 1 {
            self.pending
                .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        }

        for handler in self.handlers.read().await.iter() {
            let _ = handler.signal(level).await;
        }
    }

    #[instrument(name = "shutdown_notifier", skip(self))]
    /// Wait for the shutdown to complete
    pub async fn wait(
        &self,
    ) -> Result<(), HashMap<String, Box<dyn std::error::Error + Send + Sync>>> {
        event!(
            tracing::Level::INFO,
            "Blocking until all services has shutdown"
        );
        let _ = self
            .shutdown_rx
            .try_lock()
            .expect("Cannot lock shutdown_rx, did you call wait() from multiple places?")
            .take()
            .unwrap()
            .await;

        let errors = self.errors.lock().await.drain().collect::<HashMap<_, _>>();
        event!(
            tracing::Level::INFO,
            level = self.current_level.load(std::sync::atomic::Ordering::SeqCst),
            "Shutdown complete",
        );

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}
