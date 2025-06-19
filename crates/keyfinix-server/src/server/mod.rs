use std::{
    fmt::Debug,
    marker::PhantomData,
    net::{SocketAddr, TcpListener},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use crate::{
    abstraction::{
        shutdown::{ShutdownHandler, ShutdownLevel, ShutdownManager},
        time::{ClockSet, NormalClock},
    },
    http::InfallibleUnwrap,
    service::{
        DefaultTypeRegistry, Registry, ServiceInitError, TypeRegistry,
        concurrency_limit::ConcurrencyLimitMap,
        key_store::{KeyStoreInit, kiyoka::KiyokaInit},
        service_init,
    },
};
use axum::{
    BoxError, Extension, Router,
    body::{Body, Bytes},
    extract::connect_info::{Connected, IntoMakeServiceWithConnectInfo},
};
use axum_server::{
    accept::{Accept, DefaultAcceptor},
    service::MakeService,
    tls_rustls::RustlsAcceptor,
};
use futures::{FutureExt, future::BoxFuture};
use http::HeaderName;
use hyper::Response;
use keyfinix_sandboxing::Sandboxing;
use rustls::{crypto::CryptoProvider, pki_types::InvalidDnsNameError};
use secrecy::SecretString;
use tls::{KeyLoader, ServerKeyRouter};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::Mutex,
    sync::oneshot,
};
use tower::Service;
use tracing::{Instrument, Level, event, instrument, span};
use x509_parser::error::X509Error;

use crate::{abstraction::metrics::add_tokio_metrics, config::Config};

pub const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

/// TLS configuration
pub mod tls;

/// Server router
pub mod router;

pub(crate) type GlobalConcurrencyLimit = ConcurrencyLimitMap<(), 128_usize>;

#[derive(Debug)]
/// All the information needed to initialize a reproducible server instance.
///
/// This should work with or without a tokio reactor running.
///
/// Try not to panic here for logical errors to avoid test aborting.
///
/// This does not involve starting a socket listener, but to provide a way to make a "pure" server suitable for testing and benchmarking.
pub struct ServerInit<S: Sandboxing> {
    sandbox: <S as Sandboxing>::Init,
    config: Box<Config>,
    tls: Option<Arc<ServerKeyRouter>>,
}

#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
#[non_exhaustive]
/// Errors that can occur during server initialization.
pub enum ServerInitError {
    #[error("No TLS backend is configured, implementor: set key loader")]
    NoKeyLoader,
    #[error("Failed to read file specified in the configuration")]
    IO(#[from] std::io::Error),
    #[error("The private key is missing")]
    NoPrivateKey,
    #[error("Failed to parse the private key: {0}")]
    PrivateKey(String),
    #[error("Failed to parse the PEM file: {0}")]
    Pem(pem_rfc7468::Error),
    #[error("Failed to load the private key")]
    KeyLoad(#[from] rustls::Error),
    #[error("No TLS certificates presented")]
    NoCertificates,
    #[error("Failed to parse the X509 certificate: {0}")]
    X509Parse(#[from] x509_parser::nom::Err<X509Error>),
    #[error("Failed to parse the X509 certificate: {0}")]
    X509(#[from] X509Error),
    #[error("Failed to parse the DNS name in certificate: {0}")]
    DNSName(#[from] InvalidDnsNameError),
    #[error("The certificate does not contain any Subject Alternative Name")]
    MissingSAN,
}

impl<S: Sandboxing> ServerInit<S> {
    /// Create a new server instance.
    ///
    /// This happens before the privileges are dropped.
    pub fn new(
        config: Box<Config>,
        key_loader: &impl KeyLoader,
        sandbox: <S as Sandboxing>::Init,
    ) -> Result<Self, ServerInitError> {
        let tls = config
            .http_listen
            .tls
            .as_ref()
            .map(|l| {
                let mut router = ServerKeyRouter::new(key_loader, l)?;
                for alt in &l.alternatives {
                    router.add_sni(key_loader, alt)?;
                }
                Ok::<_, ServerInitError>(router)
            })
            .transpose()?
            .map(Arc::new);

        Ok(Self {
            config,
            tls,
            sandbox,
        })
    }
}

/// A server instance.
pub struct Server<T: TypeRegistry> {
    done_tx: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    done_rx: Mutex<Option<oneshot::Receiver<()>>>,
    ms: IntoMakeServiceWithConnectInfo<Router, SocketAddr>,
    handle: axum_server::Handle,

    reg: Arc<Registry<T>>,
    tls: Option<Arc<ServerKeyRouter>>,

    _marker: PhantomData<T>,
}

impl<T: TypeRegistry> Debug for Server<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server").finish()
    }
}

impl<S: Sandboxing> Server<DefaultTypeRegistry<S>> {
    /// Initialize a new server instance.
    pub async fn new(
        mut init: ServerInit<S>,
        provider: Arc<CryptoProvider>,
        shutdown: Arc<ShutdownManager>,
    ) -> Result<Self, ServiceInitError> {
        let key_init = tokio::task::block_in_place(|| {
            KiyokaInit::prekey_from_passphrase(std::mem::replace(
                &mut init.config.security.secret,
                SecretString::new("".into()),
            ))
        });

        let tls = init.tls;

        let config = Arc::new(*init.config);

        let registry = Arc::new(
            service_init(
                NormalClock,
                config.clone(),
                provider,
                key_init,
                init.sandbox.clone(),
            )
            .await?,
        );

        #[cfg(feature = "metrics")]
        {
            add_tokio_metrics(registry.metrics());
            registry
                .db()
                .proto()
                .metrics()
                .register(registry.metrics())
                .expect("Failed to register database metrics");
        }

        let registry_clone = registry.clone();
        let router = router::build::<DefaultTypeRegistry<S>>(registry, config);

        let ms = router
            .layer(Extension(shutdown))
            .into_make_service_with_connect_info::<SocketAddr>();

        let (tx, rx) = oneshot::channel();

        Ok(Self {
            done_tx: Arc::new(Mutex::new(Some(tx))),
            done_rx: Mutex::new(Some(rx)),
            ms,
            reg: registry_clone,
            handle: axum_server::Handle::new(),
            tls,

            _marker: PhantomData,
        })
    }
}

impl<T: TypeRegistry> Server<T> {
    /// Get the server registry of the server.
    pub fn registry(&self) -> &Registry<T> {
        &self.reg
    }

    /// Send a single shot request to the server.
    pub async fn single_shot<A: Send, B: axum::body::HttpBody<Data = Bytes> + Send + 'static>(
        &self,
        req: hyper::Request<B>,
        addr: A,
    ) -> Response<axum::body::Body>
    where
        <B as axum::body::HttpBody>::Error: Into<BoxError>,
        SocketAddr: Connected<A>,
    {
        MakeService::<A, hyper::Request<B>>::make_service(&mut self.ms.clone(), addr)
            .await
            .unwrap_infallible()
            .call(req)
            .await
            .unwrap_infallible()
    }

    #[instrument(name = "Server::listen", skip(self))]
    /// Start listening on the given listener.
    pub async fn listen(&self, listener: TcpListener) -> std::io::Result<()> {
        match &self.tls {
            None => {
                event!(Level::INFO, "Starting HTTP server");
                let mut axum = axum_server::Server::from_tcp(listener);
                Self::modify_axum_server::<
                    <IntoMakeServiceWithConnectInfo<Router, SocketAddr> as MakeService<
                        SocketAddr,
                        hyper::Request<Body>,
                    >>::Service,
                    DefaultAcceptor,
                >(&mut axum);

                event!(Level::INFO, "Ready to serve");
                axum.handle(self.handle.clone())
                    .serve(self.ms.clone())
                    .await
                    .expect("Failed to serve");
            }
            Some(tls) => {
                event!(Level::INFO, "Starting HTTPS server");

                let mut sc = rustls::ServerConfig::builder_with_provider(Arc::new(
                    rustls::crypto::aws_lc_rs::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .expect("Failed to create TLS config")
                .with_no_client_auth()
                .with_cert_resolver(tls.clone());

                sc.time_provider = Arc::new(self.reg.clock().utc());
                sc.ignore_client_order = true;
                sc.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

                let mut tls = axum_server::from_tcp_rustls(
                    listener,
                    axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(sc)),
                );
                Self::modify_axum_server::<
                    <IntoMakeServiceWithConnectInfo<Router, SocketAddr> as MakeService<
                        SocketAddr,
                        hyper::Request<Body>,
                    >>::Service,
                    RustlsAcceptor,
                >(&mut tls);

                event!(Level::INFO, "Ready to serve");
                tls.handle(self.handle.clone())
                    .serve(self.ms.clone())
                    .await
                    .expect("Failed to serve");
            }
        }
        event!(Level::INFO, "Server has stopped");

        self.done_tx.lock().await.take().map(|tx| tx.send(()));

        Ok(())
    }

    fn modify_axum_server<S, A: Accept<TcpStream, S>>(server: &mut axum_server::Server<A>)
    where
        <A as Accept<TcpStream, S>>::Stream: AsyncRead + AsyncWrite + Unpin,
    {
        struct TokioTimer;
        struct TokioSleepWrapper(tokio::time::Sleep);
        impl hyper::rt::Sleep for TokioSleepWrapper {}
        impl Future for TokioSleepWrapper {
            type Output = ();

            fn poll(
                self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Self::Output> {
                #[allow(unsafe_code)]
                unsafe {
                    self.map_unchecked_mut(|s| &mut s.0).poll(cx)
                }
            }
        }

        impl hyper::rt::Timer for TokioTimer {
            fn sleep(&self, duration: Duration) -> std::pin::Pin<Box<dyn hyper::rt::Sleep>> {
                Box::pin(TokioSleepWrapper(tokio::time::sleep(duration)))
            }

            fn sleep_until(
                &self,
                deadline: std::time::Instant,
            ) -> std::pin::Pin<Box<dyn hyper::rt::Sleep>> {
                Box::pin(TokioSleepWrapper(tokio::time::sleep_until(deadline.into())))
            }

            fn reset(
                &self,
                sleep: &mut Pin<Box<dyn hyper::rt::Sleep>>,
                new_deadline: std::time::Instant,
            ) {
                let sleep = sleep
                    .as_mut()
                    .downcast_mut_pin::<TokioSleepWrapper>()
                    .expect("Internal inconsistency: failed to downcast to TokioSleepWrapper");

                #[allow(unsafe_code)]
                unsafe {
                    sleep
                        .map_unchecked_mut(|s| &mut s.0)
                        .reset(new_deadline.into());
                }
            }
        }

        server
            .http_builder()
            .http1()
            .timer(TokioTimer)
            .header_read_timeout(Duration::from_secs(10));
        let mut http2_opts = server.http_builder().http2();
        http2_opts.adaptive_window(true);
        http2_opts.max_concurrent_streams(200);
        http2_opts.keep_alive_interval(None);
    }
}

impl<T: TypeRegistry> ShutdownHandler for Server<T> {
    fn name(&self) -> &'static str {
        "http_server"
    }

    fn wait(&self) -> BoxFuture<'static, Result<(), BoxError>> {
        let rx = self
            .done_rx
            .try_lock()
            .expect("Cannot wait on server twice")
            .take()
            .expect("Cannot wait on server twice");
        async {
            rx.await.expect("Server shutdown failed");
            Ok::<(), BoxError>(())
        }
        .boxed()
    }

    fn signal(&self, level: ShutdownLevel) -> BoxFuture<'_, ()> {
        async move {
            match level {
                1 => {
                    event!(Level::INFO, "Received interrupt, sending graceful shutdown");
                    self.handle.graceful_shutdown(None);
                }
                2 => {
                    event!(
                        Level::WARN,
                        "Received second interrupt, shutting down immediately"
                    );
                    self.handle.shutdown();
                }
                _ => {
                    event!(Level::WARN, "Received third interrupt, forcing exit");
                    self.done_tx.lock().await.take().map(|tx| tx.send(()));
                }
            }
        }
        .instrument(span!(Level::INFO, "server_shutdown"))
        .boxed()
    }
}
