use std::{marker::PhantomData, sync::Arc};

use keyfinix_sandboxing::{NoSandbox, Sandboxing};
use rustls::crypto::CryptoProvider;
use tracing::instrument;

use crate::{
    abstraction::{
        KeepAlivable,
        time::{ClockSet, NormalClock},
    },
    config::Config,
    database::pool::{DBInitError, DBPoolProto, DbPool},
    service::{
        key_store::{
            KEK_KEY_SELECTOR_PRIMARY, KeyStoreInit, KeyStoreService, KeyStoreServiceError,
            kiyoka::KiyokaKeyStore,
        },
        token::{JwtTokenService, TokenService},
    },
};

pub mod concurrency_limit;
pub mod key_store;
pub mod token;

pub trait TypeRegistry: Send + Sync + Sized + 'static {
    /// Time reference
    type Clocks: ClockSet;

    /// Sandboxing environment for less trusted computations
    type Sandbox: Sandboxing;

    /// Key store service
    type KeyStore: KeyStoreService;

    /// Token service
    type Token: TokenService<Self::Clocks, Self::KeyStore>;
}

/// Default service registry based on the current feature toggles
#[derive(Clone, Copy, Default)]
pub struct DefaultTypeRegistry<S: Sandboxing = NoSandbox> {
    _marker: PhantomData<<S as Sandboxing>::Init>,
}

impl<S: Sandboxing> TypeRegistry for DefaultTypeRegistry<S> {
    type Clocks = NormalClock;
    type Sandbox = S;
    type KeyStore = KiyokaKeyStore<aes_gcm::Aes256Gcm>;
    type Token = JwtTokenService<Self::Clocks>;
}

/// Dynamic Service Registry
///
/// You can implement your own service by satisfying contracts by implementing corresponding traits in [`TypeRegistry`].
/// Thanks to the strict type system you can be pretty confident if your service satisfy the traits it will compile,
/// and we try to document every additional behavior expectations in the trait documentation.
///
/// We prefer a completely decoupled service where you generic your service over your dependencies,
///
/// However, if a service is tightly coupled to the entire service, you can take a [`std::sync::Weak`] reference to the registry
/// and initialize the registry as a cyclic [`std::sync::Arc`].
///
/// Of course if you do this you should not hold persistent strong references to the registry to prevent memory leaks during testing or benchmarking.
pub struct Registry<T: TypeRegistry> {
    clock: T::Clocks,

    db: DbPool,

    config: Arc<Config>,

    sandbox: <<T as TypeRegistry>::Sandbox as Sandboxing>::Init,

    token: Arc<T::Token>,

    key_store: Arc<T::KeyStore>,

    #[cfg(feature = "metrics")]
    metrics: prometheus::Registry,
}

impl<T: TypeRegistry> Registry<T> {
    pub fn metrics(&self) -> &prometheus::Registry {
        &self.metrics
    }
}

#[cfg(feature = "metrics")]
impl<T: TypeRegistry> AsRef<prometheus::Registry> for Registry<T> {
    fn as_ref(&self) -> &prometheus::Registry {
        &self.metrics
    }
}

#[allow(dead_code, reason = "diagnostic use only")]
const DEFAULT_REGISTRY_SIZE: usize = std::mem::size_of::<Registry<DefaultTypeRegistry>>();

macro_rules! impl_registry_getters {
    (ref $type:ty => $field:ident) => {
        impl<T: TypeRegistry> Registry<T> {
            #[
                doc = concat!(
                    "Get the ", stringify!($field), " service",
                )
            ]
            pub fn $field(&self) -> &$type {
                &self.$field
            }
        }
    };
    (arc $type:ty => $field:ident) => {
        impl<T: TypeRegistry> Registry<T> {
            #[
                doc = concat!(
                    "Get the ", stringify!($field), " service",
                )
            ]
            pub fn $field(&self) -> Arc<$type> {
                self.$field.clone()
            }
        }
    };

    ([ $( ( $qualifier:tt $type:ty => $field:ident ) ),* $(,)? ]) => {
        $(
            impl_registry_getters!($qualifier $type => $field);
        )*
    };
}

impl_registry_getters! {
    [
        (ref Arc<Config> => config),
        (arc T::Token => token),
        (arc T::KeyStore => key_store),
        (ref DbPool => db),
        (ref T::Clocks => clock),
    ]
}

#[derive(Debug, thiserror::Error)]
pub enum ServiceInitError {
    #[error("Failed to initialize database: {0}")]
    DB(#[from] DBInitError),
    #[error("Failed to initialize key store: {0}")]
    KeyStore(#[from] KeyStoreServiceError),
}

/// Initialize the service registry
#[instrument(name = "service_init", skip_all)]
pub async fn service_init<T: TypeRegistry>(
    clock: T::Clocks,
    config: Arc<Config>,
    _provider: Arc<CryptoProvider>,
    key_init: <T::KeyStore as KeyStoreService>::Init,
    sandbox: <<T as TypeRegistry>::Sandbox as Sandboxing>::Init,
) -> Result<Registry<T>, ServiceInitError> {
    let db_proto = DBPoolProto::new(
        crate::database::pool::DBRole::Master,
        config.database.clone(),
    );

    let db_pool = DbPool::new(db_proto, None).await?;

    let key_store = key_init
        .initialize(KEK_KEY_SELECTOR_PRIMARY, db_pool.clone())
        .await?;

    Ok(Registry {
        clock: clock.clone(),
        db: db_pool,
        sandbox,
        token: Arc::new(T::Token::new(
            config.clone(),
            &key_store,
            clock.clone(),
            None,
        )),
        config,
        key_store: Arc::new(key_store),
        metrics: prometheus::Registry::new(),
    })
}
