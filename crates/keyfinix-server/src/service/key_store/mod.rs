use aes_gcm::{AeadInPlace, KeyInit, KeySizeUser, aes::cipher::Unsigned};
use chrono::{DateTime, Utc};
use derive_more::derive::Display;
use keyfinix_crypto::auth::{AssocEncoder, ScopeAssoc};
use sea_orm::{ConnectionTrait, Set};
use secrecy::{ExposeSecret, SecretString, zeroize::Zeroize};
use sha2::{Sha256, digest::generic_array::GenericArray};
use std::{future::Future, sync::Weak};
use tracing::{Instrument, Level, event};
use uuid::Uuid;

use crate::{api::result::RichError, database::pool::DbPool, impl_error_kind};

/// Kiyoka key store service (first generation)
pub mod kiyoka;

/// The default key selector for the primary key
pub const KEK_KEY_SELECTOR_PRIMARY: &str = "primary";

/// Compute the database entry name for the DEK that corresponds to the given key selector
pub fn compute_dek_db_entry_name(store: &'static str, key_selector: &str) -> String {
    format!("db-encryption-dek-{store}-{key_selector}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display)]
/// The error kind for key store service
pub enum KeyStoreServiceErrorKind {
    /// The database error
    DbErr,
    /// The internal error
    InternalErr,
    /// An existing conflicting key is found
    Conflict,
    /// The key or actor is unacceptable
    UnAcceptable,
    /// Unwrap failed, the payload is not valid
    UnwrapFailed,
    /// Unwrap failed, the payload is expired
    UnwrapExpired,
}

impl_error_kind!(permanent KeyStoreServiceErrorKind);

#[derive(thiserror::Error, Debug, RichError)]
#[kind(KeyStoreServiceErrorKind)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum KeyStoreServiceError {
    #[error("database error")]
    #[kind(KeyStoreServiceErrorKind::DbErr)]
    DbErr(#[from] sea_orm::DbErr),

    #[error("base64 decode error")]
    #[kind(KeyStoreServiceErrorKind::InternalErr)]
    Base64DecodeErr(#[from] base64::DecodeError),

    #[error("conflicting key found")]
    #[http(403)]
    #[kind(KeyStoreServiceErrorKind::Conflict)]
    Conflict,

    #[error("internal error")]
    #[kind(KeyStoreServiceErrorKind::InternalErr)]
    InternalErr,

    #[error("persistent storage unseal failure, the key is not valid")]
    #[kind(KeyStoreServiceErrorKind::UnwrapFailed)]
    #[http(403)]
    UnsealFailed,

    #[error("unwrapping failed, the key or payload is not valid")]
    #[kind(KeyStoreServiceErrorKind::UnwrapFailed)]
    #[http(403)]
    UnwrapFailed,

    #[error("private key unavailable")]
    #[kind(KeyStoreServiceErrorKind::UnwrapFailed)]
    #[http(500)]
    PrivateKeyUnavailable,

    #[error("unwrapping failed, the payload is expired")]
    #[kind(KeyStoreServiceErrorKind::UnwrapExpired)]
    #[http(403)]
    UnwrapExpired {
        /// The current time
        current: DateTime<Utc>,
        /// The expired time
        expired: DateTime<Utc>,
    },
}

/// The trait for key store initialization
pub trait KeyStoreInit: KeyInit + Sized {
    /// The key store service when initialized
    type Service: KeyStoreService;

    /// Create a new key store service with a passphrase
    #[must_use]
    fn prekey_from_passphrase(passphrase: SecretString) -> Self {
        const SALT: &[u8] = b"88d860b6-3776-4e75-9659-d43b2b67babd";

        let mut out = GenericArray::default();

        tracing::info!(
            "Key store initialization, it can take up to {} seconds on slow devices",
            if matches!(env!("VERGEN_CARGO_OPT_LEVEL"), "0" | "1") {
                10
            } else {
                2
            }
        );

        ::keyfinix_crypto::kdf::derive_persist_key(
            passphrase.expose_secret().as_bytes(),
            SALT,
            &mut out,
        )
        .expect("argon2 failed to hash password");

        let ret = Self::new(&out);
        out.zeroize();
        ret
    }

    /// List all key selectors available to this key store
    fn list_key_selectors(
        &self,
        db: &impl ConnectionTrait,
    ) -> impl Future<Output = Result<Vec<(String, String)>, KeyStoreServiceError>> + Send;

    /// Re-encrypt the data key with a new KEK and store it in the database
    ///
    /// if the new selector is not provided, the old selector will be overwritten
    ///
    /// return the wrapped DEK in base64 format
    fn reencrypt_dek(
        self,
        self_selector: &str,
        new_init: &Self,
        new_selector: &str,
        db: &impl ConnectionTrait,
    ) -> impl Future<Output = Result<String, KeyStoreServiceError>> + Send;

    /// Initialize the key store service with a recovery DEK that is not in the database
    ///
    /// Does not create a new DEK entry in the database for this key selector
    fn insert_dek(
        self,
        key_selector: &str,
        recovery_dek: String,
        db: &impl ConnectionTrait,
    ) -> impl Future<Output = Result<(), KeyStoreServiceError>> + Send;

    /// Destroy the DEK entry for the given key selector
    ///
    /// If `unchecked` is true, the provided key does not need to match the existing key in the database
    fn destroy_dek(
        &self,
        key_selector: &str,
        unchecked: bool,
        db: &impl ConnectionTrait,
    ) -> impl Future<Output = Result<(), KeyStoreServiceError>> + Send;

    /// Initialize the key store service with a database connection
    fn initialize(
        self,
        key_selector: &str,
        db: DbPool,
    ) -> impl Future<Output = Result<Self::Service, KeyStoreServiceError>> + Send;
}

/// The trait for key store service
///
/// Implementors are expected to provide the following functionality apart from private key generation.
///
/// # AEAD
///
/// The service should maintain an [`::kiyoka::auth::AssocEncoder`] and an AEAD cipher seeded by a static key.
///
/// It is intended to be used like this:
///
/// ```no_run
/// use kirame_server::prelude::*;
/// use kiyoka::auth::ScopeAssoc;
/// use rand::{thread_rng, RngCore};
/// use aes_gcm::aead::generic_array::GenericArray;
///
/// const MY_SCOPE: ScopeAssoc = ScopeAssoc::new("my_scope");
/// type MyFieldAssoc<T> = FieldAssoc<T, 0x0u64, 0x0u64>; // generate random u64 pairs
///
/// fn encrypt<S: KeyStoreService>(service: &S, data: &mut Vec<u8>) {
///     let mut nonce = GenericArray::default();
///     thread_rng().fill_bytes(&mut nonce);
///     service.begin_aead(&MY_SCOPE)
///            .push_assoc(MyFieldAssoc::new("user", "alice"))
///            .push_assoc(MyFieldAssoc::new("host", "alice.example.com"))
///            .wrap(service.borrow_cipher(), &nonce, data);
///
/// }
///
/// fn decrypt<'a, 'b: 'a, S: KeyStoreService>(service: &'b S, data: &'a mut [u8]) -> &'a mut [u8] {
///     service.begin_aead(&MY_SCOPE)
///            .push_assoc(MyFieldAssoc::new("user", "alice"))
///            .push_assoc(MyFieldAssoc::new("host", "alice.example.com"))
///            .unwrap(service.borrow_cipher(), data)
///            .expect("unwrap failed, data or key is not valid")
/// }
/// ```
///
/// # Secret Derivation
///
/// This is used to seed other static secrets like session management, cookies, etc.
/// The usage is the same, you generate an association by chaining hashes on an [`::kiyoka::auth::AssocEncoder`]
/// and then the service will emit a unique 128-bit secret for the association
///
///
pub trait KeyStoreService: Send + Sync {
    /// The initialization type for the key store
    type Init: KeyStoreInit<Service = Self>;

    /// Begin encoding an associated data
    ///
    /// It is deliberately enforced that you must pass a scope first and not possible to
    /// get the root encoder.
    fn begin_aead(&self, module: &ScopeAssoc) -> AssocEncoder;

    /// Borrow the aead cipher for finalizing a wrap
    ///
    /// It is intentionally opaque to make it only possible to do in-place operations which is
    /// less likely to accidentally leak secret
    fn borrow_cipher(&self) -> &impl AeadInPlace;

    /// Derive a secret to seed other services scoped by the encoder,
    /// it is guaranteed that the secret is the same for the same scope and
    /// indistinguishable from random if the scope changed.
    ///
    /// A default implementation provided by SipHash is implemented, it is usually good enough as the input key is already
    /// not distinguishable from random and very few outputs are needed.
    ///
    /// You should make a private [`ScopeAssoc`] and pass it in to make sure your associated data is unique
    /// then use the scope function to attach row-level fields to the encoder
    ///
    /// This is a cheap operation, so it might be better to call it
    /// for every request rather than caching the secret
    fn derive_secret<S: FnOnce(AssocEncoder) -> AssocEncoder>(
        &self,
        module: &ScopeAssoc,
        scope: S,
    ) -> u128 {
        const RUNTIME_SECRET_SCOPE: ScopeAssoc =
            ScopeAssoc::new("::keyfinix_server::KeyStoreService::derive-runtime-secret");
        scope(self.begin_aead(&RUNTIME_SECRET_SCOPE).push_assoc(module))
            .finish()
            .into()
    }

    #[cfg(any(feature = "testing", test))]
    /// Check if the key store is keyed same as another key store, only for testing purposes
    /// it should be safe to use this in production but I don't see the point
    fn keyed_same_as(&self, other: &Self) -> bool {
        use ::keyfinix_crypto::wrapping::TESTING_REUSABLE_NONCE_PREFIX;
        use aes_gcm::Nonce;

        let uuid = Uuid::new_v4();

        let mut test = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        let mut nonce = Nonce::default();
        nonce[..TESTING_REUSABLE_NONCE_PREFIX.len()].copy_from_slice(TESTING_REUSABLE_NONCE_PREFIX);

        self.begin_aead(&ScopeAssoc::new("test"))
            .push_field::<0, 0, _>("test", uuid)
            .wrap(self.borrow_cipher(), &nonce, &mut test);

        other
            .begin_aead(&ScopeAssoc::new("test"))
            .push_field::<0, 0, _>("test", uuid)
            .unwrap(other.borrow_cipher(), &mut test)
            .map_or(false, |pt| {
                pt.0 == [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
            })
    }
}
