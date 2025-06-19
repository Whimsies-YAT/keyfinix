pub mod abstraction;
pub mod api;
pub mod config;
pub(crate) mod database;
pub(crate) mod http;
pub mod log;
pub mod server;
pub(crate) mod service;

/// Implement the [`ErrorKind`] trait for the given type automatically
#[macro_export]
macro_rules! impl_error_kind {
    (permanent $ty:ty) => {
        impl crate::api::result::ErrorKind for $ty {
            fn retry_after(&self, _rep: u32) -> Option<std::time::Duration> {
                None
            }

            fn retry_after_restart(&self) -> bool {
                false
            }
        }
    };
    (after_restart $ty:ty) => {
        impl ErrorKind for $ty {
            fn retry_after(&self, rep: u32) -> Option<std::time::Duration> {
                if rep < 24 {
                    Some(std::time::Duration::from_secs(3600))
                } else {
                    None
                }
            }

            fn retry_after_restart(&self) -> bool {
                true
            }
        }
    };
    (backoff $ty:ty) => {
        impl ErrorKind for $ty {
            fn retry_after(&self, rep: u32) -> Option<std::time::Duration> {
                backoff(rep)
            }
        }
    };
}
