use axum::{Json, response::IntoResponse};
use http::{HeaderValue, header::RETRY_AFTER};
use hyper::StatusCode;
use keyfinix_crypto::wrapping::WrappingError;
pub use keyfinix_derive::RichError;
use std::{
    any::Any,
    convert::Infallible,
    fmt::{Debug, Display},
};
use uuid::Uuid;

use crate::impl_error_kind;

pub(crate) async fn fallback() -> ApiError {
    ApiError::RouteNotFound
}

pub const ONE_DAY: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);
pub const THREE_DAYS: std::time::Duration = std::time::Duration::from_secs(3 * 24 * 60 * 60);

#[derive(Debug, Clone, Copy, serde::Serialize, derive_more::Display)]
#[allow(missing_docs)]
#[non_exhaustive]
pub enum ErrorTy {
    Timeout,
    Blocked,
    KeyStore,
    RateLimited,
    BadRequest,
    NotReady,
    AclDenied,
    NotFound,
    ReadOnly,
    Auth,
    Database,
    InvalidCursor,
    InvalidLimit,
    TooManyMutations,
    TooManyQueries,
    InvalidToken,
    ExpiredToken,
    InvalidCredentials,
    FieldValidation,
    ConstraintViolation,
    Shutdown {
        #[serde(default)]
        graceful: bool,
    },
    Internal {
        #[serde(default)]
        temporary: bool,
    },
}

impl ErrorKind for ErrorTy {
    fn retry_after_restart(&self) -> bool {
        matches!(self, ErrorTy::Internal { temporary: true })
    }

    fn retry_after(&self, rep: u32) -> Option<std::time::Duration> {
        match self {
            ErrorTy::Database | ErrorTy::Internal { temporary: true } => backoff(rep),

            _ => None,
        }
    }
}

/// A serializable error kind for the backend
///
/// Job queue implementors should store all jobs with associated retry timeouts and
/// optionally record whether they can be immediately retried after a restart,
/// jobs that have expired should be discarded to prevent exhausting resources.
///
/// This trait has a macro to implement common retry patterns
pub trait ErrorKind: Any + Display + Debug + Copy + Send + Sync + 'static {
    /// Whether the wait timer should be disregarded after a restart and make a job
    /// eligible to be retried immediately
    ///
    /// A good candidate is database errors, etc.
    ///
    /// The schedule of retries will still be dictated by other throttling conditions
    fn retry_after_restart(&self) -> bool {
        false
    }

    /// Get the minimum time to wait before retrying
    ///
    /// If the error should not be retried, this should return `None`
    fn retry_after(&self, rep: u32) -> Option<std::time::Duration>;
}

#[must_use]
pub fn backoff(rep: u32) -> Option<std::time::Duration> {
    match rep {
        0 => Some(std::time::Duration::from_secs(30)),
        1..=2 => Some(std::time::Duration::from_secs(600)),
        3..=5 => Some(std::time::Duration::from_secs(3600)),
        6 => Some(ONE_DAY),
        7 => Some(THREE_DAYS),
        _ => None,
    }
}

#[must_use]
pub fn backoff_with_jitter(rep: u32, rng: &mut impl rand::Rng) -> Option<std::time::Duration> {
    let base = backoff(rep)?;
    let jitter = base / 3;
    if jitter.as_millis() == 0 {
        return Some(base);
    }
    let jitter = std::time::Duration::from_millis(rng.random_range(0..jitter.as_millis() as u64));
    Some(base + jitter)
}

impl_error_kind!(permanent Infallible);

/// Rich error trait, which provides retry-after information for the error
///
/// This trait has a derive macro that automatically generates the implementation
pub trait RichError: Any + Display + Debug + 'static {
    type Kind: ErrorKind;

    /// Whether the error originated from the upstream server or not
    ///
    /// This primarily dictates when the machine reboots and `retry_internal_errors()` is called
    fn kind(&self) -> Self::Kind;

    /// Get the UUID of the error
    fn uuid(&self) -> Uuid;

    /// Get the minimum time to wait before retrying
    ///
    /// The `rep` parameter is the number of times the job has been retried
    /// If the error should not be retried, this should return `None`
    fn retry_after(&self, rep: u32) -> Option<std::time::Duration> {
        self.kind().retry_after(rep)
    }

    /// Whether the error is eligible to be retried after a restart
    fn retry_after_restart(&self) -> bool {
        self.kind().retry_after_restart()
    }

    /// Get the HTTP status code for the error
    fn http_status(&self) -> StatusCode {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

impl RichError for Infallible {
    type Kind = Infallible;

    fn kind(&self) -> Self::Kind {
        unreachable!()
    }

    fn uuid(&self) -> Uuid {
        unreachable!()
    }

    fn retry_after(&self, _rep: u32) -> Option<std::time::Duration> {
        unreachable!()
    }

    fn http_status(&self) -> StatusCode {
        unreachable!()
    }
}

/// Must-retriable error trait, which are used in critical services
pub trait MustRetriableError: RichError {
    /// Get the minimum time to wait before retrying
    ///
    /// If you provide a more efficient implementation,
    /// this must return the same value as if you call [`RichError::retry_after`] then [`Option::unwrap`]
    fn retry_after_must(&self, rep: u32) -> std::time::Duration {
        self.retry_after(rep).unwrap()
    }
}

impl MustRetriableError for Infallible {
    fn retry_after_must(&self, _rep: u32) -> std::time::Duration {
        unreachable!()
    }
}

pub struct RichErrorResponse<T>(pub T);

impl<T: RichError> From<T> for RichErrorResponse<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

fn serialize_error_kind<K: ErrorKind, S: serde::Serializer>(
    k: &K,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(format!("{}::{}", std::any::type_name::<K>(), k.to_string()).as_str())
}

impl<T> IntoResponse for RichErrorResponse<T>
where
    T: RichError,
{
    fn into_response(self) -> axum::response::Response {
        #[derive(serde::Serialize)]
        struct ErrorWrapper<K: ErrorKind> {
            success: bool,
            #[serde(serialize_with = "serialize_error_kind")]
            kind: K,
            status: u16,
            retry_after: Option<u64>,
            uuid: Uuid,
            message: String,
        }

        let retry_after = self.0.retry_after(0).map(|d| d.as_secs());
        let status = self.0.http_status();

        let error = ErrorWrapper {
            success: false,
            kind: self.0.kind(),
            status: status.as_u16(),
            retry_after,
            uuid: self.0.uuid(),
            message: self.0.to_string(),
        };

        match retry_after {
            Some(s) => (
                status,
                [(
                    RETRY_AFTER,
                    HeaderValue::from_str(s.to_string().as_str()).unwrap(),
                )],
                Json(error),
            )
                .into_response(),
            None => (status, Json(error)).into_response(),
        }
    }
}

#[derive(Debug, RichError, thiserror::Error)]
#[kind(ErrorTy)]
#[http(500)]
#[non_exhaustive]
#[allow(missing_docs)]
/// API error type
pub enum ApiError {
    #[error("Base64 decode error: {0}")]
    #[kind(ErrorTy::BadRequest)]
    #[http(400)]
    Base64(#[from] base64::DecodeError),

    #[error("Request timed out")]
    #[kind(ErrorTy::Timeout)]
    #[http(504)]
    Timeout,

    #[error("HTTP Server error: {0}")]
    #[kind(ErrorTy::Internal { temporary: true })]
    #[http(500)]
    Axum(#[from] axum::Error),

    #[error("Cryptography error: {0}")]
    #[kind(ErrorTy::Internal { temporary: false })]
    Decryption(#[from] WrappingError),

    #[error("Rate limit exceeded, try again after {0:?} ms")]
    #[kind(ErrorTy::RateLimited)]
    #[http(429)]
    RateLimited(Option<u64>),

    #[error("Service is not ready")]
    #[kind(ErrorTy::NotReady)]
    #[http(503)]
    NotReady,

    #[error("Route not found")]
    #[kind(ErrorTy::NotFound)]
    #[http(404)]
    RouteNotFound,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let retry_after = match self {
            ApiError::RateLimited(Some(t)) => Some(t),
            _ => None,
        };

        let mut resp = RichErrorResponse(self).into_response();

        if let Some(t) = retry_after {
            t.to_string()
                .parse()
                .map(|v| resp.headers_mut().insert("Retry-After", v))
                .ok();
        }

        resp
    }
}
