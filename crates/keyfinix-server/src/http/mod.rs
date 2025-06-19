use std::{
    convert::Infallible,
    net::{IpAddr, SocketAddr},
};

use axum::{
    Extension, RequestPartsExt,
    extract::{ConnectInfo, FromRequestParts, rejection::ExtensionRejection},
    http::request::Parts,
    response::IntoResponse,
};
use axum_extra::{TypedHeader, typed_header::TypedHeaderRejection};
use header::XForwardedFor;
use uuid::Uuid;

/// Typed headers
pub mod header;

/// Limit middleware
pub mod limit;

/// Identify middleware
pub mod identify;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(missing_docs)]
pub enum RateLimitKey {
    Ip4([u8; 4]),
    Ip6([u8; 8]),
    User(Uuid),
}

impl RateLimitKey {
    /// Create a rate limit key from an IP address
    #[must_use]
    pub fn from_client_addr(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ip) => RateLimitKey::Ip4(ip.octets()),
            IpAddr::V6(ip) => match ip.to_ipv4().or_else(|| ip.to_ipv4_mapped()) {
                Some(ip) => RateLimitKey::Ip4(ip.octets()),
                None => RateLimitKey::Ip6(ip.octets()[..8].try_into().unwrap()),
            },
        }
    }
    /// add a user ID to the rate limit key
    ///
    /// Currently this will completely replace the key with the user ID, but this may change in the future
    #[must_use]
    pub fn with_user(self, user: Uuid) -> Self {
        Self::User(user)
    }
}

/// Extract if the request is over HTTPS.
#[derive(Debug, Clone, Copy)]
pub struct IsHttps(u8);

impl IsHttps {
    /// The request originated from an HTTPS connection.
    #[must_use]
    pub const fn origin(&self) -> bool {
        self.0 & 0b10 != 0
    }
    /// The request that hit the server socket was over HTTPS.
    #[must_use]
    pub const fn socket(&self) -> bool {
        self.0 & 0b01 != 0
    }
    /// Both the origin and the socket were over HTTPS.
    #[must_use]
    pub const fn both(&self) -> bool {
        self.0 & 0b11 == 0b11
    }
}

impl<S: Send + Sync> FromRequestParts<S> for IsHttps {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let socket = false; // TODO: support SSL listener

        let origin = parts
            .headers
            .get("x-forwarded-proto")
            .map_or(socket, |proto| proto == "https");

        Ok(Self(u8::from(socket) | u8::from(origin) << 1))
    }
}

/// Extension trait for unwrapping `Result<T, Infallible>` without panicking.
pub trait InfallibleUnwrap<T> {
    /// Unwrap the result that is unable to fail.
    fn unwrap_infallible(self) -> T;
}

impl<T> InfallibleUnwrap<T> for Result<T, Infallible> {
    fn unwrap_infallible(self) -> T {
        match self {
            Ok(value) => value,
            Err(_) => unreachable!(),
        }
    }
}

#[derive(Debug, Clone)]
/// Extension for the client address extractor.
pub struct ClientAddressExtension {
    /// The maximum number of forwarded addresses to follow.
    pub max_forwards: u8,
}

#[derive(Debug, Clone, Copy)]
/// The client address extractor.
pub struct ClientAddress {
    /// The client's socket address.
    pub socket_addr: SocketAddr,
    /// The forwarded address, if any.
    pub forwarded_addr: Option<IpAddr>,
}

impl ClientAddress {
    #[must_use]
    /// Check if the address was forwarded.
    pub fn is_forwarded(&self) -> bool {
        self.forwarded_addr.is_some()
    }
    #[must_use]
    /// Get the effective address.
    pub fn effective_addr(&self) -> IpAddr {
        self.forwarded_addr
            .as_ref()
            .copied()
            .unwrap_or_else(|| self.socket_addr.ip())
    }
}

#[derive(Debug, thiserror::Error)]
/// Error type for the client address extractor.
pub enum ClientAddressError {
    /// The extension was not found.
    #[error("extension not found")]
    Extension(#[from] ExtensionRejection),
    /// The x-forwarded-for header is invalid.
    #[error("invalid x-forwarded-for header")]
    HeaderFormat(#[from] TypedHeaderRejection),
}

impl IntoResponse for ClientAddressError {
    fn into_response(self) -> axum::http::Response<axum::body::Body> {
        use axum::body::Body;
        use axum::http::{Response, StatusCode};

        let status = match &self {
            Self::Extension(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::HeaderFormat(_) => StatusCode::BAD_REQUEST,
        };

        Response::builder()
            .status(status)
            .header("content-type", "text/plain")
            .body(Body::from(self.to_string()))
            .unwrap()
    }
}

impl<S: Send + Sync> FromRequestParts<S> for ClientAddress {
    type Rejection = ClientAddressError;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let ConnectInfo(addr) = parts.extract().await?;
        let Extension(ext) = parts.extract::<Extension<ClientAddressExtension>>().await?;
        let TypedHeader(XForwardedFor(forward_chain)) = parts.extract().await?;
        match forward_chain {
            Some(forward_chain) => {
                let forwarded_addr = forward_chain
                    .into_iter()
                    .nth_back(ext.max_forwards as usize);
                Ok(Self {
                    socket_addr: addr,
                    forwarded_addr,
                })
            }
            None => Ok(Self {
                socket_addr: addr,
                forwarded_addr: None,
            }),
        }
    }
}
