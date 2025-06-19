use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
};

use axum::{extract::State, http::HeaderName, response::Response};
use axum_extra::headers::Header;
use http::{
    HeaderValue,
    header::{
        HeaderMap, REFERRER_POLICY, SERVER, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
        X_XSS_PROTECTION,
    },
};

use crate::config::HTTPExtraHeadersConfig;

/// The "permissions-policy" header name.
pub const PERMISSIONS_POLICY: HeaderName = HeaderName::from_static("permissions-policy");

/// The "x-forwarded-for" header name.
pub const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");

/// The default extra headers.
#[must_use]
pub fn default_extra_headers() -> HTTPExtraHeadersConfig {
    let mut overriding = HeaderMap::new();
    for (k, v) in [
        (SERVER, concat!("keyfinix/", env!("CARGO_PKG_VERSION"))),
        (X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (X_XSS_PROTECTION, "1; mode=block"),
        (PERMISSIONS_POLICY, "interest-cohort=()"),
    ] {
        overriding.insert(k, HeaderValue::from_static(v));
    }

    let mut if_not_set = HeaderMap::new();
    for (k, v) in [
        (X_FRAME_OPTIONS, "SAMEORIGIN"),
        (PERMISSIONS_POLICY, "interest-cohort=()"),
        (REFERRER_POLICY, "strict-origin"),
    ] {
        if_not_set.insert(k, HeaderValue::from_static(v));
    }

    HTTPExtraHeadersConfig {
        overriding,
        appending: HeaderMap::new(),
        if_not_set,
    }
}

/// Add common response headers to the response.
///
/// Intended to be used with [`axum::middleware::map_response`]
pub async fn add_common_response_header<B>(
    State(extra_headers): State<Arc<HTTPExtraHeadersConfig>>,
    mut respose: Response<B>,
) -> Response<B> {
    let headers = respose.headers_mut();

    for (k, v) in &extra_headers.if_not_set {
        if !headers.contains_key(k) {
            headers.insert(k, v.clone());
        }
    }

    for (k, v) in &extra_headers.appending {
        headers.append(k, v.clone());
    }

    for (k, v) in &extra_headers.overriding {
        headers.insert(k, v.clone());
    }

    respose
}

#[derive(Debug, PartialEq)]
/// Extract the `X-Forwarded-For` header.
pub struct XForwardedFor(pub Option<Vec<IpAddr>>);

impl Header for XForwardedFor {
    fn name() -> &'static HeaderName {
        static X_FORWARDED_FOR_NAME: HeaderName = X_FORWARDED_FOR;
        &X_FORWARDED_FOR_NAME
    }
    fn decode<'i, I>(values: &mut I) -> Result<Self, axum_extra::headers::Error>
    where
        Self: Sized,
        I: Iterator<Item = &'i axum::http::HeaderValue>,
    {
        let mut addrs = None;
        let mut count = 0;

        for value in values {
            count += 1;
            if count > 1 {
                return Err(axum_extra::headers::Error::invalid());
            }

            if addrs.is_none() {
                addrs = Some(Vec::new());
            }

            for addr in value
                .to_str()
                .map_err(|_| axum_extra::headers::Error::invalid())?
                .split(',')
            {
                let addr = addr.trim();
                match addr
                    .parse()
                    .or_else(|_| SocketAddr::from_str(addr).map(|s| s.ip()))
                {
                    Ok(addr) => addrs.as_mut().unwrap().push(addr),
                    Err(_) => return Err(axum_extra::headers::Error::invalid()),
                }
            }
        }

        Ok(Self(addrs))
    }
    fn encode<E: Extend<axum::http::HeaderValue>>(&self, _values: &mut E) {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_x_forwarded_for() {
        assert_eq!(
            XForwardedFor::decode(&mut [].into_iter()).unwrap(),
            XForwardedFor(None)
        );
        assert_eq!(
            XForwardedFor::decode(
                &mut [&axum::http::HeaderValue::from_static("127.0.0.1")].into_iter()
            )
            .unwrap(),
            XForwardedFor(Some(vec!["127.0.0.1".parse().unwrap()]))
        );
        assert_eq!(
            XForwardedFor::decode(
                &mut [&axum::http::HeaderValue::from_static(
                    "127.0.0.1, 127.0.0.2"
                ),]
                .into_iter()
            )
            .unwrap(),
            XForwardedFor(Some(vec![
                "127.0.0.1".parse().unwrap(),
                "127.0.0.2".parse().unwrap()
            ]))
        );
    }
}
