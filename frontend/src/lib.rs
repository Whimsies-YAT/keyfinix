use std::{
    convert::Infallible,
    io::{Cursor, Read},
    sync::{Arc, LazyLock},
};

use axum::{
    body::{Body, Bytes},
    extract::Request,
    middleware::{self, Next},
    response::Response,
};
use flate2::bufread::GzDecoder;
use futures::FutureExt;
use http::{
    HeaderName, HeaderValue, Method, StatusCode,
    header::{
        ACCEPT_ENCODING, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, ETAG,
        LOCATION, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS, X_XSS_PROTECTION,
    },
};
use tower::service_fn;

include!(concat!(env!("OUT_DIR"), "/ui_box.rs"));

/// The "permissions-policy" header name.
const PERMISSIONS_POLICY: HeaderName = HeaderName::from_static("permissions-policy");

fn generate_response<F: Fn() -> Bytes>(
    mime: HeaderValue,
    content: F,
    size: u64,
    etag: &str,
    encoding: Option<HeaderValue>,
    req: &Request,
) -> Result<Response, Infallible> {
    let mut builder = Response::builder()
        .header(CONTENT_TYPE, mime)
        .header(CONTENT_LENGTH, size)
        .header(ETAG, etag);

    if let Some(encoding) = encoding {
        builder = builder.header(CONTENT_ENCODING, encoding);
    }

    match req.method() {
        &Method::GET => Ok(builder.body(axum::body::Body::from(content())).unwrap()),
        &Method::HEAD => Ok(builder.body(axum::body::Body::empty()).unwrap()),
        _ => Ok(builder
            .status(http::StatusCode::METHOD_NOT_ALLOWED)
            .body(axum::body::Body::empty())
            .unwrap()),
    }
}

pub fn ui_router() -> axum::Router {
    let mut router = axum::Router::new();
    for file in UI_DIST_FILES {
        let path_name = file
            .name
            .strip_suffix("index.html")
            .and_then(|s| if s.ends_with("/") { Some(s) } else { None })
            .unwrap_or(&file.name);

        if file.name.ends_with("/index.html") {
            router = router.route_service(
                &file.name,
                service_fn(move |_: Request| async move {
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(StatusCode::PERMANENT_REDIRECT)
                            .header(LOCATION, path_name)
                            .body(Body::empty())
                            .unwrap(),
                    )
                }),
            );
        }

        let mime = HeaderValue::from_static(file.mime);

        if file.is_gzipped() {
            let unzip_once = LazyLock::new(|| {
                let mut decoder = GzDecoder::new(Cursor::new(&file.buffer));
                let mut buf = Vec::new();
                decoder.read_to_end(&mut buf).unwrap();
                Bytes::from(buf)
            });
            let unzip_once = Arc::new(unzip_once);

            router = router.route_service(
                &path_name,
                service_fn(move |req: Request| {
                    let unzip_once = unzip_once.clone();
                    let mime = mime.clone();
                    async move {
                        if let Some(etag) = req.headers().get(http::header::ETAG) {
                            if etag.to_str().map_or(false, |s| s == file.etag) {
                                return Ok(Response::builder()
                                    .status(StatusCode::NOT_MODIFIED)
                                    .body(Body::empty())
                                    .unwrap());
                            }
                        }

                        if let Some(accept_encoding) = req.headers().get(ACCEPT_ENCODING) {
                            if accept_encoding
                                .to_str()
                                .map_or(false, |s| s.contains("gzip"))
                            {
                                return generate_response(
                                    mime,
                                    || Bytes::from_static(file.buffer),
                                    file.size,
                                    file.etag,
                                    Some(HeaderValue::from_static("gzip")),
                                    &req,
                                );
                            }
                        }

                        generate_response(
                            mime,
                            || {
                                let unzipped = (*unzip_once.clone().as_ref()).clone();
                                debug_assert!(unzipped.len() == file.original_size as usize);
                                unzipped
                            },
                            file.original_size,
                            file.etag,
                            None,
                            &req,
                        )
                    }
                }),
            );
        } else {
            // we already tried compressing it during build and didn't work well, so just serve it as is
            router = router.route_service(
                &path_name,
                service_fn(move |req: Request| {
                    let mime = mime.clone();
                    async move {
                        if let Some(etag) = req.headers().get(http::header::ETAG) {
                            if etag.to_str().map_or(false, |s| s == file.etag) {
                                return Ok(Response::builder()
                                    .status(StatusCode::NOT_MODIFIED)
                                    .body(Body::empty())
                                    .unwrap());
                            }
                        }

                        generate_response(
                            mime,
                            || Bytes::from_static(file.buffer),
                            file.original_size,
                            file.etag,
                            None,
                            &req,
                        )
                    }
                }),
            );
        }
    }

    router.layer(middleware::from_fn(|req: Request, next: Next| {
        next.run(req).map(|mut resp| {
            resp.headers_mut()
                .insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
            resp.headers_mut()
                .insert(X_XSS_PROTECTION, HeaderValue::from_static("1; mode=block"));

            #[cfg(not(debug_assertions))]
            resp.headers_mut()
                .insert(CACHE_CONTROL, HeaderValue::from_static("max-age=31536000"));
            #[cfg(debug_assertions)]
            resp.headers_mut()
                .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));

            resp.headers_mut().insert(
                REFERRER_POLICY,
                HeaderValue::from_static("strict-origin-when-cross-origin"),
            );
            resp.headers_mut().insert(
                PERMISSIONS_POLICY,
                HeaderValue::from_static("interest-cohort=()"),
            );
            resp.headers_mut()
                .insert(X_FRAME_OPTIONS, HeaderValue::from_static("SAMEORIGIN"));
            resp
        })
    }))
}
