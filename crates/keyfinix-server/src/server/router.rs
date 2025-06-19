use crate::{
    abstraction::{backpressure::Backpressure, metrics::add_http_metrics},
    api,
    config::Config,
    server::{GlobalConcurrencyLimit, REQUEST_ID_HEADER},
    service::{Registry, TypeRegistry},
};

use hyper::body::Body;

use axum::{
    Extension, Router,
    extract::ConnectInfo,
    http::Request,
    middleware,
    routing::{get, post},
};
use tracing::{Instrument, Span, event};

use std::{net::SocketAddr, sync::Arc, time::Duration};
use tower_http::LatencyUnit;

use tower_http::{
    catch_panic::CatchPanicLayer,
    cors::{AllowCredentials, AllowMethods, AllowOrigin, CorsLayer},
    limit::RequestBodyLimitLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    timeout::{RequestBodyTimeoutLayer, ResponseBodyTimeoutLayer},
    trace::{DefaultOnFailure, DefaultOnRequest, DefaultOnResponse, TraceLayer},
};

use crate::{
    http::{
        ClientAddressExtension, header::add_common_response_header, limit::add_resettable_timeout,
    },
    select_by_scale,
};

struct RouterState<T: TypeRegistry> {
    registry: Arc<Registry<T>>,
}
impl<T: TypeRegistry> Clone for RouterState<T> {
    fn clone(&self) -> Self {
        Self {
            registry: Arc::clone(&self.registry),
        }
    }
}

/// Create the main router
#[allow(clippy::needless_pass_by_value)]
pub fn build<T: TypeRegistry>(registry: Arc<Registry<T>>, config: Arc<Config>) -> Router {
    let global_limit = Arc::new(GlobalConcurrencyLimit::new(Backpressure::new(
        select_by_scale!(32 => 128).try_into().unwrap(),
        select_by_scale!(64 => 256).try_into().unwrap(),
    )));
    let global_limit_clone = Arc::clone(&global_limit);

    tokio::spawn(
        async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;
            loop {
                interval.tick().await;
                event!(tracing::Level::TRACE, "Running global limit GC");
                let (new_size, old_size) = global_limit_clone.gc();
                event!(
                    tracing::Level::DEBUG,
                    new_size,
                    old_size,
                    "Global limit GC completed"
                );
            }
        }
        .instrument(tracing::info_span!("global_limit_gc")),
    );

    let config_clone = Arc::clone(&config);
    let config_clone2 = Arc::clone(&config);

    #[allow(clippy::items_after_statements)]
    fn make_request_span<B: Body>(req: &Request<B>) -> Span {
        let sock_addr = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|v| v.0);

        tracing::info_span!(
            "http_r",
            method = req.method().as_str(),
            path = req.uri().path(),
            raddr = ?sock_addr,
            rid = req
                .headers()
                .get(REQUEST_ID_HEADER)
                .unwrap()
                .to_str()
                .unwrap(),
        )
    }

    let state = RouterState {
        registry: Arc::clone(&registry),
    };

    // Router for all backend routes
    let api_router = Router::new()
        .with_state(state.clone())
        .layer(
            TraceLayer::new_for_http()
                .on_request(DefaultOnRequest::new().level(tracing::Level::DEBUG))
                .on_response(
                    DefaultOnResponse::new()
                        .level(tracing::Level::DEBUG)
                        .latency_unit(LatencyUnit::Micros),
                )
                .on_body_chunk(())
                .on_eos(())
                .on_failure(
                    DefaultOnFailure::new()
                        .level(tracing::Level::ERROR)
                        .latency_unit(LatencyUnit::Micros),
                )
                .make_span_with(make_request_span),
        )
        .layer(middleware::from_fn_with_state(
            Duration::from_secs(if cfg!(debug_assertions) { 30 } else { 5 }),
            add_resettable_timeout,
        ));

    #[allow(unused_mut)]
    let mut router = api_router
        .layer(ResponseBodyTimeoutLayer::new(Duration::from_secs(15)))
        .layer(RequestBodyLimitLayer::new(2 << 20))
        .layer(Extension(ClientAddressExtension {
            max_forwards: config.http_listen.max_forwarded_for,
        }))
        .layer(PropagateRequestIdLayer::new(REQUEST_ID_HEADER));

    #[cfg(feature = "compression")]
    {
        router = router.layer(tower_http::compression::CompressionLayer::new());
    }

    #[cfg(feature = "metrics")]
    {
        use crate::abstraction::time::ClockSet;

        let prom: &prometheus::Registry = registry.as_ref().as_ref();
        router = add_http_metrics(registry.clock().tsc(), prom, router, &config);
    }

    #[cfg(feature = "decompression")]
    {
        router = router.layer(tower_http::decompression::RequestDecompressionLayer::new());
    }

    router
        .layer(RequestBodyTimeoutLayer::new(Duration::from_secs(600)))
        .layer(SetRequestIdLayer::new(REQUEST_ID_HEADER, MakeRequestUuid))
        .merge(keyfinix_frontend::ui_router())
        .fallback(api::result::fallback)
        .layer(middleware::map_response_with_state(
            config.http_listen.extra_headers.clone(),
            add_common_response_header,
        ))
}
