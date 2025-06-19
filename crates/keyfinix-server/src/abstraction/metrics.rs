use std::time::Duration;

use axum::{Router, extract::Request};
use governor::clock::{Clock, Reference};
use http::{HeaderName, HeaderValue, Method};
use prometheus::{HistogramOpts, HistogramVec};
use tower_http::timeout::ResponseBodyTimeoutLayer;

use crate::config::Config;

/// Add tokio metrics to the registry
pub(crate) fn add_tokio_metrics(reg: &prometheus::Registry) {
    use prometheus::{
        Opts,
        core::{AtomicU64, GenericGauge},
    };

    let counter_alive_tasks = GenericGauge::<AtomicU64>::with_opts(Opts::new(
        "keyfinix_tokio_alive_tasks",
        "Number of alive tasks",
    ))
    .expect("Failed to create prometheus gauge");

    let counter_num_worker_threads: GenericGauge<AtomicU64> =
        GenericGauge::<AtomicU64>::with_opts(Opts::new(
            "keyfinix_tokio_num_worker_threads",
            "Number of worker threads",
        ))
        .expect("Failed to create prometheus gauge");

    let counter_global_queue_depth = GenericGauge::<AtomicU64>::with_opts(Opts::new(
        "keyfinix_tokio_global_queue_depth",
        "Global queue depth",
    ))
    .expect("Failed to create prometheus gauge");

    reg.register(Box::new(counter_alive_tasks.clone()))
        .expect("Failed to register prometheus counter");

    reg.register(Box::new(counter_num_worker_threads.clone()))
        .expect("Failed to register prometheus counter");

    reg.register(Box::new(counter_global_queue_depth.clone()))
        .expect("Failed to register prometheus counter");

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));

        loop {
            interval.tick().await;
            let metrics = tokio::runtime::Handle::current().metrics();

            counter_alive_tasks.set(metrics.num_alive_tasks() as _);
            counter_num_worker_threads.set(metrics.num_workers() as _);
            counter_global_queue_depth.set(metrics.global_queue_depth() as _);
        }
    });
}

/// Add Prometheus metrics to the router
pub(crate) fn add_http_metrics<
    S: Clone + Send + Sync + 'static,
    C: Clock + Clone + Send + Sync + 'static,
>(
    clock: C,
    registry: &prometheus::Registry,
    mut router: Router<S>,
    _config: &Config,
) -> Router<S> {
    use std::{convert::Infallible, time::Duration};

    use axum::{
        http::HeaderMap,
        middleware::{self, Next},
    };
    use futures::TryFutureExt;
    use prometheus::{
        Opts,
        core::{AtomicU64, GenericCounterVec, GenericGauge},
    };
    use tower_http::metrics::InFlightRequestsLayer;
    use tower_service::Service;

    let gauge_in_flight = GenericGauge::<AtomicU64>::with_opts(Opts::new(
        "keyfinix_in_flight_requests",
        "Number of requests in flight",
    ))
    .expect("Failed to create prometheus gauge");

    registry
        .register(Box::new(gauge_in_flight.clone()))
        .expect("Failed to register prometheus gauge");

    let (in_flight_layer, in_flight_counter) = InFlightRequestsLayer::pair();

    tokio::spawn(
        in_flight_counter.run_emitter(Duration::from_secs(2), move |v: usize| {
            gauge_in_flight.set(v as u64);
            futures::future::always_ready(|| ())
        }),
    );

    let counter_requests_served = GenericCounterVec::<AtomicU64>::new(
        Opts::new("keyfinix_requests_served", "Number of requests served"),
        &["status"],
    )
    .expect("Failed to create prometheus counter");
    let counter_requests_received = GenericCounterVec::<AtomicU64>::new(
        Opts::new("keyfinix_requests_received", "Number of requests received"),
        &[],
    )
    .expect("Failed to create prometheus counter");

    let histogram_request_duration = HistogramVec::new(
        HistogramOpts::new("keyfinix_request_duration_ms", "Request duration"),
        &["status", "method"],
    )
    .expect("Failed to create prometheus histogram");

    registry
        .register(Box::new(counter_requests_served.clone()))
        .expect("Failed to register prometheus counter");

    registry
        .register(Box::new(counter_requests_received.clone()))
        .expect("Failed to register prometheus counter");

    let registry = registry.clone();

    router = router
        .layer(middleware::from_fn(move |req: Request, mut next: Next| {
            counter_requests_received
                .with_label_values::<&'static str>(&[])
                .inc();
            let counter_requests_served = counter_requests_served.clone();
            let now = clock.now();
            let clock = clock.clone();
            let histogram_request_duration = histogram_request_duration.clone();
            let method = match req.method() {
                &Method::HEAD => Some("HEAD"),
                &Method::POST => Some("POST"),
                &Method::PUT => Some("PUT"),
                &Method::DELETE => Some("DELETE"),
                &Method::TRACE => Some("TRACE"),
                // &Method::CONNECT => Some("CONNECT"),
                &Method::PATCH => Some("PATCH"),
                _ => None,
            };

            next.call(req)
                .map_ok(move |mut res| {
                    #[allow(clippy::match_overlapping_arm)]
                    let status = match res.status().as_u16() {
                        200 => "200",
                        201 => "201",
                        202 => "202",
                        204 => "204",
                        400 => "400",
                        401 => "401",
                        403 => "403",
                        404 => "404",
                        429 => "429",
                        500 => "500",
                        502 => "502",
                        503 => "503",
                        504 => "504",
                        100..=199 => "1xx",
                        200..=299 => "2xx",
                        300..=399 => "3xx",
                        400..=499 => "4xx",
                        500..=599 => "5xx",
                        _ => "oob",
                    };

                    counter_requests_served.with_label_values(&[status]).inc();

                    let end = clock.now();
                    let duration = end.duration_since(now);

                    let us = duration.as_u64() / 1_000;

                    if let Some(method) = method {
                        histogram_request_duration
                            .with_label_values(&[status, method])
                            .observe(us as f64 / 1000.0);
                    }

                    res.headers_mut().insert(
                        HeaderName::from_static("server-timing"),
                        HeaderValue::from_str(&format!("overall;ms={}", us / 1000)).unwrap(),
                    );

                    res
                })
                .map_err(|e: Infallible| e)
        }))
        .route(
            "/metrics",
            axum::routing::get(move || async move {
                use prometheus::Encoder;

                let enc = prometheus::TextEncoder::new();

                let metric_families = registry.gather();

                let mut buffer = Vec::new();

                enc.encode(&metric_families, &mut buffer)
                    .expect("Failed to encode metrics");

                let mut hdr = HeaderMap::new();

                hdr.insert("Content-Type", enc.format_type().try_into().unwrap());

                (hdr, buffer)
            })
            .layer(ResponseBodyTimeoutLayer::new(Duration::from_secs(5))),
        )
        .layer(in_flight_layer);

    router
}
