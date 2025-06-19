use std::time::Duration;

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use tower::Service;

use crate::{
    abstraction::timeout::{ResettableTimeout, ResettableTimeoutHandle},
    api::result::ApiError,
};

use super::InfallibleUnwrap;

/// Add a resettable timeout to the request
pub async fn add_resettable_timeout(
    State(initial): State<Duration>,
    mut req: Request,
    mut next: Next,
) -> Response {
    let handle = ResettableTimeoutHandle::new(initial);
    req.extensions_mut().insert(handle.clone());
    let timeout = ResettableTimeout::new(next.call(req), initial, handle);

    timeout
        .await
        .transpose()
        .unwrap_infallible()
        .unwrap_or_else(|| ApiError::Timeout.into_response())
}
