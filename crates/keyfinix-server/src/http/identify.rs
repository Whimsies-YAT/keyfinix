use std::sync::Arc;

use axum::{
    extract::{FromRequestParts, Query},
    http::request::Parts,
    response::IntoResponse,
};
use axum_extra::{
    TypedHeader,
    extract::CookieJar,
    headers::{Authorization, authorization::Bearer},
    typed_header::TypedHeaderRejection,
};
use uuid::Uuid;

use crate::{
    http::RateLimitKey,
    service::{
        Registry, TypeRegistry,
        concurrency_limit::ConcurrencyLimitMap,
        token::{TokenError, TokenService},
    },
};

use super::{ClientAddress, ClientAddressError, InfallibleUnwrap};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum IdentifyError {
    #[error("Failed to identify the client address")]
    ClientAddress(#[from] ClientAddressError),
    #[error("Token is invalid")]
    TokenError(#[from] TokenError),
    #[error("Token is expired")]
    TokenExpired,
    #[error("Max in-flight requests exceeded")]
    Concurrency,
    #[error("Header format error")]
    HeaderFormat(#[from] TypedHeaderRejection),
}

impl IntoResponse for IdentifyError {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;

        let status = match &self {
            Self::TokenExpired => StatusCode::FORBIDDEN,
            Self::TokenError(_) => StatusCode::UNAUTHORIZED,
            Self::Concurrency => StatusCode::TOO_MANY_REQUESTS,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };

        (status, self.to_string()).into_response()
    }
}

#[derive(Debug, Clone)]
/// Identifies the requester and enforces a per-requester concurrency limit.
pub(crate) struct IdentifyRequester;

#[derive(Debug, serde::Deserialize)]
pub(crate) struct TokenQuery {
    token: String,
}

impl<T: TypeRegistry, N: Send + Sync + 'static, const SH: usize>
    FromRequestParts<(Arc<Registry<T>>, Arc<ConcurrencyLimitMap<N, SH>>)> for IdentifyRequester
{
    type Rejection = IdentifyError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &(Arc<Registry<T>>, Arc<ConcurrencyLimitMap<N, SH>>),
    ) -> Result<Self, Self::Rejection> {
        let addr = ClientAddress::from_request_parts(parts, &()).await?;
        let token = match TypedHeader::<Authorization<Bearer>>::from_request_parts(parts, &()).await
        {
            Ok(token) => Some(state.0.token().verify_token(token.0.token()).await?),
            Err(r) if r.is_missing() => {
                let jar = CookieJar::from_request_parts(parts, &())
                    .await
                    .unwrap_infallible();
                if let Some(token) = jar.get("token") {
                    Some(state.0.token().verify_token(token.value()).await?)
                } else {
                    match Query::<TokenQuery>::from_request_parts(parts, &()).await {
                        Ok(Query(TokenQuery { token })) => {
                            Some(state.0.token().verify_token(&token).await?)
                        }
                        Err(_) => None,
                    }
                }
            }
            Err(e) => return Err(e.into()),
        };

        let mut key = RateLimitKey::from_client_addr(addr.effective_addr());
        if let Some(token) = &token {
            key = key.with_user(token.user_id);
        }

        let permit = state.1.get(key).ok_or(IdentifyError::Concurrency)?.await;

        parts.extensions.insert(Arc::new(permit));
        parts.extensions.insert(addr.effective_addr());
        parts.extensions.insert(token);
        parts.extensions.insert(key);

        Ok(Self)
    }
}
