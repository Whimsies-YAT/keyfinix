use crate::{
    abstraction::time::{ClockSet, UtcClock},
    api::result::RichError,
    impl_error_kind,
    service::key_store::KeyStoreService,
};
use jsonwebtoken::{DecodingKey, EncodingKey, Header};
use keyfinix_crypto::auth::ScopeAssoc;
use std::{borrow::Cow, future::Future, sync::Arc};
use tracing::event;
use uuid::Uuid;

use crate::config::Config;

#[derive(Debug, thiserror::Error, PartialEq, RichError, Clone, Copy, serde::Serialize)]
#[kind(TokenError)]
/// The token error
pub enum TokenError {
    #[error("Invalid token")]
    #[http(401)]
    #[kind(TokenError::InvalidToken)]
    /// The token is invalid
    InvalidToken,
    #[error("Token has already expired")]
    #[http(401)]
    #[kind(TokenError::TokenExpired)]
    /// The token has already expired
    TokenExpired,
    #[error("Internal error")]
    #[http(500)]
    #[kind(TokenError::InternalError)]
    /// An internal error occurred while manipulating the token
    InternalError,
}

impl_error_kind!(permanent TokenError);

#[ouroboros::self_referencing]
pub struct Token {
    buf: String,

    #[borrows(buf)]
    pub cookie: &'this str,

    #[borrows(buf)]
    pub api: &'this str,
}

#[derive(Debug, Clone)]
/// The token context
pub struct TokenContext {
    /// The token ID
    pub id: Uuid,
    /// The user ID
    pub user_id: Uuid,
    /// The session ID
    pub session_id: Uuid,
}

impl From<String> for Token {
    fn from(buf: String) -> Self {
        TokenBuilder {
            buf,
            cookie_builder: |buf| buf.as_str(),
            api_builder: |buf| buf.as_str(),
        }
        .build()
    }
}

impl Token {
    #[must_use]
    /// Create a new token that has different cookie and API parts
    pub fn from_split(cookie: &str, api: &str) -> Self {
        let cookie_len = cookie.len();
        let buf = format!("{cookie}:{api}");
        TokenBuilder {
            buf,
            cookie_builder: |buf| &buf[..cookie_len],
            api_builder: |buf| &buf[cookie_len + 1..],
        }
        .build()
    }

    #[must_use]
    /// Create a new token from a unified string
    pub fn pre_split(buf: String, api_start: usize) -> Self {
        TokenBuilder {
            buf,
            cookie_builder: |buf| &buf[..api_start],
            api_builder: |buf| &buf[api_start..],
        }
        .build()
    }
}

/// The token service trait
pub trait TokenService<C: ClockSet, KS: KeyStoreService>: Send + Sync {
    /// Create a new token service from the configuration
    fn new(
        config: Arc<Config>,
        secret_store: &KS,
        clock: C,
        max_lifetime: Option<chrono::Duration>,
    ) -> Self
    where
        Self: Sized;

    /// Generate a new token
    fn generate_token(
        &self,
        ctx: TokenContext,
        lifetime: chrono::Duration,
    ) -> impl Future<Output = Result<Token, TokenError>> + Send;

    /// Renew an existing token
    fn renew_token(
        &self,
        token: &str,
        lifetime: chrono::Duration,
    ) -> impl Future<Output = Result<Token, TokenError>> + Send;

    /// Verify a token
    fn verify_token(
        &self,
        token: &str,
    ) -> impl Future<Output = Result<TokenContext, TokenError>> + Send;
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
/// The JWT token claims
pub struct JwtTokenClaims<'a> {
    iss: Cow<'a, str>,
    sub: Uuid,
    jti: Uuid,
    sid: Uuid,
    nbf: u64,
    iat: u64,
    exp: u64,
}

#[derive(Clone)]
/// The JWT token service
pub struct JwtTokenService<C: ClockSet> {
    cs: C,
    issuer: String,
    max_lifetime: Option<chrono::Duration>,
    validation: jsonwebtoken::Validation,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl<C: ClockSet, KS: KeyStoreService> TokenService<C, KS> for JwtTokenService<C> {
    fn new(
        config: Arc<Config>,
        secret_store: &KS,
        cs: C,
        max_lifetime: Option<chrono::Duration>,
    ) -> Self {
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.required_spec_claims.insert("iss".to_string());
        validation.required_spec_claims.insert("sub".to_string());
        validation.required_spec_claims.insert("jti".to_string());
        validation.required_spec_claims.insert("exp".to_string());
        validation.validate_exp = false;
        validation.validate_nbf = true;

        #[cfg(test)]
        {
            validation.leeway = 0;
        }

        validation.set_issuer(&[config.identity.id.clone()]);

        const SCOPE: ScopeAssoc = ScopeAssoc::new("sys:jwt-session-token");

        let secret = secret_store
            .derive_secret(&SCOPE, |scope| {
                scope.push_field::<0x8e96_673a_c1a3_accd, 0x9107_3cbc_165b_17b8, _>(
                    "host",
                    config.identity.public_url.as_str(),
                )
            })
            .to_le_bytes();

        let encoding_key = EncodingKey::from_secret(&secret);
        let decoding_key = DecodingKey::from_secret(&secret);

        Self {
            cs,
            issuer: config.identity.id.clone(),
            max_lifetime,
            validation,
            encoding_key,
            decoding_key,
        }
    }

    async fn generate_token(
        &self,
        ctx: TokenContext,
        lifetime: chrono::Duration,
    ) -> Result<Token, TokenError> {
        #[allow(clippy::cast_sign_loss)]
        let now = self.cs.utc().now().timestamp().max(0) as u64;

        let claims = JwtTokenClaims {
            iss: Cow::Borrowed(&self.issuer),
            sid: ctx.session_id,
            sub: ctx.user_id,
            jti: ctx.id,
            nbf: now,
            iat: now,
            #[allow(clippy::cast_sign_loss)]
            exp: now.saturating_add(lifetime.num_seconds().max(0) as u64),
        };

        Ok(jsonwebtoken::encode(
            &Header::new(jsonwebtoken::Algorithm::HS256),
            &claims,
            &self.encoding_key,
        )
        .map_err(|e| {
            event!(tracing::Level::ERROR, %e, "Failed to encode JWT token");
            TokenError::InternalError
        })?
        .into())
    }

    async fn renew_token(
        &self,
        token: &str,
        lifetime: chrono::Duration,
    ) -> Result<Token, TokenError> {
        let claims =
            jsonwebtoken::decode::<JwtTokenClaims>(token, &self.decoding_key, &self.validation)
                .map_err(|e| {
                    if e.kind() == &jsonwebtoken::errors::ErrorKind::ExpiredSignature {
                        return TokenError::TokenExpired;
                    }

                    TokenError::InvalidToken
                })?
                .claims;

        #[allow(clippy::cast_sign_loss)]
        let now = self.cs.utc().now().timestamp().max(0) as u64;
        if now > claims.exp {
            return Err(TokenError::TokenExpired);
        }

        #[allow(clippy::cast_sign_loss)]
        let mut new_exp = now.saturating_add(lifetime.num_seconds().max(0) as u64);
        if let Some(max_lifetime) = self.max_lifetime {
            #[allow(clippy::cast_sign_loss)]
            let absolute_exp = claims.nbf + max_lifetime.num_seconds().max(0) as u64;
            if now > absolute_exp {
                return Err(TokenError::TokenExpired);
            }
            new_exp = new_exp.min(absolute_exp);
        }

        let new_claims = JwtTokenClaims {
            iat: now,
            exp: new_exp,
            ..claims
        };

        Ok(jsonwebtoken::encode(
            &Header::new(jsonwebtoken::Algorithm::HS256),
            &new_claims,
            &self.encoding_key,
        )
        .map_err(|e| {
            if e.kind() == &jsonwebtoken::errors::ErrorKind::ExpiredSignature {
                return TokenError::TokenExpired;
            }

            TokenError::InternalError
        })?
        .into())
    }

    async fn verify_token(&self, token: &str) -> Result<TokenContext, TokenError> {
        let claims =
            jsonwebtoken::decode::<JwtTokenClaims>(token, &self.decoding_key, &self.validation)
                .map_err(|e| {
                    if e.kind() == &jsonwebtoken::errors::ErrorKind::ExpiredSignature {
                        return TokenError::TokenExpired;
                    }

                    TokenError::InvalidToken
                })?
                .claims;
        #[allow(clippy::cast_sign_loss)]
        let now = self.cs.utc().now().timestamp().max(0) as u64;
        if now > claims.exp {
            return Err(TokenError::TokenExpired);
        }

        if let Some(max_lifetime) = self.max_lifetime {
            #[allow(clippy::cast_sign_loss)]
            if now > claims.nbf + max_lifetime.num_seconds().max(0) as u64 {
                return Err(TokenError::TokenExpired);
            }
        }

        Ok(TokenContext {
            id: claims.jti,
            session_id: claims.sid,
            user_id: claims.sub,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{abstraction::time::MockClockSet, config::test_config};

    use super::*;

    #[test]
    fn test_token_split() {
        let token = Token::from_split("cookie", "api");
        assert_eq!(*token.borrow_cookie(), "cookie");
        assert_eq!(*token.borrow_api(), "api");
    }

    #[test]
    fn test_token_pre_split() {
        let token = Token::pre_split("cookieapi".to_string(), 6);
        assert_eq!(*token.borrow_cookie(), "cookie");
        assert_eq!(*token.borrow_api(), "api");
    }

    #[test]
    fn test_token_unified() {
        let token = Token::from("cookie:api".to_string());
        assert_eq!(*token.borrow_cookie(), "cookie:api");
        assert_eq!(*token.borrow_api(), "cookie:api");
    }

    #[allow(clippy::too_many_lines)]
    async fn test_token_service<M: MockClockSet, KS: KeyStoreService, S: TokenService<M, KS>>(
        key_store: KS,
    ) {
        let clock = M::epoch();
        clock.advance_seconds(1);
        let abs_lifetime_seconds = 180;
        let service = S::new(
            Arc::new(test_config()),
            &key_store,
            clock.clone(),
            Some(chrono::Duration::seconds(abs_lifetime_seconds)),
        );
        let token_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        let lifetime = chrono::Duration::seconds(10);
        let token = service
            .generate_token(
                TokenContext {
                    id: token_id,
                    session_id,
                    user_id,
                },
                lifetime,
            )
            .await
            .unwrap();

        let ctx = service
            .verify_token(token.borrow_cookie())
            .await
            .expect("Token verification");
        assert_eq!(ctx.id, token_id);
        assert_eq!(ctx.user_id, user_id);
        assert_eq!(ctx.session_id, session_id);
        let renewed = service
            .renew_token(token.borrow_cookie(), lifetime)
            .await
            .expect("Token renewal");
        let renewed_verified = service
            .verify_token(renewed.borrow_cookie())
            .await
            .expect("Token verification");

        assert_eq!(renewed_verified.id, token_id);
        assert_eq!(renewed_verified.user_id, user_id);
        assert_eq!(renewed_verified.session_id, session_id);

        clock.advance_seconds(11);
        assert_eq!(
            service
                .verify_token(token.borrow_cookie())
                .await
                .unwrap_err(),
            TokenError::TokenExpired
        );

        assert_eq!(renewed.borrow_cookie(), token.borrow_cookie());
        assert_eq!(renewed.borrow_api(), token.borrow_api());

        clock.advance_seconds(10);

        assert_eq!(
            service
                .verify_token(renewed.borrow_cookie())
                .await
                .unwrap_err(),
            TokenError::TokenExpired
        );

        assert!(
            service
                .renew_token(renewed.borrow_cookie(), lifetime)
                .await
                .is_err()
        );
    }
}
