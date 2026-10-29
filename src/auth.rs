use crate::config::{Config, TokenType};
use crate::error::{self, Error};
use crate::server::AppState;
use axum::extract::{FromRequestParts, Request, State};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::http::{HeaderMap, Method};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::collections::HashSet;
use std::marker::PhantomData;

/// Extracts the tokens from the authorization header by token type.
///
/// `Authorization: (type) <token>`
pub(crate) fn extract_tokens(
    config: &Config,
    method: &Method,
    headers: &HeaderMap,
) -> Result<HashSet<TokenType>, Error> {
    let mut user_tokens = HashSet::with_capacity(2);

    let auth_header = headers
        .get(AUTHORIZATION)
        .map(|v| v.to_str().unwrap_or_default())
        .map(|v| v.split_whitespace().last().unwrap_or_default());

    for token_type in [TokenType::Auth, TokenType::Delete] {
        let maybe_tokens = config.get_tokens(token_type);
        if let Some(configured_tokens) = maybe_tokens {
            if configured_tokens.contains(auth_header.unwrap_or_default()) {
                user_tokens.insert(token_type);
            }
        } else if token_type == TokenType::Auth {
            // not configured `auth_tokens` means that the user is allowed to access the endpoints
            user_tokens.insert(token_type);
        } else if token_type == TokenType::Delete && method == Method::DELETE {
            // explicitly disable `DELETE` methods if no `delete_tokens` are set
            warn!("delete endpoint is not served because there are no delete_tokens set");
            Err(error::not_found(""))?;
        }
    }

    Ok(user_tokens)
}

/// Token types granted to the current request.
#[derive(Clone, Debug, Default)]
pub(crate) struct Grants(HashSet<TokenType>);

impl Grants {
    /// Returns `true` if the request was granted the given token type.
    pub(crate) fn contains(&self, token_type: TokenType) -> bool {
        self.0.contains(&token_type)
    }
}

/// Middleware that resolves the [`Grants`] of every request against the live configuration.
///
/// Tokens are read on each request, so tokens edited in the configuration file or in the
/// token files take effect without a restart.
pub(crate) async fn grant_tokens(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let tokens = state
        .config()
        .and_then(|config| extract_tokens(&config, request.method(), request.headers()));
    match tokens {
        Ok(tokens) => {
            request.extensions_mut().insert(Grants(tokens));
            next.run(request).await
        }
        Err(e) => e.into_response(),
    }
}

/// Returns the unauthorized (`401`) error with `unauthorized\n` as body.
pub(crate) fn unauthorized_error() -> Error {
    error::unauthorized("unauthorized\n")
}

/// Logs an unauthorized request.
pub(crate) fn log_unauthorized(parts: &Parts) {
    let host = crate::server::ConnectionInfo::new(parts)
        .realip_remote_addr()
        .unwrap_or("unknown host")
        .to_string();

    #[cfg(debug_assertions)]
    {
        let auth_header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("none");

        warn!("authorization failure for {host} (token: {auth_header})",);
    }
    #[cfg(not(debug_assertions))]
    warn!("authorization failure for {host}");
}

/// Type of token an endpoint is protected by.
pub(crate) trait TokenKind {
    /// The token type a request must be granted.
    const TOKEN_TYPE: TokenType;
}

/// Endpoints protected by [`TokenType::Auth`].
#[derive(Debug)]
pub(crate) struct AuthToken;

impl TokenKind for AuthToken {
    const TOKEN_TYPE: TokenType = TokenType::Auth;
}

/// Endpoints protected by [`TokenType::Delete`].
#[derive(Debug)]
pub(crate) struct DeleteToken;

impl TokenKind for DeleteToken {
    const TOKEN_TYPE: TokenType = TokenType::Delete;
}

/// Extractor that rejects requests which were not granted the token type `K`.
#[derive(Debug)]
pub(crate) struct Protected<K>(PhantomData<K>);

impl<S, K> FromRequestParts<S> for Protected<K>
where
    S: Send + Sync,
    K: TokenKind,
{
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let granted = parts
            .extensions
            .get::<Grants>()
            .is_some_and(|grants| grants.contains(K::TOKEN_TYPE));
        if granted {
            Ok(Self(PhantomData))
        } else {
            log_unauthorized(parts);
            Err(unauthorized_error())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::HeaderValue;
    use axum::http::StatusCode;

    #[test]
    fn test_extract_tokens() -> Result<(), Error> {
        let mut config = Config::default();
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("basic test_token"));

        // request without configured auth-tokens
        let tokens = extract_tokens(&config, &Method::GET, &headers)?;
        assert_eq!(HashSet::from([TokenType::Auth]), tokens);

        // request with configured auth-tokens
        config.server.auth_tokens = Some(["test_token".to_string()].into());
        let tokens = extract_tokens(&config, &Method::GET, &headers)?;
        assert_eq!(HashSet::from([TokenType::Auth]), tokens);

        // request with configured auth-tokens but wrong token in request
        config.server.auth_tokens = Some(["test_token".to_string()].into());
        let mut invalid_headers = HeaderMap::new();
        invalid_headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("basic invalid_token"),
        );
        let tokens = extract_tokens(&config, &Method::GET, &invalid_headers)?;
        assert_eq!(HashSet::new(), tokens);

        // DELETE request without configured delete-tokens
        let res = extract_tokens(&config, &Method::DELETE, &headers);
        assert!(res.is_err());
        assert_eq!(
            Some(StatusCode::NOT_FOUND),
            res.err().as_ref().map(Error::status)
        );

        // DELETE request with configured delete-tokens
        config.server.delete_tokens = Some(["delete_token".to_string()].into());
        let mut delete_headers = HeaderMap::new();
        delete_headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("basic delete_token"),
        );
        let tokens = extract_tokens(&config, &Method::DELETE, &delete_headers)?;
        assert_eq!(HashSet::from([TokenType::Delete]), tokens);

        // DELETE request with configured delete-tokens but wrong token in request
        let tokens = extract_tokens(&config, &Method::DELETE, &invalid_headers)?;
        assert_eq!(HashSet::new(), tokens);

        Ok(())
    }
}
