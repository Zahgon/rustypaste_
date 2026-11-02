use axum::body::Body;
use axum::extract::Request;
use axum::http::header::CONTENT_LENGTH;
use axum::http::StatusCode;
use axum::response::Response;
use byte_unit::Byte;
use futures_util::future::BoxFuture;
use futures_util::TryStreamExt;
use std::task::{Context, Poll};
use tower::{Layer, Service};

/// Content length limiter middleware.
#[derive(Clone, Copy, Debug)]
pub struct ContentLengthLimiter {
    // Maximum amount of bytes to allow.
    max_bytes: Byte,
}

impl ContentLengthLimiter {
    /// Constructs a new instance.
    pub fn new(max_bytes: Byte) -> Self {
        Self { max_bytes }
    }
}

impl<S> Layer<S> for ContentLengthLimiter {
    type Service = ContentLengthLimiterMiddleware<S>;

    fn layer(&self, service: S) -> Self::Service {
        ContentLengthLimiterMiddleware {
            service,
            max_bytes: self.max_bytes,
        }
    }
}

/// Content length limiter middleware implementation.
///
/// Only the `Content-Length` header is checked; a chunked body is not limited.
#[derive(Clone, Debug)]
pub struct ContentLengthLimiterMiddleware<S> {
    service: S,
    max_bytes: Byte,
}

impl<S> Service<Request> for ContentLengthLimiterMiddleware<S>
where
    S: Service<Request, Response = Response> + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        if let Some(content_length) = request
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<Byte>().ok())
        {
            if content_length > self.max_bytes {
                warn!(
                    "Upload rejected due to exceeded limit. ({:-#} > {:-#})",
                    content_length, self.max_bytes
                );
                return Box::pin(async move {
                    // drain the body so the client reads the response instead of a reset
                    let mut payload = request.into_body().into_data_stream();
                    loop {
                        match payload.try_next().await {
                            Ok(Some(_)) => {}
                            Ok(None) => break,
                            // A failed read ends the drain; the limit answer below still goes out.
                            Err(e) => {
                                warn!("could not drain the rejected upload: {}", e);
                                break;
                            }
                        }
                    }
                    let mut response = Response::new(Body::from("upload limit exceeded"));
                    *response.status_mut() = StatusCode::PAYLOAD_TOO_LARGE;
                    Ok(response)
                });
            }
        }
        Box::pin(self.service.call(request))
    }
}
