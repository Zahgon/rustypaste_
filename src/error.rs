use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use std::fmt;
use std::io::{Error as IoError, ErrorKind as IoErrorKind};

/// Error answered with its status code and its message as a `text/plain` body.
#[derive(Debug)]
pub struct Error {
    status: StatusCode,
    message: String,
}

impl Error {
    /// Constructs an error with the given status code and message.
    pub fn new(status: StatusCode, message: impl fmt::Display) -> Self {
        Self {
            status,
            message: message.to_string(),
        }
    }

    /// Returns the status code of the response this error is answered with.
    pub fn status(&self) -> StatusCode {
        self.status
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl From<IoError> for Error {
    fn from(error: IoError) -> Self {
        let status = match error.kind() {
            IoErrorKind::NotFound => StatusCode::NOT_FOUND,
            IoErrorKind::PermissionDenied => StatusCode::FORBIDDEN,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        Self::new(status, error)
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let mut response = (self.status, self.message).into_response();
        response.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        response
    }
}

/// Returns a `400 Bad Request` error.
pub fn bad_request(message: impl fmt::Display) -> Error {
    Error::new(StatusCode::BAD_REQUEST, message)
}

/// Returns a `401 Unauthorized` error.
pub fn unauthorized(message: impl fmt::Display) -> Error {
    Error::new(StatusCode::UNAUTHORIZED, message)
}

/// Returns a `404 Not Found` error.
pub fn not_found(message: impl fmt::Display) -> Error {
    Error::new(StatusCode::NOT_FOUND, message)
}

/// Returns a `409 Conflict` error.
pub fn conflict(message: impl fmt::Display) -> Error {
    Error::new(StatusCode::CONFLICT, message)
}

/// Returns a `415 Unsupported Media Type` error.
pub fn unsupported_media_type(message: impl fmt::Display) -> Error {
    Error::new(StatusCode::UNSUPPORTED_MEDIA_TYPE, message)
}

/// Returns a `500 Internal Server Error` error.
pub fn internal(message: impl fmt::Display) -> Error {
    Error::new(StatusCode::INTERNAL_SERVER_ERROR, message)
}

/// Returns a `507 Insufficient Storage` error.
pub fn insufficient_storage(message: impl fmt::Display) -> Error {
    Error::new(StatusCode::INSUFFICIENT_STORAGE, message)
}
