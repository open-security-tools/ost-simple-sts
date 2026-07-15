use lambda_http::http::StatusCode;
use lambda_http::{Body, Response};
use serde::Serialize;

use crate::error::AppError;

#[derive(Debug)]
pub(crate) enum AppResponse {
    Health(HealthResponse),
    Exchange(ExchangeResponse),
}

impl AppResponse {
    pub(crate) fn health(service: &'static str) -> Self {
        Self::Health(HealthResponse { ok: true, service })
    }

    pub(crate) fn exchange(
        token: impl AsRef<str>,
        expires_at: impl Into<String>,
        repository: impl Into<String>,
        git_ref: impl Into<String>,
    ) -> Self {
        Self::Exchange(ExchangeResponse {
            token: token.as_ref().to_string(),
            expires_at: expires_at.into(),
            repository: repository.into(),
            git_ref: git_ref.into(),
        })
    }

    pub(crate) fn into_response(self) -> Response<Body> {
        match self {
            Self::Health(body) => json_response(StatusCode::OK, &body),
            Self::Exchange(body) => json_response(StatusCode::OK, &body),
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct HealthResponse {
    ok: bool,
    service: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct ExchangeResponse {
    token: String,
    expires_at: String,
    repository: String,
    #[serde(rename = "ref")]
    git_ref: String,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    code: &'static str,
    error: String,
}

impl AppError {
    pub(crate) fn into_response(self) -> Response<Body> {
        let status = self.status();
        let body = ErrorResponse {
            code: self.code(),
            error: self.to_string(),
        };

        json_response(status, &body)
    }
}

fn json_response<T: Serialize>(status: StatusCode, body: &T) -> Response<Body> {
    match serde_json::to_vec(body) {
        Ok(body) => build_json_response(status, body),
        Err(_) => internal_server_error_response(),
    }
}

fn build_json_response(status: StatusCode, body: Vec<u8>) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("cache-control", "no-store")
        .header("content-type", "application/json; charset=utf-8")
        .header("x-content-type-options", "nosniff")
        .body(Body::Binary(body))
        .expect("failed to construct JSON response")
}

fn internal_server_error_response() -> Response<Body> {
    let body = ErrorResponse {
        code: "response_encoding_failed",
        error: "response encoding failed".to_string(),
    };

    let body = serde_json::to_vec(&body).unwrap_or_else(|_| {
        b"{\"code\":\"internal_server_error\",\"error\":\"internal server error\"}".to_vec()
    });

    build_json_response(StatusCode::INTERNAL_SERVER_ERROR, body)
}
