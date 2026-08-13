use lambda_http::http::StatusCode;
use lambda_http::{Body, Response};
use serde::Serialize;

use crate::{error::AppError, github::Token, proxy::ProxyCapabilityResult};

#[derive(Debug)]
pub(crate) enum AppResponse {
    Health(HealthResponse),
    Exchange(ExchangeResponse),
    ProxyCapability(ProxyCapabilityResult),
}

impl AppResponse {
    pub(crate) fn health(service: &'static str) -> Self {
        Self::Health(HealthResponse { ok: true, service })
    }

    pub(crate) fn exchange(
        token: Token,
        expires_at: impl Into<String>,
        repository: Option<String>,
        repositories: Option<Vec<String>>,
        git_ref: impl Into<String>,
    ) -> Self {
        Self::Exchange(ExchangeResponse {
            token,
            expires_at: expires_at.into(),
            repository,
            repositories,
            git_ref: git_ref.into(),
        })
    }

    pub(crate) fn into_response(self) -> Response<Body> {
        match self {
            Self::Health(body) => json_response(StatusCode::OK, &body),
            Self::Exchange(body) => json_response(StatusCode::OK, &body),
            Self::ProxyCapability(body) => json_response(StatusCode::OK, &body),
        }
    }

    pub(crate) fn proxy_capability(capability: ProxyCapabilityResult) -> Self {
        Self::ProxyCapability(capability)
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct HealthResponse {
    ok: bool,
    service: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct ExchangeResponse {
    token: Token,
    expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    repository: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    repositories: Option<Vec<String>>,
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

#[cfg(test)]
mod tests {
    use lambda_http::Body;
    use serde_json::json;

    use super::AppResponse;
    use crate::{github::Token, proxy::ProxyCapabilityResult};

    #[test]
    fn exchange_response_redacts_debug_and_serializes_token() {
        let token: Token = serde_json::from_str(r#""ghs_secret""#).unwrap();
        let response = AppResponse::exchange(
            token,
            "2026-03-28T00:00:00Z",
            Some("octo/tools".to_string()),
            None,
            "refs/heads/main",
        );

        assert!(!format!("{response:?}").contains("ghs_secret"));

        let response = response.into_response();
        let Body::Binary(body) = response.body() else {
            panic!("expected JSON response body");
        };
        let body: serde_json::Value = serde_json::from_slice(body).unwrap();
        assert_eq!(
            body,
            json!({
                "token": "ghs_secret",
                "expires_at": "2026-03-28T00:00:00Z",
                "repository": "octo/tools",
                "ref": "refs/heads/main"
            })
        );
    }

    #[test]
    fn multi_repository_exchange_response_serializes_the_exact_target_set() {
        let token: Token = serde_json::from_str(r#""ghs_secret""#).unwrap();
        let response = AppResponse::exchange(
            token,
            "2026-03-28T00:00:00Z",
            None,
            Some(vec!["octo/tools".to_string(), "octo/tools-dev".to_string()]),
            "refs/heads/main",
        );

        let response = response.into_response();
        let Body::Binary(body) = response.body() else {
            panic!("expected JSON response body");
        };
        let body: serde_json::Value = serde_json::from_slice(body).unwrap();
        assert_eq!(
            body,
            json!({
                "token": "ghs_secret",
                "expires_at": "2026-03-28T00:00:00Z",
                "repositories": ["octo/tools", "octo/tools-dev"],
                "ref": "refs/heads/main"
            })
        );
    }

    #[test]
    fn proxy_capability_response_redacts_debug_and_never_contains_a_github_token() {
        let response = AppResponse::proxy_capability(ProxyCapabilityResult {
            capability: "encrypted-session".to_owned().into(),
            expires_at: "2099-01-01T00:00:00Z".to_owned(),
            repository: "octo/tools".to_owned(),
            caller_ref: "refs/heads/main".to_owned(),
            branch: "refs/heads/automation/fix".to_owned(),
            expected_old_oid: "a".repeat(40),
        });
        assert!(!format!("{response:?}").contains("encrypted-session"));

        let response = response.into_response();
        let Body::Binary(body) = response.body() else {
            panic!("expected JSON response body");
        };
        let body: serde_json::Value = serde_json::from_slice(body).unwrap();

        assert_eq!(body["capability"], "encrypted-session");
        assert_eq!(body["branch"], "refs/heads/automation/fix");
        assert!(body.get("token").is_none());
    }
}
