use lambda_http::http::Method;
use lambda_http::{run, service_fn, Body, Error, Request, Response};

use crate::error::AppError;
use crate::response::AppResponse;

macro_rules! impl_string_newtype {
    ($name:ident, $error_ty:ty, $error:expr $(, validate = $validate:expr)? ) => {
        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }

        impl TryFrom<String> for $name {
            type Error = $error_ty;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                let value = value.trim().to_string();
                if value.is_empty() {
                    return Err($error);
                }
                $(
                    if !($validate)(&value) {
                        return Err($error);
                    }
                )?
                Ok(Self(value))
            }
        }

        impl TryFrom<&str> for $name {
            type Error = $error_ty;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                value.to_owned().try_into()
            }
        }
    };
}

pub(crate) use impl_string_newtype;

mod config;
mod error;
mod exchange;
mod github;
mod jwks;
mod policy_cache;
mod proxy;
mod replay;
mod response;
#[cfg(test)]
mod test_keys;

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = config::Config::load().await?;

    run(service_fn(move |request: Request| {
        let config = config.clone();
        async move {
            match handle_request(config, request).await {
                Ok(response) => Ok::<Response<Body>, Error>(response.into_response()),
                Err(error) => Ok::<Response<Body>, Error>(error.into_response()),
            }
        }
    }))
    .await
}

async fn handle_request(config: config::Config, request: Request) -> Result<AppResponse, AppError> {
    match (request.method().clone(), request.uri().path()) {
        (Method::GET, "/health") => Ok(AppResponse::health("ost-simple-sts")),
        (Method::POST, "/exchange") => {
            let result = exchange::handle(config, request).await?;
            Ok(match result {
                exchange::ExchangeOutcome::Token(result) => AppResponse::exchange(
                    result.token,
                    result.expires_at,
                    result.repository,
                    result.repositories,
                    result.git_ref,
                ),
                exchange::ExchangeOutcome::Proxy(result) => AppResponse::proxy_capability(result),
            })
        }
        _ => Err(AppError::NotFound),
    }
}

#[cfg(test)]
mod integration_tests {
    use super::handle_request;
    use crate::config;
    use crate::jwks::JwksCache;
    use lambda_http::http::{Request as HttpRequest, StatusCode};
    use lambda_http::{Body, Response};
    use serde_json::{json, Value};
    use std::sync::Arc;

    fn test_config() -> config::Config {
        let policy: config::Policy = serde_json::from_value(json!({
            "expected_audience": "https://example.com",
            "rules": [{
                "subject": "repo:octo/tools:environment:release",
                "repository": "octo/tools",
                "repository_id": 42,
                "ref": "refs/heads/main",
                "workflow_path": ".github/workflows/release.yml",
                "environment": "release"
            }]
        }))
        .unwrap();

        let http_client = config::build_http_client().unwrap();
        let jwks_cache = Arc::new(JwksCache::new(http_client.clone()));

        config::Config {
            policy_location: config::PolicyLocation::for_test(),
            policy_audience: policy.expected_audience().clone(),
            policy_cache: Arc::new(crate::policy_cache::PolicyCache::with_policy(policy)),
            app_id: "123".try_into().unwrap(),
            app_private_key: "dummy-private-key".try_into().unwrap(),
            jti_table_name: "jti-table".try_into().unwrap(),
            github_api_base: "https://api.github.com".try_into().unwrap(),
            dynamodb: aws_sdk_dynamodb::Client::from_conf(
                aws_sdk_dynamodb::Config::builder()
                    .behavior_version(aws_config::BehaviorVersion::latest())
                    .region(aws_config::Region::new("us-east-1"))
                    .credentials_provider(aws_sdk_dynamodb::config::Credentials::new(
                        "test", "test", None, None, "test",
                    ))
                    .build(),
            ),
            proxy_capability: None,
            http_client,
            jwks_cache,
        }
    }

    fn response_json(response: &Response<Body>) -> Value {
        let bytes = match response.body() {
            Body::Empty => Vec::new(),
            Body::Text(text) => text.as_bytes().to_vec(),
            Body::Binary(bytes) => bytes.to_vec(),
        };

        if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        }
    }

    #[tokio::test]
    async fn health_route_returns_json_ok() {
        let response = handle_request(
            test_config(),
            HttpRequest::builder()
                .method("GET")
                .uri("/health")
                .body(Body::Empty)
                .unwrap(),
        )
        .await
        .unwrap()
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/json; charset=utf-8")
        );
        assert_eq!(
            response_json(&response),
            json!({
                "ok": true,
                "service": "ost-simple-sts"
            })
        );
    }

    #[tokio::test]
    async fn unknown_route_returns_not_found_error() {
        let response = handle_request(
            test_config(),
            HttpRequest::builder()
                .method("GET")
                .uri("/missing")
                .body(Body::Empty)
                .unwrap(),
        )
        .await
        .unwrap_err()
        .into_response();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
        assert_eq!(
            response_json(&response),
            json!({
                "code": "not_found",
                "error": "not found"
            })
        );
    }

    #[tokio::test]
    async fn exchange_get_method_returns_not_found_error() {
        let response = handle_request(
            test_config(),
            HttpRequest::builder()
                .method("GET")
                .uri("/exchange")
                .body(Body::Empty)
                .unwrap(),
        )
        .await
        .unwrap_err()
        .into_response();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response_json(&response),
            json!({
                "code": "not_found",
                "error": "not found"
            })
        );
    }

    #[tokio::test]
    async fn exchange_missing_bearer_returns_unauthorized_error() {
        let response = handle_request(
            test_config(),
            HttpRequest::builder()
                .method("POST")
                .uri("/exchange")
                .body(Body::Empty)
                .unwrap(),
        )
        .await
        .unwrap_err()
        .into_response();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response_json(&response),
            json!({
                "code": "missing_bearer_token",
                "error": "missing bearer token"
            })
        );
    }
}
