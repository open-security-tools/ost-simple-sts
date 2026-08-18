use std::{
    env,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use reqwest::{header::HeaderMap, StatusCode};
use tokio::time::sleep;

use crate::error::AppError;

const DEFAULT_GITHUB_API_URL: &str = "https://api.github.com/";
const TRUSTED_GITHUB_API_HOST: &str = "api.github.com";
const GITHUB_API_VERSION: &str = "2022-11-28";
const GITHUB_REQUEST_MAX_ATTEMPTS: usize = 2;
const GITHUB_REQUEST_INITIAL_BACKOFF: Duration = Duration::from_millis(200);
const MAX_RATE_LIMIT_ERROR_BYTES: usize = 16 * 1024;
const DEFAULT_RATE_LIMIT_BACKOFF: Duration = Duration::from_secs(60);

/// Stores the configured base URL for GitHub API requests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GithubApiBase(reqwest::Url);

impl GithubApiBase {
    pub fn from_env() -> Result<Self, AppError> {
        let value =
            env::var("GITHUB_API_URL").unwrap_or_else(|_| DEFAULT_GITHUB_API_URL.to_string());
        Self::try_from(value)
    }

    pub fn as_url(&self) -> &reqwest::Url {
        &self.0
    }

    #[cfg(test)]
    pub(crate) fn for_test(value: &str) -> Self {
        let mut url = reqwest::Url::parse(value).expect("invalid test GitHub API URL");
        assert_eq!(url.scheme(), "http");
        assert!(url.host_str().is_some_and(is_loopback_host));
        if !url.path().ends_with('/') {
            url.set_path(&format!("{}/", url.path()));
        }
        Self(url)
    }
}

impl TryFrom<String> for GithubApiBase {
    type Error = AppError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let value = value.trim();
        if value.is_empty() {
            return Err(AppError::InvalidGithubApiUrl);
        }

        let mut url = reqwest::Url::parse(value).map_err(|_| AppError::InvalidGithubApiUrl)?;
        if url.scheme() != "https"
            || url.host_str() != Some(TRUSTED_GITHUB_API_HOST)
            || url.port().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(AppError::InvalidGithubApiUrl);
        }
        if !url.path().ends_with('/') {
            url.set_path(&format!("{}/", url.path()));
        }

        Ok(Self(url))
    }
}

impl TryFrom<&str> for GithubApiBase {
    type Error = AppError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.to_string().try_into()
    }
}

pub(super) fn github_request(
    builder: reqwest::RequestBuilder,
    token: &str,
) -> reqwest::RequestBuilder {
    builder
        .bearer_auth(token)
        .header("accept", "application/vnd.github+json")
        .header("x-github-api-version", GITHUB_API_VERSION)
}

pub(super) fn github_api_url(base: &GithubApiBase, path: &str) -> Result<reqwest::Url, AppError> {
    base.as_url()
        .join(path)
        .map_err(|_| AppError::InvalidGithubApiUrl)
}

pub(super) async fn send_github_request(
    builder: reqwest::RequestBuilder,
    operation: &'static str,
) -> Result<reqwest::Response, reqwest::Error> {
    let mut builder = builder;
    let mut backoff = GITHUB_REQUEST_INITIAL_BACKOFF;

    for attempt in 1..=GITHUB_REQUEST_MAX_ATTEMPTS {
        let next_builder = (attempt < GITHUB_REQUEST_MAX_ATTEMPTS)
            .then(|| builder.try_clone())
            .flatten();

        match builder.send().await {
            Ok(response) if is_retryable_response(response.status(), response.headers()) => {
                if let Some(next_builder) = next_builder {
                    let retry_delay = backoff;
                    tracing::warn!(
                        operation,
                        attempt,
                        status = %response.status(),
                        retry_delay_ms = retry_delay.as_millis(),
                        "github request returned retryable status"
                    );
                    sleep(retry_delay).await;
                    builder = next_builder;
                    backoff = backoff.saturating_mul(2);
                    continue;
                }
                return Ok(response);
            }
            Ok(response) => return Ok(response),
            Err(error) if error.is_timeout() || error.is_connect() => {
                if let Some(next_builder) = next_builder {
                    tracing::warn!(
                        operation,
                        attempt,
                        ?error,
                        retry_delay_ms = backoff.as_millis(),
                        "github request failed with retryable transport error"
                    );
                    sleep(backoff).await;
                    builder = next_builder;
                    backoff = backoff.saturating_mul(2);
                    continue;
                }
                return Err(error);
            }
            Err(error) => return Err(error),
        }
    }

    unreachable!("github request retry loop always returns or retries")
}

#[cfg(test)]
fn is_loopback_host(host: &str) -> bool {
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

fn is_retryable_response(status: StatusCode, _headers: &HeaderMap) -> bool {
    matches!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT
    )
}

pub(super) async fn github_rate_limit(mut response: reqwest::Response) -> Option<Duration> {
    let status = response.status();
    if !matches!(status.as_u16(), 403 | 422 | 429) {
        return None;
    }

    let remaining = response
        .headers()
        .get("x-ratelimit-remaining")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    let retry_after = response
        .headers()
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs);
    let reset_after = response
        .headers()
        .get("x-ratelimit-reset")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(|reset| {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_secs();
            Duration::from_secs(reset.saturating_sub(now))
        });
    let limited_message =
        if matches!(status.as_u16(), 403 | 422) && remaining != Some(0) && retry_after.is_none() {
            let mut body = Vec::new();
            while body.len() < MAX_RATE_LIMIT_ERROR_BYTES {
                let Ok(Some(chunk)) = response.chunk().await else {
                    break;
                };
                let remaining = MAX_RATE_LIMIT_ERROR_BYTES - body.len();
                body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
            }
            let body = String::from_utf8_lossy(&body).to_ascii_lowercase();
            body.contains("secondary rate limit")
                || body.contains("abuse detection mechanism")
                || (status == StatusCode::UNPROCESSABLE_ENTITY && body.contains("spammed"))
        } else {
            false
        };

    if status == StatusCode::TOO_MANY_REQUESTS
        || remaining == Some(0)
        || retry_after.is_some()
        || limited_message
    {
        let backoff =
            retry_after.or_else(|| (remaining == Some(0)).then_some(reset_after).flatten());
        return Some(
            backoff
                .unwrap_or(DEFAULT_RATE_LIMIT_BACKOFF)
                .max(Duration::from_secs(1)),
        );
    }
    None
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    use super::{github_api_url, send_github_request, GithubApiBase};

    #[test]
    fn api_base_normalizes_path_prefixes() {
        let base = GithubApiBase::try_from("https://api.github.com/api/v3").unwrap();
        let url = github_api_url(&base, "repos/octo/tools").unwrap();

        assert_eq!(
            url.as_str(),
            "https://api.github.com/api/v3/repos/octo/tools"
        );
    }

    #[test]
    fn api_base_requires_https() {
        assert!(GithubApiBase::try_from("http://api.github.com/api/v3").is_err());
        assert!(GithubApiBase::try_from("http://127.0.0.1:8080/api/v3").is_err());
    }

    #[test]
    fn api_base_supports_loopback_for_tests() {
        let base = GithubApiBase::for_test("http://127.0.0.1:8080/api/v3");
        let url = github_api_url(&base, "repos/octo/tools").unwrap();

        assert_eq!(
            url.as_str(),
            "http://127.0.0.1:8080/api/v3/repos/octo/tools"
        );
    }

    #[test]
    fn api_base_rejects_credentials_queries_and_fragments() {
        for value in [
            "https://token@api.github.com/api/v3",
            "https://user:token@api.github.com/api/v3",
            "https://api.github.com/api/v3?token=secret",
            "https://api.github.com/api/v3#token=secret",
        ] {
            assert!(GithubApiBase::try_from(value).is_err(), "{value}");
        }
    }

    #[test]
    fn api_base_rejects_untrusted_hosts_and_ports() {
        for value in [
            "https://attacker.example/api/v3",
            "https://api.github.com.attacker.example/api/v3",
            "https://api.github.com:8443/api/v3",
        ] {
            assert!(GithubApiBase::try_from(value).is_err(), "{value}");
        }
    }

    #[tokio::test]
    async fn retries_transient_statuses_before_success() {
        let server = MockServer::start().await;
        let client = reqwest::Client::new();

        for status in [500, 502, 503, 504] {
            server.reset().await;
            Mock::given(method("GET"))
                .and(path("/retry"))
                .respond_with(ResponseTemplate::new(status))
                .up_to_n_times(1)
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/retry"))
                .respond_with(ResponseTemplate::new(200))
                .expect(1)
                .mount(&server)
                .await;

            let response = send_github_request(
                client.get(format!("{}/retry", server.uri())),
                "retryable status test",
            )
            .await
            .unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::OK);
            assert_eq!(server.received_requests().await.unwrap().len(), 2);
        }
    }

    #[tokio::test]
    async fn never_retries_rate_limits_inline() {
        for status in [403, 422, 429] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(status).insert_header("retry-after", "120"))
                .expect(1)
                .mount(&server)
                .await;
            let response = send_github_request(reqwest::Client::new().get(server.uri()), "test")
                .await
                .unwrap();
            assert_eq!(
                super::github_rate_limit(response).await,
                Some(Duration::from_secs(120))
            );
        }
    }

    #[tokio::test]
    async fn retries_timeout_errors_before_success() {
        let server = MockServer::start().await;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(20))
            .build()
            .unwrap();
        Mock::given(method("GET"))
            .and(path("/timeout"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(100)))
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/timeout"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let response = send_github_request(
            client.get(format!("{}/timeout", server.uri())),
            "timeout retry test",
        )
        .await
        .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }
}
