use std::{env, net::IpAddr, time::Duration};

use reqwest::{
    header::{HeaderMap, RETRY_AFTER},
    StatusCode,
};
use tokio::time::sleep;

use crate::error::AppError;

const DEFAULT_GITHUB_API_URL: &str = "https://api.github.com/";
const GITHUB_API_VERSION: &str = "2022-11-28";
const GITHUB_REQUEST_MAX_ATTEMPTS: usize = 2;
const GITHUB_REQUEST_INITIAL_BACKOFF: Duration = Duration::from_millis(200);
const GITHUB_REQUEST_MAX_BACKOFF: Duration = Duration::from_secs(1);

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
}

impl TryFrom<String> for GithubApiBase {
    type Error = AppError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let value = value.trim();
        if value.is_empty() {
            return Err(AppError::InvalidGithubApiUrl);
        }

        let mut url = reqwest::Url::parse(value).map_err(|_| AppError::InvalidGithubApiUrl)?;
        let allowed_scheme = match url.scheme() {
            "https" => true,
            "http" => url.host_str().is_some_and(is_loopback_host),
            _ => false,
        };
        if !allowed_scheme
            || url.host_str().is_none()
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
                    let retry_delay = retry_delay(response.status(), response.headers(), backoff);
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

fn is_loopback_host(host: &str) -> bool {
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

fn retry_delay(status: StatusCode, headers: &HeaderMap, fallback: Duration) -> Duration {
    if is_retryable_response(status, headers) {
        headers
            .get(RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<u64>().ok())
            .map(Duration::from_secs)
            .map(|delay| delay.min(GITHUB_REQUEST_MAX_BACKOFF))
            .unwrap_or(fallback)
    } else {
        fallback
    }
}

fn is_retryable_response(status: StatusCode, headers: &HeaderMap) -> bool {
    matches!(
        status,
        StatusCode::TOO_MANY_REQUESTS
            | StatusCode::INTERNAL_SERVER_ERROR
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT
    ) || (status == StatusCode::FORBIDDEN && headers.contains_key(RETRY_AFTER))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use reqwest::header::{HeaderMap, HeaderValue, RETRY_AFTER};
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    use super::{github_api_url, retry_delay, send_github_request, GithubApiBase};

    #[test]
    fn api_base_normalizes_enterprise_path_prefixes() {
        let base = GithubApiBase::try_from("https://ghe.example.com/api/v3").unwrap();
        let url = github_api_url(&base, "repos/octo/tools").unwrap();

        assert_eq!(
            url.as_str(),
            "https://ghe.example.com/api/v3/repos/octo/tools"
        );
    }

    #[test]
    fn api_base_requires_https_or_loopback() {
        assert!(GithubApiBase::try_from("http://ghe.example.com/api/v3").is_err());
        let base = GithubApiBase::try_from("http://127.0.0.1:8080/api/v3").unwrap();
        let url = github_api_url(&base, "repos/octo/tools").unwrap();

        assert_eq!(
            url.as_str(),
            "http://127.0.0.1:8080/api/v3/repos/octo/tools"
        );
    }

    #[test]
    fn api_base_rejects_credentials_queries_and_fragments() {
        for value in [
            "https://token@ghe.example.com/api/v3",
            "https://user:token@ghe.example.com/api/v3",
            "https://ghe.example.com/api/v3?token=secret",
            "https://ghe.example.com/api/v3#token=secret",
        ] {
            assert!(GithubApiBase::try_from(value).is_err(), "{value}");
        }
    }

    #[test]
    fn retry_delay_bounds_retry_after() {
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("7"));

        assert_eq!(
            retry_delay(
                reqwest::StatusCode::TOO_MANY_REQUESTS,
                &headers,
                Duration::from_millis(200)
            ),
            Duration::from_secs(1)
        );
    }

    #[tokio::test]
    async fn retries_transient_statuses_before_success() {
        let server = MockServer::start().await;
        let client = reqwest::Client::new();

        for status in [429, 500, 502, 503, 504] {
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
    async fn retries_secondary_rate_limits_but_not_plain_forbidden() {
        let server = MockServer::start().await;
        let client = reqwest::Client::new();
        Mock::given(method("GET"))
            .and(path("/secondary-rate-limit"))
            .respond_with(ResponseTemplate::new(403).insert_header("retry-after", "1"))
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/secondary-rate-limit"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let response = send_github_request(
            client.get(format!("{}/secondary-rate-limit", server.uri())),
            "secondary rate limit test",
        )
        .await
        .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);

        server.reset().await;
        Mock::given(method("GET"))
            .and(path("/forbidden"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&server)
            .await;
        let response = send_github_request(
            client.get(format!("{}/forbidden", server.uri())),
            "forbidden test",
        )
        .await
        .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
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
