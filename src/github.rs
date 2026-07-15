use std::{
    env, fmt,
    net::IpAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use reqwest::{
    header::{HeaderMap, RETRY_AFTER},
    StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::time::sleep;

use crate::error::AppError;

const DEFAULT_GITHUB_API_URL: &str = "https://api.github.com/";
const GITHUB_API_VERSION: &str = "2022-11-28";
const GITHUB_REQUEST_MAX_ATTEMPTS: usize = 3;
const GITHUB_REQUEST_INITIAL_BACKOFF: Duration = Duration::from_millis(200);
const MIN_TOKEN_LIFETIME_MINUTES: u64 = 10;
const MAX_TOKEN_LIFETIME_MINUTES: u64 = 60;

macro_rules! id_type {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
        pub struct $name(u64);

        impl $name {
            pub fn new(value: u64) -> Option<Self> {
                (value != 0).then_some(Self(value))
            }
        }

        impl std::ops::Deref for $name {
            type Target = u64;

            fn deref(&self) -> &u64 {
                &self.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                struct Visitor;

                impl serde::de::Visitor<'_> for Visitor {
                    type Value = $name;

                    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                        write!(f, "a non-zero {} as a number or string", stringify!($name))
                    }

                    fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                        $name::new(v).ok_or_else(|| {
                            E::custom(concat!(stringify!($name), " must be non-zero"))
                        })
                    }

                    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                        let n = v.parse::<u64>().map_err(E::custom)?;
                        $name::new(n).ok_or_else(|| {
                            E::custom(concat!(stringify!($name), " must be non-zero"))
                        })
                    }
                }

                deserializer.deserialize_any(Visitor)
            }
        }
    };
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GithubApiBase(reqwest::Url);

id_type!(RepositoryId);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositoryOwner(String);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositoryNamePart(String);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositoryFullName {
    full_name: String,
    owner: RepositoryOwner,
    repo: RepositoryNamePart,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Jti(String);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExpiresInMinutes(u64);

#[derive(Clone, PartialEq, Eq)]
pub struct Token(String);

impl Token {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for Token {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(<redacted>)")
    }
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl<'de> Deserialize<'de> for Token {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self)
    }
}

#[derive(Debug, Deserialize)]
pub struct InstallationToken {
    pub token: Token,
    pub expires_at: String,
}

#[derive(Debug, Serialize)]
struct AppJwtClaims<'a> {
    iat: u64,
    exp: u64,
    iss: &'a str,
}

#[derive(Debug, Deserialize)]
struct RepositoryInstallation {
    id: u64,
}

fn is_valid_slug(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.'
        })
        && value != "."
        && value != ".."
}

crate::impl_string_newtype!(
    RepositoryOwner,
    AppError,
    AppError::RepositoryClaimInvalid,
    validate = is_valid_slug
);
crate::impl_string_newtype!(
    RepositoryNamePart,
    AppError,
    AppError::RepositoryClaimInvalid,
    validate = is_valid_slug
);
crate::impl_string_newtype!(Jti, AppError, AppError::OidcTokenMissingJti);

impl ExpiresInMinutes {
    pub fn get(self) -> u64 {
        self.0
    }
}

impl GithubApiBase {
    pub fn from_env() -> Result<Self, AppError> {
        let github_api_url =
            env::var("GITHUB_API_URL").unwrap_or_else(|_| DEFAULT_GITHUB_API_URL.to_string());
        Self::try_from(github_api_url)
    }

    pub fn as_url(&self) -> &reqwest::Url {
        &self.0
    }
}

impl AsRef<reqwest::Url> for GithubApiBase {
    fn as_ref(&self) -> &reqwest::Url {
        self.as_url()
    }
}

impl TryFrom<reqwest::Url> for GithubApiBase {
    type Error = AppError;

    fn try_from(value: reqwest::Url) -> Result<Self, Self::Error> {
        if !has_allowed_github_api_scheme(&value) {
            return Err(AppError::InvalidGithubApiUrl);
        }

        Ok(Self(normalize_github_api_base(value)))
    }
}

impl TryFrom<String> for GithubApiBase {
    type Error = AppError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let value = value.trim().to_string();
        if value.is_empty() {
            return Err(AppError::InvalidGithubApiUrl);
        }

        let url = reqwest::Url::parse(&value).map_err(|_| AppError::InvalidGithubApiUrl)?;
        Self::try_from(url)
    }
}

impl TryFrom<&str> for GithubApiBase {
    type Error = AppError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.to_string().try_into()
    }
}

impl RepositoryFullName {
    pub fn as_str(&self) -> &str {
        &self.full_name
    }

    pub fn owner(&self) -> &RepositoryOwner {
        &self.owner
    }

    pub fn repo(&self) -> &RepositoryNamePart {
        &self.repo
    }
}

impl AsRef<str> for RepositoryFullName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for RepositoryFullName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.full_name.fmt(f)
    }
}

impl TryFrom<(String, String)> for RepositoryFullName {
    type Error = AppError;

    fn try_from((owner, repo): (String, String)) -> Result<Self, Self::Error> {
        let owner = RepositoryOwner::try_from(owner)?;
        let repo = RepositoryNamePart::try_from(repo)?;
        let full_name = format!("{owner}/{repo}");
        Ok(Self {
            full_name,
            owner,
            repo,
        })
    }
}

impl TryFrom<String> for RepositoryFullName {
    type Error = AppError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let mut parts = value.split('/');
        let owner = parts.next().unwrap_or_default();
        let repo = parts.next().unwrap_or_default();
        if owner.is_empty() || repo.is_empty() || parts.next().is_some() {
            return Err(AppError::RepositoryClaimInvalid);
        }
        Self::try_from((owner.to_string(), repo.to_string()))
    }
}

impl TryFrom<&str> for RepositoryFullName {
    type Error = AppError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.to_string().try_into()
    }
}

impl TryFrom<&str> for ExpiresInMinutes {
    type Error = AppError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let value = value
            .parse::<u64>()
            .map_err(|_| AppError::InvalidExpiresIn)?;
        if !(MIN_TOKEN_LIFETIME_MINUTES..=MAX_TOKEN_LIFETIME_MINUTES).contains(&value) {
            return Err(AppError::InvalidExpiresIn);
        }

        Ok(Self(value))
    }
}

pub fn create_app_jwt(
    app_id: impl AsRef<str>,
    private_key_pem: impl AsRef<str>,
) -> Result<String, AppError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs();

    let claims = AppJwtClaims {
        iat: now.saturating_sub(60),
        exp: now + 9 * 60,
        iss: app_id.as_ref(),
    };

    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("JWT".to_string());

    jsonwebtoken::encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(private_key_pem.as_ref().as_bytes()).map_err(|error| {
            tracing::error!(?error, "failed to parse github app private key");
            AppError::GithubAppAuthInvalid
        })?,
    )
    .map_err(|error| {
        tracing::error!(?error, "failed to encode github app jwt");
        AppError::GithubAppAuthInvalid
    })
}

pub async fn find_installation(
    http_client: &reqwest::Client,
    github_api_base: &GithubApiBase,
    app_jwt: &str,
    owner: &str,
    repo: &str,
) -> Result<u64, AppError> {
    let url = github_api_url(
        github_api_base,
        &format!("repos/{owner}/{repo}/installation"),
    )?;

    let response = send_github_request(
        github_request(http_client.get(url), app_jwt),
        "installation lookup",
    )
    .await
    .map_err(|error| {
        tracing::error!(?error, "installation lookup request failed");
        AppError::GithubInstallationLookupFailed
    })?;

    match response.status().as_u16() {
        200 => {
            let installation =
                response
                    .json::<RepositoryInstallation>()
                    .await
                    .map_err(|error| {
                        tracing::error!(?error, "failed to decode installation lookup response");
                        AppError::GithubInstallationLookupFailed
                    })?;
            Ok(installation.id)
        }
        401 => Err(AppError::GithubAppAuthInvalid),
        403 => Err(AppError::GithubInstallationLookupForbidden),
        404 => Err(AppError::AppNotInstalled),
        _ => {
            tracing::error!(status = %response.status(), "unexpected installation lookup status");
            Err(AppError::GithubInstallationLookupFailed)
        }
    }
}

pub async fn mint_installation_token(
    http_client: &reqwest::Client,
    github_api_base: &GithubApiBase,
    app_jwt: &str,
    installation_id: u64,
    repository_ids: &[u64],
    permissions: Value,
    expires_at: Option<&str>,
) -> Result<InstallationToken, AppError> {
    let url = github_api_url(
        github_api_base,
        &format!("app/installations/{installation_id}/access_tokens"),
    )?;

    let mut payload = json!({
        "repository_ids": repository_ids,
        "permissions": permissions,
    });
    if let Some(expires_at) = expires_at {
        payload["expires_at"] = Value::String(expires_at.to_string());
    }

    // TODO: Revisit retries here. This endpoint is non-idempotent, so retrying after
    // an ambiguous transport failure can mint multiple valid installation tokens.
    let response = send_github_request(
        github_request(http_client.post(url), app_jwt).json(&payload),
        "installation token request",
    )
    .await
    .map_err(|error| {
        tracing::error!(?error, "installation token request failed");
        AppError::GithubAccessTokenRequestFailed
    })?;

    match response.status().as_u16() {
        201 => response.json::<InstallationToken>().await.map_err(|error| {
            tracing::error!(?error, "failed to decode installation token response");
            AppError::GithubAccessTokenRequestFailed
        }),
        401 => Err(AppError::GithubAppAuthInvalid),
        403 => Err(AppError::GithubAccessTokenRequestForbidden),
        404 => Err(AppError::InstallationNotFound),
        422 => Err(AppError::InstallationTokenRequestInvalid),
        _ => {
            tracing::error!(status = %response.status(), "unexpected installation token status");
            Err(AppError::GithubAccessTokenRequestFailed)
        }
    }
}

fn github_request(builder: reqwest::RequestBuilder, token: &str) -> reqwest::RequestBuilder {
    builder
        .bearer_auth(token)
        .header("accept", "application/vnd.github+json")
        .header("x-github-api-version", GITHUB_API_VERSION)
}

async fn send_github_request(
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
            Err(error) if is_retryable_error(&error) => {
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

fn github_api_url(base: &GithubApiBase, path: &str) -> Result<reqwest::Url, AppError> {
    base.as_url()
        .join(path)
        .map_err(|_| AppError::InvalidGithubApiUrl)
}

fn has_allowed_github_api_scheme(url: &reqwest::Url) -> bool {
    match url.scheme() {
        "https" => true,
        "http" => url.host_str().is_some_and(is_loopback_host),
        _ => false,
    }
}

fn is_loopback_host(host: &str) -> bool {
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);

    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

fn normalize_github_api_base(mut url: reqwest::Url) -> reqwest::Url {
    if !url.path().ends_with('/') {
        let normalized_path = format!("{}/", url.path());
        url.set_path(&normalized_path);
    }

    url
}

fn retry_delay(status: StatusCode, headers: &HeaderMap, fallback: Duration) -> Duration {
    if is_retryable_response(status, headers) {
        retry_after_delay(headers).unwrap_or(fallback)
    } else {
        fallback
    }
}

fn retry_after_delay(headers: &HeaderMap) -> Option<Duration> {
    headers
        .get(RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
}

fn is_retryable_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::TOO_MANY_REQUESTS
            | StatusCode::INTERNAL_SERVER_ERROR
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT
    )
}

fn is_retryable_response(status: StatusCode, headers: &HeaderMap) -> bool {
    is_retryable_status(status)
        || (status == StatusCode::FORBIDDEN && headers.contains_key(RETRY_AFTER))
}

fn is_retryable_error(error: &reqwest::Error) -> bool {
    error.is_timeout() || error.is_connect()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use reqwest::header::{HeaderMap, HeaderValue, RETRY_AFTER};
    use serde_json::json;
    use wiremock::{
        matchers::{body_json, header, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    use super::{
        find_installation, mint_installation_token, retry_delay, send_github_request,
        GithubApiBase, RepositoryFullName, RepositoryNamePart, RepositoryOwner,
    };
    use crate::error::AppError;

    fn test_http_client() -> reqwest::Client {
        reqwest::Client::builder().build().unwrap()
    }

    fn test_http_client_with_timeout(timeout: Duration) -> reqwest::Client {
        reqwest::Client::builder().timeout(timeout).build().unwrap()
    }

    fn test_base_url(server: &MockServer) -> GithubApiBase {
        GithubApiBase::try_from(server.uri().as_str()).unwrap()
    }

    #[test]
    fn github_api_base_normalizes_trailing_slash_for_path_prefixes() {
        let base = GithubApiBase::try_from(String::from("https://ghe.example.com/api/v3")).unwrap();

        let url = super::github_api_url(&base, "repos/octo/tools").unwrap();

        assert_eq!(
            url.as_str(),
            "https://ghe.example.com/api/v3/repos/octo/tools"
        );
    }

    #[test]
    fn github_api_base_rejects_non_https_non_loopback_urls() {
        assert!(GithubApiBase::try_from(String::from("http://ghe.example.com/api/v3")).is_err());
    }

    #[test]
    fn github_api_base_accepts_http_loopback_urls() {
        let base = GithubApiBase::try_from(String::from("http://127.0.0.1:8080/api/v3")).unwrap();

        let url = super::github_api_url(&base, "repos/octo/tools").unwrap();

        assert_eq!(
            url.as_str(),
            "http://127.0.0.1:8080/api/v3/repos/octo/tools"
        );
    }

    #[test]
    fn repository_owner_rejects_unsafe_characters() {
        assert!(RepositoryOwner::try_from(String::from("..")).is_err());
        assert!(RepositoryOwner::try_from(String::from("foo#bar")).is_err());
        assert!(RepositoryOwner::try_from(String::from("foo?x=1")).is_err());
        assert!(RepositoryOwner::try_from(String::from("valid-owner")).is_ok());
    }

    #[test]
    fn repository_name_rejects_unsafe_characters() {
        assert!(RepositoryNamePart::try_from(String::from("..")).is_err());
        assert!(RepositoryNamePart::try_from(String::from("repo#frag")).is_err());
        assert!(RepositoryNamePart::try_from(String::from("valid.repo-name_1")).is_ok());
    }

    #[test]
    fn repository_from_full_name_rejects_unsafe_components() {
        assert!(RepositoryFullName::try_from(String::from("../evil")).is_err());
        assert!(RepositoryFullName::try_from(String::from("owner/..")).is_err());
        assert!(RepositoryFullName::try_from(String::from("ok-owner/ok-repo")).is_ok());
    }

    #[test]
    fn retry_delay_uses_retry_after_when_present() {
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("7"));

        assert_eq!(
            retry_delay(
                reqwest::StatusCode::TOO_MANY_REQUESTS,
                &headers,
                Duration::from_millis(200)
            ),
            Duration::from_secs(7)
        );
    }

    #[tokio::test]
    async fn send_github_request_retries_retryable_statuses_once_before_success() {
        let server = MockServer::start().await;
        let client = test_http_client();

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
    async fn send_github_request_retries_forbidden_with_retry_after_before_success() {
        let server = MockServer::start().await;
        let client = test_http_client();

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
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn send_github_request_does_not_retry_forbidden_without_retry_after() {
        let server = MockServer::start().await;
        let client = test_http_client();

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
    async fn send_github_request_retries_timeout_errors_before_success() {
        let server = MockServer::start().await;
        let client = test_http_client_with_timeout(Duration::from_millis(20));

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

    #[tokio::test]
    async fn find_installation_returns_installation_id() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/octo/tools/installation"))
            .and(header("authorization", "Bearer app-jwt"))
            .and(header("accept", "application/vnd.github+json"))
            .and(header("x-github-api-version", "2022-11-28"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 456 })))
            .mount(&server)
            .await;

        let id = find_installation(
            &test_http_client(),
            &test_base_url(&server),
            "app-jwt",
            "octo",
            "tools",
        )
        .await
        .unwrap();

        assert_eq!(id, 456);
    }

    #[tokio::test]
    async fn find_installation_retries_transient_failure_before_success() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/repos/octo/tools/installation"))
            .respond_with(ResponseTemplate::new(500))
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/repos/octo/tools/installation"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 456 })))
            .expect(1)
            .mount(&server)
            .await;

        let id = find_installation(
            &test_http_client(),
            &test_base_url(&server),
            "app-jwt",
            "octo",
            "tools",
        )
        .await
        .unwrap();

        assert_eq!(id, 456);
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn find_installation_returns_not_installed_on_404() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/octo/tools/installation"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let error = find_installation(
            &test_http_client(),
            &test_base_url(&server),
            "app-jwt",
            "octo",
            "tools",
        )
        .await
        .unwrap_err();

        assert!(matches!(error, AppError::AppNotInstalled));
    }

    #[tokio::test]
    async fn mint_installation_token_posts_expected_request() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/app/installations/123/access_tokens"))
            .and(header("authorization", "Bearer app-jwt"))
            .and(body_json(json!({
                "repository_ids": [42],
                "permissions": { "contents": "write" },
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "token": "ghs_test123",
                "expires_at": "2026-03-28T00:00:00Z"
            })))
            .mount(&server)
            .await;

        let token = mint_installation_token(
            &test_http_client(),
            &test_base_url(&server),
            "app-jwt",
            123,
            &[42],
            json!({ "contents": "write" }),
            None,
        )
        .await
        .unwrap();

        assert_eq!(token.token.as_str(), "ghs_test123");
        assert_eq!(token.expires_at, "2026-03-28T00:00:00Z");
    }

    #[tokio::test]
    async fn mint_installation_token_retries_transient_failure_before_success() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/app/installations/123/access_tokens"))
            .respond_with(ResponseTemplate::new(500))
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/app/installations/123/access_tokens"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "token": "ghs_retry",
                "expires_at": "2026-03-28T00:00:00Z"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let token = mint_installation_token(
            &test_http_client(),
            &test_base_url(&server),
            "app-jwt",
            123,
            &[42],
            json!({ "contents": "write" }),
            None,
        )
        .await
        .unwrap();

        assert_eq!(token.token.as_str(), "ghs_retry");
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn mint_installation_token_maps_error_statuses() {
        let server = MockServer::start().await;

        for (status, expected) in [
            (401, "GithubAppAuthInvalid"),
            (403, "GithubAccessTokenRequestForbidden"),
            (404, "InstallationNotFound"),
            (422, "InstallationTokenRequestInvalid"),
            (500, "GithubAccessTokenRequestFailed"),
        ] {
            Mock::given(method("POST"))
                .and(path("/app/installations/999/access_tokens"))
                .respond_with(ResponseTemplate::new(status))
                .mount(&server)
                .await;

            let error = mint_installation_token(
                &test_http_client(),
                &test_base_url(&server),
                "app-jwt",
                999,
                &[1],
                json!({ "contents": "write" }),
                None,
            )
            .await
            .unwrap_err();

            assert!(
                format!("{error:?}").contains(expected),
                "status {status} should produce {expected}, got {error:?}"
            );

            server.reset().await;
        }
    }
}
