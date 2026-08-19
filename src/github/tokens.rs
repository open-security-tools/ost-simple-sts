use std::{
    collections::BTreeMap,
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::api::{github_api_url, github_request, send_github_request, GithubApiBase};
use super::{Permissions, RepositoryFullName, RepositoryId};
use crate::error::AppError;

/// Wraps a sensitive GitHub access token while redacting debug and display output.
#[derive(Clone, PartialEq, Eq)]
pub struct Token(String);

/// Contains the installation token returned by GitHub.
#[derive(Debug, Deserialize)]
pub struct InstallationToken {
    pub token: Token,
    pub expires_at: String,
    repositories: Vec<GrantedRepository>,
    #[serde(default)]
    permissions: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct GrantedRepository {
    id: u64,
    full_name: String,
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

impl Serialize for Token {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

pub fn create_app_jwt(
    app_id: impl AsRef<str>,
    private_key_pem: impl AsRef<str>,
) -> Result<String, AppError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    let claims = AppJwtClaims {
        iat: now.saturating_sub(60),
        exp: now.saturating_add(9 * 60),
        iss: app_id.as_ref(),
    };
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("JWT".to_string());
    let key = EncodingKey::from_rsa_pem(private_key_pem.as_ref().as_bytes()).map_err(|error| {
        tracing::error!(?error, "failed to parse github app private key");
        AppError::GithubAppAuthInvalid
    })?;

    jsonwebtoken::encode(&header, &claims, &key).map_err(|error| {
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
        200 => response
            .json::<RepositoryInstallation>()
            .await
            .map(|installation| installation.id)
            .map_err(|error| {
                tracing::error!(?error, "failed to decode installation lookup response");
                AppError::GithubInstallationLookupFailed
            }),
        401 => Err(AppError::GithubAppAuthInvalid),
        403 => Err(AppError::GithubInstallationLookupForbidden),
        404 => Err(AppError::AppNotInstalled),
        status => {
            tracing::error!(status, "unexpected installation lookup status");
            Err(AppError::GithubInstallationLookupFailed)
        }
    }
}

pub async fn mint_installation_token(
    http_client: &reqwest::Client,
    github_api_base: &GithubApiBase,
    app_jwt: &str,
    installation_id: u64,
    repositories: &[(RepositoryFullName, RepositoryId)],
    permissions: &Permissions,
) -> Result<InstallationToken, AppError> {
    let url = github_api_url(
        github_api_base,
        &format!("app/installations/{installation_id}/access_tokens"),
    )?;
    let payload = json!({
        "repository_ids": repositories.iter().map(|(_, id)| *id).collect::<Vec<_>>(),
        "permissions": permissions,
    });

    let response = github_request(http_client.post(url), app_jwt)
        .json(&payload)
        .send()
        .await
        .map_err(|error| {
            tracing::error!(?error, "installation token request failed");
            AppError::GithubAccessTokenRequestFailed
        })?;

    match response.status().as_u16() {
        201 => {
            let token = response
                .json::<InstallationToken>()
                .await
                .map_err(|error| {
                    tracing::error!(?error, "failed to decode installation token response");
                    AppError::GithubAccessTokenRequestFailed
                })?;
            if !permissions.matches_response(&token.permissions)
                || token.repositories.len() != repositories.len()
                || !repositories.iter().all(|(repository, repository_id)| {
                    token.repositories.iter().any(|granted| {
                        granted.id == **repository_id && granted.full_name == repository.as_str()
                    })
                })
            {
                tracing::error!("github returned an unexpectedly scoped installation token");
                return Err(AppError::InstallationTokenRequestInvalid);
            }
            Ok(token)
        }
        401 => Err(AppError::GithubAppAuthInvalid),
        403 => Err(AppError::GithubAccessTokenRequestForbidden),
        404 => Err(AppError::InstallationNotFound),
        422 => Err(AppError::InstallationTokenRequestInvalid),
        status => {
            tracing::error!(status, "unexpected installation token status");
            Err(AppError::GithubAccessTokenRequestFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wiremock::{
        matchers::{body_json, header, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    use super::{find_installation, mint_installation_token, Token};
    use crate::{
        error::AppError,
        github::{GithubApiBase, Permissions, RepositoryFullName},
    };

    #[test]
    fn token_debug_and_display_are_redacted() {
        let token = Token("ghs_secret".to_string());

        assert_eq!(format!("{token:?}"), "Token(<redacted>)");
        assert_eq!(format!("{token}"), "<redacted>");
        assert_eq!(token.as_str(), "ghs_secret");
        assert_eq!(serde_json::to_string(&token).unwrap(), r#""ghs_secret""#);
    }

    #[tokio::test]
    async fn finds_repository_installation() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/octo/tools/installation"))
            .and(header("authorization", "Bearer app-jwt"))
            .and(header("accept", "application/vnd.github+json"))
            .and(header("x-github-api-version", "2022-11-28"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 456 })))
            .expect(1)
            .mount(&server)
            .await;

        let id = find_installation(
            &reqwest::Client::new(),
            &GithubApiBase::for_test(server.uri().as_str()),
            "app-jwt",
            "octo",
            "tools",
        )
        .await
        .unwrap();
        assert_eq!(id, 456);
    }

    #[tokio::test]
    async fn retries_transient_installation_lookup_failure() {
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
            &reqwest::Client::new(),
            &GithubApiBase::for_test(server.uri().as_str()),
            "app-jwt",
            "octo",
            "tools",
        )
        .await
        .unwrap();
        assert_eq!(id, 456);
    }

    #[tokio::test]
    async fn maps_missing_installation() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/octo/tools/installation"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;

        let error = find_installation(
            &reqwest::Client::new(),
            &GithubApiBase::for_test(server.uri().as_str()),
            "app-jwt",
            "octo",
            "tools",
        )
        .await
        .unwrap_err();
        assert!(matches!(error, AppError::AppNotInstalled));
    }

    #[tokio::test]
    async fn mints_a_scoped_installation_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/app/installations/123/access_tokens"))
            .and(header("authorization", "Bearer app-jwt"))
            .and(body_json(json!({
                "repository_ids": [42],
                "permissions": { "contents": "write", "pull_requests": "read" }
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "token": "ghs_test123",
                "expires_at": "2026-03-28T00:00:00Z",
                "permissions": {"contents": "write", "pull_requests": "read"},
                "repositories": [{ "id": 42, "full_name": "octo/tools" }]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let token = mint_installation_token(
            &reqwest::Client::new(),
            &GithubApiBase::for_test(server.uri().as_str()),
            "app-jwt",
            123,
            &[(
                RepositoryFullName::try_from("octo/tools").unwrap(),
                serde_json::from_value(json!(42)).unwrap(),
            )],
            &serde_json::from_value(json!({ "contents": "write", "pull_requests": "read" }))
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(token.token.as_str(), "ghs_test123");
        assert_eq!(token.expires_at, "2026-03-28T00:00:00Z");
    }

    #[tokio::test]
    async fn validates_returned_permissions() {
        let server = MockServer::start().await;
        for (granted, accepted) in [
            (json!({"contents":"read"}), true),
            (json!({"contents":"read", "metadata":"read"}), true),
            (json!({}), false),
            (json!({"contents":"write"}), false),
            (json!({"contents":"read", "issues":"write"}), false),
            (json!({"contents":"read", "metadata":"write"}), false),
        ] {
            server.reset().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                    "token":"test", "expires_at":"2026-08-18T00:00:00Z",
                    "repositories":[{"id":42,"full_name":"octo/tools"}], "permissions":granted
                })))
                .expect(1)
                .mount(&server)
                .await;
            let result = mint_installation_token(
                &reqwest::Client::new(),
                &GithubApiBase::for_test(&server.uri()),
                "app",
                123,
                &[(
                    RepositoryFullName::try_from("octo/tools").unwrap(),
                    serde_json::from_value(json!(42)).unwrap(),
                )],
                &serde_json::from_value(json!({"contents":"read"})).unwrap(),
            )
            .await;
            assert_eq!(result.is_ok(), accepted, "{granted}");
        }
    }

    #[tokio::test]
    async fn does_not_retry_token_creation() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/app/installations/123/access_tokens"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;

        let error = mint_installation_token(
            &reqwest::Client::new(),
            &GithubApiBase::for_test(server.uri().as_str()),
            "app-jwt",
            123,
            &[(
                RepositoryFullName::try_from("octo/tools").unwrap(),
                serde_json::from_value(json!(42)).unwrap(),
            )],
            &Permissions::contents_write(),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, AppError::GithubAccessTokenRequestFailed));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn maps_token_request_error_statuses() {
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
                &reqwest::Client::new(),
                &GithubApiBase::for_test(server.uri().as_str()),
                "app-jwt",
                999,
                &[(
                    RepositoryFullName::try_from("octo/tools").unwrap(),
                    serde_json::from_value(json!(1)).unwrap(),
                )],
                &Permissions::contents_write(),
            )
            .await
            .unwrap_err();
            assert!(format!("{error:?}").contains(expected));
            server.reset().await;
        }
    }

    #[tokio::test]
    async fn rejects_an_unexpectedly_scoped_installation_token() {
        let server = MockServer::start().await;
        let target = RepositoryFullName::try_from("octo/tools").unwrap();

        for repositories in [
            json!([]),
            json!([{ "id": 43, "full_name": "octo/tools" }]),
            json!([{ "id": 42, "full_name": "octo/other" }]),
            json!([
                { "id": 42, "full_name": "octo/tools" },
                { "id": 43, "full_name": "octo/other" }
            ]),
        ] {
            Mock::given(method("POST"))
                .and(path("/app/installations/123/access_tokens"))
                .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                    "token": "ghs_test123",
                    "expires_at": "2026-03-28T00:00:00Z",
                "permissions": {"contents": "write"},
                    "repositories": repositories
                })))
                .mount(&server)
                .await;

            let error = mint_installation_token(
                &reqwest::Client::new(),
                &GithubApiBase::for_test(server.uri().as_str()),
                "app-jwt",
                123,
                &[(target.clone(), serde_json::from_value(json!(42)).unwrap())],
                &Permissions::contents_write(),
            )
            .await
            .unwrap_err();
            assert!(matches!(error, AppError::InstallationTokenRequestInvalid));
            server.reset().await;
        }
    }

    #[tokio::test]
    async fn mints_and_verifies_an_exact_multi_repository_installation_token() {
        let server = MockServer::start().await;
        let targets = vec![
            (
                RepositoryFullName::try_from("astral-sh/uv").unwrap(),
                serde_json::from_value(json!(699532645)).unwrap(),
            ),
            (
                RepositoryFullName::try_from("astral-sh/uv-dev").unwrap(),
                serde_json::from_value(json!(1302176231)).unwrap(),
            ),
        ];
        Mock::given(method("POST"))
            .and(path("/app/installations/146796415/access_tokens"))
            .and(body_json(json!({
                "repository_ids": [699532645, 1302176231],
                "permissions": { "contents": "write", "pull_requests": "write" }
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "token": "ghs_multi",
                "expires_at": "2026-03-28T00:00:00Z",
                "permissions": {"contents": "write", "pull_requests": "write"},
                "repositories": [
                    { "id": 1302176231, "full_name": "astral-sh/uv-dev" },
                    { "id": 699532645, "full_name": "astral-sh/uv" }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let token = mint_installation_token(
            &reqwest::Client::new(),
            &GithubApiBase::for_test(server.uri().as_str()),
            "app-jwt",
            146796415,
            &targets,
            &serde_json::from_value(json!({ "contents": "write", "pull_requests": "write" }))
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(token.token.as_str(), "ghs_multi");
    }

    #[tokio::test]
    async fn rejects_an_unexpected_multi_repository_installation_token_scope() {
        let server = MockServer::start().await;
        let targets = vec![
            (
                RepositoryFullName::try_from("astral-sh/uv").unwrap(),
                serde_json::from_value(json!(699532645)).unwrap(),
            ),
            (
                RepositoryFullName::try_from("astral-sh/uv-dev").unwrap(),
                serde_json::from_value(json!(1302176231)).unwrap(),
            ),
        ];

        for repositories in [
            json!([]),
            json!([{ "id": 699532645, "full_name": "astral-sh/uv" }]),
            json!([
                { "id": 699532645, "full_name": "astral-sh/uv" },
                { "id": 1302176232, "full_name": "astral-sh/uv-dev" }
            ]),
            json!([
                { "id": 699532645, "full_name": "astral-sh/uv" },
                { "id": 1302176231, "full_name": "astral-sh/other" }
            ]),
            json!([
                { "id": 699532645, "full_name": "astral-sh/uv" },
                { "id": 699532645, "full_name": "astral-sh/uv" }
            ]),
            json!([
                { "id": 699532645, "full_name": "astral-sh/uv" },
                { "id": 1302176231, "full_name": "astral-sh/uv-dev" },
                { "id": 123, "full_name": "astral-sh/other" }
            ]),
        ] {
            Mock::given(method("POST"))
                .and(path("/app/installations/146796415/access_tokens"))
                .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                    "token": "ghs_multi",
                    "expires_at": "2026-03-28T00:00:00Z",
                "permissions": {"contents": "write"},
                    "repositories": repositories
                })))
                .mount(&server)
                .await;

            let error = mint_installation_token(
                &reqwest::Client::new(),
                &GithubApiBase::for_test(server.uri().as_str()),
                "app-jwt",
                146796415,
                &targets,
                &Permissions::contents_write(),
            )
            .await
            .unwrap_err();
            assert!(matches!(error, AppError::InstallationTokenRequestInvalid));
            server.reset().await;
        }
    }
}
