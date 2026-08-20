use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::json;

use super::{
    api::{github_api_url, github_request, GithubApiBase},
    find_installation, RepositoryFullName, RepositoryId, Token,
};
use crate::{config::PolicyLocation, error::AppError};

const GITHUB_API_VERSION: &str = "2022-11-28";
const MAX_POLICY_BYTES: usize = 256 * 1024;
const MAX_RATE_LIMIT_ERROR_BYTES: usize = 16 * 1024;
const DEFAULT_RATE_LIMIT_BACKOFF: Duration = Duration::from_secs(60);
const MAX_RATE_LIMIT_BACKOFF: Duration = Duration::from_secs(60 * 60);

#[derive(Deserialize)]
struct PolicyTokenResponse {
    token: Token,
    repositories: Vec<GrantedRepository>,
    permissions: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct GrantedRepository {
    id: RepositoryId,
    full_name: String,
}

pub struct FetchedPolicy {
    pub contents: String,
    pub repository_id: RepositoryId,
    pub installation_id: u64,
}

pub async fn fetch_policy(
    client: &reqwest::Client,
    base: &GithubApiBase,
    app_jwt: &str,
    repository: &RepositoryFullName,
    location: &PolicyLocation,
) -> Result<FetchedPolicy, AppError> {
    let installation_id = find_installation(
        client,
        base,
        app_jwt,
        repository.owner().as_str(),
        repository.repo().as_str(),
    )
    .await?;
    let (token, repository_id) =
        mint_policy_token(client, base, app_jwt, repository, installation_id).await?;
    let result = fetch_policy_with_token(client, base, &token, repository, location).await;
    revoke_policy_token(client, base, &token).await;
    Ok(FetchedPolicy {
        contents: result?,
        repository_id,
        installation_id,
    })
}

async fn mint_policy_token(
    client: &reqwest::Client,
    base: &GithubApiBase,
    app_jwt: &str,
    repository: &RepositoryFullName,
    installation_id: u64,
) -> Result<(Token, RepositoryId), AppError> {
    let url = github_api_url(
        base,
        &format!("app/installations/{installation_id}/access_tokens"),
    )?;
    let response = github_request(client.post(url), app_jwt)
        .json(&json!({
            "repositories": [repository.repo().as_str()],
            "permissions": {"contents": "read"}
        }))
        .send()
        .await
        .map_err(|error| {
            tracing::error!(?error, "policy token request failed");
            AppError::GithubAccessTokenRequestFailed
        })?;

    match response.status().as_u16() {
        201 => {
            let raw = response
                .json::<serde_json::Value>()
                .await
                .map_err(|error| {
                    tracing::error!(?error, "failed to decode policy token response");
                    AppError::GithubAccessTokenRequestFailed
                })?;
            let token = raw
                .get("token")
                .cloned()
                .and_then(|value| serde_json::from_value::<Token>(value).ok())
                .filter(|token| !token.as_str().is_empty())
                .ok_or(AppError::GithubAccessTokenRequestFailed)?;
            let response = match serde_json::from_value::<PolicyTokenResponse>(raw) {
                Ok(response) => response,
                Err(error) => {
                    tracing::error!(?error, "failed to decode policy token scope");
                    revoke_policy_token(client, base, &token).await;
                    return Err(AppError::InstallationTokenRequestInvalid);
                }
            };
            let expected_permissions = BTreeMap::from([
                ("contents".to_string(), "read".to_string()),
                ("metadata".to_string(), "read".to_string()),
            ]);
            if response.repositories.len() != 1
                || response.repositories[0].full_name != repository.as_str()
                || response.permissions != expected_permissions
            {
                tracing::error!("github returned an unexpectedly scoped policy token");
                revoke_policy_token(client, base, &response.token).await;
                return Err(AppError::InstallationTokenRequestInvalid);
            }
            Ok((response.token, response.repositories[0].id))
        }
        401 => Err(AppError::GithubAppAuthInvalid),
        status @ (403 | 422 | 429) => {
            if let Some(retry_after) = github_rate_limit(response).await {
                Err(AppError::GithubRateLimited { retry_after })
            } else if status == 403 {
                Err(AppError::GithubAccessTokenRequestForbidden)
            } else if status == 422 {
                Err(AppError::InstallationTokenRequestInvalid)
            } else {
                Err(AppError::GithubAccessTokenRequestFailed)
            }
        }
        404 => Err(AppError::InstallationNotFound),
        status => {
            tracing::error!(status, "unexpected policy token response");
            Err(AppError::GithubAccessTokenRequestFailed)
        }
    }
}

async fn fetch_policy_with_token(
    client: &reqwest::Client,
    base: &GithubApiBase,
    token: &Token,
    repository: &RepositoryFullName,
    location: &PolicyLocation,
) -> Result<String, AppError> {
    let mut url = github_api_url(
        base,
        &format!("repos/{}/contents/{}", repository.as_str(), location.path()),
    )?;
    url.query_pairs_mut()
        .append_pair("ref", location.git_ref().as_str());
    let response = client
        .get(url)
        .bearer_auth(token.as_str())
        .header("accept", "application/vnd.github.raw+json")
        .header("x-github-api-version", GITHUB_API_VERSION)
        .send()
        .await
        .map_err(|error| {
            tracing::error!(?error, "policy lookup failed");
            AppError::PolicyLookupFailed
        })?;
    if response.status() != StatusCode::OK {
        tracing::error!(status = %response.status(), "github rejected policy lookup");
        if let Some(retry_after) = github_rate_limit(response).await {
            return Err(AppError::GithubRateLimited { retry_after });
        }
        return Err(AppError::PolicyLookupFailed);
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_POLICY_BYTES as u64)
    {
        tracing::error!("github policy response exceeds the size limit");
        return Err(AppError::PolicyLookupFailed);
    }

    let mut response = response;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        tracing::error!(?error, "failed to read policy response");
        AppError::PolicyLookupFailed
    })? {
        if bytes.len().saturating_add(chunk.len()) > MAX_POLICY_BYTES {
            tracing::error!("github policy response exceeds the size limit");
            return Err(AppError::PolicyLookupFailed);
        }
        bytes.extend_from_slice(&chunk);
    }
    String::from_utf8(bytes).map_err(|_| AppError::PolicyLookupFailed)
}

async fn revoke_policy_token(client: &reqwest::Client, base: &GithubApiBase, token: &Token) {
    let Ok(url) = github_api_url(base, "installation/token") else {
        return;
    };
    match github_request(client.delete(url), token.as_str())
        .send()
        .await
    {
        Ok(response) if response.status() == StatusCode::NO_CONTENT => {}
        Ok(response) => {
            tracing::warn!(status = %response.status(), "failed to revoke policy token")
        }
        Err(error) => tracing::warn!(?error, "failed to revoke policy token"),
    }
}

async fn github_rate_limit(mut response: reqwest::Response) -> Option<Duration> {
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
                .clamp(Duration::from_secs(1), MAX_RATE_LIMIT_BACKOFF),
        );
    }
    None
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wiremock::{
        matchers::{body_json, header, method, path, query_param},
        Mock, MockServer, ResponseTemplate,
    };

    use crate::{config::PolicyLocation, error::AppError, github::GithubApiBase};

    use super::{fetch_policy, MAX_POLICY_BYTES};

    async fn mount_token(server: &MockServer, response: serde_json::Value) {
        Mock::given(method("GET"))
            .and(path("/repos/octo/tools/installation"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": 456})))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path("/app/installations/456/access_tokens"))
            .and(header("authorization", "Bearer app-jwt"))
            .and(header("accept", "application/vnd.github+json"))
            .and(header("x-github-api-version", "2022-11-28"))
            .and(body_json(json!({
                "repositories": ["tools"],
                "permissions": {"contents": "read"}
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(response))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/installation/token"))
            .and(header("authorization", "Bearer policy-token"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(server)
            .await;
    }

    fn token_response() -> serde_json::Value {
        json!({
            "token": "policy-token",
            "repositories": [{"id": 42, "full_name": "octo/tools"}],
            "permissions": {"contents": "read", "metadata": "read"}
        })
    }

    #[tokio::test]
    async fn fetches_the_exact_policy_path_and_ref_with_a_read_only_token() {
        let server = MockServer::start().await;
        mount_token(&server, token_response()).await;
        Mock::given(method("GET"))
            .and(path(
                "/repos/octo/tools/contents/.github/ost-simple-sts.json",
            ))
            .and(query_param("ref", "main"))
            .and(header("authorization", "Bearer policy-token"))
            .and(header("accept", "application/vnd.github.raw+json"))
            .and(header("x-github-api-version", "2022-11-28"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"version":1,"rules":[]}"#))
            .expect(1)
            .mount(&server)
            .await;

        let policy = fetch_policy(
            &reqwest::Client::new(),
            &GithubApiBase::for_test(server.uri().as_str()),
            "app-jwt",
            &"octo/tools".try_into().unwrap(),
            &PolicyLocation::for_test(),
        )
        .await
        .unwrap();

        assert_eq!(policy.contents, r#"{"version":1,"rules":[]}"#);
        assert_eq!(*policy.repository_id, 42);
        assert_eq!(policy.installation_id, 456);
    }

    #[tokio::test]
    async fn rejects_an_unexpected_policy_token_scope_and_revokes_it() {
        for response in [
            json!({
                "token": "policy-token",
                "repositories": [{"id": 0, "full_name": "octo/tools"}],
                "permissions": {"contents": "read", "metadata": "read"}
            }),
            json!({
                "token": "policy-token",
                "repositories": [{"id": 42, "full_name": "octo/other"}],
                "permissions": {"contents": "read", "metadata": "read"}
            }),
            json!({
                "token": "policy-token",
                "repositories": [{"id": 42, "full_name": "octo/tools"}],
                "permissions": {"contents": "write", "metadata": "read"}
            }),
        ] {
            let server = MockServer::start().await;
            mount_token(&server, response).await;

            assert!(matches!(
                fetch_policy(
                    &reqwest::Client::new(),
                    &GithubApiBase::for_test(server.uri().as_str()),
                    "app-jwt",
                    &"octo/tools".try_into().unwrap(),
                    &PolicyLocation::for_test(),
                )
                .await,
                Err(AppError::InstallationTokenRequestInvalid)
            ));
        }
    }

    #[tokio::test]
    async fn rejects_missing_oversized_and_invalid_utf8_policy_responses() {
        for response in [
            ResponseTemplate::new(404),
            ResponseTemplate::new(200).set_body_bytes(vec![b'x'; MAX_POLICY_BYTES + 1]),
            ResponseTemplate::new(200).set_body_bytes(vec![0xff]),
        ] {
            let server = MockServer::start().await;
            mount_token(&server, token_response()).await;
            Mock::given(method("GET"))
                .and(path(
                    "/repos/octo/tools/contents/.github/ost-simple-sts.json",
                ))
                .respond_with(response)
                .expect(1)
                .mount(&server)
                .await;

            assert!(matches!(
                fetch_policy(
                    &reqwest::Client::new(),
                    &GithubApiBase::for_test(server.uri().as_str()),
                    "app-jwt",
                    &"octo/tools".try_into().unwrap(),
                    &PolicyLocation::for_test(),
                )
                .await,
                Err(AppError::PolicyLookupFailed)
            ));
        }
    }

    #[tokio::test]
    async fn surfaces_a_rate_limited_policy_refresh_and_revokes_the_read_token() {
        let server = MockServer::start().await;
        mount_token(&server, token_response()).await;
        Mock::given(method("GET"))
            .and(path(
                "/repos/octo/tools/contents/.github/ost-simple-sts.json",
            ))
            .respond_with(ResponseTemplate::new(403).insert_header("retry-after", "2"))
            .expect(1)
            .mount(&server)
            .await;

        assert!(matches!(
            fetch_policy(
                &reqwest::Client::new(),
                &GithubApiBase::for_test(server.uri().as_str()),
                "app-jwt",
                &"octo/tools".try_into().unwrap(),
                &PolicyLocation::for_test(),
            )
            .await,
            Err(AppError::GithubRateLimited { retry_after })
                if retry_after == std::time::Duration::from_secs(2)
        ));
    }
}
