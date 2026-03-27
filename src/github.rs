use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::AppError;

const GITHUB_API_VERSION: &str = "2022-11-28";

#[derive(Debug, Deserialize)]
pub struct InstallationToken {
    pub token: String,
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
    github_api_base: &reqwest::Url,
    app_jwt: &str,
    owner: &str,
    repo: &str,
) -> Result<u64, AppError> {
    let url = github_api_url(
        github_api_base,
        &format!("repos/{owner}/{repo}/installation"),
    )?;

    let response = github_request(http_client.get(url), app_jwt)
        .send()
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
    github_api_base: &reqwest::Url,
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

    let response = github_request(http_client.post(url), app_jwt)
        .json(&payload)
        .send()
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

fn github_api_url(base: &reqwest::Url, path: &str) -> Result<reqwest::Url, AppError> {
    base.join(path).map_err(|_| AppError::InvalidGithubApiUrl)
}
