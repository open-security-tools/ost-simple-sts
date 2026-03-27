use jsonwebtoken::{decode, decode_header, errors::ErrorKind, Algorithm, Validation};
use lambda_http::{http::header::AUTHORIZATION, Body, Error, Request, RequestExt, Response};
use serde::Deserialize;
use serde_json::json;
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};

use crate::{
    config::Config,
    error::AppError,
    github, http, replay,
    types::{ExpiresInMinutes, GitRef, Jti, RepositoryFullName, RepositoryId},
};

const ACTIONS_ISSUER: &str = "https://token.actions.githubusercontent.com";
const CLOCK_TOLERANCE_SECONDS: u64 = 5;

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum StringOrNumber {
    String(String),
    Number(u64),
}

#[derive(Debug, Clone, Deserialize)]
struct GitHubActionsClaims {
    repository: Option<String>,
    repository_id: Option<StringOrNumber>,
    #[serde(rename = "ref")]
    git_ref: Option<String>,
    event_name: Option<String>,
    workflow_ref: Option<String>,
    job_workflow_ref: Option<String>,
    environment: Option<String>,
    jti: Option<String>,
    exp: Option<u64>,
}

#[derive(Debug, Clone)]
struct VerifiedClaims {
    repository: RepositoryFullName,
    repository_id: RepositoryId,
    git_ref: GitRef,
    jti: Jti,
    expires_at_ms: u64,
}

impl TryFrom<StringOrNumber> for RepositoryId {
    type Error = AppError;

    fn try_from(value: StringOrNumber) -> Result<Self, Self::Error> {
        match value {
            StringOrNumber::String(value) => value
                .parse::<u64>()
                .map_err(|_| AppError::RepositoryIdClaimInvalid)
                .and_then(RepositoryId::try_from),
            StringOrNumber::Number(value) => RepositoryId::try_from(value),
        }
    }
}

pub async fn handle(config: Config, request: Request) -> Result<Response<Body>, Error> {
    let expires_in = match request
        .query_string_parameters()
        .first("expires_in")
        .map(ExpiresInMinutes::try_from)
        .transpose()
    {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };

    let claims = match verify_oidc_claims(&config, &request).await {
        Ok(claims) => claims,
        Err(error) => return error.into_response(),
    };

    if let Err(error) = replay::claim_jti(
        &config.dynamodb,
        &config.jti_table_name,
        ACTIONS_ISSUER,
        &claims.jti,
        claims.expires_at_ms,
    )
    .await
    {
        return error.into_response();
    }

    let response = match mint_installation_token(&config, &claims, expires_in).await {
        Ok(response) => response,
        Err(error) => return error.into_response(),
    };

    http::json(200, &response)
}

async fn verify_oidc_claims(
    config: &Config,
    request: &Request,
) -> Result<VerifiedClaims, AppError> {
    let oidc_token = get_bearer_token(request).ok_or(AppError::MissingBearerToken)?;

    let header = decode_header(oidc_token).map_err(map_jwt_error)?;
    if header.alg != Algorithm::RS256 {
        return Err(AppError::InvalidOidcToken);
    }

    let kid = header.kid.ok_or(AppError::InvalidOidcToken)?;
    let decoding_key = config.jwks_cache.decoding_key_for(&kid).await?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[ACTIONS_ISSUER]);
    validation.set_audience(&[config.policy.expected_audience().as_str()]);
    validation.leeway = CLOCK_TOLERANCE_SECONDS;
    validation.validate_nbf = false;

    let claims = decode::<GitHubActionsClaims>(oidc_token, &decoding_key, &validation)
        .map_err(map_jwt_error)?
        .claims;

    let git_ref = claims.git_ref.ok_or(AppError::RefNotAllowed)?;
    if git_ref != config.policy.allowed_ref().as_str() {
        return Err(AppError::RefNotAllowed);
    }

    if let Some(expected_environment) = config.policy.allowed_environment() {
        if claims.environment.as_deref() != Some(expected_environment.as_str()) {
            return Err(AppError::EnvironmentNotAllowed);
        }
    }

    let repository = claims
        .repository
        .ok_or(AppError::RepositoryClaimMissing)
        .and_then(RepositoryFullName::try_from)?;

    if claims.event_name.as_deref() != Some("workflow_dispatch") {
        return Err(AppError::EventNotAllowed);
    }

    let expected_workflow_ref = format!(
        "{repository}/{}@{}",
        config.policy.allowed_workflow_path(),
        config.policy.allowed_ref(),
    );
    if claims.workflow_ref.as_deref() != Some(expected_workflow_ref.as_str())
        && claims.job_workflow_ref.as_deref() != Some(expected_workflow_ref.as_str())
    {
        return Err(AppError::WorkflowNotAllowed);
    }

    let repository_id = claims
        .repository_id
        .ok_or(AppError::RepositoryIdClaimInvalid)
        .and_then(RepositoryId::try_from)?;
    let jti = claims
        .jti
        .ok_or(AppError::OidcTokenMissingJti)
        .and_then(Jti::try_from)?;
    let exp = claims.exp.ok_or(AppError::OidcTokenMissingExp)?;

    Ok(VerifiedClaims {
        repository,
        repository_id,
        git_ref: config.policy.allowed_ref().clone(),
        jti,
        expires_at_ms: exp.saturating_mul(1000) + CLOCK_TOLERANCE_SECONDS.saturating_mul(1000),
    })
}

async fn mint_installation_token(
    config: &Config,
    claims: &VerifiedClaims,
    expires_in_minutes: Option<ExpiresInMinutes>,
) -> Result<serde_json::Value, AppError> {
    let app_jwt = github::create_app_jwt(&config.app_id, &config.app_private_key)?;
    let installation_id = github::find_installation(
        &config.http_client,
        &config.github_api_base,
        &app_jwt,
        claims.repository.owner().as_str(),
        claims.repository.repo().as_str(),
    )
    .await?;

    let expires_at = expires_in_minutes
        .map(expires_at_from_minutes)
        .transpose()?;

    let token = github::mint_installation_token(
        &config.http_client,
        &config.github_api_base,
        &app_jwt,
        installation_id,
        &[claims.repository_id.get()],
        json!({ "contents": "write" }),
        expires_at.as_deref(),
    )
    .await?;

    Ok(json!({
        "token": token.token,
        "expires_at": token.expires_at,
        "repository": claims.repository.as_str(),
        "ref": claims.git_ref.as_str(),
    }))
}

fn get_bearer_token(request: &Request) -> Option<&str> {
    let authorization = request.headers().get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = authorization.split_once(' ')?;
    if scheme.eq_ignore_ascii_case("bearer") && !token.is_empty() {
        Some(token)
    } else {
        None
    }
}

fn expires_at_from_minutes(minutes: ExpiresInMinutes) -> Result<String, AppError> {
    let expires_at = OffsetDateTime::now_utc()
        .checked_add(Duration::minutes(minutes.get() as i64))
        .ok_or(AppError::TokenExchangeFailed)?;
    expires_at
        .format(&Rfc3339)
        .map_err(|_| AppError::TokenExchangeFailed)
}

fn map_jwt_error(error: jsonwebtoken::errors::Error) -> AppError {
    match error.kind() {
        ErrorKind::ExpiredSignature => AppError::OidcTokenExpired,
        ErrorKind::InvalidToken
        | ErrorKind::InvalidSignature
        | ErrorKind::InvalidEcdsaKey
        | ErrorKind::InvalidRsaKey(_)
        | ErrorKind::InvalidAlgorithmName
        | ErrorKind::InvalidAlgorithm
        | ErrorKind::MissingRequiredClaim(_)
        | ErrorKind::InvalidIssuer
        | ErrorKind::InvalidAudience
        | ErrorKind::ImmatureSignature
        | ErrorKind::InvalidSubject
        | ErrorKind::Json(_)
        | ErrorKind::Utf8(_)
        | ErrorKind::Base64(_) => AppError::InvalidOidcToken,
        _ => {
            tracing::error!(?error, "oidc verification failed");
            AppError::OidcVerificationUnavailable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::StringOrNumber;
    use crate::types::{ExpiresInMinutes, RepositoryFullName, RepositoryId};

    #[test]
    fn repository_full_name_accepts_owner_and_repo() {
        let repository = RepositoryFullName::try_from("astral-sh/uv").unwrap();
        assert_eq!(repository.owner().as_str(), "astral-sh");
        assert_eq!(repository.repo().as_str(), "uv");
        assert_eq!(repository.as_str(), "astral-sh/uv");
    }

    #[test]
    fn repository_full_name_rejects_invalid_values() {
        assert!(RepositoryFullName::try_from("astral-sh").is_err());
        assert!(RepositoryFullName::try_from("astral-sh/uv/extra").is_err());
        assert!(RepositoryFullName::try_from("/uv").is_err());
    }

    #[test]
    fn repository_id_accepts_strings_and_numbers() {
        assert_eq!(
            RepositoryId::try_from(StringOrNumber::String("42".to_string()))
                .unwrap()
                .get(),
            42
        );
        assert_eq!(
            RepositoryId::try_from(StringOrNumber::Number(7))
                .unwrap()
                .get(),
            7
        );
    }

    #[test]
    fn repository_id_rejects_invalid_values() {
        assert!(RepositoryId::try_from(StringOrNumber::String("zero".to_string())).is_err());
        assert!(RepositoryId::try_from(StringOrNumber::Number(0)).is_err());
    }

    #[test]
    fn expires_in_accepts_valid_range() {
        assert_eq!(ExpiresInMinutes::try_from("10").unwrap().get(), 10);
        assert_eq!(ExpiresInMinutes::try_from("60").unwrap().get(), 60);
    }

    #[test]
    fn expires_in_rejects_invalid_values() {
        assert!(ExpiresInMinutes::try_from("9").is_err());
        assert!(ExpiresInMinutes::try_from("61").is_err());
        assert!(ExpiresInMinutes::try_from("abc").is_err());
    }
}
