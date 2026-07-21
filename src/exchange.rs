use jsonwebtoken::{decode, decode_header, errors::ErrorKind, Algorithm, Validation};
use lambda_http::{http::header::AUTHORIZATION, Body, Request};
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    config::{Config, GitRef, Policy},
    error::AppError,
    github::{self, Jti, Permissions, RepositoryFullName, RepositoryId},
    replay,
};

const ACTIONS_ISSUER: &str = "https://token.actions.githubusercontent.com";
const CLOCK_TOLERANCE_SECONDS: u64 = 5;
const MAX_OIDC_TOKEN_BYTES: usize = 16 * 1024;
const MAX_EXCHANGE_REQUEST_BYTES: usize = 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExchangeRequest {
    #[serde(default)]
    repository: Option<String>,
    #[serde(default)]
    repositories: Option<Vec<String>>,
    permissions: Permissions,
}

#[derive(Debug)]
struct ExchangeRequest {
    repositories: Vec<RepositoryFullName>,
    multiple: bool,
    permissions: Permissions,
}

#[derive(Debug, Clone, Deserialize)]
struct GitHubActionsClaims {
    #[serde(rename = "sub")]
    subject: Option<String>,
    repository: Option<String>,
    repository_id: Option<RepositoryId>,
    #[serde(rename = "ref")]
    git_ref: Option<String>,
    event_name: Option<String>,
    workflow_ref: Option<String>,
    job_workflow_ref: Option<String>,
    environment: Option<String>,
    jti: Option<String>,
    iat: Option<u64>,
    exp: Option<u64>,
}

#[derive(Debug, Clone)]
struct VerifiedClaims {
    target_repository: RepositoryFullName,
    target_repository_id: RepositoryId,
    target_repositories: Vec<(RepositoryFullName, RepositoryId)>,
    target_installation_id: Option<u64>,
    multiple_target_repositories: bool,
    permissions: Permissions,
    git_ref: GitRef,
    jti: Jti,
    expires_at_ms: u64,
}

pub struct ExchangeResult {
    pub token: github::Token,
    pub expires_at: String,
    pub repository: Option<String>,
    pub repositories: Option<Vec<String>>,
    pub git_ref: String,
}

pub async fn handle(config: Config, request: Request) -> Result<ExchangeResult, AppError> {
    let claims = verify_oidc_claims(&config, &request).await?;

    replay::claim_jti(
        &config.dynamodb,
        &config.jti_table_name,
        ACTIONS_ISSUER,
        &claims.jti,
        claims.expires_at_ms,
    )
    .await?;

    mint_installation_token(&config, &claims).await
}

async fn verify_oidc_claims(
    config: &Config,
    request: &Request,
) -> Result<VerifiedClaims, AppError> {
    let exchange_request = get_exchange_request(request)?;
    let oidc_token = get_bearer_token(request).ok_or(AppError::MissingBearerToken)?;

    let header = decode_header(oidc_token).map_err(map_jwt_error)?;
    if header.alg != Algorithm::RS256 {
        return Err(AppError::InvalidOidcToken);
    }

    let kid = header.kid.ok_or(AppError::InvalidOidcToken)?;
    let decoding_key = config.jwks_cache.decoding_key_for(&kid).await?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[ACTIONS_ISSUER]);
    validation.set_audience(&[config.policy_audience.as_str()]);
    validation.leeway = CLOCK_TOLERANCE_SECONDS;
    validation.validate_nbf = true;
    validation.required_spec_claims = ["iss", "sub", "aud", "exp", "nbf", "iat"]
        .into_iter()
        .map(str::to_string)
        .collect();

    let claims = decode::<GitHubActionsClaims>(oidc_token, &decoding_key, &validation)
        .map_err(map_jwt_error)?
        .claims;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AppError::OidcVerificationUnavailable)?
        .as_secs();
    if claims
        .iat
        .is_none_or(|issued_at| issued_at > now.saturating_add(CLOCK_TOLERANCE_SECONDS))
    {
        return Err(AppError::InvalidOidcToken);
    }

    let loaded_policy = config
        .policy_cache
        .get_or_load(|| async {
            let app_jwt = github::create_app_jwt(&config.app_id, &config.app_private_key)?;
            let policy = github::fetch_policy(
                &config.http_client,
                &config.github_api_base,
                &app_jwt,
                &config.policy_location,
            )
            .await?;
            Policy::from_hosted(&policy, &config.policy_audience)
        })
        .await?;
    if let Some(retry_after) = loaded_policy.retry_after() {
        return Err(AppError::GithubRateLimited { retry_after });
    }
    let policy = loaded_policy.policy();
    if policy.expected_audience() != &config.policy_audience {
        return Err(AppError::InvalidPolicy);
    }

    let mut rules = policy.rules().iter().collect::<Vec<_>>();
    rules.retain(|rule| claims.subject.as_deref() == Some(rule.subject().as_str()));
    if rules.is_empty() {
        return Err(AppError::SubjectNotAllowed);
    }

    let git_ref = claims.git_ref.ok_or(AppError::RefNotAllowed)?;
    rules.retain(|rule| rule.git_ref().matches(&git_ref));
    if rules.is_empty() {
        return Err(AppError::RefNotAllowed);
    }

    rules.retain(|rule| {
        rule.environment().is_none_or(|expected_environment| {
            claims.environment.as_deref() == Some(expected_environment.as_str())
        })
    });
    if rules.is_empty() {
        return Err(AppError::EnvironmentNotAllowed);
    }

    let repository = claims
        .repository
        .ok_or(AppError::RepositoryClaimMissing)
        .and_then(RepositoryFullName::try_from)?;
    rules.retain(|rule| repository == *rule.repository());
    if rules.is_empty() {
        return Err(AppError::RepositoryNotAllowed);
    }

    let repository_id = claims
        .repository_id
        .ok_or(AppError::RepositoryIdClaimInvalid)?;
    rules.retain(|rule| repository_id == rule.repository_id());
    if rules.is_empty() {
        return Err(AppError::RepositoryIdNotAllowed);
    }

    rules.retain(|rule| {
        rule.allowed_events()
            .iter()
            .any(|event| claims.event_name.as_deref() == Some(event.as_str()))
    });
    if rules.is_empty() {
        return Err(AppError::EventNotAllowed);
    }

    rules.retain(|rule| {
        let expected_workflow_ref = format!(
            "{}/{workflow_path}@{git_ref}",
            rule.repository(),
            workflow_path = rule.workflow_path(),
        );
        if claims.workflow_ref.as_deref() != Some(expected_workflow_ref.as_str()) {
            return false;
        }

        rule.job_workflow_path().map_or_else(
            || {
                claims
                    .job_workflow_ref
                    .as_deref()
                    .is_none_or(|workflow_ref| workflow_ref == expected_workflow_ref)
            },
            |workflow_path| {
                let expected_job_workflow_ref =
                    format!("{}/{workflow_path}@{git_ref}", rule.repository());
                claims.job_workflow_ref.as_deref() == Some(expected_job_workflow_ref.as_str())
            },
        )
    });
    let rule = rules.first().ok_or(AppError::WorkflowNotAllowed)?;
    let target_repositories = rule.target_repositories();

    match exchange_request.as_ref() {
        Some(exchange_request) => {
            if exchange_request.multiple != rule.has_multiple_target_repositories()
                || exchange_request.repositories.len() != target_repositories.len()
                || !target_repositories.iter().all(|(target, _)| {
                    exchange_request
                        .repositories
                        .iter()
                        .any(|repository| repository == target)
                })
            {
                return Err(AppError::TargetRepositoryNotAllowed);
            }
            if !rule.permissions().permits(&exchange_request.permissions) {
                return Err(AppError::PermissionsNotAllowed);
            }
        }
        None if rule.has_target_repository() => {
            return Err(AppError::TargetRepositoryNotAllowed);
        }
        None => {}
    }

    let jti = claims
        .jti
        .ok_or(AppError::OidcTokenMissingJti)
        .and_then(Jti::try_from)?;
    let exp = claims.exp.ok_or(AppError::OidcTokenMissingExp)?;
    let (target_repository, target_repository_id) = target_repositories
        .first()
        .cloned()
        .ok_or(AppError::TargetRepositoryNotAllowed)?;

    Ok(VerifiedClaims {
        target_repository,
        target_repository_id,
        target_repositories,
        target_installation_id: rule.target_installation_id(),
        multiple_target_repositories: rule.has_multiple_target_repositories(),
        permissions: exchange_request.map_or_else(
            || rule.permissions().clone(),
            |request| request.permissions.clone(),
        ),
        git_ref: GitRef::try_from(git_ref).map_err(|_| AppError::RefNotAllowed)?,
        jti,
        expires_at_ms: exp.saturating_mul(1000) + CLOCK_TOLERANCE_SECONDS.saturating_mul(1000),
    })
}

async fn mint_installation_token(
    config: &Config,
    claims: &VerifiedClaims,
) -> Result<ExchangeResult, AppError> {
    let app_jwt = github::create_app_jwt(&config.app_id, &config.app_private_key)?;
    let mut installation_id = claims.target_installation_id;
    for (repository, _) in &claims.target_repositories {
        let found = github::find_installation(
            &config.http_client,
            &config.github_api_base,
            &app_jwt,
            repository.owner().as_str(),
            repository.repo().as_str(),
        )
        .await?;
        if installation_id.is_some_and(|expected| expected != found) {
            return Err(AppError::TargetInstallationNotAllowed);
        }
        installation_id = Some(found);
    }
    let installation_id = installation_id.ok_or(AppError::TargetInstallationNotAllowed)?;

    let token = github::mint_installation_token(
        &config.http_client,
        &config.github_api_base,
        &app_jwt,
        installation_id,
        &claims.target_repositories,
        &claims.permissions,
    )
    .await?;

    let repositories = claims
        .target_repositories
        .iter()
        .map(|(repository, _)| repository.as_str().to_string())
        .collect::<Vec<_>>();
    debug_assert_eq!(
        claims.target_repositories.first().map(|(_, id)| *id),
        Some(claims.target_repository_id)
    );

    Ok(ExchangeResult {
        token: token.token,
        expires_at: token.expires_at,
        repository: (!claims.multiple_target_repositories)
            .then(|| claims.target_repository.as_str().to_string()),
        repositories: claims.multiple_target_repositories.then_some(repositories),
        git_ref: claims.git_ref.as_str().to_string(),
    })
}

fn get_bearer_token(request: &Request) -> Option<&str> {
    let authorization = request.headers().get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = authorization.split_once(' ')?;
    if scheme.eq_ignore_ascii_case("bearer")
        && !token.is_empty()
        && token.len() <= MAX_OIDC_TOKEN_BYTES
        && !token.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        Some(token)
    } else {
        None
    }
}

fn get_exchange_request(request: &Request) -> Result<Option<ExchangeRequest>, AppError> {
    let body = match request.body() {
        Body::Empty => return Ok(None),
        Body::Text(body) => body.as_bytes(),
        Body::Binary(body) => body.as_slice(),
    };
    if body.is_empty() {
        return Ok(None);
    }
    if body.len() > MAX_EXCHANGE_REQUEST_BYTES {
        return Err(AppError::InvalidExchangeRequest);
    }
    let request = serde_json::from_slice::<RawExchangeRequest>(body)
        .map_err(|_| AppError::InvalidExchangeRequest)?;
    let (repositories, multiple) = match (request.repository, request.repositories) {
        (Some(repository), None) => (vec![repository], false),
        (None, Some(repositories)) if repositories.len() >= 2 => (repositories, true),
        _ => return Err(AppError::InvalidExchangeRequest),
    };
    let repositories = repositories
        .into_iter()
        .map(RepositoryFullName::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| AppError::InvalidExchangeRequest)?;
    if repositories.iter().enumerate().any(|(index, repository)| {
        repositories[..index]
            .iter()
            .any(|previous| previous.as_str().eq_ignore_ascii_case(repository.as_str()))
    }) {
        return Err(AppError::InvalidExchangeRequest);
    }

    Ok(Some(ExchangeRequest {
        repositories,
        multiple,
        permissions: request.permissions,
    }))
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
    use super::{get_bearer_token, get_exchange_request, MAX_EXCHANGE_REQUEST_BYTES};
    use crate::github::{RepositoryFullName, RepositoryId};
    use lambda_http::{http::Request, Body};

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
    fn repository_id_deserializes_from_strings_and_numbers() {
        assert_eq!(*serde_json::from_str::<RepositoryId>("42").unwrap(), 42);
        assert_eq!(*serde_json::from_str::<RepositoryId>(r#""7""#).unwrap(), 7);
    }

    #[test]
    fn repository_id_rejects_invalid_values() {
        assert!(serde_json::from_str::<RepositoryId>(r#""zero""#).is_err());
        assert!(serde_json::from_str::<RepositoryId>("0").is_err());
    }

    #[test]
    fn get_bearer_token_extracts_token() {
        let request = Request::builder()
            .header("authorization", "Bearer my-token")
            .body(Body::Empty)
            .unwrap();
        assert_eq!(get_bearer_token(&request), Some("my-token"));
    }

    #[test]
    fn get_bearer_token_is_case_insensitive() {
        let request = Request::builder()
            .header("authorization", "bearer my-token")
            .body(Body::Empty)
            .unwrap();
        assert_eq!(get_bearer_token(&request), Some("my-token"));
    }

    #[test]
    fn get_bearer_token_rejects_missing_header() {
        let request = Request::builder().body(Body::Empty).unwrap();
        assert_eq!(get_bearer_token(&request), None);
    }

    #[test]
    fn get_bearer_token_rejects_wrong_scheme() {
        let request = Request::builder()
            .header("authorization", "Basic abc123")
            .body(Body::Empty)
            .unwrap();
        assert_eq!(get_bearer_token(&request), None);
    }

    #[test]
    fn get_bearer_token_rejects_empty_token() {
        let request = Request::builder()
            .header("authorization", "Bearer ")
            .body(Body::Empty)
            .unwrap();
        assert_eq!(get_bearer_token(&request), None);
    }

    #[test]
    fn get_bearer_token_rejects_whitespace_in_token() {
        let request = Request::builder()
            .header("authorization", "Bearer token with-spaces")
            .body(Body::Empty)
            .unwrap();
        assert_eq!(get_bearer_token(&request), None);
    }

    #[test]
    fn get_bearer_token_rejects_oversized_token() {
        let request = Request::builder()
            .header(
                "authorization",
                format!("Bearer {}", "a".repeat(super::MAX_OIDC_TOKEN_BYTES + 1)),
            )
            .body(Body::Empty)
            .unwrap();
        assert_eq!(get_bearer_token(&request), None);
    }

    #[test]
    fn exchange_request_accepts_empty_and_valid_bodies() {
        let empty = Request::builder().body(Body::Empty).unwrap();
        assert!(get_exchange_request(&empty).unwrap().is_none());

        let valid = Request::builder()
            .body(Body::Text(
                r#"{"repository":"octo/tools","permissions":{"contents":"write"}}"#.into(),
            ))
            .unwrap();
        assert!(get_exchange_request(&valid).unwrap().is_some());

        let multiple = Request::builder()
            .body(Body::Text(
                r#"{"repositories":["octo/tools","octo/tools-dev"],"permissions":{"contents":"write"}}"#
                    .into(),
            ))
            .unwrap();
        let multiple = get_exchange_request(&multiple).unwrap().unwrap();
        assert!(multiple.multiple);
        assert_eq!(multiple.repositories.len(), 2);
    }

    #[test]
    fn exchange_request_rejects_malformed_unknown_duplicate_and_oversized_bodies() {
        for body in [
            "not-json".to_string(),
            r#"{"repository":"octo/tools"}"#.to_string(),
            r#"{"repository":"octo/tools","permissions":{"contents":"write"},"extra":true}"#
                .to_string(),
            r#"{"repository":"octo/tools","permissions":{"contents":"write","contents":"read"}}"#
                .to_string(),
            r#"{"repository":"octo/tools","repositories":["octo/tools","octo/tools-dev"],"permissions":{"contents":"write"}}"#
                .to_string(),
            r#"{"repositories":[],"permissions":{"contents":"write"}}"#.to_string(),
            r#"{"repositories":["octo/tools"],"permissions":{"contents":"write"}}"#.to_string(),
            r#"{"repositories":["octo/tools","OCTO/TOOLS"],"permissions":{"contents":"write"}}"#
                .to_string(),
            r#"{"repositories":["octo/tools","../evil"],"permissions":{"contents":"write"}}"#
                .to_string(),
            "x".repeat(MAX_EXCHANGE_REQUEST_BYTES + 1),
        ] {
            let request = Request::builder().body(Body::Text(body)).unwrap();
            assert!(get_exchange_request(&request).is_err());
        }
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::{
        config::{Config, Policy},
        error::AppError,
        github::GithubApiBase,
        jwks::JwksCache,
        test_keys::{RSA_EXPONENT, RSA_MODULUS, RSA_PRIVATE_KEY},
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use lambda_http::{http::Request, Body};
    use serde_json::json;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use wiremock::{
        matchers::{body_json, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    struct TestFixture {
        server: MockServer,
        encoding_key: EncodingKey,
        kid: String,
    }

    impl TestFixture {
        async fn new() -> Self {
            let server = MockServer::start().await;

            let encoding_key = EncodingKey::from_rsa_pem(RSA_PRIVATE_KEY.as_bytes()).unwrap();

            let kid = "test-kid-001".to_string();

            let jwks_response = json!({
                "keys": [{
                    "kty": "RSA",
                    "n": RSA_MODULUS,
                    "e": RSA_EXPONENT,
                    "kid": kid,
                    "alg": "RS256",
                    "use": "sig",
                }]
            });

            Mock::given(method("GET"))
                .and(path("/.well-known/jwks"))
                .respond_with(ResponseTemplate::new(200).set_body_json(jwks_response))
                .mount(&server)
                .await;

            Self {
                server,
                encoding_key,
                kid,
            }
        }

        fn now_secs(&self) -> u64 {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        }

        fn sign_claims(&self, claims: serde_json::Value) -> String {
            let mut header = Header::new(Algorithm::RS256);
            header.kid = Some(self.kid.clone());
            encode(&header, &claims, &self.encoding_key).unwrap()
        }

        fn base_url(&self) -> GithubApiBase {
            GithubApiBase::for_test(self.server.uri().as_str())
        }

        fn policy(&self) -> Policy {
            serde_json::from_value(json!({
                "expected_audience": self.server.uri(),
                "rules": [{
                    "subject": "repo:octo/tools:environment:release",
                    "repository": "octo/tools",
                    "repository_id": 42,
                    "ref": "refs/heads/main",
                    "workflow_path": ".github/workflows/release.yml",
                    "environment": "release"
                }]
            }))
            .unwrap()
        }

        fn valid_claims(&self) -> serde_json::Value {
            let now = self.now_secs();
            json!({
                "iss": ACTIONS_ISSUER,
                "sub": "repo:octo/tools:environment:release",
                "aud": self.server.uri(),
                "iat": now - 10,
                "nbf": now - 10,
                "exp": now + 300,
                "jti": format!("test-jti-{now}"),
                "ref": "refs/heads/main",
                "repository": "octo/tools",
                "repository_id": "42",
                "event_name": "workflow_dispatch",
                "workflow_ref": format!("octo/tools/.github/workflows/release.yml@refs/heads/main"),
                "environment": "release",
            })
        }

        fn make_request(&self, token: &str) -> Request<Body> {
            Request::builder()
                .method("POST")
                .uri("/exchange")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::Empty)
                .unwrap()
        }

        fn make_scoped_request(
            &self,
            token: &str,
            repository: &str,
            permissions: serde_json::Value,
        ) -> Request<Body> {
            Request::builder()
                .method("POST")
                .uri("/exchange")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::Text(
                    json!({ "repository": repository, "permissions": permissions }).to_string(),
                ))
                .unwrap()
        }

        fn make_multi_scoped_request(
            &self,
            token: &str,
            repositories: &[&str],
            permissions: serde_json::Value,
        ) -> Request<Body> {
            Request::builder()
                .method("POST")
                .uri("/exchange")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::Text(
                    json!({ "repositories": repositories, "permissions": permissions }).to_string(),
                ))
                .unwrap()
        }

        fn build_config(&self, policy: Policy) -> Config {
            let http_client = reqwest::Client::builder().build().unwrap();
            let jwks_url = format!("{}/.well-known/jwks", self.server.uri());
            let jwks_cache = Arc::new(JwksCache::new_with_url(http_client.clone(), jwks_url));

            Config {
                policy_location: crate::config::PolicyLocation::for_test(),
                policy_audience: policy.expected_audience().clone(),
                policy_cache: Arc::new(crate::policy_cache::PolicyCache::with_policy(policy)),
                app_id: "test-app-id".try_into().unwrap(),
                app_private_key: "test-key-not-used".try_into().unwrap(),
                jti_table_name: "test-table".try_into().unwrap(),
                github_api_base: self.base_url(),
                dynamodb: aws_sdk_dynamodb::Client::from_conf(
                    aws_sdk_dynamodb::Config::builder()
                        .behavior_version(aws_config::BehaviorVersion::latest())
                        .region(aws_config::Region::new("us-east-1"))
                        .credentials_provider(aws_sdk_dynamodb::config::Credentials::new(
                            "test", "test", None, None, "test",
                        ))
                        .build(),
                ),
                http_client,
                jwks_cache,
            }
        }
    }

    #[tokio::test]
    async fn verify_oidc_claims_accepts_valid_token() {
        let fixture = TestFixture::new().await;
        let policy = fixture.policy();
        let config = fixture.build_config(policy);
        let claims = fixture.valid_claims();
        let token = fixture.sign_claims(claims);
        let request = fixture.make_request(&token);

        let verified = verify_oidc_claims(&config, &request).await.unwrap();

        assert_eq!(verified.target_repository.as_str(), "octo/tools");
        assert_eq!(*verified.target_repository_id, 42);
        assert_eq!(verified.git_ref.as_str(), "refs/heads/main");
    }

    #[tokio::test]
    async fn verify_oidc_claims_accepts_another_policy_rule() {
        let fixture = TestFixture::new().await;
        let policy: Policy = serde_json::from_value(json!({
            "expected_audience": fixture.server.uri(),
            "rules": [{
                "subject": "repo:octo/tools:environment:release",
                "repository": "octo/tools",
                "repository_id": 42,
                "ref": "refs/heads/main",
                "workflow_path": ".github/workflows/release.yml",
                "environment": "release"
            }, {
                "subject": "repo:octo/docs:environment:publish",
                "repository": "octo/docs",
                "repository_id": 43,
                "ref": "refs/tags/v1",
                "workflow_path": ".github/workflows/publish.yml",
                "environment": "publish"
            }]
        }))
        .unwrap();
        let config = fixture.build_config(policy);
        let mut claims = fixture.valid_claims();
        claims["sub"] = json!("repo:octo/docs:environment:publish");
        claims["repository"] = json!("octo/docs");
        claims["repository_id"] = json!(43);
        claims["ref"] = json!("refs/tags/v1");
        claims["workflow_ref"] = json!("octo/docs/.github/workflows/publish.yml@refs/tags/v1");
        claims["environment"] = json!("publish");
        let token = fixture.sign_claims(claims);
        let request = fixture.make_request(&token);

        let verified = verify_oidc_claims(&config, &request).await.unwrap();

        assert_eq!(verified.target_repository.as_str(), "octo/docs");
        assert_eq!(*verified.target_repository_id, 43);
        assert_eq!(verified.git_ref.as_str(), "refs/tags/v1");
    }

    #[tokio::test]
    async fn verify_oidc_claims_rejects_a_cross_product_of_policy_rules() {
        let fixture = TestFixture::new().await;
        let policy: Policy = serde_json::from_value(json!({
            "expected_audience": fixture.server.uri(),
            "rules": [{
                "subject": "repo:octo/tools:environment:release",
                "repository": "octo/tools",
                "repository_id": 42,
                "ref": "refs/heads/main",
                "workflow_path": ".github/workflows/release.yml",
                "environment": "release"
            }, {
                "subject": "repo:octo/tools:environment:release",
                "repository": "octo/tools",
                "repository_id": 42,
                "ref": "refs/tags/v1",
                "workflow_path": ".github/workflows/publish.yml",
                "environment": "release"
            }]
        }))
        .unwrap();
        let config = fixture.build_config(policy);
        let mut claims = fixture.valid_claims();
        claims["workflow_ref"] = json!("octo/tools/.github/workflows/publish.yml@refs/heads/main");
        let token = fixture.sign_claims(claims);
        let request = fixture.make_request(&token);

        let error = verify_oidc_claims(&config, &request).await.unwrap_err();
        assert!(matches!(error, AppError::WorkflowNotAllowed));
    }

    #[tokio::test]
    async fn verify_oidc_claims_accepts_matching_job_workflow_ref() {
        let fixture = TestFixture::new().await;
        let policy = fixture.policy();
        let config = fixture.build_config(policy);
        let mut claims = fixture.valid_claims();
        claims["job_workflow_ref"] =
            json!("octo/tools/.github/workflows/release.yml@refs/heads/main");
        let token = fixture.sign_claims(claims);
        let request = fixture.make_request(&token);

        let verified = verify_oidc_claims(&config, &request).await.unwrap();
        assert_eq!(verified.target_repository.as_str(), "octo/tools");
    }

    #[tokio::test]
    async fn verify_oidc_claims_rejects_missing_caller_workflow_ref() {
        let fixture = TestFixture::new().await;
        let config = fixture.build_config(fixture.policy());
        let mut claims = fixture.valid_claims();
        claims["workflow_ref"] = serde_json::Value::Null;
        claims["job_workflow_ref"] =
            json!("octo/tools/.github/workflows/release.yml@refs/heads/main");
        let token = fixture.sign_claims(claims);
        let request = fixture.make_request(&token);

        let error = verify_oidc_claims(&config, &request).await.unwrap_err();
        assert!(matches!(error, AppError::WorkflowNotAllowed));
    }

    #[tokio::test]
    async fn verify_oidc_claims_rejects_mismatched_job_workflow_ref() {
        let fixture = TestFixture::new().await;
        let config = fixture.build_config(fixture.policy());
        let mut claims = fixture.valid_claims();
        claims["job_workflow_ref"] =
            json!("octo/untrusted/.github/workflows/release.yml@refs/heads/main");
        let token = fixture.sign_claims(claims);
        let request = fixture.make_request(&token);

        let error = verify_oidc_claims(&config, &request).await.unwrap_err();
        assert!(matches!(error, AppError::WorkflowNotAllowed));
    }

    #[tokio::test]
    async fn verify_oidc_claims_rejects_missing_repository_claim() {
        let fixture = TestFixture::new().await;
        let policy = fixture.policy();
        let config = fixture.build_config(policy);
        let mut claims = fixture.valid_claims();
        claims["repository"] = serde_json::Value::Null;
        let token = fixture.sign_claims(claims);
        let request = fixture.make_request(&token);

        let error = verify_oidc_claims(&config, &request).await.unwrap_err();
        assert!(matches!(error, AppError::RepositoryClaimMissing));
    }

    #[tokio::test]
    async fn verify_oidc_claims_rejects_wrong_ref() {
        let fixture = TestFixture::new().await;
        let policy = fixture.policy();
        let config = fixture.build_config(policy);
        let mut claims = fixture.valid_claims();
        claims["ref"] = json!("refs/heads/develop");
        let token = fixture.sign_claims(claims);
        let request = fixture.make_request(&token);

        let error = verify_oidc_claims(&config, &request).await.unwrap_err();
        assert!(matches!(error, AppError::RefNotAllowed));
    }

    #[tokio::test]
    async fn verify_oidc_claims_rejects_wrong_subject() {
        let fixture = TestFixture::new().await;
        let config = fixture.build_config(fixture.policy());
        let mut claims = fixture.valid_claims();
        claims["sub"] = json!("repo:octo/other:environment:release");
        let token = fixture.sign_claims(claims);
        let request = fixture.make_request(&token);

        let error = verify_oidc_claims(&config, &request).await.unwrap_err();
        assert!(matches!(error, AppError::SubjectNotAllowed));
    }

    #[tokio::test]
    async fn verify_oidc_claims_rejects_wrong_repository() {
        let fixture = TestFixture::new().await;
        let config = fixture.build_config(fixture.policy());
        let mut claims = fixture.valid_claims();
        claims["repository"] = json!("octo/other");
        let token = fixture.sign_claims(claims);
        let request = fixture.make_request(&token);

        let error = verify_oidc_claims(&config, &request).await.unwrap_err();
        assert!(matches!(error, AppError::RepositoryNotAllowed));
    }

    #[tokio::test]
    async fn verify_oidc_claims_rejects_wrong_repository_id() {
        let fixture = TestFixture::new().await;
        let config = fixture.build_config(fixture.policy());
        let mut claims = fixture.valid_claims();
        claims["repository_id"] = json!(43);
        let token = fixture.sign_claims(claims);
        let request = fixture.make_request(&token);

        let error = verify_oidc_claims(&config, &request).await.unwrap_err();
        assert!(matches!(error, AppError::RepositoryIdNotAllowed));
    }

    #[tokio::test]
    async fn verify_oidc_claims_rejects_wrong_environment() {
        let fixture = TestFixture::new().await;
        let policy = fixture.policy();
        let config = fixture.build_config(policy);
        let mut claims = fixture.valid_claims();
        claims["environment"] = json!("staging");
        let token = fixture.sign_claims(claims);
        let request = fixture.make_request(&token);

        let error = verify_oidc_claims(&config, &request).await.unwrap_err();
        assert!(matches!(error, AppError::EnvironmentNotAllowed));
    }

    #[tokio::test]
    async fn verify_oidc_claims_rejects_wrong_event() {
        let fixture = TestFixture::new().await;
        let policy = fixture.policy();
        let config = fixture.build_config(policy);
        let mut claims = fixture.valid_claims();
        claims["event_name"] = json!("push");
        let token = fixture.sign_claims(claims);
        let request = fixture.make_request(&token);

        let error = verify_oidc_claims(&config, &request).await.unwrap_err();
        assert!(matches!(error, AppError::EventNotAllowed));
    }

    #[tokio::test]
    async fn verify_oidc_claims_accepts_allowed_events_for_a_target_repository() {
        let fixture = TestFixture::new().await;
        let policy: Policy = serde_json::from_value(json!({
            "expected_audience": fixture.server.uri(),
            "rules": [{
                "subject": "repo:octo/tools:environment:release",
                "repository": "octo/tools",
                "repository_id": 42,
                "ref": "refs/heads/main",
                "workflow_path": ".github/workflows/release.yml",
                "environment": "release",
                "allowed_events": ["push", "workflow_dispatch"],
                "permissions": { "contents": "write" },
                "target_repository": "octo/tools-dev",
                "target_repository_id": 84
            }]
        }))
        .unwrap();
        let config = fixture.build_config(policy);

        for event in ["push", "workflow_dispatch"] {
            let mut claims = fixture.valid_claims();
            claims["event_name"] = json!(event);
            let token = fixture.sign_claims(claims);
            let request = fixture.make_scoped_request(
                &token,
                "octo/tools-dev",
                json!({ "contents": "write" }),
            );

            let verified = verify_oidc_claims(&config, &request).await.unwrap();

            assert_eq!(verified.target_repository.as_str(), "octo/tools-dev");
            assert_eq!(*verified.target_repository_id, 84);
        }
    }

    #[tokio::test]
    async fn verify_oidc_claims_accepts_the_uv_fork_sync_rule() {
        let fixture = TestFixture::new().await;
        let policy: Policy = serde_json::from_value(json!({
            "expected_audience": fixture.server.uri(),
            "rules": [{
                "subject": "repo:astral-sh/uv:environment:automations",
                "repository": "astral-sh/uv",
                "repository_id": 699532645,
                "ref": "refs/heads/main",
                "workflow_path": ".github/workflows/sync-uv-dev.yml",
                "environment": "automations",
                "allowed_events": ["push", "workflow_dispatch"],
                "permissions": { "contents": "write" },
                "target_repository": "astral-sh/uv-dev",
                "target_repository_id": 1302176231
            }]
        }))
        .unwrap();
        let config = fixture.build_config(policy);

        for event in ["push", "workflow_dispatch"] {
            let mut claims = fixture.valid_claims();
            claims["sub"] = json!("repo:astral-sh/uv:environment:automations");
            claims["repository"] = json!("astral-sh/uv");
            claims["repository_id"] = json!(699532645);
            claims["event_name"] = json!(event);
            claims["workflow_ref"] =
                json!("astral-sh/uv/.github/workflows/sync-uv-dev.yml@refs/heads/main");
            claims["environment"] = json!("automations");
            let token = fixture.sign_claims(claims);
            let request = fixture.make_scoped_request(
                &token,
                "astral-sh/uv-dev",
                json!({ "contents": "write" }),
            );

            let verified = verify_oidc_claims(&config, &request).await.unwrap();

            assert_eq!(verified.target_repository.as_str(), "astral-sh/uv-dev");
            assert_eq!(*verified.target_repository_id, 1302176231);
        }
    }

    #[tokio::test]
    async fn verify_oidc_claims_rejects_invalid_uv_fork_sync_claims() {
        let fixture = TestFixture::new().await;
        let policy: Policy = serde_json::from_value(json!({
            "expected_audience": fixture.server.uri(),
            "rules": [{
                "subject": "repo:astral-sh/uv:environment:automations",
                "repository": "astral-sh/uv",
                "repository_id": 699532645,
                "ref": "refs/heads/main",
                "workflow_path": ".github/workflows/sync-uv-dev.yml",
                "environment": "automations",
                "allowed_events": ["push", "workflow_dispatch"],
                "target_repository": "astral-sh/uv-dev",
                "target_repository_id": 1302176231
            }]
        }))
        .unwrap();
        let config = fixture.build_config(policy);
        let mut valid_claims = fixture.valid_claims();
        valid_claims["sub"] = json!("repo:astral-sh/uv:environment:automations");
        valid_claims["repository"] = json!("astral-sh/uv");
        valid_claims["repository_id"] = json!(699532645);
        valid_claims["event_name"] = json!("push");
        valid_claims["workflow_ref"] =
            json!("astral-sh/uv/.github/workflows/sync-uv-dev.yml@refs/heads/main");
        valid_claims["environment"] = json!("automations");

        for (field, value, expected_code) in [
            (
                "sub",
                json!("repo:astral-sh/uv-dev:environment:automations"),
                "subject_not_allowed",
            ),
            (
                "repository",
                json!("astral-sh/uv-dev"),
                "repository_not_allowed",
            ),
            (
                "repository_id",
                json!(1302176231),
                "repository_id_not_allowed",
            ),
            ("ref", json!("refs/heads/other"), "ref_not_allowed"),
            (
                "workflow_ref",
                json!("astral-sh/uv/.github/workflows/ci.yml@refs/heads/main"),
                "workflow_not_allowed",
            ),
            ("environment", json!("release"), "environment_not_allowed"),
            ("event_name", json!("pull_request"), "event_not_allowed"),
        ] {
            let mut claims = valid_claims.clone();
            claims[field] = value;
            let token = fixture.sign_claims(claims);
            let request = fixture.make_scoped_request(
                &token,
                "astral-sh/uv-dev",
                json!({ "contents": "write" }),
            );

            let error = verify_oidc_claims(&config, &request).await.unwrap_err();

            assert_eq!(error.code(), expected_code, "field {field}");
        }

        let token = fixture.sign_claims(valid_claims);
        let request =
            fixture.make_scoped_request(&token, "astral-sh/uv", json!({ "contents": "write" }));
        let error = verify_oidc_claims(&config, &request).await.unwrap_err();
        assert_eq!(error.code(), "target_repository_not_allowed");

        let request = fixture.make_request(&token);
        let error = verify_oidc_claims(&config, &request).await.unwrap_err();
        assert_eq!(error.code(), "target_repository_not_allowed");

        let read_request =
            fixture.make_scoped_request(&token, "astral-sh/uv-dev", json!({ "contents": "read" }));
        let verified = verify_oidc_claims(&config, &read_request).await.unwrap();
        assert_eq!(
            serde_json::to_value(verified.permissions).unwrap(),
            json!({ "contents": "read" })
        );

        for permissions in [
            json!({ "actions": "write" }),
            json!({ "contents": "write", "actions": "write" }),
        ] {
            let request = fixture.make_scoped_request(&token, "astral-sh/uv-dev", permissions);
            let error = verify_oidc_claims(&config, &request).await.unwrap_err();
            assert_eq!(error.code(), "permissions_not_allowed");
        }

        for permissions in [json!({ "contents": "admin" }), json!({ "members": "read" })] {
            let request = fixture.make_scoped_request(&token, "astral-sh/uv-dev", permissions);
            let error = verify_oidc_claims(&config, &request).await.unwrap_err();
            assert_eq!(error.code(), "invalid_exchange_request");
        }
    }

    #[tokio::test]
    async fn verify_oidc_claims_accepts_the_uv_security_review_publisher_rule() {
        let fixture = TestFixture::new().await;
        let policy: Policy = serde_json::from_value(json!({
            "expected_audience": fixture.server.uri(),
            "rules": [{
                "subject": "repo:astral-sh/uv:environment:automations",
                "repository": "astral-sh/uv",
                "repository_id": 699532645,
                "ref": "refs/pull/*/merge",
                "workflow_path": ".github/workflows/ci.yml",
                "job_workflow_path": ".github/workflows/pull-request-security-review.yml",
                "environment": "automations",
                "allowed_events": ["pull_request"],
                "permissions": { "pull_requests": "write" },
                "target_repository": "astral-sh/uv",
                "target_repository_id": 699532645
            }]
        }))
        .unwrap();
        let config = fixture.build_config(policy);
        let mut claims = fixture.valid_claims();
        claims["sub"] = json!("repo:astral-sh/uv:environment:automations");
        claims["repository"] = json!("astral-sh/uv");
        claims["repository_id"] = json!(699532645);
        claims["ref"] = json!("refs/pull/20474/merge");
        claims["event_name"] = json!("pull_request");
        claims["workflow_ref"] =
            json!("astral-sh/uv/.github/workflows/ci.yml@refs/pull/20474/merge");
        claims["job_workflow_ref"] = json!(
            "astral-sh/uv/.github/workflows/pull-request-security-review.yml@refs/pull/20474/merge"
        );
        claims["environment"] = json!("automations");
        let token = fixture.sign_claims(claims);
        let request = fixture.make_scoped_request(
            &token,
            "astral-sh/uv",
            json!({ "pull_requests": "write" }),
        );

        let verified = verify_oidc_claims(&config, &request).await.unwrap();

        assert_eq!(verified.target_repository.as_str(), "astral-sh/uv");
        assert_eq!(*verified.target_repository_id, 699532645);
        assert_eq!(verified.git_ref.as_str(), "refs/pull/20474/merge");
        assert_eq!(
            serde_json::to_value(verified.permissions).unwrap(),
            json!({ "pull_requests": "write" })
        );
    }

    #[tokio::test]
    async fn verify_oidc_claims_rejects_invalid_uv_security_review_publisher_claims() {
        let fixture = TestFixture::new().await;
        let policy: Policy = serde_json::from_value(json!({
            "expected_audience": fixture.server.uri(),
            "rules": [{
                "subject": "repo:astral-sh/uv:environment:automations",
                "repository": "astral-sh/uv",
                "repository_id": 699532645,
                "ref": "refs/pull/*/merge",
                "workflow_path": ".github/workflows/ci.yml",
                "job_workflow_path": ".github/workflows/pull-request-security-review.yml",
                "environment": "automations",
                "allowed_events": ["pull_request"],
                "permissions": { "pull_requests": "write" },
                "target_repository": "astral-sh/uv",
                "target_repository_id": 699532645
            }]
        }))
        .unwrap();
        let config = fixture.build_config(policy);
        let mut valid_claims = fixture.valid_claims();
        valid_claims["sub"] = json!("repo:astral-sh/uv:environment:automations");
        valid_claims["repository"] = json!("astral-sh/uv");
        valid_claims["repository_id"] = json!(699532645);
        valid_claims["ref"] = json!("refs/pull/20474/merge");
        valid_claims["event_name"] = json!("pull_request");
        valid_claims["workflow_ref"] =
            json!("astral-sh/uv/.github/workflows/ci.yml@refs/pull/20474/merge");
        valid_claims["job_workflow_ref"] = json!(
            "astral-sh/uv/.github/workflows/pull-request-security-review.yml@refs/pull/20474/merge"
        );
        valid_claims["environment"] = json!("automations");

        for (field, value, expected_code) in [
            (
                "sub",
                json!("repo:astral-sh/uv-dev:environment:automations"),
                "subject_not_allowed",
            ),
            (
                "repository",
                json!("astral-sh/uv-dev"),
                "repository_not_allowed",
            ),
            (
                "repository_id",
                json!(1302176231),
                "repository_id_not_allowed",
            ),
            ("ref", json!("refs/heads/main"), "ref_not_allowed"),
            ("ref", json!("refs/pull/20474/head"), "ref_not_allowed"),
            ("ref", json!("refs/pull/0/merge"), "ref_not_allowed"),
            (
                "workflow_ref",
                json!("astral-sh/uv/.github/workflows/release.yml@refs/pull/20474/merge"),
                "workflow_not_allowed",
            ),
            (
                "job_workflow_ref",
                json!("astral-sh/uv/.github/workflows/release.yml@refs/pull/20474/merge"),
                "workflow_not_allowed",
            ),
            ("job_workflow_ref", json!(null), "workflow_not_allowed"),
            ("environment", json!("release"), "environment_not_allowed"),
            ("event_name", json!("push"), "event_not_allowed"),
        ] {
            let mut claims = valid_claims.clone();
            claims[field] = value;
            let token = fixture.sign_claims(claims);
            let request = fixture.make_scoped_request(
                &token,
                "astral-sh/uv",
                json!({ "pull_requests": "write" }),
            );

            let error = verify_oidc_claims(&config, &request).await.unwrap_err();

            assert_eq!(error.code(), expected_code, "field {field}");
        }

        let token = fixture.sign_claims(valid_claims);
        let wrong_target = fixture.make_scoped_request(
            &token,
            "astral-sh/uv-dev",
            json!({ "pull_requests": "write" }),
        );
        let error = verify_oidc_claims(&config, &wrong_target)
            .await
            .unwrap_err();
        assert_eq!(error.code(), "target_repository_not_allowed");

        for permissions in [
            json!({ "contents": "read" }),
            json!({ "pull_requests": "write", "contents": "read" }),
            json!({ "pull_requests": "write", "workflows": "write" }),
        ] {
            let request = fixture.make_scoped_request(&token, "astral-sh/uv", permissions);
            let error = verify_oidc_claims(&config, &request).await.unwrap_err();
            assert_eq!(error.code(), "permissions_not_allowed");
        }
    }

    #[tokio::test]
    async fn verify_oidc_claims_does_not_mix_caller_and_reusable_workflow_paths() {
        let fixture = TestFixture::new().await;
        let policy: Policy = serde_json::from_value(json!({
            "expected_audience": fixture.server.uri(),
            "rules": [{
                "subject": "repo:astral-sh/uv:environment:automations",
                "repository": "astral-sh/uv",
                "repository_id": 699532645,
                "ref": "refs/pull/*/merge",
                "workflow_path": ".github/workflows/ci.yml",
                "job_workflow_path": ".github/workflows/pull-request-security-review.yml",
                "environment": "automations",
                "allowed_events": ["pull_request"],
                "permissions": { "pull_requests": "write" },
                "target_repository": "astral-sh/uv",
                "target_repository_id": 699532645
            }, {
                "subject": "repo:astral-sh/uv:environment:automations",
                "repository": "astral-sh/uv",
                "repository_id": 699532645,
                "ref": "refs/pull/*/merge",
                "workflow_path": ".github/workflows/other-ci.yml",
                "job_workflow_path": ".github/workflows/publish.yml",
                "environment": "automations",
                "allowed_events": ["pull_request"],
                "permissions": { "contents": "write" },
                "target_repository": "astral-sh/uv-dev",
                "target_repository_id": 1302176231
            }]
        }))
        .unwrap();
        let config = fixture.build_config(policy);
        let mut claims = fixture.valid_claims();
        claims["sub"] = json!("repo:astral-sh/uv:environment:automations");
        claims["repository"] = json!("astral-sh/uv");
        claims["repository_id"] = json!(699532645);
        claims["ref"] = json!("refs/pull/20474/merge");
        claims["event_name"] = json!("pull_request");
        claims["workflow_ref"] =
            json!("astral-sh/uv/.github/workflows/ci.yml@refs/pull/20474/merge");
        claims["job_workflow_ref"] =
            json!("astral-sh/uv/.github/workflows/publish.yml@refs/pull/20474/merge");
        claims["environment"] = json!("automations");
        let token = fixture.sign_claims(claims);
        let request =
            fixture.make_scoped_request(&token, "astral-sh/uv-dev", json!({ "contents": "write" }));

        let error = verify_oidc_claims(&config, &request).await.unwrap_err();

        assert_eq!(error.code(), "workflow_not_allowed");
    }

    #[tokio::test]
    async fn verify_oidc_claims_accepts_the_uv_issue_triage_reusable_workflow_rule() {
        let fixture = TestFixture::new().await;
        let policy: Policy = serde_json::from_value(json!({
            "expected_audience": fixture.server.uri(),
            "rules": [{
                "subject": "repo:astral-sh/uv:environment:automations",
                "repository": "astral-sh/uv",
                "repository_id": 699532645,
                "ref": "refs/heads/main",
                "workflow_path": ".github/workflows/issue-triage.yml",
                "job_workflow_path": ".github/workflows/reproduce-bug.yml",
                "environment": "automations",
                "allowed_events": ["issues", "workflow_dispatch"],
                "permissions": { "contents": "write", "pull_requests": "write" },
                "target_repository": "astral-sh/uv-dev",
                "target_repository_id": 1302176231
            }]
        }))
        .unwrap();
        let config = fixture.build_config(policy);

        for event in ["issues", "workflow_dispatch"] {
            let mut claims = fixture.valid_claims();
            claims["sub"] = json!("repo:astral-sh/uv:environment:automations");
            claims["repository"] = json!("astral-sh/uv");
            claims["repository_id"] = json!(699532645);
            claims["event_name"] = json!(event);
            claims["workflow_ref"] =
                json!("astral-sh/uv/.github/workflows/issue-triage.yml@refs/heads/main");
            claims["job_workflow_ref"] =
                json!("astral-sh/uv/.github/workflows/reproduce-bug.yml@refs/heads/main");
            claims["environment"] = json!("automations");
            let token = fixture.sign_claims(claims);
            let request = fixture.make_scoped_request(
                &token,
                "astral-sh/uv-dev",
                json!({ "contents": "write", "pull_requests": "write" }),
            );

            let verified = verify_oidc_claims(&config, &request).await.unwrap();

            assert_eq!(verified.target_repository.as_str(), "astral-sh/uv-dev");
            assert_eq!(*verified.target_repository_id, 1302176231);
            assert_eq!(verified.git_ref.as_str(), "refs/heads/main");
            assert_eq!(
                serde_json::to_value(verified.permissions).unwrap(),
                json!({ "contents": "write", "pull_requests": "write" })
            );
        }
    }

    #[tokio::test]
    async fn verify_oidc_claims_accepts_the_uv_caller_rebase_reusable_workflow_rule() {
        let fixture = TestFixture::new().await;
        let policy: Policy = serde_json::from_value(json!({
            "expected_audience": fixture.server.uri(),
            "rules": [{
                "subject": "repo:astral-sh/uv:environment:automations",
                "repository": "astral-sh/uv",
                "repository_id": 699532645,
                "ref": "refs/heads/main",
                "workflow_path": ".github/workflows/pull-request-conflicts.yml",
                "job_workflow_path": ".github/workflows/rebase-conflicted-pull-request.yml",
                "allowed_events": ["push", "workflow_dispatch"],
                "permissions": {"contents": "write", "workflows": "write"},
                "target_repository": "astral-sh/uv-dev",
                "target_repository_id": 1302176231
            }]
        }))
        .unwrap();
        let config = fixture.build_config(policy);

        for event in ["push", "workflow_dispatch"] {
            let mut claims = fixture.valid_claims();
            claims["sub"] = json!("repo:astral-sh/uv:environment:automations");
            claims["repository"] = json!("astral-sh/uv");
            claims["repository_id"] = json!(699532645);
            claims["event_name"] = json!(event);
            claims["workflow_ref"] =
                json!("astral-sh/uv/.github/workflows/pull-request-conflicts.yml@refs/heads/main");
            claims["job_workflow_ref"] = json!(
                "astral-sh/uv/.github/workflows/rebase-conflicted-pull-request.yml@refs/heads/main"
            );
            claims["environment"] = json!("automations");
            let token = fixture.sign_claims(claims);
            let request = fixture.make_scoped_request(
                &token,
                "astral-sh/uv-dev",
                json!({"contents": "write", "workflows": "write"}),
            );

            let verified = verify_oidc_claims(&config, &request).await.unwrap();

            assert_eq!(verified.target_repository.as_str(), "astral-sh/uv-dev");
            assert_eq!(*verified.target_repository_id, 1302176231);
            assert_eq!(verified.git_ref.as_str(), "refs/heads/main");
        }
    }

    #[tokio::test]
    async fn verify_oidc_claims_accepts_the_uv_caller_diagnose_workflow_rule() {
        let fixture = TestFixture::new().await;
        let policy: Policy = serde_json::from_value(json!({
            "expected_audience": fixture.server.uri(),
            "rules": [{
                "subject": "repo:astral-sh/uv:environment:automations",
                "repository": "astral-sh/uv",
                "repository_id": 699532645,
                "ref": "refs/heads/main",
                "workflow_path": ".github/workflows/diagnose-workflow-failure.yml",
                "allowed_events": ["workflow_dispatch"],
                "permissions": {"issues": "write"},
                "target_repository": "astral-sh/uv-dev",
                "target_repository_id": 1302176231
            }]
        }))
        .unwrap();
        let config = fixture.build_config(policy);
        let mut claims = fixture.valid_claims();
        claims["sub"] = json!("repo:astral-sh/uv:environment:automations");
        claims["repository"] = json!("astral-sh/uv");
        claims["repository_id"] = json!(699532645);
        claims["event_name"] = json!("workflow_dispatch");
        claims["workflow_ref"] =
            json!("astral-sh/uv/.github/workflows/diagnose-workflow-failure.yml@refs/heads/main");
        claims["job_workflow_ref"] = json!(null);
        claims["environment"] = json!("automations");
        let token = fixture.sign_claims(claims);
        let request =
            fixture.make_scoped_request(&token, "astral-sh/uv-dev", json!({"issues": "write"}));

        let verified = verify_oidc_claims(&config, &request).await.unwrap();

        assert_eq!(verified.target_repository.as_str(), "astral-sh/uv-dev");
        assert_eq!(*verified.target_repository_id, 1302176231);
        assert_eq!(verified.git_ref.as_str(), "refs/heads/main");
        assert_eq!(
            serde_json::to_value(verified.permissions).unwrap(),
            json!({"issues": "write"})
        );
    }

    #[tokio::test]
    async fn verify_oidc_claims_fails_closed_when_the_hosted_policy_cannot_be_refreshed() {
        for response in [
            ResponseTemplate::new(404),
            ResponseTemplate::new(200).set_body_string(r#"{"version":2,"rules":[]}"#),
            ResponseTemplate::new(403).insert_header("retry-after", "2"),
        ] {
            let fixture = TestFixture::new().await;
            let mut config = fixture.build_config(fixture.policy());
            config.policy_cache = Arc::new(crate::policy_cache::PolicyCache::default());
            config.app_private_key = RSA_PRIVATE_KEY.try_into().unwrap();
            Mock::given(method("POST"))
                .and(path("/app/installations/456/access_tokens"))
                .and(body_json(json!({
                    "repository_ids": [42],
                    "permissions": {"contents": "read"}
                })))
                .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                    "token": "policy-token",
                    "repositories": [{"id": 42, "full_name": "octo/tools"}],
                    "permissions": {"contents": "read", "metadata": "read"}
                })))
                .expect(1)
                .mount(&fixture.server)
                .await;
            Mock::given(method("GET"))
                .and(path(
                    "/repos/octo/tools/contents/.github/ost-simple-sts.json",
                ))
                .respond_with(response)
                .expect(1)
                .mount(&fixture.server)
                .await;
            Mock::given(method("DELETE"))
                .and(path("/installation/token"))
                .respond_with(ResponseTemplate::new(204))
                .expect(1)
                .mount(&fixture.server)
                .await;

            let token = fixture.sign_claims(fixture.valid_claims());
            let request = fixture.make_request(&token);
            let error = verify_oidc_claims(&config, &request).await.unwrap_err();

            assert!(matches!(
                error,
                AppError::PolicyLookupFailed
                    | AppError::InvalidPolicy
                    | AppError::GithubRateLimited { .. }
            ));
        }
    }

    #[tokio::test]
    async fn verify_oidc_claims_rejects_invalid_uv_issue_triage_reusable_workflow_claims() {
        let fixture = TestFixture::new().await;
        let policy: Policy = serde_json::from_value(json!({
            "expected_audience": fixture.server.uri(),
            "rules": [{
                "subject": "repo:astral-sh/uv:environment:automations",
                "repository": "astral-sh/uv",
                "repository_id": 699532645,
                "ref": "refs/heads/main",
                "workflow_path": ".github/workflows/issue-triage.yml",
                "job_workflow_path": ".github/workflows/reproduce-bug.yml",
                "environment": "automations",
                "allowed_events": ["issues", "workflow_dispatch"],
                "permissions": { "contents": "write", "pull_requests": "write" },
                "target_repository": "astral-sh/uv-dev",
                "target_repository_id": 1302176231
            }]
        }))
        .unwrap();
        let config = fixture.build_config(policy);
        let mut valid_claims = fixture.valid_claims();
        valid_claims["sub"] = json!("repo:astral-sh/uv:environment:automations");
        valid_claims["repository"] = json!("astral-sh/uv");
        valid_claims["repository_id"] = json!(699532645);
        valid_claims["event_name"] = json!("issues");
        valid_claims["workflow_ref"] =
            json!("astral-sh/uv/.github/workflows/issue-triage.yml@refs/heads/main");
        valid_claims["job_workflow_ref"] =
            json!("astral-sh/uv/.github/workflows/reproduce-bug.yml@refs/heads/main");
        valid_claims["environment"] = json!("automations");

        for (field, value, expected_code) in [
            (
                "sub",
                json!("repo:astral-sh/uv-dev:environment:automations"),
                "subject_not_allowed",
            ),
            (
                "repository",
                json!("astral-sh/uv-dev"),
                "repository_not_allowed",
            ),
            (
                "repository_id",
                json!(1302176231),
                "repository_id_not_allowed",
            ),
            ("ref", json!("refs/heads/other"), "ref_not_allowed"),
            ("environment", json!("release"), "environment_not_allowed"),
            ("event_name", json!("push"), "event_not_allowed"),
            (
                "workflow_ref",
                json!("astral-sh/uv/.github/workflows/reproduce-bug.yml@refs/heads/main"),
                "workflow_not_allowed",
            ),
            (
                "job_workflow_ref",
                json!("astral-sh/uv/.github/workflows/issue-triage.yml@refs/heads/main"),
                "workflow_not_allowed",
            ),
            ("job_workflow_ref", json!(null), "workflow_not_allowed"),
        ] {
            let mut claims = valid_claims.clone();
            claims[field] = value;
            let token = fixture.sign_claims(claims);
            let request = fixture.make_scoped_request(
                &token,
                "astral-sh/uv-dev",
                json!({ "contents": "write", "pull_requests": "write" }),
            );

            let error = verify_oidc_claims(&config, &request).await.unwrap_err();

            assert_eq!(error.code(), expected_code, "field {field}");
        }

        let token = fixture.sign_claims(valid_claims);
        let wrong_target = fixture.make_scoped_request(
            &token,
            "astral-sh/uv",
            json!({ "contents": "write", "pull_requests": "write" }),
        );
        let error = verify_oidc_claims(&config, &wrong_target)
            .await
            .unwrap_err();
        assert_eq!(error.code(), "target_repository_not_allowed");

        for permissions in [
            json!({ "workflows": "write" }),
            json!({ "contents": "write", "pull_requests": "write", "workflows": "write" }),
        ] {
            let request = fixture.make_scoped_request(&token, "astral-sh/uv-dev", permissions);
            let error = verify_oidc_claims(&config, &request).await.unwrap_err();
            assert_eq!(error.code(), "permissions_not_allowed");
        }
    }

    #[tokio::test]
    async fn verify_oidc_claims_does_not_mix_events_or_targets_across_rules() {
        let fixture = TestFixture::new().await;
        let policy: Policy = serde_json::from_value(json!({
            "expected_audience": fixture.server.uri(),
            "rules": [{
                "subject": "repo:octo/tools:environment:release",
                "repository": "octo/tools",
                "repository_id": 42,
                "ref": "refs/heads/main",
                "workflow_path": ".github/workflows/release.yml",
                "environment": "release",
                "allowed_events": ["workflow_dispatch"],
                "target_repository": "octo/tools-dev",
                "target_repository_id": 84
            }, {
                "subject": "repo:octo/docs:environment:publish",
                "repository": "octo/docs",
                "repository_id": 43,
                "ref": "refs/heads/main",
                "workflow_path": ".github/workflows/publish.yml",
                "environment": "publish",
                "allowed_events": ["push"],
                "target_repository": "octo/docs-dev",
                "target_repository_id": 85
            }]
        }))
        .unwrap();
        let config = fixture.build_config(policy);
        let mut claims = fixture.valid_claims();
        claims["event_name"] = json!("push");
        let token = fixture.sign_claims(claims);
        let request =
            fixture.make_scoped_request(&token, "octo/tools-dev", json!({ "contents": "write" }));

        let error = verify_oidc_claims(&config, &request).await.unwrap_err();

        assert!(matches!(error, AppError::EventNotAllowed));
    }

    #[tokio::test]
    async fn verify_oidc_claims_does_not_mix_event_workflow_or_target_across_rules() {
        let fixture = TestFixture::new().await;
        let policy: Policy = serde_json::from_value(json!({
            "expected_audience": fixture.server.uri(),
            "rules": [{
                "subject": "repo:octo/tools:environment:release",
                "repository": "octo/tools",
                "repository_id": 42,
                "ref": "refs/heads/main",
                "workflow_path": ".github/workflows/release.yml",
                "environment": "release",
                "allowed_events": ["workflow_dispatch"],
                "target_repository": "octo/tools-dev",
                "target_repository_id": 84
            }, {
                "subject": "repo:octo/tools:environment:release",
                "repository": "octo/tools",
                "repository_id": 42,
                "ref": "refs/heads/main",
                "workflow_path": ".github/workflows/publish.yml",
                "environment": "release",
                "allowed_events": ["push"],
                "target_repository": "octo/docs-dev",
                "target_repository_id": 85
            }]
        }))
        .unwrap();
        let config = fixture.build_config(policy);

        let mut mixed_claims = fixture.valid_claims();
        mixed_claims["event_name"] = json!("push");
        let mixed_token = fixture.sign_claims(mixed_claims);
        let mixed_request = fixture.make_scoped_request(
            &mixed_token,
            "octo/docs-dev",
            json!({ "contents": "write" }),
        );

        let error = verify_oidc_claims(&config, &mixed_request)
            .await
            .unwrap_err();
        assert!(matches!(error, AppError::WorkflowNotAllowed));

        let mut publish_claims = fixture.valid_claims();
        publish_claims["event_name"] = json!("push");
        publish_claims["workflow_ref"] =
            json!("octo/tools/.github/workflows/publish.yml@refs/heads/main");
        let publish_token = fixture.sign_claims(publish_claims);
        let publish_request = fixture.make_scoped_request(
            &publish_token,
            "octo/docs-dev",
            json!({ "contents": "write" }),
        );

        let verified = verify_oidc_claims(&config, &publish_request).await.unwrap();
        assert_eq!(verified.target_repository.as_str(), "octo/docs-dev");
        assert_eq!(*verified.target_repository_id, 85);
    }

    #[tokio::test]
    async fn verify_oidc_claims_does_not_mix_permissions_across_rules() {
        let fixture = TestFixture::new().await;
        let policy: Policy = serde_json::from_value(json!({
            "expected_audience": fixture.server.uri(),
            "rules": [{
                "subject": "repo:octo/tools:environment:release",
                "repository": "octo/tools",
                "repository_id": 42,
                "ref": "refs/heads/main",
                "workflow_path": ".github/workflows/release.yml",
                "environment": "release",
                "allowed_events": ["workflow_dispatch"],
                "permissions": { "contents": "read" },
                "target_repository": "octo/tools-dev",
                "target_repository_id": 84
            }, {
                "subject": "repo:octo/docs:environment:publish",
                "repository": "octo/docs",
                "repository_id": 43,
                "ref": "refs/heads/main",
                "workflow_path": ".github/workflows/publish.yml",
                "environment": "publish",
                "allowed_events": ["workflow_dispatch"],
                "permissions": { "contents": "write", "pull_requests": "write" },
                "target_repository": "octo/docs-dev",
                "target_repository_id": 85
            }]
        }))
        .unwrap();
        let config = fixture.build_config(policy);
        let token = fixture.sign_claims(fixture.valid_claims());

        for permissions in [
            json!({ "contents": "write" }),
            json!({ "contents": "read", "pull_requests": "write" }),
        ] {
            let request = fixture.make_scoped_request(&token, "octo/tools-dev", permissions);
            let error = verify_oidc_claims(&config, &request).await.unwrap_err();
            assert!(matches!(error, AppError::PermissionsNotAllowed));
        }
    }

    #[tokio::test]
    async fn mint_installation_token_uses_only_the_matched_target_repository() {
        let fixture = TestFixture::new().await;
        let mut config = fixture.build_config(fixture.policy());
        config.app_private_key = RSA_PRIVATE_KEY.try_into().unwrap();

        Mock::given(method("GET"))
            .and(path("/repos/octo/tools-dev/installation"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 123 })))
            .expect(1)
            .mount(&fixture.server)
            .await;
        Mock::given(method("POST"))
            .and(path("/app/installations/123/access_tokens"))
            .and(body_json(json!({
                "repository_ids": [84],
                "permissions": { "contents": "write" }
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "token": "ghs_target_only",
                "expires_at": "2026-07-16T14:00:00Z",
                "repositories": [{ "id": 84, "full_name": "octo/tools-dev" }]
            })))
            .expect(1)
            .mount(&fixture.server)
            .await;

        let claims = VerifiedClaims {
            target_repository: "octo/tools-dev".try_into().unwrap(),
            target_repository_id: serde_json::from_value(json!(84)).unwrap(),
            target_repositories: vec![(
                "octo/tools-dev".try_into().unwrap(),
                serde_json::from_value(json!(84)).unwrap(),
            )],
            target_installation_id: None,
            multiple_target_repositories: false,
            permissions: Permissions::contents_write(),
            git_ref: "refs/heads/main".try_into().unwrap(),
            jti: "test-jti".try_into().unwrap(),
            expires_at_ms: 0,
        };

        let result = mint_installation_token(&config, &claims).await.unwrap();

        assert_eq!(result.repository.as_deref(), Some("octo/tools-dev"));
        assert!(result.repositories.is_none());
        assert_eq!(result.git_ref, "refs/heads/main");
        assert_eq!(result.token.as_str(), "ghs_target_only");
    }

    #[tokio::test]
    async fn verify_oidc_claims_accepts_only_the_exact_multi_repository_target_set() {
        let fixture = TestFixture::new().await;
        let policy: Policy = serde_json::from_value(json!({
            "expected_audience": fixture.server.uri(),
            "rules": [{
                "subject": "repo:astral-sh/uv-dev:environment:automations",
                "repository": "astral-sh/uv-dev",
                "repository_id": 1302176231,
                "ref": "refs/heads/main",
                "workflow_path": ".github/workflows/promote-pull-request.yml",
                "environment": "automations",
                "allowed_events": ["workflow_dispatch"],
                "permissions": { "contents": "write", "pull_requests": "write" },
                "target_repositories": [
                    { "repository": "astral-sh/uv", "repository_id": 699532645 },
                    { "repository": "astral-sh/uv-dev", "repository_id": 1302176231 }
                ],
                "target_installation_id": 146796415
            }]
        }))
        .unwrap();
        let config = fixture.build_config(policy);
        let mut claims = fixture.valid_claims();
        claims["sub"] = json!("repo:astral-sh/uv-dev:environment:automations");
        claims["repository"] = json!("astral-sh/uv-dev");
        claims["repository_id"] = json!(1302176231);
        claims["workflow_ref"] =
            json!("astral-sh/uv-dev/.github/workflows/promote-pull-request.yml@refs/heads/main");
        claims["environment"] = json!("automations");
        let token = fixture.sign_claims(claims.clone());

        let request = fixture.make_multi_scoped_request(
            &token,
            &["astral-sh/uv-dev", "astral-sh/uv"],
            json!({ "contents": "write", "pull_requests": "write" }),
        );
        let verified = verify_oidc_claims(&config, &request).await.unwrap();
        assert!(verified.multiple_target_repositories);
        assert_eq!(verified.target_installation_id, Some(146796415));
        assert_eq!(
            verified
                .target_repositories
                .iter()
                .map(|(repository, id)| (repository.as_str(), **id))
                .collect::<Vec<_>>(),
            [
                ("astral-sh/uv", 699532645),
                ("astral-sh/uv-dev", 1302176231)
            ]
        );

        for repositories in [
            vec!["astral-sh/uv"],
            vec!["astral-sh/uv", "astral-sh/other"],
            vec!["astral-sh/uv", "astral-sh/uv-dev", "astral-sh/other"],
        ] {
            let request = fixture.make_multi_scoped_request(
                &token,
                &repositories,
                json!({ "contents": "write", "pull_requests": "write" }),
            );
            assert!(verify_oidc_claims(&config, &request).await.is_err());
        }

        let singular = fixture.make_scoped_request(
            &token,
            "astral-sh/uv",
            json!({ "contents": "write", "pull_requests": "write" }),
        );
        assert!(matches!(
            verify_oidc_claims(&config, &singular).await,
            Err(AppError::TargetRepositoryNotAllowed)
        ));
        let broader = fixture.make_multi_scoped_request(
            &token,
            &["astral-sh/uv", "astral-sh/uv-dev"],
            json!({ "contents": "write", "pull_requests": "write", "workflows": "write" }),
        );
        assert!(matches!(
            verify_oidc_claims(&config, &broader).await,
            Err(AppError::PermissionsNotAllowed)
        ));

        for (claim, value, expected) in [
            (
                "sub",
                json!("repo:astral-sh/other:environment:automations"),
                "subject_not_allowed",
            ),
            (
                "repository",
                json!("astral-sh/other"),
                "repository_not_allowed",
            ),
            (
                "repository_id",
                json!(699532645),
                "repository_id_not_allowed",
            ),
            ("ref", json!("refs/heads/other"), "ref_not_allowed"),
            ("environment", json!("other"), "environment_not_allowed"),
            ("event_name", json!("push"), "event_not_allowed"),
            (
                "workflow_ref",
                json!("astral-sh/uv-dev/.github/workflows/other.yml@refs/heads/main"),
                "workflow_not_allowed",
            ),
        ] {
            let mut invalid_claims = claims.clone();
            invalid_claims[claim] = value;
            let token = fixture.sign_claims(invalid_claims);
            let request = fixture.make_multi_scoped_request(
                &token,
                &["astral-sh/uv", "astral-sh/uv-dev"],
                json!({ "contents": "write", "pull_requests": "write" }),
            );
            let error = verify_oidc_claims(&config, &request).await.unwrap_err();
            assert_eq!(error.code(), expected, "unexpected error for {claim}");
        }
    }

    #[tokio::test]
    async fn verify_oidc_claims_does_not_mix_multi_repository_targets_across_rules() {
        let fixture = TestFixture::new().await;
        let policy: Policy = serde_json::from_value(json!({
            "expected_audience": fixture.server.uri(),
            "rules": [{
                "subject": "repo:octo/tools:environment:release",
                "repository": "octo/tools",
                "repository_id": 42,
                "ref": "refs/heads/main",
                "workflow_path": ".github/workflows/release.yml",
                "environment": "release",
                "allowed_events": ["workflow_dispatch"],
                "target_repositories": [
                    { "repository": "octo/tools", "repository_id": 42 },
                    { "repository": "octo/tools-dev", "repository_id": 84 }
                ],
                "target_installation_id": 123
            }, {
                "subject": "repo:octo/tools:environment:release",
                "repository": "octo/tools",
                "repository_id": 42,
                "ref": "refs/heads/main",
                "workflow_path": ".github/workflows/publish.yml",
                "environment": "release",
                "allowed_events": ["push"],
                "target_repositories": [
                    { "repository": "octo/docs", "repository_id": 43 },
                    { "repository": "octo/docs-dev", "repository_id": 85 }
                ],
                "target_installation_id": 123
            }]
        }))
        .unwrap();
        let config = fixture.build_config(policy);
        let token = fixture.sign_claims(fixture.valid_claims());
        let mixed = fixture.make_multi_scoped_request(
            &token,
            &["octo/tools", "octo/docs-dev"],
            json!({ "contents": "write" }),
        );

        assert!(matches!(
            verify_oidc_claims(&config, &mixed).await,
            Err(AppError::TargetRepositoryNotAllowed)
        ));
    }

    #[tokio::test]
    async fn mint_installation_token_uses_all_exact_targets_from_one_installation() {
        let fixture = TestFixture::new().await;
        let mut config = fixture.build_config(fixture.policy());
        config.app_private_key = RSA_PRIVATE_KEY.try_into().unwrap();

        for path_suffix in [
            "/repos/astral-sh/uv/installation",
            "/repos/astral-sh/uv-dev/installation",
        ] {
            Mock::given(method("GET"))
                .and(path(path_suffix))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 146796415 })))
                .expect(1)
                .mount(&fixture.server)
                .await;
        }
        Mock::given(method("POST"))
            .and(path("/app/installations/146796415/access_tokens"))
            .and(body_json(json!({
                "repository_ids": [699532645, 1302176231],
                "permissions": { "contents": "write", "pull_requests": "write" }
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "token": "ghs_multi_target",
                "expires_at": "2026-07-16T14:00:00Z",
                "repositories": [
                    { "id": 1302176231, "full_name": "astral-sh/uv-dev" },
                    { "id": 699532645, "full_name": "astral-sh/uv" }
                ]
            })))
            .expect(1)
            .mount(&fixture.server)
            .await;

        let claims = VerifiedClaims {
            target_repository: "astral-sh/uv".try_into().unwrap(),
            target_repository_id: serde_json::from_value(json!(699532645)).unwrap(),
            target_repositories: vec![
                (
                    "astral-sh/uv".try_into().unwrap(),
                    serde_json::from_value(json!(699532645)).unwrap(),
                ),
                (
                    "astral-sh/uv-dev".try_into().unwrap(),
                    serde_json::from_value(json!(1302176231)).unwrap(),
                ),
            ],
            target_installation_id: Some(146796415),
            multiple_target_repositories: true,
            permissions: serde_json::from_value(
                json!({ "contents": "write", "pull_requests": "write" }),
            )
            .unwrap(),
            git_ref: "refs/heads/main".try_into().unwrap(),
            jti: "test-jti".try_into().unwrap(),
            expires_at_ms: 0,
        };

        let result = mint_installation_token(&config, &claims).await.unwrap();
        assert!(result.repository.is_none());
        assert_eq!(
            result.repositories.as_deref(),
            Some(["astral-sh/uv".to_string(), "astral-sh/uv-dev".to_string()].as_slice())
        );
        assert_eq!(result.token.as_str(), "ghs_multi_target");
    }

    #[tokio::test]
    async fn mint_installation_token_rejects_a_wrong_target_installation() {
        let fixture = TestFixture::new().await;
        let mut config = fixture.build_config(fixture.policy());
        config.app_private_key = RSA_PRIVATE_KEY.try_into().unwrap();

        Mock::given(method("GET"))
            .and(path("/repos/astral-sh/uv/installation"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 146796415 })))
            .expect(1)
            .mount(&fixture.server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/astral-sh/uv-dev/installation"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 999 })))
            .expect(1)
            .mount(&fixture.server)
            .await;

        let claims = VerifiedClaims {
            target_repository: "astral-sh/uv".try_into().unwrap(),
            target_repository_id: serde_json::from_value(json!(699532645)).unwrap(),
            target_repositories: vec![
                (
                    "astral-sh/uv".try_into().unwrap(),
                    serde_json::from_value(json!(699532645)).unwrap(),
                ),
                (
                    "astral-sh/uv-dev".try_into().unwrap(),
                    serde_json::from_value(json!(1302176231)).unwrap(),
                ),
            ],
            target_installation_id: Some(146796415),
            multiple_target_repositories: true,
            permissions: Permissions::contents_write(),
            git_ref: "refs/heads/main".try_into().unwrap(),
            jti: "test-jti".try_into().unwrap(),
            expires_at_ms: 0,
        };

        assert!(matches!(
            mint_installation_token(&config, &claims).await,
            Err(AppError::TargetInstallationNotAllowed)
        ));
        assert!(fixture
            .server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|request| request.method != "POST"));
    }

    #[tokio::test]
    async fn verify_oidc_claims_rejects_wrong_workflow() {
        let fixture = TestFixture::new().await;
        let policy = fixture.policy();
        let config = fixture.build_config(policy);
        let mut claims = fixture.valid_claims();
        claims["workflow_ref"] = json!("octo/tools/.github/workflows/ci.yml@refs/heads/main");
        let token = fixture.sign_claims(claims);
        let request = fixture.make_request(&token);

        let error = verify_oidc_claims(&config, &request).await.unwrap_err();
        assert!(matches!(error, AppError::WorkflowNotAllowed));
    }

    #[tokio::test]
    async fn verify_oidc_claims_rejects_expired_token() {
        let fixture = TestFixture::new().await;
        let policy = fixture.policy();
        let config = fixture.build_config(policy);
        let mut claims = fixture.valid_claims();
        let past = fixture.now_secs() - 600;
        claims["iat"] = json!(past - 10);
        claims["exp"] = json!(past);
        let token = fixture.sign_claims(claims);
        let request = fixture.make_request(&token);

        let error = verify_oidc_claims(&config, &request).await.unwrap_err();
        assert!(matches!(error, AppError::OidcTokenExpired));
    }

    #[tokio::test]
    async fn verify_oidc_claims_rejects_tampered_signature() {
        let fixture = TestFixture::new().await;
        let config = fixture.build_config(fixture.policy());
        let token = fixture.sign_claims(fixture.valid_claims());
        let (header_and_claims, signature) = token.rsplit_once('.').unwrap();
        let mut signature = URL_SAFE_NO_PAD.decode(signature).unwrap();
        signature[0] ^= 1;
        let token = format!("{header_and_claims}.{}", URL_SAFE_NO_PAD.encode(signature));
        let request = fixture.make_request(&token);

        let error = verify_oidc_claims(&config, &request).await.unwrap_err();
        assert!(matches!(error, AppError::InvalidOidcToken));
    }

    #[tokio::test]
    async fn verify_oidc_claims_rejects_future_not_before() {
        let fixture = TestFixture::new().await;
        let config = fixture.build_config(fixture.policy());
        let mut claims = fixture.valid_claims();
        claims["nbf"] = json!(fixture.now_secs() + 60);
        let token = fixture.sign_claims(claims);
        let request = fixture.make_request(&token);

        let error = verify_oidc_claims(&config, &request).await.unwrap_err();
        assert!(matches!(error, AppError::InvalidOidcToken));
    }

    #[tokio::test]
    async fn verify_oidc_claims_rejects_future_issued_at() {
        let fixture = TestFixture::new().await;
        let config = fixture.build_config(fixture.policy());
        let mut claims = fixture.valid_claims();
        claims["iat"] = json!(fixture.now_secs() + 60);
        let token = fixture.sign_claims(claims);
        let request = fixture.make_request(&token);

        let error = verify_oidc_claims(&config, &request).await.unwrap_err();
        assert!(matches!(error, AppError::InvalidOidcToken));
    }

    #[tokio::test]
    async fn verify_oidc_claims_rejects_missing_required_claim() {
        let fixture = TestFixture::new().await;
        let config = fixture.build_config(fixture.policy());
        let mut claims = fixture.valid_claims();
        claims.as_object_mut().unwrap().remove("nbf");
        let token = fixture.sign_claims(claims);
        let request = fixture.make_request(&token);

        let error = verify_oidc_claims(&config, &request).await.unwrap_err();
        assert!(matches!(error, AppError::InvalidOidcToken));
    }

    #[tokio::test]
    async fn verify_oidc_claims_rejects_missing_bearer() {
        let fixture = TestFixture::new().await;
        let policy = fixture.policy();
        let config = fixture.build_config(policy);
        let request = Request::builder()
            .method("POST")
            .uri("/exchange")
            .body(Body::Empty)
            .unwrap();

        let error = verify_oidc_claims(&config, &request).await.unwrap_err();
        assert!(matches!(error, AppError::MissingBearerToken));
    }
}
