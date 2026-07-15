use jsonwebtoken::{decode, decode_header, errors::ErrorKind, Algorithm, Validation};
use lambda_http::{http::header::AUTHORIZATION, Request};
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    config::{Config, GitRef},
    error::AppError,
    github::{self, Jti, RepositoryFullName, RepositoryId},
    replay,
};

const ACTIONS_ISSUER: &str = "https://token.actions.githubusercontent.com";
const CLOCK_TOLERANCE_SECONDS: u64 = 5;
const MAX_OIDC_TOKEN_BYTES: usize = 16 * 1024;

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
    repository: RepositoryFullName,
    repository_id: RepositoryId,
    git_ref: GitRef,
    jti: Jti,
    expires_at_ms: u64,
}

pub struct ExchangeResult {
    pub token: github::Token,
    pub expires_at: String,
    pub repository: String,
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

    if claims.subject.as_deref() != Some(config.policy.allowed_subject().as_str()) {
        return Err(AppError::SubjectNotAllowed);
    }

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
    if repository != *config.policy.allowed_repository() {
        return Err(AppError::RepositoryNotAllowed);
    }

    let repository_id = claims
        .repository_id
        .ok_or(AppError::RepositoryIdClaimInvalid)?;
    if repository_id != config.policy.allowed_repository_id() {
        return Err(AppError::RepositoryIdNotAllowed);
    }

    if claims.event_name.as_deref() != Some("workflow_dispatch") {
        return Err(AppError::EventNotAllowed);
    }

    let expected_workflow_ref = format!(
        "{repository}/{}@{}",
        config.policy.allowed_workflow_path(),
        config.policy.allowed_ref(),
    );
    if claims.workflow_ref.as_deref() != Some(expected_workflow_ref.as_str())
        || claims
            .job_workflow_ref
            .as_deref()
            .is_some_and(|workflow_ref| workflow_ref != expected_workflow_ref)
    {
        return Err(AppError::WorkflowNotAllowed);
    }

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
) -> Result<ExchangeResult, AppError> {
    let app_jwt = github::create_app_jwt(&config.app_id, &config.app_private_key)?;
    let installation_id = github::find_installation(
        &config.http_client,
        &config.github_api_base,
        &app_jwt,
        claims.repository.owner().as_str(),
        claims.repository.repo().as_str(),
    )
    .await?;

    let token = github::mint_installation_token(
        &config.http_client,
        &config.github_api_base,
        &app_jwt,
        installation_id,
        *claims.repository_id,
    )
    .await?;

    Ok(ExchangeResult {
        token: token.token,
        expires_at: token.expires_at,
        repository: claims.repository.as_str().to_string(),
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
    use super::get_bearer_token;
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
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::{
        config::{Config, Policy},
        error::AppError,
        github::GithubApiBase,
        jwks::JwksCache,
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use lambda_http::{http::Request, Body};
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::traits::PublicKeyParts;
    use serde_json::json;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use wiremock::{
        matchers::{method, path},
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

            let mut rng = rand::thread_rng();
            let private_key =
                rsa::RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate RSA key");
            let pem = private_key
                .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
                .expect("failed to encode private key");

            let encoding_key = EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();
            let public_key = private_key.to_public_key();
            let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
            let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

            let kid = "test-kid-001".to_string();

            let jwks_response = json!({
                "keys": [{
                    "kty": "RSA",
                    "n": n,
                    "e": e,
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
            GithubApiBase::try_from(self.server.uri().as_str()).unwrap()
        }

        fn policy(&self) -> Policy {
            serde_json::from_value(json!({
                "expected_audience": self.server.uri(),
                "allowed_subject": "repo:octo/tools:environment:release",
                "allowed_repository": "octo/tools",
                "allowed_repository_id": 42,
                "allowed_ref": "refs/heads/main",
                "allowed_workflow_path": ".github/workflows/release.yml",
                "allowed_environment": "release"
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

        fn build_config(&self, policy: Policy) -> Config {
            let http_client = reqwest::Client::builder().build().unwrap();
            let jwks_url = format!("{}/.well-known/jwks", self.server.uri());
            let jwks_cache = Arc::new(JwksCache::new_with_url(http_client.clone(), jwks_url));

            Config {
                policy,
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

        assert_eq!(verified.repository.as_str(), "octo/tools");
        assert_eq!(verified.git_ref.as_str(), "refs/heads/main");
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
        assert_eq!(verified.repository.as_str(), "octo/tools");
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
