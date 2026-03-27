use std::{env, sync::Arc};

use aws_config::BehaviorVersion;
use aws_sdk_dynamodb::Client as DynamoDbClient;
use aws_sdk_secretsmanager::Client as SecretsManagerClient;
use aws_sdk_ssm::Client as SsmClient;
use lambda_http::Error;
use serde::Deserialize;

use crate::{
    error::AppError,
    jwks::JwksCache,
    types::{AppId, AppPrivateKey, Audience, EnvironmentName, GitRef, JtiTableName, WorkflowPath},
};

const DEFAULT_GITHUB_API_URL: &str = "https://api.github.com/";

#[derive(Clone, Debug, Deserialize)]
#[serde(try_from = "RawPolicy")]
pub struct Policy {
    expected_audience: Audience,
    allowed_ref: GitRef,
    allowed_workflow_path: WorkflowPath,
    allowed_environment: Option<EnvironmentName>,
}

#[derive(Debug, Deserialize)]
struct RawPolicy {
    expected_audience: String,
    allowed_ref: String,
    allowed_workflow_path: String,
    #[serde(default)]
    allowed_environment: Option<String>,
}

impl Policy {
    pub fn expected_audience(&self) -> &Audience {
        &self.expected_audience
    }

    pub fn allowed_ref(&self) -> &GitRef {
        &self.allowed_ref
    }

    pub fn allowed_workflow_path(&self) -> &WorkflowPath {
        &self.allowed_workflow_path
    }

    pub fn allowed_environment(&self) -> Option<&EnvironmentName> {
        self.allowed_environment.as_ref()
    }

    pub fn from_env() -> Result<Self, AppError> {
        let policy_json = env::var("POLICY_JSON").map_err(|_| AppError::PolicyNotConfigured)?;
        policy_json.parse()
    }
}

impl std::str::FromStr for Policy {
    type Err = AppError;

    fn from_str(policy_json: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(policy_json).map_err(|_| AppError::InvalidPolicy)
    }
}

impl TryFrom<RawPolicy> for Policy {
    type Error = AppError;

    fn try_from(raw: RawPolicy) -> Result<Self, Self::Error> {
        Ok(Self {
            expected_audience: raw.expected_audience.try_into()?,
            allowed_ref: raw.allowed_ref.try_into()?,
            allowed_workflow_path: raw.allowed_workflow_path.try_into()?,
            allowed_environment: raw.allowed_environment.map(TryInto::try_into).transpose()?,
        })
    }
}

impl AppId {
    async fn from_env_or_ssm(ssm: &SsmClient) -> Result<Self, Error> {
        if let Ok(app_id) = env::var("APP_ID") {
            let trimmed = app_id.trim();
            if !trimmed.is_empty() {
                return Self::try_from(trimmed).map_err(Into::into);
            }
        }

        let parameter_name =
            env::var("APP_ID_PARAMETER").map_err(|_| AppError::AppIdNotConfigured)?;
        let response = ssm
            .get_parameter()
            .name(parameter_name)
            .with_decryption(true)
            .send()
            .await?;
        let value = response
            .parameter()
            .and_then(|parameter| parameter.value())
            .ok_or(AppError::AppIdNotConfigured)?;

        Self::try_from(value).map_err(Into::into)
    }
}

impl AppPrivateKey {
    async fn from_env_or_secret(secrets: &SecretsManagerClient) -> Result<Self, Error> {
        if let Ok(value) = env::var("APP_PRIVATE_KEY") {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Self::try_from(trimmed).map_err(Into::into);
            }
        }

        let secret_id = env::var("APP_PRIVATE_KEY_SECRET_NAME")
            .or_else(|_| env::var("APP_PRIVATE_KEY_SECRET_ARN"))
            .map_err(|_| AppError::AppPrivateKeyNotConfigured)?;
        let response = secrets
            .get_secret_value()
            .secret_id(secret_id)
            .send()
            .await?;
        let value = response
            .secret_string()
            .ok_or(AppError::AppPrivateKeyNotConfigured)?;

        Self::try_from(value).map_err(Into::into)
    }
}

impl JtiTableName {
    fn from_env() -> Result<Self, AppError> {
        env::var("JTI_TABLE_NAME")
            .map_err(|_| AppError::JtiTableNotConfigured)
            .and_then(Self::try_from)
    }
}

#[derive(Clone)]
pub struct Config {
    pub policy: Policy,
    pub app_id: AppId,
    pub app_private_key: AppPrivateKey,
    pub jti_table_name: JtiTableName,
    pub github_api_base: reqwest::Url,
    pub dynamodb: DynamoDbClient,
    pub http_client: reqwest::Client,
    pub jwks_cache: Arc<JwksCache>,
}

pub async fn load() -> Result<Config, Error> {
    let policy = Policy::from_env()?;
    let shared_config = aws_config::load_defaults(BehaviorVersion::latest()).await;
    let ssm = SsmClient::new(&shared_config);
    let secrets = SecretsManagerClient::new(&shared_config);

    let app_id = AppId::from_env_or_ssm(&ssm).await?;
    let app_private_key = AppPrivateKey::from_env_or_secret(&secrets).await?;
    let jti_table_name = JtiTableName::from_env()?;
    let github_api_base = load_github_api_base()?;

    let http_client = reqwest::Client::builder()
        .user_agent("ost-simple-sts")
        .build()?;

    let jwks_cache = Arc::new(JwksCache::new(http_client.clone()));

    Ok(Config {
        policy,
        app_id,
        app_private_key,
        jti_table_name,
        github_api_base,
        dynamodb: DynamoDbClient::new(&shared_config),
        http_client,
        jwks_cache,
    })
}

fn load_github_api_base() -> Result<reqwest::Url, Error> {
    let github_api_url =
        env::var("GITHUB_API_URL").unwrap_or_else(|_| DEFAULT_GITHUB_API_URL.to_string());
    reqwest::Url::parse(&github_api_url).map_err(|_| AppError::InvalidGithubApiUrl.into())
}

#[cfg(test)]
mod tests {
    use super::Policy;
    use crate::types::EnvironmentName;
    use serde_json::json;

    #[test]
    fn policy_deserializes_into_validated_types() {
        let policy: Policy = serde_json::from_value(json!({
            "expected_audience": "https://example.com",
            "allowed_ref": "refs/heads/main",
            "allowed_workflow_path": ".github/workflows/release.yml",
            "allowed_environment": "release"
        }))
        .unwrap();

        assert_eq!(policy.expected_audience().as_str(), "https://example.com");
        assert_eq!(policy.allowed_ref().as_str(), "refs/heads/main");
        assert_eq!(
            policy.allowed_workflow_path().as_str(),
            ".github/workflows/release.yml"
        );
        assert_eq!(
            policy.allowed_environment().map(EnvironmentName::as_str),
            Some("release")
        );
    }

    #[test]
    fn policy_from_str_deserializes_into_validated_types() {
        let policy: Policy = r#"{
            "expected_audience": "https://example.com",
            "allowed_ref": "refs/heads/main",
            "allowed_workflow_path": ".github/workflows/release.yml",
            "allowed_environment": "release"
        }"#
        .parse()
        .unwrap();

        assert_eq!(policy.expected_audience().as_str(), "https://example.com");
        assert_eq!(policy.allowed_ref().as_str(), "refs/heads/main");
    }

    #[test]
    fn policy_rejects_empty_strings() {
        let result: Result<Policy, _> = serde_json::from_value(json!({
            "expected_audience": "",
            "allowed_ref": "refs/heads/main",
            "allowed_workflow_path": ".github/workflows/release.yml"
        }));

        assert!(result.is_err());
    }

    #[test]
    fn git_ref_rejects_non_canonical_refs() {
        assert!(crate::types::GitRef::try_from("main").is_err());
        assert!(crate::types::GitRef::try_from("refs/pull/1/head").is_err());
        assert!(crate::types::GitRef::try_from("refs/heads/main").is_ok());
        assert!(crate::types::GitRef::try_from("refs/tags/v1.2.3").is_ok());
    }

    #[test]
    fn workflow_path_requires_github_workflows_prefix() {
        assert!(crate::types::WorkflowPath::try_from("release.yml").is_err());
        assert!(crate::types::WorkflowPath::try_from(".github/workflows/release.yml").is_ok());
    }
}
