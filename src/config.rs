use std::{env, fmt, sync::Arc, time::Duration};

use aws_config::BehaviorVersion;
use aws_sdk_dynamodb::Client as DynamoDbClient;
use aws_sdk_secretsmanager::Client as SecretsManagerClient;
use aws_sdk_ssm::Client as SsmClient;
use lambda_http::Error;
use serde::Deserialize;

use crate::{
    error::AppError,
    github::{GithubApiBase, RepositoryFullName, RepositoryId},
    jwks::JwksCache,
};

const WORKFLOWS_PREFIX: &str = ".github/workflows/";
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(6);

#[derive(Clone, Debug, Deserialize)]
#[serde(try_from = "RawPolicy")]
pub struct Policy {
    expected_audience: Audience,
    allowed_subject: Subject,
    allowed_repository: RepositoryFullName,
    allowed_repository_id: RepositoryId,
    allowed_ref: GitRef,
    allowed_workflow_path: WorkflowPath,
    allowed_environment: Option<EnvironmentName>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    expected_audience: String,
    allowed_subject: String,
    allowed_repository: String,
    allowed_repository_id: RepositoryId,
    allowed_ref: String,
    allowed_workflow_path: String,
    #[serde(default)]
    allowed_environment: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Audience(String);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subject(String);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitRef(String);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkflowPath(String);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvironmentName(String);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppId(String);

#[derive(Clone, PartialEq, Eq)]
pub struct AppPrivateKey(String);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JtiTableName(String);

fn is_valid_git_ref(value: &str) -> bool {
    value
        .strip_prefix("refs/heads/")
        .is_some_and(|suffix| !suffix.is_empty())
        || value
            .strip_prefix("refs/tags/")
            .is_some_and(|suffix| !suffix.is_empty())
}

fn is_valid_workflow_path(value: &str) -> bool {
    value
        .strip_prefix(WORKFLOWS_PREFIX)
        .is_some_and(|suffix| !suffix.is_empty())
        && (value.ends_with(".yml") || value.ends_with(".yaml"))
}

crate::impl_string_newtype!(Audience, AppError, AppError::InvalidPolicy);
crate::impl_string_newtype!(Subject, AppError, AppError::InvalidPolicy);
crate::impl_string_newtype!(
    GitRef,
    AppError,
    AppError::InvalidPolicy,
    validate = is_valid_git_ref
);
crate::impl_string_newtype!(
    WorkflowPath,
    AppError,
    AppError::InvalidPolicy,
    validate = is_valid_workflow_path
);
crate::impl_string_newtype!(EnvironmentName, AppError, AppError::InvalidPolicy);
crate::impl_string_newtype!(AppId, AppError, AppError::AppIdNotConfigured);
crate::impl_string_newtype!(JtiTableName, AppError, AppError::JtiTableNotConfigured);

impl fmt::Debug for AppPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AppPrivateKey").field(&"<redacted>").finish()
    }
}

impl AppPrivateKey {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn from_env() -> Result<Self, AppError> {
        env::var("APP_PRIVATE_KEY")
            .map_err(|_| AppError::AppPrivateKeyNotConfigured)
            .and_then(Self::try_from)
    }

    async fn from_secrets_manager(secrets: &SecretsManagerClient) -> Result<Self, Error> {
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

        Self::try_from(value.to_owned()).map_err(Into::into)
    }
}

impl AsRef<str> for AppPrivateKey {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Policy {
    pub fn expected_audience(&self) -> &Audience {
        &self.expected_audience
    }

    pub fn allowed_subject(&self) -> &Subject {
        &self.allowed_subject
    }

    pub fn allowed_repository(&self) -> &RepositoryFullName {
        &self.allowed_repository
    }

    pub fn allowed_repository_id(&self) -> RepositoryId {
        self.allowed_repository_id
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
            allowed_subject: raw.allowed_subject.try_into()?,
            allowed_repository: raw
                .allowed_repository
                .try_into()
                .map_err(|_| AppError::InvalidPolicy)?,
            allowed_repository_id: raw.allowed_repository_id,
            allowed_ref: raw.allowed_ref.try_into()?,
            allowed_workflow_path: raw.allowed_workflow_path.try_into()?,
            allowed_environment: raw.allowed_environment.map(TryInto::try_into).transpose()?,
        })
    }
}

impl AppId {
    fn from_env() -> Result<Self, AppError> {
        env::var("APP_ID")
            .map_err(|_| AppError::AppIdNotConfigured)
            .and_then(Self::try_from)
    }

    async fn from_ssm(ssm: &SsmClient) -> Result<Self, Error> {
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

        Self::try_from(value.to_owned()).map_err(Into::into)
    }
}

impl JtiTableName {
    fn from_env() -> Result<Self, AppError> {
        env::var("JTI_TABLE_NAME")
            .map_err(|_| AppError::JtiTableNotConfigured)
            .and_then(Self::try_from)
    }
}

impl TryFrom<String> for AppPrivateKey {
    type Error = AppError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let value = value.replace("\\n", "\n").trim().to_string();
        if value.is_empty() {
            return Err(AppError::AppPrivateKeyNotConfigured);
        }

        Ok(Self(value))
    }
}

impl TryFrom<&str> for AppPrivateKey {
    type Error = AppError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.to_owned().try_into()
    }
}

#[derive(Clone)]
pub struct Config {
    pub policy: Policy,
    pub app_id: AppId,
    pub app_private_key: AppPrivateKey,
    pub jti_table_name: JtiTableName,
    pub github_api_base: GithubApiBase,
    pub dynamodb: DynamoDbClient,
    pub http_client: reqwest::Client,
    pub jwks_cache: Arc<JwksCache>,
}

pub(crate) fn build_http_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .user_agent("ost-simple-sts")
        .connect_timeout(HTTP_CONNECT_TIMEOUT)
        .timeout(HTTP_REQUEST_TIMEOUT)
        .build()
}

impl Config {
    pub async fn load() -> Result<Self, Error> {
        let policy = Policy::from_env()?;
        let shared_config = aws_config::load_defaults(BehaviorVersion::latest()).await;
        let ssm = SsmClient::new(&shared_config);
        let secrets = SecretsManagerClient::new(&shared_config);

        let app_id = match AppId::from_env() {
            Ok(app_id) => app_id,
            Err(AppError::AppIdNotConfigured) => AppId::from_ssm(&ssm).await?,
            Err(error) => return Err(error.into()),
        };

        let app_private_key = match AppPrivateKey::from_env() {
            Ok(app_private_key) => app_private_key,
            Err(AppError::AppPrivateKeyNotConfigured) => {
                AppPrivateKey::from_secrets_manager(&secrets).await?
            }
            Err(error) => return Err(error.into()),
        };

        let jti_table_name = JtiTableName::from_env()?;
        let github_api_base = GithubApiBase::from_env()?;
        let http_client = build_http_client()?;
        let jwks_cache = Arc::new(JwksCache::new(http_client.clone()));

        Ok(Self {
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
}

#[cfg(test)]
mod tests {
    use super::{AppPrivateKey, GitRef, Policy, WorkflowPath};
    use serde_json::json;

    #[test]
    fn policy_deserializes_into_validated_types() {
        let policy: Policy = serde_json::from_value(json!({
            "expected_audience": "https://example.com",
            "allowed_subject": "repo:octo/tools:environment:release",
            "allowed_repository": "octo/tools",
            "allowed_repository_id": 42,
            "allowed_ref": "refs/heads/main",
            "allowed_workflow_path": ".github/workflows/release.yml",
            "allowed_environment": "release"
        }))
        .unwrap();

        assert_eq!(policy.expected_audience().as_str(), "https://example.com");
        assert_eq!(
            policy.allowed_subject().as_str(),
            "repo:octo/tools:environment:release"
        );
        assert_eq!(policy.allowed_repository().as_str(), "octo/tools");
        assert_eq!(*policy.allowed_repository_id(), 42);
        assert_eq!(policy.allowed_ref().as_str(), "refs/heads/main");
        assert_eq!(
            policy.allowed_workflow_path().as_str(),
            ".github/workflows/release.yml"
        );
    }

    #[test]
    fn policy_from_str_works() {
        let policy: Policy = r#"{
            "expected_audience": "https://example.com",
            "allowed_subject": "repo:octo/tools:ref:refs/heads/main",
            "allowed_repository": "octo/tools",
            "allowed_repository_id": "42",
            "allowed_ref": "refs/heads/main",
            "allowed_workflow_path": ".github/workflows/release.yml"
        }"#
        .parse()
        .unwrap();
        assert_eq!(policy.allowed_ref().as_str(), "refs/heads/main");
    }

    #[test]
    fn policy_rejects_empty_strings() {
        let result: Result<Policy, _> = serde_json::from_value(json!({
            "expected_audience": "",
            "allowed_subject": "repo:octo/tools:ref:refs/heads/main",
            "allowed_repository": "octo/tools",
            "allowed_repository_id": 42,
            "allowed_ref": "refs/heads/main",
            "allowed_workflow_path": ".github/workflows/release.yml"
        }));
        assert!(result.is_err());
    }

    #[test]
    fn policy_rejects_unknown_fields() {
        let result: Result<Policy, _> = serde_json::from_value(json!({
            "expected_audience": "https://example.com",
            "allowed_subject": "repo:octo/tools:environment:release",
            "allowed_repository": "octo/tools",
            "allowed_repository_id": 42,
            "allowed_ref": "refs/heads/main",
            "allowed_workflow_path": ".github/workflows/release.yml",
            "allowed_enviroment": "release"
        }));

        assert!(result.is_err());
    }

    #[test]
    fn policy_rejects_invalid_repository_identity() {
        for (repository, repository_id) in [("octo", 42), ("octo/tools", 0)] {
            let result: Result<Policy, _> = serde_json::from_value(json!({
                "expected_audience": "https://example.com",
                "allowed_subject": "repo:octo/tools:ref:refs/heads/main",
                "allowed_repository": repository,
                "allowed_repository_id": repository_id,
                "allowed_ref": "refs/heads/main",
                "allowed_workflow_path": ".github/workflows/release.yml"
            }));

            assert!(result.is_err());
        }
    }

    #[test]
    fn git_ref_rejects_non_canonical_refs() {
        assert!(GitRef::try_from("main").is_err());
        assert!(GitRef::try_from("refs/pull/1/head").is_err());
        assert!(GitRef::try_from("refs/heads/main").is_ok());
        assert!(GitRef::try_from("refs/tags/v1.2.3").is_ok());
    }

    #[test]
    fn workflow_path_requires_github_workflows_prefix() {
        assert!(WorkflowPath::try_from("release.yml").is_err());
        assert!(WorkflowPath::try_from(".github/workflows/release.yml").is_ok());
    }

    #[test]
    fn app_private_key_normalizes_escaped_newlines_and_whitespace() {
        let key = AppPrivateKey::try_from("  line1\\nline2  ").unwrap();
        assert_eq!(key.as_str(), "line1\nline2");
    }

    #[test]
    fn app_private_key_debug_is_redacted() {
        let key = AppPrivateKey::try_from("super-secret-private-key").unwrap();
        assert_eq!(format!("{key:?}"), "AppPrivateKey(\"<redacted>\")");
    }
}
