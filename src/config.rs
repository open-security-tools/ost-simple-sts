use std::{env, fmt, sync::Arc, time::Duration};

use aws_config::BehaviorVersion;
use aws_sdk_dynamodb::Client as DynamoDbClient;
use aws_sdk_secretsmanager::Client as SecretsManagerClient;
use aws_sdk_ssm::Client as SsmClient;
use lambda_http::Error;
use serde::Deserialize;

use crate::{
    error::AppError,
    github::{GithubApiBase, Permissions, RepositoryFullName, RepositoryId},
    jwks::JwksCache,
};

const WORKFLOWS_PREFIX: &str = ".github/workflows/";
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(6);

#[derive(Clone, Debug, Deserialize)]
#[serde(try_from = "RawPolicy")]
pub struct Policy {
    expected_audience: Audience,
    rules: Vec<PolicyRule>,
}

#[derive(Clone, Debug)]
pub struct PolicyRule {
    subject: Subject,
    repository: RepositoryFullName,
    repository_id: RepositoryId,
    git_ref: GitRef,
    workflow_path: WorkflowPath,
    environment: Option<EnvironmentName>,
    allowed_events: Vec<EventName>,
    permissions: Permissions,
    target: Option<RepositoryTarget>,
}

#[derive(Clone, Debug)]
struct RepositoryTarget {
    repository: RepositoryFullName,
    repository_id: RepositoryId,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    expected_audience: String,
    rules: Vec<RawPolicyRule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicyRule {
    subject: String,
    repository: String,
    repository_id: RepositoryId,
    #[serde(rename = "ref")]
    git_ref: String,
    workflow_path: String,
    #[serde(default)]
    environment: Option<String>,
    #[serde(default = "default_allowed_events")]
    allowed_events: Vec<String>,
    #[serde(default)]
    permissions: Option<Permissions>,
    #[serde(default)]
    target_repository: Option<String>,
    #[serde(default)]
    target_repository_id: Option<RepositoryId>,
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
pub struct EventName(String);

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

fn is_valid_event_name(value: &str) -> bool {
    matches!(value, "push" | "workflow_dispatch")
}

fn default_allowed_events() -> Vec<String> {
    vec!["workflow_dispatch".to_string()]
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
crate::impl_string_newtype!(
    EventName,
    AppError,
    AppError::InvalidPolicy,
    validate = is_valid_event_name
);
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

    pub fn rules(&self) -> &[PolicyRule] {
        &self.rules
    }

    pub fn from_env() -> Result<Self, AppError> {
        let policy_json = env::var("POLICY_JSON").map_err(|_| AppError::PolicyNotConfigured)?;
        policy_json.parse()
    }
}

impl PolicyRule {
    pub fn subject(&self) -> &Subject {
        &self.subject
    }

    pub fn repository(&self) -> &RepositoryFullName {
        &self.repository
    }

    pub fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    pub fn git_ref(&self) -> &GitRef {
        &self.git_ref
    }

    pub fn workflow_path(&self) -> &WorkflowPath {
        &self.workflow_path
    }

    pub fn environment(&self) -> Option<&EnvironmentName> {
        self.environment.as_ref()
    }

    pub fn allowed_events(&self) -> &[EventName] {
        &self.allowed_events
    }

    pub fn permissions(&self) -> &Permissions {
        &self.permissions
    }

    pub fn target_repository(&self) -> &RepositoryFullName {
        self.target
            .as_ref()
            .map_or(&self.repository, |target| &target.repository)
    }

    pub fn target_repository_id(&self) -> RepositoryId {
        self.target
            .as_ref()
            .map_or(self.repository_id, |target| target.repository_id)
    }

    pub fn has_target_repository(&self) -> bool {
        self.target.is_some()
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
        let rules = raw
            .rules
            .into_iter()
            .map(PolicyRule::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        if rules.is_empty() {
            return Err(AppError::InvalidPolicy);
        }

        Ok(Self {
            expected_audience: raw.expected_audience.try_into()?,
            rules,
        })
    }
}

impl TryFrom<RawPolicyRule> for PolicyRule {
    type Error = AppError;

    fn try_from(raw: RawPolicyRule) -> Result<Self, Self::Error> {
        let allowed_events = raw
            .allowed_events
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()?;
        if allowed_events.is_empty() {
            return Err(AppError::InvalidPolicy);
        }

        let target = match (raw.target_repository, raw.target_repository_id) {
            (Some(repository), Some(repository_id)) => Some(RepositoryTarget {
                repository: repository.try_into().map_err(|_| AppError::InvalidPolicy)?,
                repository_id,
            }),
            (None, None) => None,
            _ => return Err(AppError::InvalidPolicy),
        };

        Ok(Self {
            subject: raw.subject.try_into()?,
            repository: raw
                .repository
                .try_into()
                .map_err(|_| AppError::InvalidPolicy)?,
            repository_id: raw.repository_id,
            git_ref: raw.git_ref.try_into()?,
            workflow_path: raw.workflow_path.try_into()?,
            environment: raw.environment.map(TryInto::try_into).transpose()?,
            allowed_events,
            permissions: raw.permissions.unwrap_or_else(Permissions::contents_write),
            target,
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
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
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
    use super::{build_http_client, AppPrivateKey, GitRef, Policy, WorkflowPath};
    use serde_json::json;

    #[test]
    fn policy_deserializes_into_validated_types() {
        let policy: Policy = serde_json::from_value(json!({
            "expected_audience": "https://example.com",
            "rules": [{
                "subject": "repo:octo/tools:environment:release",
                "repository": "octo/tools",
                "repository_id": 42,
                "ref": "refs/heads/main",
                "workflow_path": ".github/workflows/release.yml",
                "environment": "release"
            }, {
                "subject": "repo:octo/docs:ref:refs/tags/v1",
                "repository": "octo/docs",
                "repository_id": 43,
                "ref": "refs/tags/v1",
                "workflow_path": ".github/workflows/publish.yml",
                "allowed_events": ["push", "workflow_dispatch"],
                "permissions": { "contents": "write", "pull_requests": "read" },
                "target_repository": "octo/docs-preview",
                "target_repository_id": 44
            }]
        }))
        .unwrap();

        assert_eq!(policy.expected_audience().as_str(), "https://example.com");
        assert_eq!(policy.rules().len(), 2);
        let rule = &policy.rules()[0];
        assert_eq!(
            rule.subject().as_str(),
            "repo:octo/tools:environment:release"
        );
        assert_eq!(rule.repository().as_str(), "octo/tools");
        assert_eq!(*rule.repository_id(), 42);
        assert_eq!(rule.git_ref().as_str(), "refs/heads/main");
        assert_eq!(
            rule.workflow_path().as_str(),
            ".github/workflows/release.yml"
        );
        assert_eq!(rule.environment().unwrap().as_str(), "release");
        assert_eq!(rule.allowed_events()[0].as_str(), "workflow_dispatch");
        assert_eq!(rule.target_repository().as_str(), "octo/tools");
        assert_eq!(*rule.target_repository_id(), 42);
        assert_eq!(policy.rules()[1].repository().as_str(), "octo/docs");
        assert!(policy.rules()[1].environment().is_none());
        assert_eq!(
            policy.rules()[1]
                .allowed_events()
                .iter()
                .map(|event| event.as_str())
                .collect::<Vec<_>>(),
            ["push", "workflow_dispatch"]
        );
        assert_eq!(
            policy.rules()[1].target_repository().as_str(),
            "octo/docs-preview"
        );
        assert_eq!(*policy.rules()[1].target_repository_id(), 44);
        assert_eq!(
            serde_json::to_value(policy.rules()[1].permissions()).unwrap(),
            json!({ "contents": "write", "pull_requests": "read" })
        );
    }

    #[test]
    fn policy_from_str_works() {
        let policy: Policy = r#"{
            "expected_audience": "https://example.com",
            "rules": [{
                "subject": "repo:octo/tools:ref:refs/heads/main",
                "repository": "octo/tools",
                "repository_id": "42",
                "ref": "refs/heads/main",
                "workflow_path": ".github/workflows/release.yml"
            }]
        }"#
        .parse()
        .unwrap();
        assert_eq!(policy.rules()[0].git_ref().as_str(), "refs/heads/main");
    }

    #[test]
    fn policy_rejects_empty_strings() {
        let result: Result<Policy, _> = serde_json::from_value(json!({
            "expected_audience": "",
            "rules": [{
                "subject": "repo:octo/tools:ref:refs/heads/main",
                "repository": "octo/tools",
                "repository_id": 42,
                "ref": "refs/heads/main",
                "workflow_path": ".github/workflows/release.yml"
            }]
        }));
        assert!(result.is_err());
    }

    #[test]
    fn policy_rejects_empty_rules() {
        let result: Result<Policy, _> = serde_json::from_value(json!({
            "expected_audience": "https://example.com",
            "rules": []
        }));
        assert!(result.is_err());
    }

    #[test]
    fn policy_rejects_unknown_fields() {
        let result: Result<Policy, _> = serde_json::from_value(json!({
            "expected_audience": "https://example.com",
            "rules": [{
                "subject": "repo:octo/tools:environment:release",
                "repository": "octo/tools",
                "repository_id": 42,
                "ref": "refs/heads/main",
                "workflow_path": ".github/workflows/release.yml",
                "enviroment": "release"
            }]
        }));

        assert!(result.is_err());
    }

    #[test]
    fn policy_rejects_invalid_repository_identity() {
        for (repository, repository_id) in [("octo", 42), ("octo/tools", 0)] {
            let result: Result<Policy, _> = serde_json::from_value(json!({
                "expected_audience": "https://example.com",
                "rules": [{
                    "subject": "repo:octo/tools:ref:refs/heads/main",
                    "repository": repository,
                    "repository_id": repository_id,
                    "ref": "refs/heads/main",
                    "workflow_path": ".github/workflows/release.yml"
                }]
            }));

            assert!(result.is_err());
        }
    }

    #[test]
    fn policy_rejects_invalid_event_allowlists() {
        for allowed_events in [
            json!([]),
            json!([""]),
            json!(["pull_request"]),
            json!(["push", "pull_request_target"]),
        ] {
            let result: Result<Policy, _> = serde_json::from_value(json!({
                "expected_audience": "https://example.com",
                "rules": [{
                    "subject": "repo:octo/tools:ref:refs/heads/main",
                    "repository": "octo/tools",
                    "repository_id": 42,
                    "ref": "refs/heads/main",
                    "workflow_path": ".github/workflows/release.yml",
                    "allowed_events": allowed_events
                }]
            }));

            assert!(result.is_err());
        }
    }

    #[test]
    fn policy_rejects_incomplete_or_invalid_target_identity() {
        for target in [
            json!({ "target_repository": "octo/docs" }),
            json!({ "target_repository_id": 43 }),
            json!({ "target_repository": "octo", "target_repository_id": 43 }),
            json!({ "target_repository": "octo/docs", "target_repository_id": 0 }),
        ] {
            let mut rule = json!({
                "subject": "repo:octo/tools:ref:refs/heads/main",
                "repository": "octo/tools",
                "repository_id": 42,
                "ref": "refs/heads/main",
                "workflow_path": ".github/workflows/release.yml"
            });
            rule.as_object_mut()
                .unwrap()
                .extend(target.as_object().unwrap().clone());

            let result: Result<Policy, _> = serde_json::from_value(json!({
                "expected_audience": "https://example.com",
                "rules": [rule]
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

    #[tokio::test]
    async fn http_client_rejects_insecure_urls() {
        let client = build_http_client().unwrap();
        let error = client
            .get("http://127.0.0.1:1/github-api")
            .send()
            .await
            .unwrap_err();

        assert!(error.is_builder());
    }
}
