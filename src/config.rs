use std::{collections::BTreeMap, env, fmt, sync::Arc, time::Duration};

use aws_config::BehaviorVersion;
use aws_sdk_dynamodb::Client as DynamoDbClient;
use aws_sdk_secretsmanager::Client as SecretsManagerClient;
use aws_sdk_ssm::Client as SsmClient;
use lambda_http::Error;
use serde::Deserialize;
use serde_json::Value;

use crate::{
    error::AppError,
    github::{GithubApiBase, Permissions, RepositoryFullName, RepositoryId},
    jwks::JwksCache,
    policy_cache::PolicyCache,
};

const WORKFLOWS_PREFIX: &str = ".github/workflows/";
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(6);
const MAX_HOSTED_POLICY_RULES: usize = 100;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(try_from = "RawPolicy")]
pub struct Policy {
    expected_audience: Audience,
    rules: Vec<PolicyRule>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyRule {
    subject: Subject,
    repository: RepositoryFullName,
    repository_id: RepositoryId,
    git_ref: GitRef,
    workflow_path: WorkflowPath,
    job_workflow_path: Option<WorkflowPath>,
    environment: Option<EnvironmentName>,
    allowed_events: Vec<EventName>,
    permissions: Permissions,
    target: Option<RepositoryTarget>,
    targets: Option<Vec<RepositoryTarget>>,
    target_installation_id: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
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
struct RawHostedPolicy {
    version: u64,
    rules: Vec<RawPolicyRule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHostedPolicyV2 {
    version: u64,
    repositories: BTreeMap<String, RawRepositoryV2>,
    #[serde(default)]
    installations: BTreeMap<String, u64>,
    rules: Vec<RawPolicyRuleV2>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRepositoryV2 {
    name: String,
    id: RepositoryId,
    oidc_subject: OidcSubjectFormat,
    #[serde(default)]
    owner_id: Option<RepositoryId>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OidcSubjectFormat {
    Legacy,
    Immutable,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicyRuleV2 {
    caller: String,
    #[serde(default)]
    environment: Option<String>,
    #[serde(default = "default_caller_ref")]
    caller_ref: String,
    caller_workflow: String,
    #[serde(default)]
    reusable_workflow: Option<String>,
    on: Vec<String>,
    permissions: Permissions,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    targets: Option<Vec<String>>,
    #[serde(default)]
    installation: Option<String>,
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
    job_workflow_path: Option<String>,
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
    #[serde(default)]
    target_repositories: Option<Vec<RawRepositoryTarget>>,
    #[serde(default)]
    target_installation_id: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRepositoryTarget {
    repository: String,
    repository_id: RepositoryId,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyPath(String);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyRef(String);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyLocation {
    repository: RepositoryFullName,
    repository_id: RepositoryId,
    installation_id: u64,
    path: PolicyPath,
    git_ref: PolicyRef,
}

fn is_valid_git_ref(value: &str) -> bool {
    value
        .strip_prefix("refs/heads/")
        .is_some_and(|suffix| !suffix.is_empty())
        || value
            .strip_prefix("refs/tags/")
            .is_some_and(|suffix| !suffix.is_empty())
        || value == "refs/pull/*/merge"
        || is_pull_request_merge_ref(value)
}

fn is_pull_request_merge_ref(value: &str) -> bool {
    value
        .strip_prefix("refs/pull/")
        .and_then(|suffix| suffix.strip_suffix("/merge"))
        .is_some_and(|number| {
            !number.is_empty()
                && !number.starts_with('0')
                && number.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn is_valid_workflow_path(value: &str) -> bool {
    value
        .strip_prefix(WORKFLOWS_PREFIX)
        .is_some_and(|suffix| !suffix.is_empty())
        && (value.ends_with(".yml") || value.ends_with(".yaml"))
}

fn is_valid_workflow_filename(value: &str) -> bool {
    !value.is_empty()
        && !value.contains('/')
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && (value.ends_with(".yml") || value.ends_with(".yaml"))
}

fn is_valid_alias(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn is_valid_event_name(value: &str) -> bool {
    matches!(
        value,
        "issue_comment" | "issues" | "push" | "pull_request" | "schedule" | "workflow_dispatch"
    )
}

fn is_valid_policy_path(value: &str) -> bool {
    let Some(path) = value.strip_prefix(".github/") else {
        return false;
    };
    value.len() <= 300
        && path.ends_with(".json")
        && path.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
}

fn is_valid_policy_ref(value: &str) -> bool {
    value == "main"
}

fn default_allowed_events() -> Vec<String> {
    vec!["workflow_dispatch".to_string()]
}

fn default_caller_ref() -> String {
    "refs/heads/main".to_string()
}

struct StrictValue(Value);

fn parse_strict_json(value: &[u8]) -> Result<Value, serde_json::Error> {
    serde_json::from_slice::<StrictValue>(value).map(|value| value.0)
}

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StrictVisitor;

        impl<'de> serde::de::Visitor<'de> for StrictVisitor {
            type Value = StrictValue;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON value without duplicate object keys")
            }

            fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Bool(value)))
            }

            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Number(value.into())))
            }

            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Number(value.into())))
            }

            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(value)
                    .map(|number| StrictValue(Value::Number(number)))
                    .ok_or_else(|| E::custom("invalid JSON number"))
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::String(value.to_string())))
            }

            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::String(value)))
            }

            fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }

            fn visit_some<D: serde::Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error> {
                StrictValue::deserialize(deserializer)
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut access: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = access.next_element::<StrictValue>()? {
                    values.push(value.0);
                }
                Ok(StrictValue(Value::Array(values)))
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut access: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some((key, value)) = access.next_entry::<String, StrictValue>()? {
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom(format!(
                            "duplicate JSON key: {key}"
                        )));
                    }
                    values.insert(key, value.0);
                }
                Ok(StrictValue(Value::Object(values)))
            }
        }

        deserializer.deserialize_any(StrictVisitor)
    }
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
crate::impl_string_newtype!(
    PolicyPath,
    AppError,
    AppError::PolicyNotConfigured,
    validate = is_valid_policy_path
);
crate::impl_string_newtype!(
    PolicyRef,
    AppError,
    AppError::PolicyNotConfigured,
    validate = is_valid_policy_ref
);

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

    pub fn from_hosted(policy_json: &str, expected_audience: &Audience) -> Result<Self, AppError> {
        let strict =
            parse_strict_json(policy_json.as_bytes()).map_err(|_| AppError::InvalidPolicy)?;
        match strict.get("version").and_then(Value::as_u64) {
            Some(1) => {
                let raw: RawHostedPolicy =
                    serde_json::from_value(strict).map_err(|_| AppError::InvalidPolicy)?;
                if raw.version != 1 || raw.rules.len() > MAX_HOSTED_POLICY_RULES {
                    return Err(AppError::InvalidPolicy);
                }
                Self::try_from(RawPolicy {
                    expected_audience: expected_audience.as_str().to_string(),
                    rules: raw.rules,
                })
            }
            Some(2) => {
                let raw: RawHostedPolicyV2 =
                    serde_json::from_value(strict).map_err(|_| AppError::InvalidPolicy)?;
                raw.into_policy(expected_audience)
            }
            _ => Err(AppError::InvalidPolicy),
        }
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

    pub fn job_workflow_path(&self) -> Option<&WorkflowPath> {
        self.job_workflow_path.as_ref()
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
        self.target.is_some() || self.targets.is_some()
    }

    pub fn has_multiple_target_repositories(&self) -> bool {
        self.targets.is_some()
    }

    pub fn target_repositories(&self) -> Vec<(RepositoryFullName, RepositoryId)> {
        self.targets.as_ref().map_or_else(
            || {
                vec![(
                    self.target_repository().clone(),
                    self.target_repository_id(),
                )]
            },
            |targets| {
                targets
                    .iter()
                    .map(|target| (target.repository.clone(), target.repository_id))
                    .collect()
            },
        )
    }

    pub fn target_installation_id(&self) -> Option<u64> {
        self.target_installation_id
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
        if rules.iter().enumerate().any(|(index, rule)| {
            rules[..index].iter().any(|previous| {
                previous.subject == rule.subject
                    && previous.repository == rule.repository
                    && previous.repository_id == rule.repository_id
                    && previous.git_ref.overlaps(&rule.git_ref)
                    && previous.workflow_path == rule.workflow_path
                    && previous.job_workflow_path == rule.job_workflow_path
                    && previous.environment == rule.environment
                    && previous
                        .allowed_events
                        .iter()
                        .any(|event| rule.allowed_events.contains(event))
            })
        }) {
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
        if allowed_events.iter().enumerate().any(|(index, event)| {
            allowed_events[..index]
                .iter()
                .any(|previous| previous == event)
        }) {
            return Err(AppError::InvalidPolicy);
        }
        if raw.git_ref == "refs/pull/*/merge"
            && allowed_events
                .iter()
                .any(|event: &EventName| event.as_str() != "pull_request")
        {
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
        let targets = raw
            .target_repositories
            .map(|targets| {
                targets
                    .into_iter()
                    .map(|target| {
                        Ok(RepositoryTarget {
                            repository: target
                                .repository
                                .try_into()
                                .map_err(|_| AppError::InvalidPolicy)?,
                            repository_id: target.repository_id,
                        })
                    })
                    .collect::<Result<Vec<_>, AppError>>()
            })
            .transpose()?;
        if target.is_some() && targets.is_some() {
            return Err(AppError::InvalidPolicy);
        }
        if let Some(targets) = targets.as_ref() {
            if targets.len() < 2
                || raw.target_installation_id.is_none_or(|id| id == 0)
                || targets.iter().enumerate().any(|(index, target)| {
                    targets[..index].iter().any(|previous| {
                        previous.repository_id == target.repository_id
                            || previous
                                .repository
                                .as_str()
                                .eq_ignore_ascii_case(target.repository.as_str())
                    })
                })
            {
                return Err(AppError::InvalidPolicy);
            }
        } else if raw.target_installation_id.is_some() {
            return Err(AppError::InvalidPolicy);
        }

        Ok(Self {
            subject: raw.subject.try_into()?,
            repository: raw
                .repository
                .try_into()
                .map_err(|_| AppError::InvalidPolicy)?,
            repository_id: raw.repository_id,
            git_ref: raw.git_ref.try_into()?,
            workflow_path: raw.workflow_path.try_into()?,
            job_workflow_path: raw.job_workflow_path.map(TryInto::try_into).transpose()?,
            environment: raw.environment.map(TryInto::try_into).transpose()?,
            allowed_events,
            permissions: raw.permissions.unwrap_or_else(Permissions::contents_write),
            target,
            targets,
            target_installation_id: raw.target_installation_id,
        })
    }
}

impl RawHostedPolicyV2 {
    fn into_policy(self, expected_audience: &Audience) -> Result<Policy, AppError> {
        if self.version != 2
            || self.repositories.is_empty()
            || self.repositories.len() > MAX_HOSTED_POLICY_RULES
            || self.installations.len() > MAX_HOSTED_POLICY_RULES
            || self.rules.is_empty()
            || self.rules.len() > MAX_HOSTED_POLICY_RULES
        {
            return Err(AppError::InvalidPolicy);
        }

        for (alias, repository) in &self.repositories {
            if !is_valid_alias(alias) {
                return Err(AppError::InvalidPolicy);
            }
            RepositoryFullName::try_from(repository.name.as_str())
                .map_err(|_| AppError::InvalidPolicy)?;
            match (repository.oidc_subject, repository.owner_id) {
                (OidcSubjectFormat::Legacy, None) | (OidcSubjectFormat::Immutable, Some(_)) => {}
                (OidcSubjectFormat::Legacy, Some(_)) | (OidcSubjectFormat::Immutable, None) => {
                    return Err(AppError::InvalidPolicy);
                }
            }
        }
        if self
            .repositories
            .values()
            .enumerate()
            .any(|(index, repository)| {
                self.repositories.values().take(index).any(|previous| {
                    previous.id == repository.id
                        || previous.name.eq_ignore_ascii_case(&repository.name)
                })
            })
        {
            return Err(AppError::InvalidPolicy);
        }
        if self
            .installations
            .iter()
            .any(|(alias, id)| !is_valid_alias(alias) || *id == 0)
        {
            return Err(AppError::InvalidPolicy);
        }

        let mut rules = Vec::with_capacity(self.rules.len());
        for rule in self.rules {
            if !is_valid_workflow_filename(&rule.caller_workflow)
                || rule
                    .reusable_workflow
                    .as_deref()
                    .is_some_and(|workflow| !is_valid_workflow_filename(workflow))
            {
                return Err(AppError::InvalidPolicy);
            }
            let caller = self
                .repositories
                .get(&rule.caller)
                .ok_or(AppError::InvalidPolicy)?;
            let caller_name = RepositoryFullName::try_from(caller.name.as_str())
                .map_err(|_| AppError::InvalidPolicy)?;
            let subject_prefix = match (caller.oidc_subject, caller.owner_id) {
                (OidcSubjectFormat::Legacy, None) => format!("repo:{}", caller.name),
                (OidcSubjectFormat::Immutable, Some(owner_id)) => format!(
                    "repo:{}@{}/{}@{}",
                    caller_name.owner(),
                    *owner_id,
                    caller_name.repo(),
                    *caller.id
                ),
                (OidcSubjectFormat::Legacy, Some(_)) | (OidcSubjectFormat::Immutable, None) => {
                    return Err(AppError::InvalidPolicy);
                }
            };
            let subject = rule.environment.as_ref().map_or_else(
                || format!("{subject_prefix}:ref:{}", rule.caller_ref),
                |environment| format!("{subject_prefix}:environment:{environment}"),
            );

            let target = rule
                .target
                .as_ref()
                .map(|alias| self.repositories.get(alias).ok_or(AppError::InvalidPolicy))
                .transpose()?;
            let targets = rule
                .targets
                .as_ref()
                .map(|aliases| {
                    aliases
                        .iter()
                        .map(|alias| {
                            self.repositories
                                .get(alias)
                                .map(|repository| RawRepositoryTarget {
                                    repository: repository.name.clone(),
                                    repository_id: repository.id,
                                })
                                .ok_or(AppError::InvalidPolicy)
                        })
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()?;
            let installation = rule
                .installation
                .as_ref()
                .map(|alias| {
                    self.installations
                        .get(alias)
                        .copied()
                        .ok_or(AppError::InvalidPolicy)
                })
                .transpose()?;
            if target.is_some() && targets.is_some() || targets.is_some() != installation.is_some()
            {
                return Err(AppError::InvalidPolicy);
            }

            rules.push(RawPolicyRule {
                subject,
                repository: caller.name.clone(),
                repository_id: caller.id,
                git_ref: rule.caller_ref,
                workflow_path: format!("{WORKFLOWS_PREFIX}{}", rule.caller_workflow),
                job_workflow_path: rule
                    .reusable_workflow
                    .map(|workflow| format!("{WORKFLOWS_PREFIX}{workflow}")),
                environment: rule.environment,
                allowed_events: rule.on,
                permissions: Some(rule.permissions),
                target_repository: target.map(|repository| repository.name.clone()),
                target_repository_id: target.map(|repository| repository.id),
                target_repositories: targets,
                target_installation_id: installation,
            });
        }

        Policy::try_from(RawPolicy {
            expected_audience: expected_audience.as_str().to_string(),
            rules,
        })
    }
}

impl GitRef {
    fn overlaps(&self, other: &Self) -> bool {
        self == other || self.matches(other.as_str()) || other.matches(self.as_str())
    }

    pub fn matches(&self, value: &str) -> bool {
        if self.as_str() == "refs/pull/*/merge" {
            is_pull_request_merge_ref(value)
        } else {
            self.as_str() == value
        }
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

impl PolicyLocation {
    pub fn from_env() -> Result<Self, AppError> {
        let repository = env::var("POLICY_REPOSITORY")
            .map_err(|_| AppError::PolicyNotConfigured)?
            .try_into()
            .map_err(|_| AppError::PolicyNotConfigured)?;
        let repository_id = env::var("POLICY_REPOSITORY_ID")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .and_then(RepositoryId::new)
            .ok_or(AppError::PolicyNotConfigured)?;
        let installation_id = env::var("POLICY_INSTALLATION_ID")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value != 0)
            .ok_or(AppError::PolicyNotConfigured)?;
        let path = env::var("POLICY_PATH")
            .map_err(|_| AppError::PolicyNotConfigured)?
            .try_into()?;
        let git_ref = env::var("POLICY_REF")
            .map_err(|_| AppError::PolicyNotConfigured)?
            .try_into()?;

        Ok(Self {
            repository,
            repository_id,
            installation_id,
            path,
            git_ref,
        })
    }

    pub fn repository(&self) -> &RepositoryFullName {
        &self.repository
    }

    pub fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    pub fn installation_id(&self) -> u64 {
        self.installation_id
    }

    pub fn path(&self) -> &str {
        self.path.as_str()
    }

    pub fn git_ref(&self) -> &PolicyRef {
        &self.git_ref
    }

    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        Self {
            repository: "octo/tools".try_into().unwrap(),
            repository_id: RepositoryId::new(42).unwrap(),
            installation_id: 456,
            path: ".github/ost-simple-sts.json".try_into().unwrap(),
            git_ref: "main".try_into().unwrap(),
        }
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
    pub policy_location: PolicyLocation,
    pub policy_audience: Audience,
    pub policy_cache: Arc<PolicyCache>,
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
        let policy_location = PolicyLocation::from_env()?;
        let policy_audience = env::var("POLICY_AUDIENCE")
            .map_err(|_| AppError::PolicyNotConfigured)?
            .try_into()?;
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
            policy_location,
            policy_audience,
            policy_cache: Arc::new(PolicyCache::default()),
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
    use super::{
        build_http_client, AppPrivateKey, Audience, GitRef, Policy, PolicyPath, PolicyRef,
        WorkflowPath,
    };
    use serde_json::json;

    #[test]
    fn policy_rejects_semantically_overlapping_pull_request_refs() {
        let wildcard = json!({
            "subject":"repo:octo/tools:environment:review", "repository":"octo/tools",
            "repository_id":42, "ref":"refs/pull/*/merge",
            "workflow_path":".github/workflows/review.yml", "environment":"review",
            "allowed_events":["pull_request"], "permissions":{"pull_requests":"write"}
        });
        let mut exact = wildcard.clone();
        exact["ref"] = json!("refs/pull/17/merge");
        for rules in [json!([wildcard, exact]), json!([exact, wildcard])] {
            assert!(serde_json::from_value::<Policy>(json!({
                "expected_audience":"https://example.com", "rules":rules
            }))
            .is_err());
        }
        let mut distinct = exact.clone();
        distinct["ref"] = json!("refs/pull/18/merge");
        assert!(serde_json::from_value::<Policy>(json!({
            "expected_audience":"https://example.com", "rules":[exact,distinct]
        }))
        .is_ok());
    }

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
    fn hosted_policy_accepts_the_versioned_rule_document() {
        let audience = Audience::try_from("https://example.com").unwrap();
        let policy = Policy::from_hosted(
            r#"{
                "version": 1,
                "rules": [{
                    "subject": "repo:astral-sh/uv:environment:automations",
                    "repository": "astral-sh/uv",
                    "repository_id": 699532645,
                    "ref": "refs/heads/main",
                    "workflow_path": ".github/workflows/pull-request-conflicts.yml",
                    "job_workflow_path": ".github/workflows/rebase-conflicted-pull-request.yml",
                    "allowed_events": ["push", "workflow_dispatch"],
                    "target_repository": "astral-sh/uv-dev",
                    "target_repository_id": 1302176231,
                    "permissions": {"contents": "write", "workflows": "write"}
                }]
            }"#,
            &audience,
        )
        .unwrap();

        let rule = &policy.rules()[0];
        assert_eq!(policy.expected_audience(), &audience);
        assert_eq!(
            rule.subject().as_str(),
            "repo:astral-sh/uv:environment:automations"
        );
        assert_eq!(rule.repository().as_str(), "astral-sh/uv");
        assert_eq!(*rule.repository_id(), 699532645);
        assert_eq!(rule.git_ref().as_str(), "refs/heads/main");
        assert_eq!(
            rule.workflow_path().as_str(),
            ".github/workflows/pull-request-conflicts.yml"
        );
        assert_eq!(
            rule.job_workflow_path().unwrap().as_str(),
            ".github/workflows/rebase-conflicted-pull-request.yml"
        );
        assert_eq!(
            rule.allowed_events()
                .iter()
                .map(|event| event.as_str())
                .collect::<Vec<_>>(),
            ["push", "workflow_dispatch"]
        );
        assert_eq!(rule.target_repository().as_str(), "astral-sh/uv-dev");
        assert_eq!(*rule.target_repository_id(), 1302176231);
        assert_eq!(
            serde_json::to_value(rule.permissions()).unwrap(),
            json!({"contents": "write", "workflows": "write"})
        );
    }

    #[test]
    fn hosted_policy_v2_derives_the_same_rules_as_v1() {
        let audience = Audience::try_from("https://example.com").unwrap();
        let v1 = Policy::from_hosted(
            r#"{
                "version": 1,
                "rules": [{
                    "subject": "repo:astral-sh@115962839/uv-dev@1302176231:environment:automations",
                    "repository": "astral-sh/uv-dev",
                    "repository_id": 1302176231,
                    "ref": "refs/heads/main",
                    "workflow_path": ".github/workflows/promote-pull-request.yml",
                    "environment": "automations",
                    "allowed_events": ["workflow_dispatch"],
                    "permissions": {"contents": "write", "pull_requests": "write"},
                    "target_repositories": [
                        {"repository": "astral-sh/uv", "repository_id": 699532645},
                        {"repository": "astral-sh/uv-dev", "repository_id": 1302176231}
                    ],
                    "target_installation_id": 146796415
                }, {
                    "subject": "repo:astral-sh/uv:environment:automations",
                    "repository": "astral-sh/uv",
                    "repository_id": 699532645,
                    "ref": "refs/pull/*/merge",
                    "workflow_path": ".github/workflows/ci.yml",
                    "job_workflow_path": ".github/workflows/pull-request-security-review.yml",
                    "environment": "automations",
                    "allowed_events": ["pull_request"],
                    "permissions": {"pull_requests": "write"},
                    "target_repository": "astral-sh/uv",
                    "target_repository_id": 699532645
                }, {
                    "subject": "repo:astral-sh/uv:ref:refs/heads/main",
                    "repository": "astral-sh/uv",
                    "repository_id": 699532645,
                    "ref": "refs/heads/main",
                    "workflow_path": ".github/workflows/sync-uv-dev.yml",
                    "allowed_events": ["push", "workflow_dispatch"],
                    "permissions": {"contents": "write", "workflows": "write"},
                    "target_repository": "astral-sh/uv-dev",
                    "target_repository_id": 1302176231
                }]
            }"#,
            &audience,
        )
        .unwrap();
        let v2 = Policy::from_hosted(
            r#"{
                "version": 2,
                "repositories": {
                    "uv": {
                        "name": "astral-sh/uv",
                        "id": 699532645,
                        "oidc_subject": "legacy"
                    },
                    "uv-dev": {
                        "name": "astral-sh/uv-dev",
                        "id": 1302176231,
                        "oidc_subject": "immutable",
                        "owner_id": 115962839
                    }
                },
                "installations": {"automations": 146796415},
                "rules": [{
                    "caller": "uv-dev",
                    "environment": "automations",
                    "caller_workflow": "promote-pull-request.yml",
                    "on": ["workflow_dispatch"],
                    "permissions": {"contents": "write", "pull_requests": "write"},
                    "targets": ["uv", "uv-dev"],
                    "installation": "automations"
                }, {
                    "caller": "uv",
                    "environment": "automations",
                    "caller_ref": "refs/pull/*/merge",
                    "caller_workflow": "ci.yml",
                    "reusable_workflow": "pull-request-security-review.yml",
                    "on": ["pull_request"],
                    "permissions": {"pull_requests": "write"},
                    "target": "uv"
                }, {
                    "caller": "uv",
                    "caller_workflow": "sync-uv-dev.yml",
                    "on": ["push", "workflow_dispatch"],
                    "permissions": {"contents": "write", "workflows": "write"},
                    "target": "uv-dev"
                }]
            }"#,
            &audience,
        )
        .unwrap();

        assert_eq!(v2, v1);
    }

    #[test]
    fn hosted_policy_example_or_override_is_valid() {
        let audience = Audience::try_from("https://example.com").unwrap();
        let policy = match std::env::var("HOSTED_POLICY_TEST_FILE") {
            Ok(path) => std::fs::read_to_string(path).unwrap(),
            Err(_) => include_str!("../policy-example.json").to_string(),
        };

        assert!(Policy::from_hosted(&policy, &audience).is_ok());
    }

    #[test]
    fn hosted_policy_rejects_unknown_or_invalid_schema_and_rules() {
        let audience = Audience::try_from("https://example.com").unwrap();
        for invalid in [
            r#"{"rules":[]}"#,
            r#"{"version":2,"rules":[]}"#,
            r#"{"version":1,"rules":[],"expected_audience":"https://example.com"}"#,
            r#"{"version":1,"rules":[],"unknown":true}"#,
            r#"{"version":1,"version":1,"rules":[]}"#,
            r#"{"version":1,"rules":[{"subject":"repo:octo/tools:environment:automations","repository":"octo/tools","repository_id":42,"ref":"refs/heads/main","workflow_path":".github/workflows/release.yml","permissions":{"contents":"admin"}}]}"#,
        ] {
            assert!(
                Policy::from_hosted(invalid, &audience).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn hosted_policy_v2_rejects_ambiguous_or_invalid_schema_and_rules() {
        let audience = Audience::try_from("https://example.com").unwrap();
        for invalid in [
            r#"{"version":2,"repositories":{},"rules":[]}"#,
            r#"{"version":2,"repositories":{"uv":{"name":"astral-sh/uv","id":699532645,"oidc_subject":"standard"}},"rules":[{"caller":"uv","caller_workflow":"release.yml","on":["workflow_dispatch"],"permissions":{"contents":"write"}}]}"#,
            r#"{"version":2,"repositories":{"uv":{"name":"astral-sh/uv","id":699532645,"oidc_subject":"immutable"}},"rules":[{"caller":"uv","caller_workflow":"release.yml","on":["workflow_dispatch"],"permissions":{"contents":"write"}}]}"#,
            r#"{"version":2,"repositories":{"uv":{"name":"astral-sh/uv","id":699532645,"oidc_subject":"legacy","owner_id":115962839}},"rules":[{"caller":"uv","caller_workflow":"release.yml","on":["workflow_dispatch"],"permissions":{"contents":"write"}}]}"#,
            r#"{"version":2,"repositories":{"uv/other":{"name":"astral-sh/uv","id":699532645,"oidc_subject":"legacy"}},"rules":[{"caller":"uv/other","caller_workflow":"release.yml","on":["workflow_dispatch"],"permissions":{"contents":"write"}}]}"#,
            r#"{"version":2,"repositories":{"uv":{"name":"astral-sh/uv","id":699532645,"oidc_subject":"legacy"},"same":{"name":"ASTRAL-SH/UV","id":42,"oidc_subject":"legacy"}},"rules":[{"caller":"uv","caller_workflow":"release.yml","on":["workflow_dispatch"],"permissions":{"contents":"write"}}]}"#,
            r#"{"version":2,"repositories":{"uv":{"name":"astral-sh/uv","id":699532645,"oidc_subject":"legacy"},"same":{"name":"astral-sh/other","id":699532645,"oidc_subject":"legacy"}},"rules":[{"caller":"uv","caller_workflow":"release.yml","on":["workflow_dispatch"],"permissions":{"contents":"write"}}]}"#,
            r#"{"version":2,"repositories":{"uv":{"name":"astral-sh/uv","id":699532645,"oidc_subject":"legacy"}},"installations":{"automations":0},"rules":[{"caller":"uv","caller_workflow":"release.yml","on":["workflow_dispatch"],"permissions":{"contents":"write"}}]}"#,
            r#"{"version":2,"repositories":{"uv":{"name":"astral-sh/uv","id":699532645,"oidc_subject":"legacy"}},"rules":[{"caller":"missing","caller_workflow":"release.yml","on":["workflow_dispatch"],"permissions":{"contents":"write"}}]}"#,
            r#"{"version":2,"repositories":{"uv":{"name":"astral-sh/uv","id":699532645,"oidc_subject":"legacy"}},"rules":[{"caller":"uv","caller_workflow":".github/workflows/release.yml","on":["workflow_dispatch"],"permissions":{"contents":"write"}}]}"#,
            r#"{"version":2,"repositories":{"uv":{"name":"astral-sh/uv","id":699532645,"oidc_subject":"legacy"}},"rules":[{"caller":"uv","caller_workflow":"release.yml","reusable_workflow":"../release.yml","on":["workflow_dispatch"],"permissions":{"contents":"write"}}]}"#,
            r#"{"version":2,"repositories":{"uv":{"name":"astral-sh/uv","id":699532645,"oidc_subject":"legacy"}},"rules":[{"caller":"uv","caller_ref":"main","caller_workflow":"release.yml","on":["workflow_dispatch"],"permissions":{"contents":"write"}}]}"#,
            r#"{"version":2,"repositories":{"uv":{"name":"astral-sh/uv","id":699532645,"oidc_subject":"legacy"}},"rules":[{"caller":"uv","caller_workflow":"release.yml","on":[],"permissions":{"contents":"write"}}]}"#,
            r#"{"version":2,"repositories":{"uv":{"name":"astral-sh/uv","id":699532645,"oidc_subject":"legacy"}},"rules":[{"caller":"uv","caller_workflow":"release.yml","on":["push","push"],"permissions":{"contents":"write"}}]}"#,
            r#"{"version":2,"repositories":{"uv":{"name":"astral-sh/uv","id":699532645,"oidc_subject":"legacy"}},"rules":[{"caller":"uv","caller_workflow":"release.yml","on":["pull_request_target"],"permissions":{"contents":"write"}}]}"#,
            r#"{"version":2,"repositories":{"uv":{"name":"astral-sh/uv","id":699532645,"oidc_subject":"legacy"}},"rules":[{"caller":"uv","caller_ref":"refs/pull/*/merge","caller_workflow":"release.yml","on":["push"],"permissions":{"contents":"write"}}]}"#,
            r#"{"version":2,"repositories":{"uv":{"name":"astral-sh/uv","id":699532645,"oidc_subject":"legacy"}},"rules":[{"caller":"uv","caller_workflow":"release.yml","on":["workflow_dispatch"],"permissions":{"contents":"write"},"target":"missing"}]}"#,
            r#"{"version":2,"repositories":{"uv":{"name":"astral-sh/uv","id":699532645,"oidc_subject":"legacy"}},"installations":{"automations":146796415},"rules":[{"caller":"uv","caller_workflow":"release.yml","on":["workflow_dispatch"],"permissions":{"contents":"write"},"targets":["uv","uv"],"installation":"automations"}]}"#,
            r#"{"version":2,"repositories":{"uv":{"name":"astral-sh/uv","id":699532645,"oidc_subject":"legacy"},"uv-dev":{"name":"astral-sh/uv-dev","id":1302176231,"oidc_subject":"legacy"}},"rules":[{"caller":"uv","caller_workflow":"release.yml","on":["workflow_dispatch"],"permissions":{"contents":"write"},"targets":["uv","uv-dev"],"installation":"missing"}]}"#,
            r#"{"version":2,"repositories":{"uv":{"name":"astral-sh/uv","id":699532645,"oidc_subject":"legacy"}},"installations":{"automations":146796415},"rules":[{"caller":"uv","caller_workflow":"release.yml","on":["workflow_dispatch"],"permissions":{"contents":"write"},"target":"uv","installation":"automations"}]}"#,
            r#"{"version":2,"repositories":{"uv":{"name":"astral-sh/uv","id":699532645,"oidc_subject":"legacy"}},"installations":{"automations":146796415},"rules":[{"caller":"uv","caller_workflow":"release.yml","on":["workflow_dispatch"],"permissions":{"contents":"write"},"target":"uv","targets":["uv","uv"],"installation":"automations"}]}"#,
            r#"{"version":2,"repositories":{"uv":{"name":"astral-sh/uv","id":699532645,"oidc_subject":"legacy"}},"rules":[{"caller":"uv","caller_workflow":"release.yml","on":["workflow_dispatch"],"permissions":{"contents":"write"},"unknown":true}]}"#,
            r#"{"version":2,"repositories":{"uv":{"name":"astral-sh/uv","id":699532645,"oidc_subject":"legacy"}},"rules":[{"caller":"uv","caller_workflow":"release.yml","on":["workflow_dispatch"],"permissions":{"contents":"admin"}}]}"#,
            r#"{"version":2,"repositories":{"uv":{"name":"astral-sh/uv","id":699532645,"oidc_subject":"legacy"},"uv-dev":{"name":"astral-sh/uv-dev","id":1302176231,"oidc_subject":"legacy"}},"rules":[{"caller":"uv","caller_workflow":"release.yml","on":["workflow_dispatch"],"permissions":{"contents":"write"},"target":"uv"},{"caller":"uv","caller_workflow":"release.yml","on":["workflow_dispatch"],"permissions":{"contents":"write"},"target":"uv-dev"}]}"#,
            r#"{"version":2,"repositories":{"uv":{"name":"astral-sh/uv","id":699532645,"oidc_subject":"legacy"},"uv":{"name":"astral-sh/other","id":42,"oidc_subject":"legacy"}},"rules":[{"caller":"uv","caller_workflow":"release.yml","on":["workflow_dispatch"],"permissions":{"contents":"write"}}]}"#,
            r#"{"version":2,"repositories":{"uv":{"name":"astral-sh/uv","id":699532645,"oidc_subject":"legacy"}},"installations":{"automations":146796415,"automations":42},"rules":[{"caller":"uv","caller_workflow":"release.yml","on":["workflow_dispatch"],"permissions":{"contents":"write"}}]}"#,
            r#"{"version":2,"repositories":{"uv":{"name":"astral-sh/uv","id":699532645,"oidc_subject":"legacy"}},"rules":[{"caller":"uv","caller":"other","caller_workflow":"release.yml","on":["workflow_dispatch"],"permissions":{"contents":"write"}}]}"#,
        ] {
            assert!(
                Policy::from_hosted(invalid, &audience).is_err(),
                "accepted invalid v2 policy: {invalid}"
            );
        }
    }

    #[test]
    fn policy_rejects_overlapping_identity_rules_with_different_targets() {
        let result: Result<Policy, _> = serde_json::from_value(json!({
            "expected_audience": "https://example.com",
            "rules": [{
                "subject": "repo:octo/tools:environment:automations",
                "repository": "octo/tools",
                "repository_id": 42,
                "ref": "refs/heads/main",
                "workflow_path": ".github/workflows/release.yml",
                "allowed_events": ["push", "workflow_dispatch"],
                "target_repository": "octo/tools-dev",
                "target_repository_id": 84,
                "permissions": {"contents": "write"}
            }, {
                "subject": "repo:octo/tools:environment:automations",
                "repository": "octo/tools",
                "repository_id": 42,
                "ref": "refs/heads/main",
                "workflow_path": ".github/workflows/release.yml",
                "allowed_events": ["workflow_dispatch"],
                "target_repository": "octo/other",
                "target_repository_id": 85,
                "permissions": {"contents": "write"}
            }]
        }));

        assert!(result.is_err());
    }

    #[test]
    fn policy_accepts_matching_identities_with_disjoint_events() {
        let policy: Policy = serde_json::from_value(json!({
            "expected_audience": "https://example.com",
            "rules": [{
                "subject": "repo:octo/tools:environment:automations",
                "repository": "octo/tools",
                "repository_id": 42,
                "ref": "refs/heads/main",
                "workflow_path": ".github/workflows/release.yml",
                "allowed_events": ["push"],
                "target_repository": "octo/tools-dev",
                "target_repository_id": 84,
                "permissions": {"contents": "write"}
            }, {
                "subject": "repo:octo/tools:environment:automations",
                "repository": "octo/tools",
                "repository_id": 42,
                "ref": "refs/heads/main",
                "workflow_path": ".github/workflows/release.yml",
                "allowed_events": ["workflow_dispatch"],
                "target_repository": "octo/other",
                "target_repository_id": 85,
                "permissions": {"contents": "write"}
            }]
        }))
        .unwrap();

        assert_eq!(policy.rules().len(), 2);
    }

    #[test]
    fn policy_accepts_a_pull_request_reusable_workflow_rule() {
        let policy: Policy = serde_json::from_value(json!({
            "expected_audience": "https://example.com",
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

        let rule = &policy.rules()[0];
        assert_eq!(rule.git_ref().as_str(), "refs/pull/*/merge");
        assert_eq!(rule.workflow_path().as_str(), ".github/workflows/ci.yml");
        assert_eq!(
            rule.job_workflow_path().unwrap().as_str(),
            ".github/workflows/pull-request-security-review.yml"
        );
        assert_eq!(rule.allowed_events()[0].as_str(), "pull_request");
        assert_eq!(
            serde_json::to_value(rule.permissions()).unwrap(),
            json!({ "pull_requests": "write" })
        );
    }

    #[test]
    fn policy_accepts_an_issues_reusable_workflow_rule() {
        let policy: Policy = serde_json::from_value(json!({
            "expected_audience": "https://example.com",
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

        let rule = &policy.rules()[0];
        assert_eq!(rule.git_ref().as_str(), "refs/heads/main");
        assert_eq!(
            rule.workflow_path().as_str(),
            ".github/workflows/issue-triage.yml"
        );
        assert_eq!(
            rule.job_workflow_path().unwrap().as_str(),
            ".github/workflows/reproduce-bug.yml"
        );
        assert_eq!(
            rule.allowed_events()
                .iter()
                .map(|event| event.as_str())
                .collect::<Vec<_>>(),
            ["issues", "workflow_dispatch"]
        );
    }

    #[test]
    fn hosted_policy_v2_accepts_a_scoped_issue_comment_rule() {
        let audience = Audience::try_from("https://example.com").unwrap();
        let document = json!({
            "version": 2,
            "repositories": {
                "uv": {
                    "name": "astral-sh/uv",
                    "id": 699532645,
                    "oidc_subject": "legacy"
                },
                "uv-dev": {
                    "name": "astral-sh/uv-dev",
                    "id": 1302176231,
                    "oidc_subject": "legacy"
                }
            },
            "rules": [{
                "caller": "uv",
                "environment": "automations",
                "caller_workflow": "update-issue-context.yml",
                "on": ["issue_comment"],
                "permissions": {"contents": "write"},
                "target": "uv-dev"
            }]
        });
        let policy = Policy::from_hosted(&document.to_string(), &audience).unwrap();

        let rule = &policy.rules()[0];
        assert_eq!(rule.allowed_events()[0].as_str(), "issue_comment");
        assert_eq!(rule.target_repository().as_str(), "astral-sh/uv-dev");
    }

    #[test]
    fn hosted_policy_v2_accepts_schedule_events() {
        let audience = Audience::try_from("https://example.com").unwrap();
        let policy = Policy::from_hosted(
            r#"{
                "version": 2,
                "repositories": {
                    "uv": {
                        "name": "astral-sh/uv",
                        "id": 699532645,
                        "oidc_subject": "legacy"
                    }
                },
                "rules": [{
                    "caller": "uv",
                    "environment": "automations",
                    "caller_workflow": "sync-python-releases.yml",
                    "on": ["schedule", "workflow_dispatch"],
                    "permissions": {"contents": "write", "pull_requests": "write"},
                    "target": "uv"
                }]
            }"#,
            &audience,
        )
        .unwrap();

        let rule = &policy.rules()[0];
        assert_eq!(rule.git_ref().as_str(), "refs/heads/main");
        assert_eq!(
            rule.workflow_path().as_str(),
            ".github/workflows/sync-python-releases.yml"
        );
        assert_eq!(
            rule.allowed_events()
                .iter()
                .map(|event| event.as_str())
                .collect::<Vec<_>>(),
            ["schedule", "workflow_dispatch"]
        );
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
            json!(["workflow_run"]),
            json!(["push", "pull_request_target"]),
            json!(["push", "push"]),
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
    fn policy_rejects_non_pull_request_events_for_a_pull_request_ref_pattern() {
        for allowed_events in [
            json!(["issue_comment"]),
            json!(["push"]),
            json!(["schedule"]),
            json!(["workflow_dispatch"]),
            json!(["pull_request", "issue_comment"]),
            json!(["pull_request", "push"]),
        ] {
            let result: Result<Policy, _> = serde_json::from_value(json!({
                "expected_audience": "https://example.com",
                "rules": [{
                    "subject": "repo:astral-sh/uv:environment:automations",
                    "repository": "astral-sh/uv",
                    "repository_id": 699532645,
                    "ref": "refs/pull/*/merge",
                    "workflow_path": ".github/workflows/ci.yml",
                    "job_workflow_path": ".github/workflows/pull-request-security-review.yml",
                    "environment": "automations",
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
    fn policy_accepts_an_exact_multi_repository_target_set() {
        let policy: Policy = serde_json::from_value(json!({
            "expected_audience": "https://example.com",
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

        let rule = &policy.rules()[0];
        assert!(rule.has_target_repository());
        assert!(rule.has_multiple_target_repositories());
        assert_eq!(rule.target_installation_id(), Some(146796415));
        assert_eq!(
            rule.target_repositories()
                .into_iter()
                .map(|(repository, id)| (repository.as_str().to_string(), *id))
                .collect::<Vec<_>>(),
            [
                ("astral-sh/uv".to_string(), 699532645),
                ("astral-sh/uv-dev".to_string(), 1302176231)
            ]
        );
    }

    #[test]
    fn policy_rejects_invalid_or_mixed_multi_repository_targets() {
        for target in [
            json!({ "target_repositories": [], "target_installation_id": 146796415 }),
            json!({
                "target_repositories": [
                    { "repository": "astral-sh/uv", "repository_id": 699532645 }
                ],
                "target_installation_id": 146796415
            }),
            json!({
                "target_repositories": [
                    { "repository": "astral-sh/uv", "repository_id": 699532645 },
                    { "repository": "astral-sh/uv-dev", "repository_id": 1302176231 }
                ]
            }),
            json!({
                "target_repositories": [
                    { "repository": "astral-sh/uv", "repository_id": 699532645 },
                    { "repository": "astral-sh/uv-dev", "repository_id": 1302176231 }
                ],
                "target_installation_id": 0
            }),
            json!({
                "target_repositories": [
                    { "repository": "astral-sh/uv", "repository_id": 699532645 },
                    { "repository": "ASTRAL-SH/UV", "repository_id": 1302176231 }
                ],
                "target_installation_id": 146796415
            }),
            json!({
                "target_repositories": [
                    { "repository": "astral-sh/uv", "repository_id": 699532645 },
                    { "repository": "astral-sh/uv-dev", "repository_id": 699532645 }
                ],
                "target_installation_id": 146796415
            }),
            json!({
                "target_repositories": [
                    { "repository": "astral-sh", "repository_id": 699532645 },
                    { "repository": "astral-sh/uv-dev", "repository_id": 1302176231 }
                ],
                "target_installation_id": 146796415
            }),
            json!({
                "target_repositories": [
                    { "repository": "astral-sh/uv" },
                    { "repository": "astral-sh/uv-dev", "repository_id": 1302176231 }
                ],
                "target_installation_id": 146796415
            }),
            json!({
                "target_repository": "astral-sh/uv",
                "target_repository_id": 699532645,
                "target_repositories": [
                    { "repository": "astral-sh/uv", "repository_id": 699532645 },
                    { "repository": "astral-sh/uv-dev", "repository_id": 1302176231 }
                ],
                "target_installation_id": 146796415
            }),
            json!({ "target_installation_id": 146796415 }),
        ] {
            let mut rule = json!({
                "subject": "repo:astral-sh/uv-dev:environment:automations",
                "repository": "astral-sh/uv-dev",
                "repository_id": 1302176231,
                "ref": "refs/heads/main",
                "workflow_path": ".github/workflows/promote-pull-request.yml",
                "environment": "automations"
            });
            rule.as_object_mut()
                .unwrap()
                .extend(target.as_object().unwrap().clone());

            let result: Result<Policy, _> = serde_json::from_value(json!({
                "expected_audience": "https://example.com",
                "rules": [rule]
            }));
            assert!(result.is_err(), "accepted invalid target: {target}");
        }
    }

    #[test]
    fn git_ref_rejects_non_canonical_refs() {
        assert!(GitRef::try_from("main").is_err());
        assert!(GitRef::try_from("refs/pull/1/head").is_err());
        assert!(GitRef::try_from("refs/pull/0/merge").is_err());
        assert!(GitRef::try_from("refs/pull/01/merge").is_err());
        assert!(GitRef::try_from("refs/pull/one/merge").is_err());
        assert!(GitRef::try_from("refs/pull/*/head").is_err());
        assert!(GitRef::try_from("refs/pull/1/merge").is_ok());
        assert!(GitRef::try_from("refs/pull/*/merge").is_ok());
        assert!(GitRef::try_from("refs/heads/main").is_ok());
        assert!(GitRef::try_from("refs/tags/v1.2.3").is_ok());
    }

    #[test]
    fn pull_request_ref_pattern_matches_only_canonical_merge_refs() {
        let pattern = GitRef::try_from("refs/pull/*/merge").unwrap();

        assert!(pattern.matches("refs/pull/1/merge"));
        assert!(pattern.matches("refs/pull/20474/merge"));
        assert!(!pattern.matches("refs/pull/0/merge"));
        assert!(!pattern.matches("refs/pull/01/merge"));
        assert!(!pattern.matches("refs/pull/one/merge"));
        assert!(!pattern.matches("refs/pull/1/head"));
        assert!(!pattern.matches("refs/heads/main"));
    }

    #[test]
    fn workflow_path_requires_github_workflows_prefix() {
        assert!(WorkflowPath::try_from("release.yml").is_err());
        assert!(WorkflowPath::try_from(".github/workflows/release.yml").is_ok());
    }

    #[test]
    fn hosted_policy_location_rejects_unsafe_paths_and_non_default_refs() {
        assert!(PolicyPath::try_from(".github/ost-simple-sts.json").is_ok());
        assert!(PolicyPath::try_from(".github/policies/simple-sts.json").is_ok());
        for invalid in [
            "ost-simple-sts.json",
            ".github/../policy.json",
            ".github//policy.json",
            ".github/policy.yaml",
            ".github/policy.json?ref=other",
            ".github/policy%2fother.json",
        ] {
            assert!(PolicyPath::try_from(invalid).is_err(), "{invalid}");
        }
        assert!(PolicyRef::try_from("main").is_ok());
        for invalid in ["refs/heads/main", "feature", "main?ref=feature", ""] {
            assert!(PolicyRef::try_from(invalid).is_err(), "{invalid}");
        }
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
