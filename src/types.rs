use std::{env, fmt};

use crate::error::AppError;

const WORKFLOWS_PREFIX: &str = ".github/workflows/";
const MIN_TOKEN_LIFETIME_MINUTES: u64 = 10;
const MAX_TOKEN_LIFETIME_MINUTES: u64 = 60;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Audience(String);

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositoryOwner(String);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositoryNamePart(String);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositoryFullName {
    full_name: String,
    owner: RepositoryOwner,
    repo: RepositoryNamePart,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RepositoryId(u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExpiresInMinutes(u64);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Jti(String);

macro_rules! impl_string_wrapper {
    ($name:ident) => {
        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}

impl_string_wrapper!(Audience);
impl_string_wrapper!(GitRef);
impl_string_wrapper!(WorkflowPath);
impl_string_wrapper!(EnvironmentName);
impl_string_wrapper!(AppId);
impl_string_wrapper!(JtiTableName);
impl_string_wrapper!(RepositoryOwner);
impl_string_wrapper!(RepositoryNamePart);
impl_string_wrapper!(Jti);

impl fmt::Debug for AppPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AppPrivateKey").field(&"<redacted>").finish()
    }
}

impl AppPrivateKey {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for AppPrivateKey {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl RepositoryFullName {
    pub fn as_str(&self) -> &str {
        &self.full_name
    }

    pub fn owner(&self) -> &RepositoryOwner {
        &self.owner
    }

    pub fn repo(&self) -> &RepositoryNamePart {
        &self.repo
    }
}

impl AsRef<str> for RepositoryFullName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for RepositoryFullName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.full_name.fmt(f)
    }
}

impl RepositoryId {
    pub fn get(self) -> u64 {
        self.0
    }
}

impl ExpiresInMinutes {
    pub fn get(self) -> u64 {
        self.0
    }
}

impl TryFrom<String> for Audience {
    type Error = AppError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(Self(normalize_non_empty(value, AppError::InvalidPolicy)?))
    }
}

impl TryFrom<&str> for Audience {
    type Error = AppError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.to_string().try_into()
    }
}

impl TryFrom<String> for GitRef {
    type Error = AppError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let value = normalize_non_empty(value, AppError::InvalidPolicy)?;
        let is_valid_branch = value
            .strip_prefix("refs/heads/")
            .is_some_and(|suffix| !suffix.is_empty());
        let is_valid_tag = value
            .strip_prefix("refs/tags/")
            .is_some_and(|suffix| !suffix.is_empty());

        if is_valid_branch || is_valid_tag {
            Ok(Self(value))
        } else {
            Err(AppError::InvalidPolicy)
        }
    }
}

impl TryFrom<&str> for GitRef {
    type Error = AppError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.to_string().try_into()
    }
}

impl TryFrom<String> for WorkflowPath {
    type Error = AppError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let value = normalize_non_empty(value, AppError::InvalidPolicy)?;
        let has_valid_prefix = value
            .strip_prefix(WORKFLOWS_PREFIX)
            .is_some_and(|suffix| !suffix.is_empty());
        let has_valid_extension = value.ends_with(".yml") || value.ends_with(".yaml");

        if has_valid_prefix && has_valid_extension {
            Ok(Self(value))
        } else {
            Err(AppError::InvalidPolicy)
        }
    }
}

impl TryFrom<&str> for WorkflowPath {
    type Error = AppError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.to_string().try_into()
    }
}

impl TryFrom<String> for EnvironmentName {
    type Error = AppError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(Self(normalize_non_empty(value, AppError::InvalidPolicy)?))
    }
}

impl TryFrom<&str> for EnvironmentName {
    type Error = AppError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.to_string().try_into()
    }
}

impl TryFrom<String> for AppId {
    type Error = AppError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(Self(normalize_non_empty(
            value,
            AppError::AppIdNotConfigured,
        )?))
    }
}

impl TryFrom<&str> for AppId {
    type Error = AppError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.to_string().try_into()
    }
}

impl TryFrom<String> for AppPrivateKey {
    type Error = AppError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let value = normalize_non_empty(value, AppError::AppPrivateKeyNotConfigured)?;
        Ok(Self(normalize_private_key(&value)))
    }
}

impl TryFrom<&str> for AppPrivateKey {
    type Error = AppError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.to_string().try_into()
    }
}

impl TryFrom<String> for JtiTableName {
    type Error = AppError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(Self(normalize_non_empty(
            value,
            AppError::JtiTableNotConfigured,
        )?))
    }
}

impl TryFrom<&str> for JtiTableName {
    type Error = AppError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.to_string().try_into()
    }
}

impl TryFrom<String> for RepositoryOwner {
    type Error = AppError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(Self(validate_repository_segment(
            value,
            AppError::RepositoryClaimInvalid,
        )?))
    }
}

impl TryFrom<&str> for RepositoryOwner {
    type Error = AppError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.to_string().try_into()
    }
}

impl TryFrom<String> for RepositoryNamePart {
    type Error = AppError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(Self(validate_repository_segment(
            value,
            AppError::RepositoryClaimInvalid,
        )?))
    }
}

impl TryFrom<&str> for RepositoryNamePart {
    type Error = AppError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.to_string().try_into()
    }
}

impl TryFrom<(String, String)> for RepositoryFullName {
    type Error = AppError;

    fn try_from((owner, repo): (String, String)) -> Result<Self, Self::Error> {
        let owner = RepositoryOwner::try_from(owner)?;
        let repo = RepositoryNamePart::try_from(repo)?;
        let full_name = format!("{owner}/{repo}");

        Ok(Self {
            full_name,
            owner,
            repo,
        })
    }
}

impl TryFrom<String> for RepositoryFullName {
    type Error = AppError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let mut parts = value.split('/');
        let owner = parts.next().unwrap_or_default();
        let repo = parts.next().unwrap_or_default();
        if owner.is_empty() || repo.is_empty() || parts.next().is_some() {
            return Err(AppError::RepositoryClaimInvalid);
        }

        Self::try_from((owner.to_string(), repo.to_string()))
    }
}

impl TryFrom<&str> for RepositoryFullName {
    type Error = AppError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.to_string().try_into()
    }
}

impl TryFrom<u64> for RepositoryId {
    type Error = AppError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if value == 0 {
            Err(AppError::RepositoryIdClaimInvalid)
        } else {
            Ok(Self(value))
        }
    }
}

impl TryFrom<&str> for ExpiresInMinutes {
    type Error = AppError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let value = value
            .parse::<u64>()
            .map_err(|_| AppError::InvalidExpiresIn)?;
        if !(MIN_TOKEN_LIFETIME_MINUTES..=MAX_TOKEN_LIFETIME_MINUTES).contains(&value) {
            return Err(AppError::InvalidExpiresIn);
        }

        Ok(Self(value))
    }
}

impl TryFrom<String> for ExpiresInMinutes {
    type Error = AppError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

impl TryFrom<String> for Jti {
    type Error = AppError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(Self(normalize_non_empty(
            value,
            AppError::OidcTokenMissingJti,
        )?))
    }
}

impl TryFrom<&str> for Jti {
    type Error = AppError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.to_string().try_into()
    }
}

fn normalize_non_empty(value: String, error: AppError) -> Result<String, AppError> {
    let normalized = value.trim();
    if normalized.is_empty() {
        Err(error)
    } else {
        Ok(normalized.to_string())
    }
}

fn validate_repository_segment(value: String, error: AppError) -> Result<String, AppError> {
    let value = normalize_non_empty(value, error)?;
    if value.contains('/') {
        Err(AppError::RepositoryClaimInvalid)
    } else {
        Ok(value)
    }
}

fn normalize_private_key(value: &str) -> String {
    if value.contains("\\n") {
        value.replace("\\n", "\n")
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::{AppId, AppPrivateKey, JtiTableName, RepositoryFullName};

    #[test]
    fn app_id_rejects_empty_values() {
        assert!(AppId::try_from("").is_err());
        assert!(AppId::try_from("   ").is_err());
    }

    #[test]
    fn jti_table_name_rejects_empty_values() {
        assert!(JtiTableName::try_from("").is_err());
        assert!(JtiTableName::try_from("   ").is_err());
    }

    #[test]
    fn app_private_key_normalizes_escaped_newlines() {
        let private_key = AppPrivateKey::try_from("line-1\\nline-2").unwrap();
        assert_eq!(private_key.as_str(), "line-1\nline-2");
    }

    #[test]
    fn repository_full_name_normalizes_owner_and_repo_segments() {
        let repository = RepositoryFullName::try_from(" astral-sh / uv ").unwrap();
        assert_eq!(repository.owner().as_str(), "astral-sh");
        assert_eq!(repository.repo().as_str(), "uv");
        assert_eq!(repository.as_str(), "astral-sh/uv");
    }
}
