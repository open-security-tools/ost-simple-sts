use std::fmt;

use crate::error::AppError;

/// Stores a non-zero GitHub repository identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub struct RepositoryId(u64);

/// Stores a validated GitHub repository owner name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositoryOwner(String);

/// Stores a validated GitHub repository name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositoryNamePart(String);

/// Identifies a GitHub repository by its owner and name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositoryFullName {
    full_name: String,
    owner: RepositoryOwner,
    repo: RepositoryNamePart,
}

/// Stores a validated GitHub Actions OIDC token identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Jti(String);

fn is_valid_slug(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

crate::impl_string_newtype!(
    RepositoryOwner,
    AppError,
    AppError::RepositoryClaimInvalid,
    validate = is_valid_slug
);
crate::impl_string_newtype!(
    RepositoryNamePart,
    AppError,
    AppError::RepositoryClaimInvalid,
    validate = is_valid_slug
);
crate::impl_string_newtype!(Jti, AppError, AppError::OidcTokenMissingJti);

impl RepositoryId {
    pub fn new(value: u64) -> Option<Self> {
        (value != 0).then_some(Self(value))
    }
}

impl std::ops::Deref for RepositoryId {
    type Target = u64;

    fn deref(&self) -> &u64 {
        &self.0
    }
}

impl<'de> serde::Deserialize<'de> for RepositoryId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl serde::de::Visitor<'_> for Visitor {
            type Value = RepositoryId;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a non-zero repository id as a number or string")
            }

            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                RepositoryId::new(value).ok_or_else(|| E::custom("repository id must be non-zero"))
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                let value = value.parse::<u64>().map_err(E::custom)?;
                self.visit_u64(value)
            }
        }

        deserializer.deserialize_any(Visitor)
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

impl fmt::Display for RepositoryFullName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.full_name.fmt(f)
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
        let (owner, repo) = value
            .split_once('/')
            .ok_or(AppError::RepositoryClaimInvalid)?;
        if owner.is_empty() || repo.is_empty() || repo.contains('/') {
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

#[cfg(test)]
mod tests {
    use super::{RepositoryFullName, RepositoryId, RepositoryNamePart, RepositoryOwner};

    #[test]
    fn repository_parts_reject_unsafe_characters() {
        assert!(RepositoryOwner::try_from("..".to_string()).is_err());
        assert!(RepositoryOwner::try_from("foo#bar".to_string()).is_err());
        assert!(RepositoryOwner::try_from("foo?x=1".to_string()).is_err());
        assert!(RepositoryNamePart::try_from("..".to_string()).is_err());
        assert!(RepositoryNamePart::try_from("repo#frag".to_string()).is_err());
        assert!(RepositoryOwner::try_from("valid-owner".to_string()).is_ok());
        assert!(RepositoryNamePart::try_from("valid.repo-name_1".to_string()).is_ok());
    }

    #[test]
    fn repository_full_name_accepts_owner_and_repo() {
        let repository = RepositoryFullName::try_from("astral-sh/uv").unwrap();

        assert_eq!(repository.owner().as_str(), "astral-sh");
        assert_eq!(repository.repo().as_str(), "uv");
        assert_eq!(repository.as_str(), "astral-sh/uv");
    }

    #[test]
    fn repository_full_name_rejects_unsafe_components() {
        for value in [
            "astral-sh",
            "/uv",
            "astral-sh/uv/extra",
            "../evil",
            "owner/..",
        ] {
            assert!(RepositoryFullName::try_from(value).is_err());
        }
    }

    #[test]
    fn repository_id_accepts_strings_and_numbers_but_rejects_zero() {
        assert_eq!(*serde_json::from_str::<RepositoryId>("42").unwrap(), 42);
        assert_eq!(*serde_json::from_str::<RepositoryId>(r#""7""#).unwrap(), 7);
        assert!(serde_json::from_str::<RepositoryId>("0").is_err());
        assert!(serde_json::from_str::<RepositoryId>(r#""zero""#).is_err());
    }
}
