use std::{collections::BTreeMap, fmt};

use serde::{de::MapAccess, Deserialize, Deserializer, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Permissions(BTreeMap<String, PermissionLevel>);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum PermissionLevel {
    Read,
    Write,
    Admin,
}

impl Permissions {
    pub fn contents_write() -> Self {
        Self(BTreeMap::from([(
            "contents".to_string(),
            PermissionLevel::Write,
        )]))
    }

    pub fn matches_response(&self, granted: &BTreeMap<String, String>) -> bool {
        let expected = self
            .0
            .iter()
            .map(|(name, level)| {
                let value = match level {
                    PermissionLevel::Read => "read",
                    PermissionLevel::Write => "write",
                    PermissionLevel::Admin => "admin",
                };
                (name.clone(), value.to_string())
            })
            .collect::<BTreeMap<_, _>>();
        let mut granted = granted.clone();
        if !expected.contains_key("metadata")
            && granted.get("metadata").is_some_and(|v| v == "read")
        {
            granted.remove("metadata");
        }
        granted == expected
    }

    pub fn permits(&self, requested: &Self) -> bool {
        requested
            .0
            .iter()
            .all(|(name, level)| self.0.get(name).is_some_and(|allowed| allowed >= level))
    }
}

impl<'de> Deserialize<'de> for Permissions {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PermissionsVisitor;

        impl<'de> serde::de::Visitor<'de> for PermissionsVisitor {
            type Value = Permissions;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a non-empty map of GitHub App repository permissions")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut permissions = BTreeMap::new();
                while let Some((name, level)) = map.next_entry::<String, PermissionLevel>()? {
                    if !is_valid_repository_permission(&name, level) {
                        return Err(serde::de::Error::custom("invalid repository permission"));
                    }
                    if permissions.insert(name, level).is_some() {
                        return Err(serde::de::Error::custom("duplicate repository permission"));
                    }
                }
                if permissions.is_empty() {
                    return Err(serde::de::Error::custom("permissions must not be empty"));
                }
                Ok(Permissions(permissions))
            }
        }

        deserializer.deserialize_map(PermissionsVisitor)
    }
}

fn is_valid_repository_permission(name: &str, level: PermissionLevel) -> bool {
    match name {
        "repository_projects" => true,
        "workflows" => level == PermissionLevel::Write,
        "actions"
        | "administration"
        | "artifact_metadata"
        | "attestations"
        | "checks"
        | "code_quality"
        | "codespaces"
        | "contents"
        | "dependabot_secrets"
        | "deployments"
        | "discussions"
        | "environments"
        | "issues"
        | "merge_queues"
        | "metadata"
        | "packages"
        | "pages"
        | "pull_requests"
        | "repository_custom_properties"
        | "repository_hooks"
        | "secret_scanning_alerts"
        | "secrets"
        | "security_events"
        | "single_file"
        | "statuses"
        | "vulnerability_alerts" => level != PermissionLevel::Admin,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::Permissions;

    #[test]
    fn permissions_accept_repository_permissions_and_levels() {
        let permissions: Permissions = serde_json::from_value(json!({
            "contents": "write",
            "issues": "read",
            "repository_projects": "admin",
            "workflows": "write"
        }))
        .unwrap();

        assert_eq!(
            serde_json::to_value(permissions).unwrap(),
            json!({
                "contents": "write",
                "issues": "read",
                "repository_projects": "admin",
                "workflows": "write"
            })
        );
    }

    #[test]
    fn permissions_reject_empty_unknown_invalid_and_duplicate_entries() {
        for invalid in [
            r#"{}"#,
            r#"{"members":"read"}"#,
            r#"{"contents":"admin"}"#,
            r#"{"workflows":"read"}"#,
            r#"{"contents":"write","contents":"read"}"#,
        ] {
            assert!(
                serde_json::from_str::<Permissions>(invalid).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn permissions_authorize_only_requested_subset() {
        let allowed: Permissions = serde_json::from_value(json!({
            "contents": "write",
            "issues": "read"
        }))
        .unwrap();
        let read_contents: Permissions =
            serde_json::from_value(json!({ "contents": "read" })).unwrap();
        let write_contents: Permissions =
            serde_json::from_value(json!({ "contents": "write" })).unwrap();
        let write_issues: Permissions =
            serde_json::from_value(json!({ "issues": "write" })).unwrap();
        let extra: Permissions = serde_json::from_value(json!({ "actions": "read" })).unwrap();

        assert!(allowed.permits(&read_contents));
        assert!(allowed.permits(&write_contents));
        assert!(!allowed.permits(&write_issues));
        assert!(!allowed.permits(&extra));
    }
}
