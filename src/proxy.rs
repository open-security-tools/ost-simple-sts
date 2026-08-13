use std::fmt;

use aws_sdk_kms::primitives::Blob;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};

use crate::{config::ProxyCapabilityConfig, error::AppError, exchange::ExchangeResult};

const KMS_CONTEXT_SERVICE: &str = "ost-github-proxy";
const KMS_CONTEXT_VERSION: &str = "1";

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProxyDelivery {
    GithubProxy {
        #[serde(rename = "ref")]
        git_ref: String,
        expected_old_oid: String,
    },
}

/// An encrypted bearer capability that must not appear in logs.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct EncryptedCapability(String);

impl From<String> for EncryptedCapability {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl fmt::Debug for EncryptedCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EncryptedCapability(<redacted>)")
    }
}

impl fmt::Display for EncryptedCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

#[derive(Debug, Serialize)]
pub struct ProxyCapabilityResult {
    pub capability: EncryptedCapability,
    pub expires_at: String,
    pub repository: String,
    #[serde(rename = "ref")]
    pub caller_ref: String,
    pub branch: String,
    pub expected_old_oid: String,
}

#[derive(Serialize)]
struct CapabilityPlaintext<'a> {
    version: u8,
    repository: &'a str,
    #[serde(rename = "ref")]
    git_ref: &'a str,
    expected_old_oid: &'a str,
    expires_at: &'a str,
    github_token: &'a str,
}

impl ProxyDelivery {
    pub fn git_ref(&self) -> &str {
        match self {
            Self::GithubProxy { git_ref, .. } => git_ref,
        }
    }

    pub fn validate(&self) -> Result<(), AppError> {
        let Self::GithubProxy {
            git_ref,
            expected_old_oid,
        } = self;

        if !valid_branch_ref(git_ref)
            || !valid_object_id(expected_old_oid)
            || matches!(git_ref.as_str(), "refs/heads/main" | "refs/heads/master")
        {
            return Err(AppError::InvalidExchangeRequest);
        }
        Ok(())
    }
}

pub async fn encrypt_capability(
    config: &ProxyCapabilityConfig,
    exchange: &ExchangeResult,
    delivery: &ProxyDelivery,
) -> Result<ProxyCapabilityResult, AppError> {
    let ProxyDelivery::GithubProxy {
        git_ref,
        expected_old_oid,
    } = delivery;
    let repository = exchange
        .repository
        .as_deref()
        .ok_or(AppError::InvalidExchangeRequest)?;
    let plaintext = serde_json::to_vec(&CapabilityPlaintext {
        version: 1,
        repository,
        git_ref,
        expected_old_oid,
        expires_at: &exchange.expires_at,
        github_token: exchange.token.as_str(),
    })
    .map_err(|_| AppError::ProxyCapabilityEncryptionFailed)?;

    let response = config
        .client
        .encrypt()
        .key_id(&config.key_id)
        .plaintext(Blob::new(plaintext))
        .encryption_context("service", KMS_CONTEXT_SERVICE)
        .encryption_context("version", KMS_CONTEXT_VERSION)
        .send()
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "failed to encrypt a GitHub proxy capability");
            AppError::ProxyCapabilityEncryptionFailed
        })?;
    let ciphertext = response
        .ciphertext_blob()
        .ok_or(AppError::ProxyCapabilityEncryptionFailed)?;

    Ok(ProxyCapabilityResult {
        capability: URL_SAFE_NO_PAD.encode(ciphertext.as_ref()).into(),
        expires_at: exchange.expires_at.clone(),
        repository: repository.to_owned(),
        caller_ref: exchange.git_ref.clone(),
        branch: git_ref.clone(),
        expected_old_oid: expected_old_oid.clone(),
    })
}

pub(crate) fn valid_branch_ref(value: &str) -> bool {
    let Some(branch) = value.strip_prefix("refs/heads/") else {
        return false;
    };
    !branch.is_empty()
        && value.len() <= 255
        && !branch.starts_with('-')
        && !branch.ends_with('.')
        && !branch.contains("..")
        && branch
            .split('/')
            .all(|part| !part.is_empty() && !part.starts_with('.') && !part.ends_with(".lock"))
        && branch
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/'))
}

fn valid_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde_json::json;
    use wiremock::{
        matchers::{body_partial_json, header, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    use super::{
        encrypt_capability, CapabilityPlaintext, EncryptedCapability, ProxyCapabilityResult,
        ProxyDelivery,
    };
    use crate::{config::ProxyCapabilityConfig, exchange::ExchangeResult};

    fn delivery(git_ref: &str) -> ProxyDelivery {
        ProxyDelivery::GithubProxy {
            git_ref: git_ref.to_owned(),
            expected_old_oid: "a".repeat(40),
        }
    }

    #[test]
    fn accepts_exact_safe_branches_and_rejects_protected_or_unsafe_refs() {
        assert!(delivery("refs/heads/automation/fix").validate().is_ok());
        assert!(delivery("refs/heads/automation/fix-123_v2.0")
            .validate()
            .is_ok());
        for git_ref in [
            "refs/heads/main",
            "refs/heads/master",
            "refs/tags/v1",
            "refs/heads/",
            "refs/heads/-unsafe",
            "refs/heads/a/../b",
            "refs/heads/.hidden",
            "refs/heads/a/.hidden",
            "refs/heads/a.lock",
            "refs/heads/a.lock/b",
            "refs/heads/a//b",
            "refs/heads/a/",
            "refs/heads/a.",
            "refs/heads/a+b",
            "refs/heads/a@b",
            "refs/heads/a b",
            "refs/heads/a\\b",
            "refs/heads/naïve",
        ] {
            assert!(delivery(git_ref).validate().is_err(), "{git_ref}");
        }

        let oversized = format!("refs/heads/{}", "a".repeat(245));
        assert!(delivery(&oversized).validate().is_err());
    }

    #[test]
    fn delivery_rejects_unknown_kinds_unknown_fields_and_duplicate_fields() {
        let expected_head = "a".repeat(40);
        let valid = json!({
            "kind": "github_proxy",
            "ref": "refs/heads/automation/fix",
            "expected_old_oid": expected_head,
        });
        assert!(serde_json::from_value::<ProxyDelivery>(valid.clone()).is_ok());

        for invalid in [
            json!({
                "kind": "unknown",
                "ref": "refs/heads/automation/fix",
                "expected_old_oid": expected_head,
            }),
            json!({
                "ref": "refs/heads/automation/fix",
                "expected_old_oid": expected_head,
            }),
            json!({
                "kind": "github_proxy",
                "ref": "refs/heads/automation/fix",
                "expected_old_oid": expected_head,
                "extra": true,
            }),
        ] {
            assert!(serde_json::from_value::<ProxyDelivery>(invalid).is_err());
        }

        let duplicate_ref = format!(
            r#"{{"kind":"github_proxy","ref":"refs/heads/safe","ref":"refs/heads/main","expected_old_oid":"{expected_head}"}}"#
        );
        assert!(serde_json::from_str::<ProxyDelivery>(&duplicate_ref).is_err());
    }

    #[test]
    fn delivery_accepts_sha1_and_sha256_and_rejects_ambiguous_object_ids() {
        for expected_old_oid in ["0".repeat(40), "a".repeat(40), "f".repeat(64)] {
            let delivery = ProxyDelivery::GithubProxy {
                git_ref: "refs/heads/automation/fix".to_owned(),
                expected_old_oid,
            };
            assert!(delivery.validate().is_ok());
        }

        for expected_old_oid in [
            String::new(),
            "a".repeat(39),
            "a".repeat(41),
            "a".repeat(63),
            "a".repeat(65),
            "A".repeat(40),
            "g".repeat(40),
        ] {
            let delivery = ProxyDelivery::GithubProxy {
                git_ref: "refs/heads/automation/fix".to_owned(),
                expected_old_oid: expected_old_oid.clone(),
            };
            assert!(delivery.validate().is_err(), "{expected_old_oid}");
        }
    }

    #[test]
    fn encrypted_capability_redacts_debug_and_display_without_changing_json() {
        let capability: EncryptedCapability = "encrypted-session".to_owned().into();
        assert_eq!(format!("{capability:?}"), "EncryptedCapability(<redacted>)");
        assert_eq!(format!("{capability}"), "<redacted>");
        assert_eq!(
            serde_json::to_string(&capability).unwrap(),
            r#""encrypted-session""#
        );

        let result = ProxyCapabilityResult {
            capability,
            expires_at: "2099-01-01T00:00:00Z".to_owned(),
            repository: "octo/widgets".to_owned(),
            caller_ref: "refs/heads/main".to_owned(),
            branch: "refs/heads/automation/fix".to_owned(),
            expected_old_oid: "a".repeat(40),
        };
        assert!(!format!("{result:?}").contains("encrypted-session"));
    }

    #[tokio::test]
    async fn encrypts_exact_repository_branch_and_lease_without_returning_the_github_token() {
        let server = MockServer::start().await;
        let expected_head = "a".repeat(40);
        let expected_plaintext = serde_json::to_vec(&CapabilityPlaintext {
            version: 1,
            repository: "octo/widgets",
            git_ref: "refs/heads/automation/fix",
            expected_old_oid: &expected_head,
            expires_at: "2099-01-01T00:00:00Z",
            github_token: "ghs_secret",
        })
        .unwrap();
        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("x-amz-target", "TrentService.Encrypt"))
            .and(body_partial_json(json!({
                "KeyId": "alias/test-proxy",
                "EncryptionContext": { "service": "ost-github-proxy", "version": "1" },
                "Plaintext": STANDARD.encode(expected_plaintext)
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "KeyId": "arn:aws:kms:us-east-1:123456789012:key/test",
                "CiphertextBlob": STANDARD.encode("encrypted-session")
            })))
            .expect(1)
            .mount(&server)
            .await;

        let config = ProxyCapabilityConfig {
            client: aws_sdk_kms::Client::from_conf(
                aws_sdk_kms::Config::builder()
                    .behavior_version(aws_config::BehaviorVersion::latest())
                    .region(aws_sdk_kms::config::Region::new("us-east-1"))
                    .credentials_provider(aws_sdk_kms::config::Credentials::new(
                        "test", "test", None, None, "test",
                    ))
                    .endpoint_url(server.uri())
                    .build(),
            ),
            key_id: "alias/test-proxy".to_owned(),
        };
        let exchange = ExchangeResult {
            token: serde_json::from_str(r#""ghs_secret""#).unwrap(),
            expires_at: "2099-01-01T00:00:00Z".to_owned(),
            repository: Some("octo/widgets".to_owned()),
            repositories: None,
            git_ref: "refs/heads/main".to_owned(),
        };

        let result = encrypt_capability(&config, &exchange, &delivery("refs/heads/automation/fix"))
            .await
            .unwrap();

        let serialized = serde_json::to_value(&result).unwrap();
        assert_eq!(serialized["capability"], "ZW5jcnlwdGVkLXNlc3Npb24");
        assert!(!serialized.to_string().contains("ghs_secret"));
        assert!(!format!("{result:?}").contains("ZW5jcnlwdGVkLXNlc3Npb24"));
    }
}
