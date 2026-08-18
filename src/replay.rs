use aws_sdk_dynamodb::types::AttributeValue;
use sha2::{Digest, Sha256};

use crate::error::AppError;

pub async fn claim_jti(
    client: &aws_sdk_dynamodb::Client,
    table_name: impl AsRef<str>,
    issuer: &str,
    jti: impl AsRef<str>,
    expires_at_ms: u64,
) -> Result<(), AppError> {
    let key = sha256_hex(&format!("{issuer}\0{}", jti.as_ref()));
    let ttl = (expires_at_ms / 1000) + 60;

    let result = client
        .put_item()
        .table_name(table_name.as_ref())
        .item("jti_hash", AttributeValue::S(key))
        .item("ttl", AttributeValue::N(ttl.to_string()))
        .condition_expression("attribute_not_exists(jti_hash)")
        .send()
        .await;

    match result {
        Ok(_) => Ok(()),
        Err(error) => {
            if error
                .as_service_error()
                .is_some_and(|service_error| service_error.is_conditional_check_failed_exception())
            {
                return Err(AppError::OidcTokenReplayed);
            }

            tracing::error!(?error, "failed to claim oidc token jti");
            Err(AppError::JtiReplayGuardUnavailable)
        }
    }
}

fn sha256_hex(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    hex::encode(digest)
}

// Bound cold-worker refresh traffic across the entire deployment. A denied
// refresh fails closed; the caller must obtain a new OIDC token before retrying.
pub async fn claim_policy_refresh(
    client: &aws_sdk_dynamodb::Client,
    table: impl AsRef<str>,
    location: &crate::config::PolicyLocation,
) -> Result<(), AppError> {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AppError::JtiReplayGuardUnavailable)?
        .as_secs();
    let key = format!(
        "policy-refresh:{}",
        sha256_hex(&format!(
            "{}:{}:{}:{}",
            *location.repository_id(),
            location.installation_id(),
            location.git_ref(),
            location.path()
        ))
    );
    let result = client
        .put_item()
        .table_name(table.as_ref())
        .item("jti_hash", AttributeValue::S(key))
        .item("ttl", AttributeValue::N(now.saturating_add(5).to_string()))
        .condition_expression("attribute_not_exists(jti_hash) OR #ttl <= :now")
        .expression_attribute_names("#ttl", "ttl")
        .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
        .send()
        .await;
    match result {
        Ok(_) => Ok(()),
        Err(error)
            if error
                .as_service_error()
                .is_some_and(|e| e.is_conditional_check_failed_exception()) =>
        {
            Err(AppError::GithubRateLimited {
                retry_after: Duration::from_secs(5),
            })
        }
        Err(error) => {
            tracing::error!(?error, "policy refresh admission unavailable");
            Err(AppError::JtiReplayGuardUnavailable)
        }
    }
}
