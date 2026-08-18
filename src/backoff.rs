use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_sdk_dynamodb::types::AttributeValue;
use sha2::{Digest, Sha256};

use crate::{config::Config, error::AppError};

fn now() -> Result<u64, AppError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| AppError::JtiReplayGuardUnavailable)
}

fn key(config: &Config) -> String {
    format!(
        "github-backoff:{}",
        hex::encode(Sha256::digest(config.app_id.as_str()))
    )
}

pub async fn check(config: &Config) -> Result<(), AppError> {
    let response = config
        .dynamodb
        .get_item()
        .table_name(config.jti_table_name.as_str())
        .key("jti_hash", AttributeValue::S(key(config)))
        .consistent_read(true)
        .send()
        .await
        .map_err(|_| AppError::JtiReplayGuardUnavailable)?;
    let until = response
        .item
        .as_ref()
        .and_then(|item| item.get("ttl"))
        .and_then(|v| v.as_n().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    let remaining = until.saturating_sub(now()?);
    if remaining > 0 {
        return Err(AppError::GithubRateLimited {
            retry_after: Duration::from_secs(remaining),
        });
    }
    Ok(())
}

pub async fn record(config: &Config, delay: Duration) -> Result<(), AppError> {
    let seconds = delay
        .as_secs()
        .saturating_add(u64::from(delay.subsec_nanos() > 0))
        .max(1);
    let until = now()?.saturating_add(seconds).to_string();
    let result = config
        .dynamodb
        .put_item()
        .table_name(config.jti_table_name.as_str())
        .item("jti_hash", AttributeValue::S(key(config)))
        .item("ttl", AttributeValue::N(until.clone()))
        .condition_expression("attribute_not_exists(jti_hash) OR #ttl < :until")
        .expression_attribute_names("#ttl", "ttl")
        .expression_attribute_values(":until", AttributeValue::N(until))
        .send()
        .await;
    match result {
        Ok(_) => Ok(()),
        Err(e)
            if e.as_service_error()
                .is_some_and(|e| e.is_conditional_check_failed_exception()) =>
        {
            Ok(())
        }
        Err(_) => Err(AppError::JtiReplayGuardUnavailable),
    }
}
