use std::time::{Duration, Instant};

use jsonwebtoken::{jwk::JwkSet, DecodingKey};
use tokio::sync::RwLock;

use crate::error::AppError;

const ACTIONS_JWKS_URL: &str = "https://token.actions.githubusercontent.com/.well-known/jwks";
const JWKS_TTL: Duration = Duration::from_secs(300);

pub struct JwksCache {
    http_client: reqwest::Client,
    inner: RwLock<Option<CachedJwks>>,
}

struct CachedJwks {
    fetched_at: Instant,
    jwk_set: JwkSet,
}

impl JwksCache {
    pub fn new(http_client: reqwest::Client) -> Self {
        Self {
            http_client,
            inner: RwLock::new(None),
        }
    }

    pub async fn decoding_key_for(&self, kid: &str) -> Result<DecodingKey, AppError> {
        if let Some(key) = self.lookup_cached(kid).await {
            return Ok(key);
        }

        let jwk_set = self.refresh().await?;
        Self::find_key(&jwk_set, kid).ok_or(AppError::InvalidOidcToken)
    }

    async fn lookup_cached(&self, kid: &str) -> Option<DecodingKey> {
        let guard = self.inner.read().await;
        let cached = guard.as_ref()?;
        if cached.fetched_at.elapsed() >= JWKS_TTL {
            return None;
        }

        Self::find_key(&cached.jwk_set, kid)
    }

    async fn refresh(&self) -> Result<JwkSet, AppError> {
        let response = self
            .http_client
            .get(ACTIONS_JWKS_URL)
            .send()
            .await
            .map_err(|error| {
                tracing::error!(?error, "failed to fetch actions jwks");
                AppError::OidcVerificationUnavailable
            })?;

        let response = response.error_for_status().map_err(|error| {
            tracing::error!(?error, "actions jwks returned non-success status");
            AppError::OidcVerificationUnavailable
        })?;

        let jwk_set = response.json::<JwkSet>().await.map_err(|error| {
            tracing::error!(?error, "failed to decode actions jwks");
            AppError::OidcVerificationUnavailable
        })?;

        let mut guard = self.inner.write().await;
        *guard = Some(CachedJwks {
            fetched_at: Instant::now(),
            jwk_set: jwk_set.clone(),
        });

        Ok(jwk_set)
    }

    fn find_key(jwk_set: &JwkSet, kid: &str) -> Option<DecodingKey> {
        let jwk = jwk_set
            .keys
            .iter()
            .find(|jwk| jwk.common.key_id.as_deref() == Some(kid))?;

        DecodingKey::from_jwk(jwk).ok()
    }
}
