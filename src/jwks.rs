use std::time::{Duration, Instant};

use jsonwebtoken::{jwk::JwkSet, DecodingKey};
use tokio::sync::RwLock;

use crate::error::AppError;

const ACTIONS_JWKS_URL: &str = "https://token.actions.githubusercontent.com/.well-known/jwks";
const JWKS_TTL: Duration = Duration::from_secs(300);

pub struct JwksCache {
    http_client: reqwest::Client,
    jwks_url: String,
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
            jwks_url: ACTIONS_JWKS_URL.to_string(),
            inner: RwLock::new(None),
        }
    }

    #[cfg(test)]
    pub fn new_with_url(http_client: reqwest::Client, jwks_url: String) -> Self {
        Self {
            http_client,
            jwks_url,
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
            .get(&self.jwks_url)
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

#[cfg(test)]
mod tests {
    use super::JwksCache;
    use crate::error::AppError;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use rsa::traits::PublicKeyParts;
    use serde_json::json;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    fn test_http_client() -> reqwest::Client {
        reqwest::Client::builder().build().unwrap()
    }

    fn jwks_body(kid: &str) -> serde_json::Value {
        let mut rng = rand::thread_rng();
        let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = private_key.to_public_key();
        let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

        json!({
            "keys": [{
                "kty": "RSA",
                "n": n,
                "e": e,
                "kid": kid,
                "alg": "RS256",
                "use": "sig"
            }]
        })
    }

    #[tokio::test]
    async fn decoding_key_for_uses_cached_jwks() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks_body("kid-1")))
            .expect(1)
            .mount(&server)
            .await;

        let cache = JwksCache::new_with_url(
            test_http_client(),
            format!("{}/.well-known/jwks", server.uri()),
        );

        cache.decoding_key_for("kid-1").await.unwrap();
        cache.decoding_key_for("kid-1").await.unwrap();
    }

    #[tokio::test]
    async fn decoding_key_for_returns_invalid_oidc_token_for_unknown_kid() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks_body("known-kid")))
            .mount(&server)
            .await;

        let cache = JwksCache::new_with_url(
            test_http_client(),
            format!("{}/.well-known/jwks", server.uri()),
        );

        let error = cache
            .decoding_key_for("missing-kid")
            .await
            .err()
            .expect("expected missing kid to fail");
        assert!(matches!(error, AppError::InvalidOidcToken));
    }

    #[tokio::test]
    async fn decoding_key_for_maps_http_failure_to_unavailable() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let cache = JwksCache::new_with_url(
            test_http_client(),
            format!("{}/.well-known/jwks", server.uri()),
        );

        let error = cache
            .decoding_key_for("any-kid")
            .await
            .err()
            .expect("expected jwks fetch to fail");
        assert!(matches!(error, AppError::OidcVerificationUnavailable));
    }
}
