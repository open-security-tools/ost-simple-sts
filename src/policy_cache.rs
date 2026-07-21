use std::{future::Future, time::Duration};

use tokio::{sync::Mutex, time::Instant};
use uuid::Uuid;

use crate::{config::Policy, error::AppError};

const PRIMARY_TTL: Duration = Duration::from_secs(5 * 60);
const STALE_TTL: Duration = Duration::from_secs(60 * 60);
const MAX_JITTER: Duration = Duration::from_secs(30);
const MAX_BACKOFF: Duration = Duration::from_secs(60 * 60);

pub struct PolicyCache {
    state: Mutex<CacheState>,
    primary_ttl: Duration,
    stale_ttl: Duration,
    jitter: Duration,
}

pub struct LoadedPolicy {
    policy: Policy,
    retry_after: Option<Duration>,
}

impl LoadedPolicy {
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    pub fn retry_after(&self) -> Option<Duration> {
        self.retry_after
    }
}

#[derive(Default)]
struct CacheState {
    policy: Option<CachedPolicy>,
    retry_at: Option<Instant>,
    consecutive_rate_limits: u32,
}

struct CachedPolicy {
    policy: Policy,
    loaded_at: Instant,
}

impl Default for PolicyCache {
    fn default() -> Self {
        let entropy = Uuid::new_v4();
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&entropy.as_bytes()[..8]);
        let jitter = u64::from_le_bytes(bytes) % (MAX_JITTER.as_millis() as u64 + 1);
        Self::with_jitter(PRIMARY_TTL, STALE_TTL, Duration::from_millis(jitter))
    }
}

impl PolicyCache {
    fn with_jitter(primary_ttl: Duration, stale_ttl: Duration, jitter: Duration) -> Self {
        Self {
            state: Mutex::new(CacheState::default()),
            primary_ttl,
            stale_ttl,
            jitter: jitter.min(MAX_JITTER),
        }
    }

    fn set_backoff(&self, state: &mut CacheState, retry_after: Duration) -> Duration {
        state.consecutive_rate_limits = state.consecutive_rate_limits.saturating_add(1);
        let multiplier = 1u32
            .checked_shl(state.consecutive_rate_limits.saturating_sub(1))
            .unwrap_or(u32::MAX);
        let retry_after = retry_after
            .clamp(Duration::from_secs(1), MAX_BACKOFF)
            .saturating_mul(multiplier)
            .min(MAX_BACKOFF)
            .saturating_add(self.jitter);
        state.retry_at = Some(Instant::now() + retry_after);
        retry_after
    }

    pub async fn get_or_load<F, Fut>(&self, loader: F) -> Result<LoadedPolicy, AppError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Policy, AppError>>,
    {
        let mut state = self.state.lock().await;
        if let Some(retry_at) = state.retry_at {
            if Instant::now() < retry_at {
                if let Some(cached) = state.policy.as_ref() {
                    if cached.loaded_at.elapsed() < self.stale_ttl {
                        return Ok(LoadedPolicy {
                            policy: cached.policy.clone(),
                            retry_after: Some(retry_at.saturating_duration_since(Instant::now())),
                        });
                    }
                }
                state.policy = None;
                return Err(AppError::GithubRateLimited {
                    retry_after: retry_at.saturating_duration_since(Instant::now()),
                });
            }
            state.retry_at = None;
        }

        if let Some(cached) = state.policy.as_ref() {
            if cached.loaded_at.elapsed() < self.primary_ttl.saturating_sub(self.jitter) {
                return Ok(LoadedPolicy {
                    policy: cached.policy.clone(),
                    retry_after: None,
                });
            }
        }

        match loader().await {
            Ok(policy) => {
                state.policy = Some(CachedPolicy {
                    policy: policy.clone(),
                    loaded_at: Instant::now(),
                });
                state.retry_at = None;
                state.consecutive_rate_limits = 0;
                Ok(LoadedPolicy {
                    policy,
                    retry_after: None,
                })
            }
            Err(AppError::GithubRateLimited { retry_after }) => {
                let retry_after = self.set_backoff(&mut state, retry_after);
                if let Some(cached) = state.policy.as_ref() {
                    if cached.loaded_at.elapsed() < self.stale_ttl {
                        return Ok(LoadedPolicy {
                            policy: cached.policy.clone(),
                            retry_after: Some(retry_after),
                        });
                    }
                }
                state.policy = None;
                Err(AppError::GithubRateLimited { retry_after })
            }
            Err(error) => {
                *state = CacheState::default();
                Err(error)
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn with_policy(policy: Policy) -> Self {
        Self {
            state: Mutex::new(CacheState {
                policy: Some(CachedPolicy {
                    policy,
                    loaded_at: Instant::now(),
                }),
                retry_at: None,
                consecutive_rate_limits: 0,
            }),
            primary_ttl: PRIMARY_TTL,
            stale_ttl: STALE_TTL,
            jitter: Duration::ZERO,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        sync::Arc,
        time::Duration,
    };

    use serde_json::json;

    use crate::{config::Policy, error::AppError};

    use super::PolicyCache;

    fn policy(workflow: &str) -> Policy {
        serde_json::from_value(json!({
            "expected_audience": "https://example.com",
            "rules": [{
                "subject": "repo:octo/tools:environment:automations",
                "repository": "octo/tools",
                "repository_id": 42,
                "ref": "refs/heads/main",
                "workflow_path": workflow,
                "permissions": {"contents": "write"}
            }]
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn reuses_a_fresh_policy_without_reloading() {
        let cache = PolicyCache::with_jitter(
            Duration::from_secs(300),
            Duration::from_secs(3600),
            Duration::ZERO,
        );
        let loads = AtomicUsize::new(0);

        for _ in 0..2 {
            let loaded = cache
                .get_or_load(|| async {
                    loads.fetch_add(1, Ordering::SeqCst);
                    Ok(policy(".github/workflows/first.yml"))
                })
                .await
                .unwrap();
            assert!(loaded.retry_after().is_none());
        }

        assert_eq!(loads.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn replaces_an_expired_policy_only_after_a_valid_refresh() {
        let cache =
            PolicyCache::with_jitter(Duration::ZERO, Duration::from_secs(3600), Duration::ZERO);
        cache
            .get_or_load(|| async { Ok(policy(".github/workflows/first.yml")) })
            .await
            .unwrap();

        let loaded = cache
            .get_or_load(|| async { Ok(policy(".github/workflows/updated.yml")) })
            .await
            .unwrap();

        assert_eq!(
            loaded.policy().rules()[0].workflow_path().as_str(),
            ".github/workflows/updated.yml"
        );
        assert!(loaded.retry_after().is_none());
    }

    #[tokio::test]
    async fn invalid_refresh_clears_the_last_known_good_policy() {
        let cache =
            PolicyCache::with_jitter(Duration::ZERO, Duration::from_secs(3600), Duration::ZERO);
        cache
            .get_or_load(|| async { Ok(policy(".github/workflows/first.yml")) })
            .await
            .unwrap();

        assert!(matches!(
            cache
                .get_or_load(|| async { Err(AppError::InvalidPolicy) })
                .await,
            Err(AppError::InvalidPolicy)
        ));
        assert!(cache.state.lock().await.policy.is_none());
    }

    #[tokio::test]
    async fn rate_limited_refresh_keeps_a_bounded_stale_snapshot_and_signals_failure() {
        let cache =
            PolicyCache::with_jitter(Duration::ZERO, Duration::from_secs(3600), Duration::ZERO);
        cache
            .get_or_load(|| async { Ok(policy(".github/workflows/first.yml")) })
            .await
            .unwrap();

        let loaded = cache
            .get_or_load(|| async {
                Err(AppError::GithubRateLimited {
                    retry_after: Duration::from_secs(2),
                })
            })
            .await
            .unwrap();

        assert_eq!(loaded.retry_after(), Some(Duration::from_secs(2)));
        let loads = AtomicUsize::new(0);
        let loaded = cache
            .get_or_load(|| async {
                loads.fetch_add(1, Ordering::SeqCst);
                Ok(policy(".github/workflows/unexpected.yml"))
            })
            .await
            .unwrap();
        assert!(loaded.retry_after().is_some());
        assert_eq!(loads.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn stale_policy_is_never_returned_after_the_stale_window() {
        let cache = PolicyCache::with_jitter(Duration::ZERO, Duration::ZERO, Duration::ZERO);
        cache
            .get_or_load(|| async { Ok(policy(".github/workflows/first.yml")) })
            .await
            .unwrap();

        assert!(matches!(
            cache
                .get_or_load(|| async {
                    Err(AppError::GithubRateLimited {
                        retry_after: Duration::from_secs(2),
                    })
                })
                .await,
            Err(AppError::GithubRateLimited { .. })
        ));
        assert!(cache.state.lock().await.policy.is_none());
    }

    #[tokio::test]
    async fn collapses_concurrent_cold_policy_loads() {
        let cache = Arc::new(PolicyCache::with_jitter(
            Duration::from_secs(300),
            Duration::from_secs(3600),
            Duration::ZERO,
        ));
        let loads = Arc::new(AtomicUsize::new(0));
        let tasks = (0..20)
            .map(|_| {
                let cache = Arc::clone(&cache);
                let loads = Arc::clone(&loads);
                tokio::spawn(async move {
                    cache
                        .get_or_load(|| async {
                            loads.fetch_add(1, Ordering::SeqCst);
                            tokio::task::yield_now().await;
                            Ok(policy(".github/workflows/first.yml"))
                        })
                        .await
                        .unwrap()
                })
            })
            .collect::<Vec<_>>();

        for task in tasks {
            assert!(task.await.unwrap().retry_after().is_none());
        }
        assert_eq!(loads.load(Ordering::SeqCst), 1);
    }
}
