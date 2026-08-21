use std::{collections::BTreeMap, future::Future, sync::Arc};

use tokio::{sync::Mutex, time::Instant};

use crate::{
    config::Policy,
    error::AppError,
    github::{RepositoryFullName, RepositoryId},
    policy_cache::{LoadedPolicy, PolicyCache},
};

const MAX_CACHED_REPOSITORIES: usize = 128;

#[derive(Clone, Debug)]
pub struct RepositoryPolicy {
    pub repository_id: RepositoryId,
    pub installation_id: u64,
    pub policy: Policy,
}

#[derive(Default)]
pub struct PolicyStore {
    entries: Mutex<BTreeMap<String, CacheEntry>>,
}

struct CacheEntry {
    cache: Arc<PolicyCache<RepositoryPolicy>>,
    last_used: Instant,
}

impl PolicyStore {
    pub async fn get_or_load<F, Fut>(
        &self,
        repository: &RepositoryFullName,
        loader: F,
    ) -> Result<LoadedPolicy<RepositoryPolicy>, AppError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<RepositoryPolicy, AppError>>,
    {
        let cache = {
            let mut entries = self.entries.lock().await;
            if !entries.contains_key(repository.as_str())
                && entries.len() >= MAX_CACHED_REPOSITORIES
            {
                // Never evict a cache with an active reader or refresh: that would
                // allow concurrent requests to refresh the same repository twice.
                let oldest = entries
                    .iter()
                    .filter(|(_, entry)| Arc::strong_count(&entry.cache) == 1)
                    .min_by_key(|(_, entry)| entry.last_used)
                    .map(|(key, _)| key.clone())
                    .ok_or(AppError::PolicyLookupFailed)?;
                entries.remove(&oldest);
            }
            let entry = entries
                .entry(repository.as_str().to_owned())
                .or_insert_with(|| CacheEntry {
                    cache: Arc::new(PolicyCache::default()),
                    last_used: Instant::now(),
                });
            entry.last_used = Instant::now();
            Arc::clone(&entry.cache)
        };
        cache.get_or_load(loader).await
    }

    #[cfg(test)]
    pub(crate) fn with_policies(
        policies: impl IntoIterator<Item = (RepositoryFullName, RepositoryPolicy)>,
    ) -> Self {
        Self {
            entries: Mutex::new(
                policies
                    .into_iter()
                    .map(|(repository, policy)| {
                        (
                            repository.as_str().to_owned(),
                            CacheEntry {
                                cache: Arc::new(PolicyCache::with_policy(policy)),
                                last_used: Instant::now(),
                            },
                        )
                    })
                    .collect(),
            ),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_policy(policy: Policy) -> Self {
        // Existing authorization fixtures model repositories carrying identical
        // policy files. Ownership tests use with_policies explicitly instead.
        let mut repositories = BTreeMap::new();
        for rule in policy.rules() {
            for (repository, repository_id) in
                std::iter::once((rule.repository().clone(), rule.repository_id()))
                    .chain(rule.target_repositories())
            {
                let entry = repositories
                    .entry(repository.as_str().to_owned())
                    .or_insert((
                        repository,
                        RepositoryPolicy {
                            repository_id,
                            installation_id: 456,
                            policy: policy.clone(),
                        },
                    ));
                if let Some(installation_id) = rule.target_installation_id() {
                    entry.1.installation_id = installation_id;
                }
            }
        }
        Self::with_policies(repositories.into_values())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use serde_json::json;

    use super::*;

    fn policy(id: u64) -> RepositoryPolicy {
        RepositoryPolicy {
            repository_id: RepositoryId::new(id).unwrap(),
            installation_id: 456,
            policy: serde_json::from_value(json!({
                "expected_audience": "https://example.com",
                "rules": [{
                    "subject": "repo:octo/tools:environment:release",
                    "repository": "octo/tools",
                    "repository_id": 42,
                    "ref": "refs/heads/main",
                    "workflow_path": ".github/workflows/release.yml"
                }]
            }))
            .unwrap(),
        }
    }

    #[tokio::test]
    async fn caches_repository_identities_independently() {
        let store = PolicyStore::default();
        let loads = AtomicUsize::new(0);
        for _ in 0..2 {
            for (name, id) in [("octo/first", 42), ("octo/second", 43)] {
                let loaded = store
                    .get_or_load(&name.try_into().unwrap(), || async {
                        loads.fetch_add(1, Ordering::SeqCst);
                        Ok(policy(id))
                    })
                    .await
                    .unwrap();
                assert_eq!(*loaded.policy().repository_id, id);
            }
        }
        assert_eq!(loads.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn evicts_idle_entries_without_exceeding_the_bound() {
        let store = PolicyStore::default();
        for id in 1..=MAX_CACHED_REPOSITORIES + 1 {
            let name = format!("octo/repo-{id}").try_into().unwrap();
            store
                .get_or_load(&name, || async { Ok(policy(id as u64)) })
                .await
                .unwrap();
        }
        let entries = store.entries.lock().await;
        assert_eq!(entries.len(), MAX_CACHED_REPOSITORIES);
        assert!(!entries.contains_key("octo/repo-1"));
        assert!(entries.contains_key(&format!("octo/repo-{}", MAX_CACHED_REPOSITORIES + 1)));
    }

    #[tokio::test]
    async fn refuses_to_evict_active_caches() {
        let store = PolicyStore::default();
        let mut active = Vec::new();
        {
            let mut entries = store.entries.lock().await;
            for id in 1..=MAX_CACHED_REPOSITORIES {
                let cache = Arc::new(PolicyCache::with_policy(policy(id as u64)));
                active.push(Arc::clone(&cache));
                entries.insert(
                    format!("octo/repo-{id}"),
                    CacheEntry {
                        cache,
                        last_used: Instant::now(),
                    },
                );
            }
        }
        let extra = "octo/extra".try_into().unwrap();
        assert!(matches!(
            store
                .get_or_load(&extra, || async {
                    panic!("no refresh should start while all cache slots are active")
                })
                .await,
            Err(AppError::PolicyLookupFailed)
        ));
        assert_eq!(store.entries.lock().await.len(), MAX_CACHED_REPOSITORIES);
        drop(active);
        store
            .get_or_load(&extra, || async { Ok(policy(999)) })
            .await
            .unwrap();
    }
}
