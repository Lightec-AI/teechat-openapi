//! Bounded in-memory store for optional ephemeral OpenAI-compat IDs (batches, files, threads).
//!
//! Nothing is persisted to disk; entries expire after TTL and are lost on process restart.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct EphemeralStoreConfig {
    pub default_ttl: Duration,
    pub max_entries: usize,
    pub max_bytes_per_entry: usize,
}

impl Default for EphemeralStoreConfig {
    fn default() -> Self {
        Self {
            default_ttl: Duration::from_secs(3600),
            max_entries: 10_000,
            max_bytes_per_entry: 4 * 1024 * 1024,
        }
    }
}

#[derive(Debug)]
struct Entry {
    value: Vec<u8>,
    expires_at: Instant,
}

#[derive(Debug, Default)]
pub struct EphemeralStore {
    cfg: EphemeralStoreConfig,
    entries: Mutex<HashMap<String, Entry>>,
}

impl EphemeralStore {
    pub fn new(cfg: EphemeralStoreConfig) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            entries: Mutex::new(HashMap::new()),
        })
    }

    pub fn put(&self, key: impl Into<String>, value: Vec<u8>) -> Result<(), EphemeralError> {
        if value.len() > self.cfg.max_bytes_per_entry {
            return Err(EphemeralError::TooLarge);
        }
        let mut map = self.entries.lock().expect("ephemeral lock");
        Self::evict_expired(&mut map);
        let key = key.into();
        if map.len() >= self.cfg.max_entries && !map.contains_key(&key) {
            return Err(EphemeralError::Capacity);
        }
        map.insert(
            key,
            Entry {
                value,
                expires_at: Instant::now() + self.cfg.default_ttl,
            },
        );
        Ok(())
    }

    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        let mut map = self.entries.lock().expect("ephemeral lock");
        Self::evict_expired(&mut map);
        map.get(key).map(|e| e.value.clone())
    }

    pub fn remove(&self, key: &str) -> bool {
        let mut map = self.entries.lock().expect("ephemeral lock");
        map.remove(key).is_some()
    }

    fn evict_expired(map: &mut HashMap<String, Entry>) {
        let now = Instant::now();
        map.retain(|_, e| e.expires_at > now);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EphemeralError {
    TooLarge,
    Capacity,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_get_roundtrip() {
        let store = EphemeralStore::new(EphemeralStoreConfig {
            default_ttl: Duration::from_secs(60),
            ..Default::default()
        });
        store.put("batch_1", b"{}".to_vec()).unwrap();
        assert_eq!(store.get("batch_1"), Some(b"{}".to_vec()));
    }

    #[test]
    fn entry_expires() {
        let store = EphemeralStore::new(EphemeralStoreConfig {
            default_ttl: Duration::from_millis(1),
            ..Default::default()
        });
        store.put("k", b"x".to_vec()).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        assert!(store.get("k").is_none());
    }
}
