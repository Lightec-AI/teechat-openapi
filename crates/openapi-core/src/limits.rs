use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::error::ApiError;

#[derive(Debug, Clone)]
pub struct Limits {
    pub requests_per_minute: u32,
    pub max_body_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            requests_per_minute: 120,
            max_body_bytes: 4 * 1024 * 1024,
        }
    }
}

#[derive(Debug)]
struct Bucket {
    window_start: Instant,
    count: u32,
}

#[derive(Debug, Default)]
pub struct RateLimiter {
    rpm: u32,
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl RateLimiter {
    pub fn new(rpm: u32) -> Self {
        Self {
            rpm,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    pub fn check(&self, key_id: &str) -> Result<(), ApiError> {
        let mut buckets = self.buckets.lock().expect("rate limiter lock");
        let now = Instant::now();
        let bucket = buckets.entry(key_id.to_string()).or_insert(Bucket {
            window_start: now,
            count: 0,
        });

        if now.duration_since(bucket.window_start) >= Duration::from_secs(60) {
            bucket.window_start = now;
            bucket.count = 0;
        }

        if bucket.count >= self.rpm {
            return Err(ApiError::RateLimited);
        }

        bucket.count += 1;
        Ok(())
    }
}

impl Limits {
    pub fn rate_limiter(&self) -> Arc<RateLimiter> {
        Arc::new(RateLimiter::new(self.requests_per_minute))
    }

    pub fn validate_body_size(&self, len: usize) -> Result<(), ApiError> {
        if len > self.max_body_bytes {
            return Err(ApiError::PayloadTooLarge);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit_resets_after_window() {
        let limiter = RateLimiter::new(2);
        limiter.check("k1").unwrap();
        limiter.check("k1").unwrap();
        assert!(limiter.check("k1").is_err());

        {
            let mut buckets = limiter.buckets.lock().unwrap();
            if let Some(b) = buckets.get_mut("k1") {
                b.window_start = Instant::now() - Duration::from_secs(61);
            }
        }
        limiter.check("k1").unwrap();
    }

    #[test]
    fn body_size_limit() {
        let limits = Limits {
            max_body_bytes: 10,
            ..Default::default()
        };
        assert!(limits.validate_body_size(10).is_ok());
        assert!(limits.validate_body_size(11).is_err());
    }
}
