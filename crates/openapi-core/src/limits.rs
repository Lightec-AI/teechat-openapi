use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::error::ApiError;

#[derive(Debug, Clone)]
pub struct Limits {
    pub requests_per_minute: u32,
    pub max_body_bytes: usize,
    /// Public `POST /v1/attestation/challenge` per client IP (or shared `unknown`).
    pub challenge_requests_per_minute: u32,
    /// Max concurrent challenge handlers (SNP/DCAP quotes are expensive).
    pub challenge_max_inflight: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            requests_per_minute: 120,
            max_body_bytes: 4 * 1024 * 1024,
            // Hybrid verifiers challenge rarely; monitors need a few probes/min.
            challenge_requests_per_minute: 10,
            challenge_max_inflight: 4,
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
        if self.rpm == 0 {
            return Err(ApiError::RateLimited);
        }
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

/// Bounded concurrency for expensive attestation quotes.
#[derive(Debug)]
pub struct InflightGate {
    max: u32,
    current: Mutex<u32>,
}

pub struct InflightPermit<'a> {
    gate: &'a InflightGate,
}

impl InflightGate {
    pub fn new(max: u32) -> Self {
        Self {
            max: max.max(1),
            current: Mutex::new(0),
        }
    }

    pub fn try_acquire(&self) -> Result<InflightPermit<'_>, ApiError> {
        let mut cur = self.current.lock().expect("inflight lock");
        if *cur >= self.max {
            return Err(ApiError::RateLimited);
        }
        *cur += 1;
        Ok(InflightPermit { gate: self })
    }
}

impl Drop for InflightPermit<'_> {
    fn drop(&mut self) {
        if let Ok(mut cur) = self.gate.current.lock() {
            *cur = cur.saturating_sub(1);
        }
    }
}

impl Limits {
    pub fn rate_limiter(&self) -> Arc<RateLimiter> {
        Arc::new(RateLimiter::new(self.requests_per_minute))
    }

    pub fn challenge_rate_limiter(&self) -> Arc<RateLimiter> {
        Arc::new(RateLimiter::new(self.challenge_requests_per_minute))
    }

    pub fn challenge_inflight_gate(&self) -> Arc<InflightGate> {
        Arc::new(InflightGate::new(self.challenge_max_inflight))
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

    #[test]
    fn inflight_gate_caps_concurrency() {
        let gate = InflightGate::new(1);
        let a = gate.try_acquire().unwrap();
        assert!(gate.try_acquire().is_err());
        drop(a);
        assert!(gate.try_acquire().is_ok());
    }
}
