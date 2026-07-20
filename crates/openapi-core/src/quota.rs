//! Near-exhaust admission gate (QUOTA-001).
//!
//! When L0 includes `policy.remaining_tokens`, the edge rejects:
//! - remaining == 0 (hard stop)
//! - estimated prompt tokens already exceeding remaining
//! - remaining "tight" **and** estimated prompt "large"
//!
//! Small prompts may still run when tight (soft overshoot of purchase is OK).

use serde_json::Value;

use crate::authz::OpenApiKeyPolicy;
use crate::error::ApiError;

/// Remaining budget below this is treated as "tight" (near exhaust).
pub const TIGHT_REMAINING_TOKENS: u64 = 32_000;
/// Estimated prompt above this is "large" when budget is tight.
pub const LARGE_PROMPT_TOKENS: u64 = 8_000;

/// Coarse prompt-token estimate for admission only — not billing.
/// Billing remains engine-signed ([METER-002]).
pub fn estimate_prompt_tokens(body: &[u8]) -> u64 {
    let Ok(v) = serde_json::from_slice::<Value>(body) else {
        // Unparseable bodies still hit body-size / JSON validate later; treat as large-ish.
        return ((body.len() as u64) / 4).max(1);
    };
    let mut chars: u64 = 0;
    if let Some(msgs) = v.get("messages").and_then(|m| m.as_array()) {
        for m in msgs {
            chars += content_chars(m.get("content"));
        }
    } else if let Some(input) = v.get("input") {
        chars += content_chars(Some(input));
    } else if let Some(prompt) = v.get("prompt") {
        chars += content_chars(Some(prompt));
    } else {
        chars = body.len() as u64;
    }
    (chars / 4).max(1)
}

fn content_chars(content: Option<&Value>) -> u64 {
    match content {
        None => 0,
        Some(Value::String(s)) => s.len() as u64,
        Some(Value::Array(parts)) => parts
            .iter()
            .map(|p| match p {
                Value::String(s) => s.len() as u64,
                Value::Object(o) => o
                    .get("text")
                    .and_then(|t| t.as_str())
                    .map(|s| s.len() as u64)
                    .unwrap_or(0),
                _ => 0,
            })
            .sum(),
        Some(other) => other.to_string().len() as u64,
    }
}

/// Enforce near-exhaust gate. No-op when `remaining_tokens` is unset (legacy catalog keys).
pub fn enforce_token_quota(policy: &OpenApiKeyPolicy, body: &[u8]) -> Result<(), ApiError> {
    let Some(remaining) = policy.remaining_tokens else {
        return Ok(());
    };
    if remaining == 0 {
        return Err(ApiError::InsufficientQuota(
            "token quota exhausted".into(),
        ));
    }
    let est = estimate_prompt_tokens(body);
    if est > remaining {
        return Err(ApiError::InsufficientQuota(format!(
            "estimated prompt tokens ({est}) exceed remaining quota ({remaining})"
        )));
    }
    let tight = remaining < TIGHT_REMAINING_TOKENS;
    let large = est >= LARGE_PROMPT_TOKENS;
    if tight && large {
        return Err(ApiError::InsufficientQuota(format!(
            "remaining quota ({remaining}) is near exhaust; refuse large prompt (~{est} tokens)"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(remaining: Option<u64>) -> OpenApiKeyPolicy {
        OpenApiKeyPolicy {
            models: vec!["*".into()],
            rpm: 30,
            key_set: "api".into(),
            remaining_tokens: remaining,
        }
    }

    #[test]
    fn unset_remaining_skips_gate() {
        let body = br#"{"messages":[{"role":"user","content":"hi"}]}"#;
        assert!(enforce_token_quota(&policy(None), body).is_ok());
    }

    #[test]
    fn zero_remaining_hard_stop() {
        let body = br#"{"messages":[{"role":"user","content":"hi"}]}"#;
        assert!(matches!(
            enforce_token_quota(&policy(Some(0)), body),
            Err(ApiError::InsufficientQuota(_))
        ));
    }

    #[test]
    fn small_prompt_ok_when_tight() {
        let body = br#"{"messages":[{"role":"user","content":"hi"}]}"#;
        assert!(enforce_token_quota(&policy(Some(1_000)), body).is_ok());
    }

    #[test]
    fn large_prompt_rejected_when_tight() {
        let big = "x".repeat(40_000); // ~10k tokens estimate
        let body = format!(r#"{{"messages":[{{"role":"user","content":"{big}"}}]}}"#);
        assert!(matches!(
            enforce_token_quota(&policy(Some(10_000)), body.as_bytes()),
            Err(ApiError::InsufficientQuota(_))
        ));
    }

    #[test]
    fn large_prompt_ok_when_healthy_budget() {
        let big = "x".repeat(40_000);
        let body = format!(r#"{{"messages":[{{"role":"user","content":"{big}"}}]}}"#);
        assert!(enforce_token_quota(&policy(Some(500_000)), body.as_bytes()).is_ok());
    }
}
