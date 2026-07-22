use serde_json::Value;

use crate::error::ApiError;
use crate::handler::UpstreamResponse;

pub fn decode_upstream_response(
    status: u16,
    content_type: &str,
    bytes: Vec<u8>,
    wants_stream: bool,
) -> Result<UpstreamResponse, ApiError> {
    if !(200..300).contains(&status) {
        return Err(ApiError::Upstream(format!(
            "upstream status {status}: {}",
            String::from_utf8_lossy(&bytes)
        )));
    }
    if wants_stream || content_type.contains("text/event-stream") {
        return Ok(UpstreamResponse::Raw {
            bytes,
            content_type: content_type.to_string(),
        });
    }
    let json: Value = serde_json::from_slice(&bytes)
        .map_err(|e| ApiError::Upstream(format!("invalid upstream json: {e}")))?;
    Ok(UpstreamResponse::Json(json))
}

pub fn body_wants_stream(body: &[u8]) -> bool {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v.get("stream").and_then(|s| s.as_bool()))
        .unwrap_or(false)
}

pub fn model_from_body(body: &[u8]) -> String {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v.get("model").and_then(|m| m.as_str()).map(str::to_string))
        .unwrap_or_else(|| "unknown".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_json_ok() {
        let resp =
            decode_upstream_response(200, "application/json", br#"{"ok":true}"#.to_vec(), false)
                .unwrap();
        match resp {
            UpstreamResponse::Json(v) => assert_eq!(v["ok"], true),
            _ => panic!("expected json"),
        }
    }

    #[test]
    fn detects_stream_flag() {
        assert!(body_wants_stream(br#"{"stream":true}"#));
        assert!(!body_wants_stream(br#"{"stream":false}"#));
    }
}
