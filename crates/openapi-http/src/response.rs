use openapi_core::ApiError;

/// Public challenge is unauthenticated; allow browser SPA / researchers to POST from any origin.
const CHALLENGE_CORS: &str = concat!(
    "Access-Control-Allow-Origin: *\r\n",
    "Access-Control-Allow-Methods: POST, OPTIONS\r\n",
    "Access-Control-Allow-Headers: content-type\r\n",
    "Access-Control-Max-Age: 86400\r\n",
);

pub fn is_attestation_challenge_path(path: &str) -> bool {
    let path = path.split('?').next().unwrap_or(path);
    path == "/v1/attestation/challenge"
}

pub fn build_challenge_cors_preflight() -> Vec<u8> {
    format!(
        "HTTP/1.1 204 No Content\r\n{CHALLENGE_CORS}Content-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

/// Insert challenge CORS headers before the header/body separator.
///
/// Insert **after** the last header's trailing `\r\n` (at `i + 2` of `\r\n\r\n`).
/// Inserting at `i` would steal that CRLF and glue `Connection: close` onto
/// `Access-Control-…`, corrupting the response for HTTP clients.
pub fn with_challenge_cors(mut response: Vec<u8>) -> Vec<u8> {
    const SEP: &[u8] = b"\r\n\r\n";
    if let Some(i) = response.windows(SEP.len()).position(|w| w == SEP) {
        response.splice(i + 2..i + 2, CHALLENGE_CORS.as_bytes().iter().copied());
    }
    response
}

pub fn build_json_response(status: u16, body: &[u8]) -> Vec<u8> {
    let headers = format!(
        "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut out = headers.into_bytes();
    out.extend_from_slice(body);
    out
}

/// Buffered SSE body (non-chunked). No client-visible TeeChat metering (METER-002).
pub fn build_sse_buffered_response(body: &[u8]) -> Vec<u8> {
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut out = headers.into_bytes();
    out.extend_from_slice(body);
    out
}

pub fn build_error_response(err: ApiError) -> Vec<u8> {
    let status = err.status_code();
    let retry_after = err.retry_after_secs();
    let body = serde_json::to_vec(&err.into_body()).unwrap_or_default();
    let reason = match status {
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    };
    let mut out = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        body.len()
    );
    if let Some(secs) = retry_after {
        out.push_str(&format!("Retry-After: {secs}\r\n"));
    }
    out.push_str("Connection: close\r\n\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(&body);
    bytes
}

/// Regression guard: OpenAPI must not expose TeeChat billing artifacts to third-party clients.
pub fn response_bytes_lack_client_metering(text: &str) -> bool {
    !text.contains("teechat_usage") && !text.contains("X-TeeChat-Usage-Report:")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_response_has_json_body() {
        let bytes = build_error_response(ApiError::Unauthorized);
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("HTTP/1.1 401"));
        assert!(text.contains("invalid_api_key"));
        assert!(response_bytes_lack_client_metering(&text));
    }

    #[test]
    fn json_response_has_no_usage_header() {
        let bytes = build_json_response(200, br#"{"id":"x"}"#);
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("HTTP/1.1 200"));
        assert!(text.contains("application/json"));
        assert!(response_bytes_lack_client_metering(&text));
    }

    #[test]
    fn sse_buffered_response_has_no_teechat_metering() {
        let bytes = build_sse_buffered_response(b"data: {\"choices\":[]}\n\ndata: [DONE]\n\n");
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("text/event-stream"));
        assert!(text.contains("[DONE]"));
        assert!(response_bytes_lack_client_metering(&text));
    }

    #[test]
    fn forbidden_model_error_is_403_with_code() {
        let bytes = build_error_response(ApiError::Forbidden(
            "model `x` is not allowed for this API key".into(),
        ));
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("HTTP/1.1 403"));
        assert!(text.contains("model_not_allowed"));
        assert!(text.contains("not allowed"));
    }

    #[test]
    fn rate_limited_is_429_with_retry_after() {
        let bytes = build_error_response(ApiError::RateLimited);
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("HTTP/1.1 429"));
        assert!(text.contains("Retry-After: 1"));
        assert!(text.contains("rate_limit_exceeded"));
    }

    #[test]
    fn maintenance_is_503_with_retry_after() {
        let bytes = build_error_response(ApiError::ServiceUnavailable {
            message: "Planned maintenance".into(),
            code: "maintenance".into(),
            retry_after_secs: 900,
        });
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("HTTP/1.1 503"));
        assert!(text.contains("Retry-After: 900"));
        assert!(text.contains("maintenance"));
        assert!(text.contains("Planned maintenance"));
    }

    #[test]
    fn challenge_cors_preflight_is_204() {
        let text = String::from_utf8(build_challenge_cors_preflight()).unwrap();
        assert!(text.starts_with("HTTP/1.1 204"));
        assert!(text.contains("Access-Control-Allow-Origin: *"));
        assert!(text.contains("Access-Control-Allow-Methods: POST, OPTIONS"));
    }

    #[test]
    fn with_challenge_cors_injects_headers() {
        let raw = build_json_response(200, b"{}");
        let text = String::from_utf8(with_challenge_cors(raw)).unwrap();
        assert!(text.contains("Access-Control-Allow-Origin: *"));
        assert!(text.contains("\r\n\r\n{}"));
        // Must not glue last header onto Access-Control-
        assert!(text.contains("Connection: close\r\nAccess-Control-Allow-Origin"));
        assert!(!text.contains("closeAccess-Control"));
    }

    #[test]
    fn client_metering_guard_detects_teechat_artifacts() {
        let bad = "data: {\"teechat_usage\":{\"key_id\":\"k\"}}\n\n";
        assert!(!response_bytes_lack_client_metering(bad));
        let good = "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n";
        assert!(response_bytes_lack_client_metering(good));
    }

    #[test]
    fn challenge_path_matcher() {
        assert!(is_attestation_challenge_path("/v1/attestation/challenge"));
        assert!(is_attestation_challenge_path(
            "/v1/attestation/challenge?x=1"
        ));
        assert!(!is_attestation_challenge_path("/v1/chat/completions"));
    }
}
