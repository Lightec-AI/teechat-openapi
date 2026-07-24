use openapi_core::usage::UsageReport;
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
    format!("HTTP/1.1 204 No Content\r\n{CHALLENGE_CORS}Content-Length: 0\r\nConnection: close\r\n\r\n")
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

pub fn build_json_response(status: u16, body: &[u8], usage: Option<&UsageReport>) -> Vec<u8> {
    let mut headers = format!(
        "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        body.len()
    );
    if let Some(report) = usage {
        headers.push_str(&format!(
            "X-TeeChat-Usage-Report: {}\r\n",
            serde_json::to_string(report).unwrap_or_default()
        ));
    }
    headers.push_str("Connection: close\r\n\r\n");
    let mut out = headers.into_bytes();
    out.extend_from_slice(body);
    out
}

pub fn build_sse_response(body: &[u8], usage: &UsageReport) -> Vec<u8> {
    let mut payload = body.to_vec();
    if !payload.ends_with(b"\n\n") {
        if payload.ends_with(b"\n") {
            payload.push(b'\n');
        } else {
            payload.extend_from_slice(b"\n\n");
        }
    }
    let trailer = format!("data: {}\n\n", serde_json::json!({"teechat_usage": usage}));
    payload.extend_from_slice(trailer.as_bytes());

    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    let mut out = headers.into_bytes();
    out.extend_from_slice(&payload);
    out
}

pub fn build_error_response(err: ApiError) -> Vec<u8> {
    let status = err.status_code();
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
        _ => "Internal Server Error",
    };
    let mut out = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        body.len()
    );
    if status == 429 {
        out.push_str("Retry-After: 1\r\n");
    }
    out.push_str("Connection: close\r\n\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(&body);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use openapi_core::usage::UsageSigner;

    #[test]
    fn error_response_has_json_body() {
        let bytes = build_error_response(ApiError::Unauthorized);
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("HTTP/1.1 401"));
        assert!(text.contains("invalid_api_key"));
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
    fn sse_response_appends_usage_trailer() {
        let signer = UsageSigner::from_seed([2u8; 32]);
        let usage = signer.sign_report("k", "m", 1, 2, 3).unwrap();
        let bytes = build_sse_response(b"data: {}\n\n", &usage);
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("text/event-stream"));
        assert!(text.contains("teechat_usage"));
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
        let raw = build_json_response(200, b"{}", None);
        let text = String::from_utf8(with_challenge_cors(raw)).unwrap();
        assert!(text.contains("Access-Control-Allow-Origin: *"));
        assert!(text.contains("\r\n\r\n{}"));
        // Must not glue last header onto Access-Control-
        assert!(text.contains("Connection: close\r\nAccess-Control-Allow-Origin"));
        assert!(!text.contains("closeAccess-Control"));
    }

    #[test]
    fn challenge_path_matcher() {
        assert!(is_attestation_challenge_path("/v1/attestation/challenge"));
        assert!(is_attestation_challenge_path("/v1/attestation/challenge?x=1"));
        assert!(!is_attestation_challenge_path("/v1/chat/completions"));
    }
}
