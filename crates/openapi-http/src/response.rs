use openapi_core::usage::UsageReport;
use openapi_core::ApiError;

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
    let trailer = format!(
        "data: {}\n\n",
        serde_json::json!({"teechat_usage": usage})
    );
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
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(&body);
    out
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
    fn sse_response_appends_usage_trailer() {
        let signer = UsageSigner::from_seed([2u8; 32]);
        let usage = signer.sign_report("k", "m", 1, 2, 3).unwrap();
        let bytes = build_sse_response(b"data: {}\n\n", &usage);
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("text/event-stream"));
        assert!(text.contains("teechat_usage"));
    }
}
