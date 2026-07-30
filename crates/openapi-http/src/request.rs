use std::collections::HashMap;

use httparse::{Request, Status};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("incomplete request")]
    Incomplete,
    #[error("request body exceeds configured limit")]
    BodyTooLarge,
    #[error("invalid request: {0}")]
    Invalid(String),
}

pub struct ParsedRequest;

impl ParsedRequest {
    pub fn parse(buffer: &[u8], max_body_bytes: usize) -> Result<Option<HttpRequest>, ParseError> {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = Request::new(&mut headers);
        let status = req
            .parse(buffer)
            .map_err(|e| ParseError::Invalid(e.to_string()))?;

        let header_len = match status {
            Status::Complete(len) => len,
            Status::Partial => return Ok(None),
        };

        let method = req
            .method
            .ok_or_else(|| ParseError::Invalid("missing method".into()))?;
        let path = req
            .path
            .ok_or_else(|| ParseError::Invalid("missing path".into()))?;

        let mut header_map = HashMap::new();
        let mut content_length = None;
        for h in req.headers {
            let name = h.name.to_ascii_lowercase();
            let value = std::str::from_utf8(h.value)
                .map_err(|e| ParseError::Invalid(format!("header utf8: {e}")))?;

            if name == "transfer-encoding" {
                return Err(ParseError::Invalid(
                    "Transfer-Encoding is not supported".into(),
                ));
            }
            if name == "content-length" {
                if content_length.is_some() {
                    return Err(ParseError::Invalid("duplicate Content-Length".into()));
                }
                let value = value.trim();
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(ParseError::Invalid("invalid Content-Length".into()));
                }
                let parsed = value
                    .parse::<usize>()
                    .map_err(|_| ParseError::Invalid("invalid Content-Length".into()))?;
                if parsed > max_body_bytes {
                    return Err(ParseError::BodyTooLarge);
                }
                content_length = Some(parsed);
            }

            let value = value.to_string();
            header_map.insert(name, value);
        }

        let content_length = content_length.unwrap_or(0);

        let body_start = header_len;
        let needed = body_start
            .checked_add(content_length)
            .ok_or_else(|| ParseError::Invalid("request length overflow".into()))?;
        if buffer.len() < needed {
            return Ok(None);
        }

        let body = buffer
            .get(body_start..needed)
            .ok_or_else(|| ParseError::Invalid("invalid request body range".into()))?
            .to_vec();

        Ok(Some(HttpRequest {
            method: method.to_string(),
            path: path.to_string(),
            headers: header_map,
            body,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_get_without_body() {
        let raw = b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let req = ParsedRequest::parse(raw, 1024).unwrap().unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/healthz");
        assert!(req.body.is_empty());
    }

    #[test]
    fn parse_post_with_body() {
        let raw =
            b"POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}";
        let req = ParsedRequest::parse(raw, 1024).unwrap().unwrap();
        assert_eq!(req.body, b"{}");
    }

    #[test]
    fn parse_partial_waits_for_body() {
        let raw = b"POST /v1/chat/completions HTTP/1.1\r\nContent-Length: 10\r\n\r\n{}";
        assert!(ParsedRequest::parse(raw, 1024).unwrap().is_none());
    }

    #[test]
    fn rejects_malformed_content_length() {
        let raw = b"POST / HTTP/1.1\r\nContent-Length: abc\r\n\r\n";
        assert!(matches!(
            ParsedRequest::parse(raw, 1024),
            Err(ParseError::Invalid(_))
        ));
    }

    #[test]
    fn rejects_duplicate_content_length() {
        let raw = b"POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx";
        assert!(matches!(
            ParsedRequest::parse(raw, 1024),
            Err(ParseError::Invalid(_))
        ));
    }

    #[test]
    fn rejects_transfer_encoding() {
        let raw = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        assert!(matches!(
            ParsedRequest::parse(raw, 1024),
            Err(ParseError::Invalid(_))
        ));
    }

    #[test]
    fn rejects_declared_body_over_limit_before_buffering() {
        let raw = b"POST / HTTP/1.1\r\nContent-Length: 1025\r\n\r\n";
        assert!(matches!(
            ParsedRequest::parse(raw, 1024),
            Err(ParseError::BodyTooLarge)
        ));
    }

    #[test]
    fn rejects_content_length_overflow_without_panicking() {
        let raw = format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n", usize::MAX);
        assert!(matches!(
            ParsedRequest::parse(raw.as_bytes(), usize::MAX),
            Err(ParseError::Invalid(_))
        ));
    }
}
