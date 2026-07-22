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
    #[error("invalid request: {0}")]
    Invalid(String),
}

pub struct ParsedRequest;

impl ParsedRequest {
    pub fn parse(buffer: &[u8]) -> Result<Option<HttpRequest>, ParseError> {
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
        for h in req.headers {
            let name = h.name.to_ascii_lowercase();
            let value = std::str::from_utf8(h.value)
                .map_err(|e| ParseError::Invalid(format!("header utf8: {e}")))?
                .to_string();
            header_map.insert(name, value);
        }

        let content_length = header_map
            .get("content-length")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);

        let body_start = header_len;
        let needed = body_start + content_length;
        if buffer.len() < needed {
            return Ok(None);
        }

        let body = buffer[body_start..needed].to_vec();

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
        let req = ParsedRequest::parse(raw).unwrap().unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/healthz");
        assert!(req.body.is_empty());
    }

    #[test]
    fn parse_post_with_body() {
        let raw =
            b"POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}";
        let req = ParsedRequest::parse(raw).unwrap().unwrap();
        assert_eq!(req.body, b"{}");
    }

    #[test]
    fn parse_partial_waits_for_body() {
        let raw = b"POST /v1/chat/completions HTTP/1.1\r\nContent-Length: 10\r\n\r\n{}";
        assert!(ParsedRequest::parse(raw).unwrap().is_none());
    }
}
