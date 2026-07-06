//! Incremental HTTP/1.1 response body reader (after headers consumed).

use std::io::{Read, Write};

use crate::error::ApiError;

/// How the upstream response body is framed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyFraming {
    ContentLength(usize),
    Chunked,
    UntilClose,
}

/// Copy an upstream body to `out` using the given framing.
pub fn copy_body<R: Read, W: Write + ?Sized>(
    reader: &mut R,
    framing: &BodyFraming,
    out: &mut W,
    buf: &mut [u8],
) -> Result<u64, ApiError> {
    match framing {
        BodyFraming::ContentLength(len) => copy_fixed(reader, *len, out, buf),
        BodyFraming::Chunked => copy_chunked(reader, out, buf),
        BodyFraming::UntilClose => copy_until_eof(reader, out, buf),
    }
}

fn copy_fixed<R: Read, W: Write + ?Sized>(
    reader: &mut R,
    mut remaining: usize,
    out: &mut W,
    buf: &mut [u8],
) -> Result<u64, ApiError> {
    let mut total = 0u64;
    while remaining > 0 {
        let cap = buf.len().min(remaining);
        let n = reader
            .read(&mut buf[..cap])
            .map_err(|e| ApiError::Upstream(e.to_string()))?;
        if n == 0 {
            return Err(ApiError::Upstream(format!(
                "upstream closed early ({remaining} bytes remaining)"
            )));
        }
        out.write_all(&buf[..n])
            .map_err(|e| ApiError::Upstream(e.to_string()))?;
        remaining -= n;
        total += n as u64;
    }
    Ok(total)
}

fn copy_until_eof<R: Read, W: Write + ?Sized>(
    reader: &mut R,
    out: &mut W,
    buf: &mut [u8],
) -> Result<u64, ApiError> {
    let mut total = 0u64;
    loop {
        let n = reader
            .read(buf)
            .map_err(|e| ApiError::Upstream(e.to_string()))?;
        if n == 0 {
            break;
        }
        out.write_all(&buf[..n])
            .map_err(|e| ApiError::Upstream(e.to_string()))?;
        total += n as u64;
    }
    Ok(total)
}

fn copy_chunked<R: Read, W: Write + ?Sized>(
    reader: &mut R,
    out: &mut W,
    buf: &mut [u8],
) -> Result<u64, ApiError> {
    let mut total = 0u64;
    loop {
        let size_line = read_line(reader)?;
        let size_line = size_line.trim();
        if size_line.is_empty() {
            continue;
        }
        let size = usize::from_str_radix(size_line.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|e| ApiError::Upstream(format!("invalid chunk size: {e}")))?;
        if size == 0 {
            let _ = read_line(reader)?;
            break;
        }
        let mut remaining = size;
        while remaining > 0 {
            let cap = buf.len().min(remaining);
            let n = reader
                .read(&mut buf[..cap])
                .map_err(|e| ApiError::Upstream(e.to_string()))?;
            if n == 0 {
                return Err(ApiError::Upstream("upstream closed mid-chunk".into()));
            }
            out.write_all(&buf[..n])
                .map_err(|e| ApiError::Upstream(e.to_string()))?;
            remaining -= n;
            total += n as u64;
        }
        let trailer = read_line(reader)?;
        if !trailer.is_empty() && trailer != "\r" {
            return Err(ApiError::Upstream("expected chunk CRLF".into()));
        }
    }
    Ok(total)
}

fn read_line<R: Read>(reader: &mut R) -> Result<String, ApiError> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = reader
            .read(&mut byte)
            .map_err(|e| ApiError::Upstream(e.to_string()))?;
        if n == 0 {
            if line.is_empty() {
                return Err(ApiError::Upstream("unexpected EOF reading header line".into()));
            }
            break;
        }
        line.push(byte[0]);
        if line.len() >= 2 && line[line.len() - 2..] == *b"\r\n" {
            line.truncate(line.len() - 2);
            break;
        }
        if line.len() > 8192 {
            return Err(ApiError::Upstream("header line too long".into()));
        }
    }
    String::from_utf8(line).map_err(|e| ApiError::Upstream(e.to_string()))
}

/// Read status line + headers; returns status, raw headers text, content-type, body framing.
pub fn read_response_headers<R: Read>(reader: &mut R) -> Result<(u16, String, BodyFraming), ApiError> {
    let mut raw = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = reader
            .read(&mut byte)
            .map_err(|e| ApiError::Upstream(e.to_string()))?;
        if n == 0 {
            return Err(ApiError::Upstream("EOF reading response headers".into()));
        }
        raw.push(byte[0]);
        if raw.len() >= 4 && raw[raw.len() - 4..] == *b"\r\n\r\n" {
            break;
        }
        if raw.len() > 64 * 1024 {
            return Err(ApiError::Upstream("response headers too large".into()));
        }
    }
    let headers_text = String::from_utf8_lossy(&raw).to_string();
    let status_line = headers_text.lines().next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(502);
    let framing = parse_body_framing(&headers_text);
    Ok((status, headers_text, framing))
}

/// Parse response headers (without status line requirements beyond status code).
pub fn parse_body_framing(headers: &str) -> BodyFraming {
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for line in headers.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
        {
            chunked = true;
        }
        if name.eq_ignore_ascii_case("content-length") {
            if let Ok(n) = value.trim().parse::<usize>() {
                content_length = Some(n);
            }
        }
    }
    if chunked {
        BodyFraming::Chunked
    } else if let Some(n) = content_length {
        BodyFraming::ContentLength(n)
    } else {
        BodyFraming::UntilClose
    }
}

/// Read a non-2xx upstream body into a string for error reporting.
pub fn read_error_body<R: Read>(
    reader: &mut R,
    framing: &BodyFraming,
    buf: &mut [u8],
) -> Result<String, ApiError> {
    let mut body = Vec::new();
    copy_body(reader, framing, &mut body, buf)?;
    Ok(String::from_utf8_lossy(&body).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn copy_fixed_body() {
        let mut reader = Cursor::new(b"hello");
        let mut out = Vec::new();
        let mut buf = [0u8; 8];
        let n = copy_fixed(
            &mut reader,
            5,
            &mut out,
            &mut buf,
        )
        .unwrap();
        assert_eq!(n, 5);
        assert_eq!(out, b"hello");
    }

    #[test]
    fn copy_chunked_body() {
        let raw = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let mut reader = Cursor::new(raw);
        let mut out = Vec::new();
        let mut buf = [0u8; 4];
        let n = copy_chunked(&mut reader, &mut out, &mut buf).unwrap();
        assert_eq!(n, 11);
        assert_eq!(out, b"hello world");
    }

    #[test]
    fn parse_framing_prefers_chunked() {
        let headers = "Transfer-Encoding: chunked\r\nContent-Length: 99\r\n";
        assert_eq!(parse_body_framing(headers), BodyFraming::Chunked);
    }

    #[test]
    fn parse_framing_content_length() {
        let headers = "Content-Length: 42\r\n";
        assert_eq!(
            parse_body_framing(headers),
            BodyFraming::ContentLength(42)
        );
    }
}
