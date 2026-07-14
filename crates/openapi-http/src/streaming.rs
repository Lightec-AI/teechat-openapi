//! Chunked SSE response writer for incremental upstream passthrough.
//!
//! **UTF-8 / Unicode:** The edge forwards upstream bytes unchanged. HTTP chunked
//! framing may split UTF-8 code points across chunk boundaries; clients must
//! decode the reassembled byte stream (e.g. `TextDecoder` with `{ stream: true }`).
//! Do **not** slice decoded text at UTF-16 code units and re-encode — that was the
//! InferenceEngine `takeUtf16SafePrefix` class of bugs (permanent U+FFFD in history).
//!
//! **Gemma stop-on-repeat / penalties:** Client (`chat-stop-on-repeat.ts`) and
//! engine/vLLM (`frequency_penalty`, `presence_penalty` in JSON body) — openapi
//! only forwards the request body; it does not implement collapse detection.

use std::io::Write;

use openapi_core::usage::UsageReport;
use openapi_core::ApiError;

use crate::sse::usage_trailer_bytes;

/// Wraps a writer so each `write_all` becomes one HTTP/1.1 chunk.
pub struct ChunkedWriter<'a, W: Write + ?Sized> {
    pub inner: &'a mut W,
}

impl<'a, W: Write + ?Sized> ChunkedWriter<'a, W> {
    pub fn new(inner: &'a mut W) -> Self {
        Self { inner }
    }
}

impl<W: Write + ?Sized> Write for ChunkedWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.write_all(buf)?;
        Ok(buf.len())
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        write_chunk(self.inner, buf).map_err(std::io::Error::other)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Write HTTP/1.1 response headers for a chunked SSE stream.
///
/// Signed usage is **not** in response headers for streaming (METER-001): counts are
/// only known after upstream SSE completes. The final signed report is in the
/// `teechat_usage` trailer (and `X-TeeChat-Usage-Report` is omitted on the open).
pub fn write_sse_stream_headers<W: Write + ?Sized>(out: &mut W) -> Result<(), ApiError> {
    let headers = "HTTP/1.1 200 OK\r\n\
         Content-Type: text/event-stream\r\n\
         Cache-Control: no-cache, no-transform\r\n\
         X-Accel-Buffering: no\r\n\
         Transfer-Encoding: chunked\r\n\
         Connection: close\r\n\r\n";
    out.write_all(headers.as_bytes())
        .map_err(|e| ApiError::Internal(e.to_string()))
}

/// Write one HTTP/1.1 chunked body fragment.
pub fn write_chunk<W: Write + ?Sized>(out: &mut W, data: &[u8]) -> Result<(), ApiError> {
    if data.is_empty() {
        return Ok(());
    }
    let prefix = format!("{:x}\r\n", data.len());
    out.write_all(prefix.as_bytes())
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    out.write_all(data)
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    out.write_all(b"\r\n")
        .map_err(|e| ApiError::Internal(e.to_string()))
}

/// Append signed usage as a final SSE chunk, then terminate the chunked body.
pub fn write_sse_usage_trailer<W: Write + ?Sized>(out: &mut W, usage: &UsageReport) -> Result<(), ApiError> {
    write_chunk(out, &usage_trailer_bytes(usage))?;
    out.write_all(b"0\r\n\r\n")
        .map_err(|e| ApiError::Internal(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openapi_core::usage::UsageSigner;

    #[test]
    fn chunked_headers_and_trailer() {
        let signer = UsageSigner::from_seed([4u8; 32]);
        let usage = signer.sign_report("k", "m", 3, 5, 1).unwrap();
        let mut out = Vec::new();
        write_sse_stream_headers(&mut out).unwrap();
        write_chunk(&mut out, b"data: hi\n\n").unwrap();
        write_sse_usage_trailer(&mut out, &usage).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("Transfer-Encoding: chunked"));
        assert!(text.contains("no-transform"));
        assert!(text.contains("X-Accel-Buffering: no"));
        assert!(!text.contains("X-TeeChat-Usage-Report"));
        assert!(text.contains("data: hi"));
        assert!(text.contains("teechat_usage"));
        assert!(text.contains("\"prompt_tokens\":3"));
        assert!(text.ends_with("0\r\n\r\n"));
    }
}
