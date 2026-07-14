//! Accumulate OpenAI-compatible SSE `usage` fields while streaming (METER-001).

use serde_json::Value;

/// Byte-forwarding writer that tracks the latest `usage` object seen in SSE `data:` events.
pub struct SseUsageAccumulator<W: std::io::Write> {
    inner: W,
    buf: Vec<u8>,
    prompt_tokens: u64,
    completion_tokens: u64,
    saw_usage: bool,
}

impl<W: std::io::Write> SseUsageAccumulator<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            buf: Vec::new(),
            prompt_tokens: 0,
            completion_tokens: 0,
            saw_usage: false,
        }
    }

    pub fn token_counts(&self) -> (u64, u64) {
        (self.prompt_tokens, self.completion_tokens)
    }

    pub fn saw_usage(&self) -> bool {
        self.saw_usage
    }

    pub fn into_inner(self) -> W {
        self.inner
    }

    fn absorb(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
        while let Some(end) = find_event_end(&self.buf) {
            let event = self.buf[..end].to_vec();
            let rest = self.buf[end..].to_vec();
            self.buf = rest;
            if let Some((p, c)) = usage_from_sse_event(&event) {
                self.prompt_tokens = p;
                self.completion_tokens = c;
                self.saw_usage = true;
            }
        }
    }
}

impl<W: std::io::Write> std::io::Write for SseUsageAccumulator<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf).map(|n| {
            if n > 0 {
                self.absorb(&buf[..n]);
            }
            n
        })
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.inner.write_all(buf)?;
        self.absorb(buf);
        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn find_event_end(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\n\n").map(|i| i + 2)
}

fn usage_from_sse_event(event: &[u8]) -> Option<(u64, u64)> {
    let text = std::str::from_utf8(event).ok()?;
    let mut data_lines = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("data:") {
            let payload = rest.trim();
            if payload == "[DONE]" {
                return None;
            }
            data_lines.push(payload);
        }
    }
    if data_lines.is_empty() {
        return None;
    }
    let joined = data_lines.join("\n");
    let v: Value = serde_json::from_str(&joined).ok()?;
    usage_from_value(&v)
}

/// Extract prompt/completion tokens from a chat completion JSON object (final or delta).
pub fn usage_from_value(v: &Value) -> Option<(u64, u64)> {
    let usage = v.get("usage")?;
    let prompt = usage
        .get("prompt_tokens")
        .or_else(|| usage.get("input_tokens"))
        .and_then(|t| t.as_u64())
        .unwrap_or(0);
    let completion = usage
        .get("completion_tokens")
        .or_else(|| usage.get("output_tokens"))
        .and_then(|t| t.as_u64())
        .unwrap_or(0);
    Some((prompt, completion))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn accumulates_usage_across_chunk_boundary() {
        let mut sink = Vec::new();
        let mut acc = SseUsageAccumulator::new(&mut sink);
        let part1 = b"data: {\"id\":\"1\",\"choices\":[]}\n\ndata: {\"usage\":{\"prompt_tok";
        let part2 = b"ens\":11,\"completion_tokens\":22}}\n\ndata: [DONE]\n\n";
        acc.write_all(part1).unwrap();
        acc.write_all(part2).unwrap();
        assert_eq!(acc.token_counts(), (11, 22));
        assert!(acc.saw_usage());
        assert!(String::from_utf8_lossy(&sink).contains("[DONE]"));
    }

    #[test]
    fn takes_latest_usage_event() {
        let mut sink = Vec::new();
        let mut acc = SseUsageAccumulator::new(&mut sink);
        acc.write_all(
            br#"data: {"usage":{"prompt_tokens":1,"completion_tokens":1}}

data: {"usage":{"prompt_tokens":9,"completion_tokens":8}}

data: [DONE]

"#,
        )
        .unwrap();
        assert_eq!(acc.token_counts(), (9, 8));
    }
}
