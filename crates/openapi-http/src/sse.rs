use openapi_core::usage::UsageReport;

/// Append a signed usage report as the final SSE event.
pub fn append_usage_trailer(mut stream: Vec<u8>, usage: &UsageReport) -> Vec<u8> {
    let trailer = format!(
        "data: {}\n\n",
        serde_json::json!({"teechat_usage": usage})
    );
    if !stream.ends_with(b"\n\n") {
        if stream.ends_with(b"\n") {
            stream.push(b'\n');
        } else {
            stream.extend_from_slice(b"\n\n");
        }
    }
    stream.extend_from_slice(trailer.as_bytes());
    stream
}

/// Split an SSE byte stream into discrete `data:` event payloads (without prefixes).
pub fn parse_sse_chunks(input: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(input);
    text.split("\n\n")
        .filter_map(|block| {
            let data_lines: Vec<&str> = block
                .lines()
                .filter(|l| l.starts_with("data:"))
                .map(|l| l.trim_start_matches("data:").trim())
                .collect();
            if data_lines.is_empty() {
                None
            } else {
                Some(data_lines.join("\n"))
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use openapi_core::usage::UsageSigner;

    #[test]
    fn parse_sse_chunks_basic() {
        let raw = b"data: {\"a\":1}\n\ndata: [DONE]\n\n";
        let chunks = parse_sse_chunks(raw);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0], "{\"a\":1}");
    }

    #[test]
    fn append_usage_trailer_adds_event() {
        let signer = UsageSigner::from_seed([3u8; 32]);
        let usage = signer.sign_report("k", "m", 0, 0, 1).unwrap();
        let out = append_usage_trailer(b"data: x\n\n".to_vec(), &usage);
        let chunks = parse_sse_chunks(&out);
        assert!(chunks.last().unwrap().contains("teechat_usage"));
    }
}
