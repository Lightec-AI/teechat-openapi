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

    #[test]
    fn parse_sse_chunks_basic() {
        let raw = b"data: {\"a\":1}\n\ndata: [DONE]\n\n";
        let chunks = parse_sse_chunks(raw);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0], "{\"a\":1}");
    }

    #[test]
    fn parse_sse_chunks_includes_all_data_events() {
        let raw = br#"data: {"choices":[{"delta":{"content":"hi"}}]}

data: {"teechat_usage":{"key_id":"k"}}

data: [DONE]

"#;
        let chunks = parse_sse_chunks(raw);
        assert_eq!(chunks.len(), 3);
        assert!(chunks[1].contains("teechat_usage"));
    }
}
