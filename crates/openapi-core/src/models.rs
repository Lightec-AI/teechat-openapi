use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModelsListResponse {
    pub object: String,
    pub data: Vec<ModelObject>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModelObject {
    pub id: String,
    pub object: String,
    pub created: u64,
    pub owned_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChatCompletionRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    #[serde(default)]
    pub stream: bool,
    #[serde(flatten)]
    pub extra: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChatMessage {
    pub role: String,
    /// OpenAI allows omitting `content` on assistant turns that only carry
    /// `tool_calls` (and some clients send `content: null`). Default to null
    /// so edge validation does not 400; original body is still forwarded.
    #[serde(default)]
    pub content: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttestationChallengeRequest {
    pub nonce_b64: String,
}

pub fn default_models() -> ModelsListResponse {
    ModelsListResponse {
        object: "list".into(),
        data: vec![ModelObject {
            id: "teechat-default".into(),
            object: "model".into(),
            created: 1_700_000_000,
            owned_by: "teechat".into(),
        }],
    }
}

/// Parse `GET /v1/models` JSON from upstream.
pub fn parse_models_json(
    value: serde_json::Value,
) -> Result<ModelsListResponse, crate::error::ApiError> {
    serde_json::from_value(value)
        .map_err(|e| crate::error::ApiError::Upstream(format!("invalid models list: {e}")))
}

pub fn parse_models_bytes(bytes: &[u8]) -> Result<ModelsListResponse, crate::error::ApiError> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| crate::error::ApiError::Upstream(format!("invalid models json: {e}")))?;
    parse_models_json(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_request_parses_stream_default_false() {
        let raw = r#"{"model":"m","messages":[{"role":"user","content":"hi"}]}"#;
        let req: ChatCompletionRequest = serde_json::from_str(raw).unwrap();
        assert!(!req.stream);
        assert_eq!(req.model, "m");
    }

    #[test]
    fn chat_request_parses_stream_true() {
        let raw = r#"{"model":"m","messages":[],"stream":true}"#;
        let req: ChatCompletionRequest = serde_json::from_str(raw).unwrap();
        assert!(req.stream);
    }

    #[test]
    fn chat_request_allows_missing_content_on_tool_call_turn() {
        // WorkBuddy / OpenAI clients often omit `content` when only tool_calls.
        let raw = r#"{"model":"m","messages":[
            {"role":"user","content":"hi"},
            {"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"t","arguments":"{}"}}]},
            {"role":"tool","tool_call_id":"c1","content":"ok"}
        ]}"#;
        let req: ChatCompletionRequest = serde_json::from_str(raw).unwrap();
        assert_eq!(req.messages.len(), 3);
        assert!(req.messages[1].content.is_null());
        assert_eq!(req.messages[2].content, Value::String("ok".into()));
    }

    #[test]
    fn chat_request_allows_null_content() {
        let raw = r#"{"model":"m","messages":[{"role":"assistant","content":null}]}"#;
        let req: ChatCompletionRequest = serde_json::from_str(raw).unwrap();
        assert!(req.messages[0].content.is_null());
    }
}
