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
    pub content: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttestationChallengeRequest {
    pub nonce_b64: String,
}

pub fn default_models() -> ModelsListResponse {
    ModelsListResponse {
        object: "list".into(),
        data: vec![
            ModelObject {
                id: "teechat-default".into(),
                object: "model".into(),
                created: 1_700_000_000,
                owned_by: "teechat".into(),
            },
        ],
    }
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
}
