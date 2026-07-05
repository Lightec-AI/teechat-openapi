use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub region: String,
    pub upstream_base_url: String,
    pub max_body_bytes: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            region: "global".to_string(),
            upstream_base_url: "http://127.0.0.1:8000".to_string(),
            max_body_bytes: 4 * 1024 * 1024,
        }
    }
}
