use serde::{Deserialize, Serialize};

use crate::routes::ProxyMode;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub region: String,
    pub upstream_base_url: String,
    pub max_body_bytes: usize,
    /// PROXY-001: prod must stay [`ProxyMode::Allowlist`] (default).
    #[serde(default)]
    pub proxy_mode: ProxyMode,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            region: "global".to_string(),
            upstream_base_url: "http://127.0.0.1:8000".to_string(),
            max_body_bytes: 4 * 1024 * 1024,
            proxy_mode: ProxyMode::Allowlist,
        }
    }
}
