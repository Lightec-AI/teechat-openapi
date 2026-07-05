use openapi_core::error::ApiError;
use openapi_core::handler::{UpstreamForwarder, UpstreamResponse};
use openapi_core::models::{default_models, ModelsListResponse};
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct UreqUpstream {
    base_url: String,
    agent: ureq::Agent,
}

impl UreqUpstream {
    pub fn new(base_url: impl Into<String>) -> Self {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        Self {
            base_url,
            agent: ureq::Agent::new(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

impl UpstreamForwarder for UreqUpstream {
    fn forward_chat(
        &self,
        request_json: &Value,
        stream: bool,
    ) -> Result<UpstreamResponse, ApiError> {
        let url = self.url("/v1/chat/completions");
        let body = serde_json::to_vec(request_json)
            .map_err(|e| ApiError::Internal(e.to_string()))?;

        let response = self
            .agent
            .post(&url)
            .set("Content-Type", "application/json")
            .send_bytes(&body)
            .map_err(|e| ApiError::Upstream(e.to_string()))?;

        let status = response.status();
        let content_type = response
            .header("Content-Type")
            .unwrap_or("")
            .to_string();

        let bytes = response
            .into_string()
            .map_err(|e| ApiError::Upstream(e.to_string()))?
            .into_bytes();

        if !(200..300).contains(&status) {
            return Err(ApiError::Upstream(format!(
                "upstream status {status}: {}",
                String::from_utf8_lossy(&bytes)
            )));
        }

        if stream || content_type.contains("text/event-stream") {
            return Ok(UpstreamResponse::Raw {
                bytes,
                content_type,
            });
        }

        let json: Value = serde_json::from_slice(&bytes)
            .map_err(|e| ApiError::Upstream(format!("invalid upstream json: {e}")))?;
        Ok(UpstreamResponse::Json(json))
    }

    fn list_models(&self) -> Result<ModelsListResponse, ApiError> {
        let url = self.url("/v1/models");
        match self.agent.get(&url).call() {
            Ok(resp) if (200..300).contains(&resp.status()) => {
                let body = resp.into_string().map_err(|e| ApiError::Upstream(e.to_string()))?;
                serde_json::from_str(&body).map_err(|e| ApiError::Upstream(e.to_string()))
            }
            Ok(resp) => {
                let status = resp.status();
                Err(ApiError::Upstream(format!("models status {status}")))
            }
            Err(_) => Ok(default_models()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_joins_paths() {
        let u = UreqUpstream::new("http://engine:8000/");
        assert_eq!(u.url("/v1/models"), "http://engine:8000/v1/models");
    }
}
