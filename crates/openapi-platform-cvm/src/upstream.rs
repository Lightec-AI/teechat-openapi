use openapi_core::error::ApiError;
use openapi_core::handler::{HttpMethod, UpstreamForwarder, UpstreamResponse};
use openapi_core::models::{default_models, ModelsListResponse};
use openapi_core::upstream::decode_upstream_response;

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
    fn forward_v1(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<UpstreamResponse, ApiError> {
        let wants_stream = body.map(body_wants_stream).unwrap_or(false);
        let url = self.url(path);

        match method {
            HttpMethod::Get => {
                let response = self
                    .agent
                    .get(&url)
                    .call()
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
                decode_upstream_response(status, &content_type, bytes, false)
            }
            HttpMethod::Post => {
                let body = body.unwrap_or(&[]);
                let response = self
                    .agent
                    .post(&url)
                    .set("Content-Type", "application/json")
                    .send_bytes(body)
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
                decode_upstream_response(status, &content_type, bytes, wants_stream)
            }
            HttpMethod::Other => Err(ApiError::MethodNotAllowed),
        }
    }

    fn list_models(&self) -> Result<ModelsListResponse, ApiError> {
        match self.forward_v1(HttpMethod::Get, "/v1/models", None) {
            Ok(UpstreamResponse::Json(v)) => {
                serde_json::from_value(v).map_err(|e| ApiError::Upstream(e.to_string()))
            }
            Ok(_) => Err(ApiError::Upstream("unexpected models response".into())),
            Err(_) => Ok(default_models()),
        }
    }
}

fn body_wants_stream(body: &[u8]) -> bool {
    openapi_core::upstream::body_wants_stream(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_joins_paths() {
        let u = UreqUpstream::new("http://engine:8000");
        assert_eq!(u.url("/v1/models"), "http://engine:8000/v1/models");
    }
}
