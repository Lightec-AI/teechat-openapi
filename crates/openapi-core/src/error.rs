use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("not found")]
    NotFound,
    #[error("method not allowed")]
    MethodNotAllowed,
    #[error("payload too large")]
    PayloadTooLarge,
    #[error("rate limited")]
    RateLimited,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("upstream error: {0}")]
    Upstream(String),
    #[error("not implemented: {0}")]
    NotImplemented(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl ApiError {
    pub fn status_code(&self) -> u16 {
        match self {
            Self::Unauthorized => 401,
            Self::Forbidden(_) => 403,
            Self::NotFound => 404,
            Self::MethodNotAllowed => 405,
            Self::PayloadTooLarge => 413,
            Self::RateLimited => 429,
            Self::BadRequest(_) => 400,
            Self::NotImplemented(_) => 501,
            Self::Upstream(_) => 502,
            Self::Internal(_) => 500,
        }
    }

    pub fn openai_type(&self) -> &'static str {
        match self {
            Self::Unauthorized | Self::Forbidden(_) => "invalid_request_error",
            Self::NotFound => "invalid_request_error",
            Self::MethodNotAllowed => "invalid_request_error",
            Self::PayloadTooLarge => "invalid_request_error",
            Self::RateLimited => "rate_limit_exceeded",
            Self::BadRequest(_) => "invalid_request_error",
            Self::NotImplemented(_) => "invalid_request_error",
            Self::Upstream(_) => "server_error",
            Self::Internal(_) => "server_error",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ApiErrorBody {
    pub error: ApiErrorDetail,
}

#[derive(Debug, Serialize)]
pub struct ApiErrorDetail {
    pub message: String,
    #[serde(rename = "type")]
    pub error_type: String,
    pub code: Option<String>,
}

impl ApiError {
    pub fn into_body(self) -> ApiErrorBody {
        let code = match &self {
            Self::Unauthorized => Some("invalid_api_key".to_string()),
            Self::Forbidden(_) => Some("model_not_allowed".to_string()),
            Self::RateLimited => Some("rate_limit_exceeded".to_string()),
            Self::NotImplemented(_) => Some("not_supported".to_string()),
            _ => None,
        };
        ApiErrorBody {
            error: ApiErrorDetail {
                message: self.to_string(),
                error_type: self.openai_type().to_string(),
                code,
            },
        }
    }
}
