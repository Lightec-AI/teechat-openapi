use thiserror::Error;

#[derive(Debug, Error)]
pub enum AttestError {
    #[error("http: {0}")]
    Http(String),
    #[error("tls: {0}")]
    Tls(String),
    #[error("manifest: {0}")]
    Manifest(String),
    #[error("challenge: {0}")]
    Challenge(String),
    #[error("quote: {0}")]
    Quote(String),
    #[error("policy: {0}")]
    Policy(String),
    #[error("io: {0}")]
    Io(String),
}

pub type Result<T> = std::result::Result<T, AttestError>;
