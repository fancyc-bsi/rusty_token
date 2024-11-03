use thiserror::Error;

#[derive(Error, Debug)]
pub enum JWTAnalyzerError {
    #[error("Invalid JWT format")]
    InvalidFormat,
    #[error("Signature verification failed")]
    SignatureVerification,
    #[error("Header manipulation failed: {0}")]
    HeaderManipulation(String),
    #[error("Payload manipulation failed: {0}")]
    PayloadManipulation(String),
    #[error("Algorithm mismatch: {0}")]
    AlgorithmMismatch(String),
    #[error("Key format error: {0}")]
    KeyFormat(String),
    #[error("Timeout error")]
    Timeout,
    #[error("Async task failed: {0}")]
    AsyncTaskError(#[from] tokio::task::JoinError),
}