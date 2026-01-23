use std::error::Error;
use thiserror::Error;
use wasmer::RuntimeError;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ChainError {
    #[error("data store disconnected")]
    InternalError(Option<String>),
    #[error("genesis error: {0}")]
    GenesisError(String),
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("authorization error: {0}")]
    AuthorizationError(String),
    #[error("permission not found: {0}@{1}")]
    PermissionNotFound(String, String),
    #[error("signature recover error: {0}")]
    SignatureRecoverError(String),
    #[error("transaction error: {0}")]
    TransactionError(String),
    #[error("network error: {0}")]
    NetworkError(String),
    #[error("wasm runtime error: {0}")]
    WasmRuntimeError(String),
    #[error("database error: {0}")]
    DatabaseError(String),
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("serialization error: {0}")]
    SerializationError(String),
    #[error("missing required authority: {0}")]
    MissingAuthError(String),
    #[error("action validation error: {0}")]
    ActionValidationError(String),
    #[error("irrelevant authorization exception: {0}")]
    IrrelevantAuth(String),
}

impl From<Box<dyn Error>> for ChainError {
    fn from(_: Box<dyn Error>) -> Self {
        ChainError::InternalError(None)
    }
}

impl<T> From<std::sync::PoisonError<T>> for ChainError {
    fn from(_: std::sync::PoisonError<T>) -> Self {
        ChainError::InternalError(Some("failed to acquire read/write lock".into()))
    }
}

impl From<RuntimeError> for ChainError {
    fn from(err: RuntimeError) -> Self {
        ChainError::WasmRuntimeError(err.to_string())
    }
}

impl From<ChainError> for RuntimeError {
    fn from(err: ChainError) -> Self {
        RuntimeError::new(err.to_string())
    }
}
