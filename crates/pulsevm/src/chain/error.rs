use std::{error::Error, fmt};

use super::Name;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    InternalError(Option<String>),
    GenesisError(String),
    ParseError(String),
    AuthorizationError(String),
    PermissionNotFound(Name, Name),
    SignatureRecoverError(String),
    TransactionError(String),
    NetworkError(String),
    WasmRuntimeError(String),
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainError::InternalError(msg) => {
                if let Some(m) = msg {
                    write!(f, "internal error: {}", m)
                } else {
                    write!(f, "internal error")
                }
            }
            ChainError::GenesisError(msg) => write!(f, "genesis error: {}", msg),
            ChainError::ParseError(msg) => write!(f, "parse error: {}", msg),
            ChainError::AuthorizationError(msg) => write!(f, "authorization error: {}", msg),
            ChainError::PermissionNotFound(actor, permission) => {
                write!(f, "permission not found: {}@{}", actor, permission)
            }
            ChainError::SignatureRecoverError(msg) => {
                write!(f, "signature recover error: {}", msg)
            }
            ChainError::TransactionError(msg) => write!(f, "transaction error: {}", msg),
            ChainError::NetworkError(msg) => write!(f, "network error: {}", msg),
            ChainError::WasmRuntimeError(msg) => write!(f, "wasm runtime error: {}", msg),
        }
    }
}

impl Error for ChainError {}

impl From<pulsevm_serialization::ReadError> for ChainError {
    fn from(_: pulsevm_serialization::ReadError) -> Self {
        ChainError::InternalError(None)
    }
}

impl From<Box<dyn Error>> for ChainError {
    fn from(_: Box<dyn Error>) -> Self {
        ChainError::InternalError(None)
    }
}
