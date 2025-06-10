use std::{error::Error, fmt};

use super::Name;

#[derive(Debug, Clone)]
pub enum ChainError {
    InternalError(),
    AuthorizationError(String),
    PermissionNotFound(Name, Name),
    SignatureRecoverError(String),
    TransactionError(String),
    NetworkError(String),
    WasmRuntimeError(String),
    LockError(String),
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainError::InternalError() => write!(f, "internal error"),
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
            ChainError::LockError(msg) => write!(f, "lock error: {}", msg),
        }
    }
}

impl Error for ChainError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ChainError::InternalError() => None,
            ChainError::AuthorizationError(_) => None,
            ChainError::PermissionNotFound(_, _) => None,
            ChainError::SignatureRecoverError(_) => None,
            ChainError::TransactionError(_) => None,
            ChainError::NetworkError(_) => None,
            ChainError::WasmRuntimeError(_) => None,
            ChainError::LockError(_) => None,
        }
    }
}
