use std::fmt;

use super::Name;

#[derive(Debug, Clone)]
pub enum ChainError {
    InternalError(),
    AuthorizationError(String),
    PermissionNotFound(Name, Name),
    SignatureRecoverError(String),
    TransactionError(String),
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
        }
    }
}
