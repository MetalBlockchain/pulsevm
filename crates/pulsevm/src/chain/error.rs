use std::{error::Error, fmt};

use jsonrpsee::types::ErrorObjectOwned;
use pulsevm_chainbase::ChainbaseError;

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
    DatabaseError(String),
    InvalidArgument(String),
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
            ChainError::DatabaseError(msg) => write!(f, "database error: {}", msg),
            ChainError::InvalidArgument(msg) => write!(f, "invalid argument: {}", msg),
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

impl From<ChainbaseError> for ChainError {
    fn from(e: ChainbaseError) -> Self {
        match e {
            ChainbaseError::NotFound => ChainError::DatabaseError("item not found".to_string()),
            ChainbaseError::AlreadyExists => {
                ChainError::DatabaseError("item already exists".to_string())
            }
            ChainbaseError::InvalidData => {
                ChainError::DatabaseError("invalid data provided".to_string())
            }
            ChainbaseError::ReadError => {
                ChainError::DatabaseError("error reading data".to_string())
            }
            ChainbaseError::InternalError(msg) => ChainError::DatabaseError(msg),
        }
    }
}
