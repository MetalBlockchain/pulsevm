use jsonrpsee::types::ErrorObjectOwned;
use std::error::Error;
use thiserror::Error;
use wasmer::RuntimeError;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ChainError {
    /// A fallible persistence operation crossed its publication boundary and
    /// could not restore the previously live state. Continuing to process
    /// consensus messages could build on a partially published view, so callers
    /// at the process boundary must fail-stop instead of returning to the engine.
    #[error("fatal consistency error: {0}")]
    FatalConsistency(String),
    #[error("internal error: {0:?}")]
    InternalError(String),
    #[error("block error: {0}")]
    BlockError(String),
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
    #[error("apply error: {0}")]
    ApplyError(String),
    #[error("database error: {0}")]
    DatabaseError(String),
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("serialization error: {0}")]
    SerializationError(String),
    #[error("{0}")]
    MissingAuthError(String),
    #[error("action validation error: {0}")]
    ActionValidationError(String),
    #[error("irrelevant authorization exception: {0}")]
    IrrelevantAuth(String),
    /// Wall-clock deadline exceeded during execution. This is a SUBJECTIVE failure
    /// — it depends on how fast this particular node is, not on the transaction's
    /// deterministic result — so it must be handled by dropping the transaction
    /// locally, never by rejecting a block another node produced. Distinct from the
    /// objective op-metering exhaustion (`ApplyError`/`TransactionError`), which is
    /// consensus.
    #[error("deadline exceeded: {0}")]
    DeadlineError(String),
    /// Cross-chain (Avalanche Interchain Messaging / warp) error: malformed
    /// message, failed signature verification, insufficient validator weight, or
    /// replay of an already-consumed message.
    #[error("warp messaging error: {0}")]
    WarpError(String),
}

impl ChainError {
    /// Construct an error that requires the VM process to fail-stop.
    pub fn fatal_consistency(message: impl Into<String>) -> Self {
        Self::FatalConsistency(message.into())
    }

    /// Whether continuing in this process could expose partially published
    /// consensus state.
    pub const fn is_fatal_consistency(&self) -> bool {
        matches!(self, Self::FatalConsistency(_))
    }
}

impl From<Box<dyn Error>> for ChainError {
    fn from(_: Box<dyn Error>) -> Self {
        ChainError::InternalError("internal error".into())
    }
}

impl<T> From<std::sync::PoisonError<T>> for ChainError {
    fn from(_: std::sync::PoisonError<T>) -> Self {
        ChainError::InternalError("failed to acquire read/write lock".into())
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

impl From<ChainError> for ErrorObjectOwned {
    fn from(err: ChainError) -> Self {
        ErrorObjectOwned::owned(-32000, err.to_string(), None::<()>)
    }
}

#[cfg(test)]
mod tests {
    use super::ChainError;

    #[test]
    fn fatal_consistency_is_explicitly_classified() {
        let fatal = ChainError::fatal_consistency("published only half the state");
        assert!(fatal.is_fatal_consistency());
        assert_eq!(
            fatal.to_string(),
            "fatal consistency error: published only half the state"
        );
        assert!(!ChainError::InternalError("retryable".into()).is_fatal_consistency());
    }
}
