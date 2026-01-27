use cxx::UniquePtr;
use pulsevm_error::ChainError;

use crate::bridge::ffi::{CxxGenesisState, parse_genesis_state};

impl CxxGenesisState {
    pub fn new(json: &str) -> Result<UniquePtr<CxxGenesisState>, ChainError> {
        parse_genesis_state(json).map_err(|e| ChainError::ParseError(format!("failed to parse genesis state: {}", e)))
    }
}