use cxx::UniquePtr;
use pulsevm_error::ChainError;

use crate::bridge::ffi::{
    CxxGenesisState, extract_chain_id_from_genesis_state, parse_genesis_state,
};

impl CxxGenesisState {
    pub fn new(json: &str) -> Result<UniquePtr<CxxGenesisState>, ChainError> {
        parse_genesis_state(json)
            .map_err(|e| ChainError::ParseError(format!("failed to parse genesis state: {}", e)))
    }

    pub fn compute_chain_id(&self) -> Vec<u8> {
        extract_chain_id_from_genesis_state(self)
    }
}
