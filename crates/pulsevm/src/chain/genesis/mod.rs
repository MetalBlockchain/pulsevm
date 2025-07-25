use chrono::{DateTime, Utc};
use pulsevm_proc_macros::NumBytes;
use pulsevm_proc_macros::Read;
use pulsevm_proc_macros::Write;
use core::str;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::chain::error::ChainError;

use super::{PublicKey, block::BlockTimestamp};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash, Default, Read, Write, NumBytes)]
pub struct ChainConfig {
    pub max_inline_action_size: u32,
    pub max_action_return_value_size: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Genesis {
    initial_timestamp: String,
    initial_key: String,
    initial_configuration: ChainConfig,
}

impl Genesis {
    pub fn parse(bytes: &Vec<u8>) -> Result<Self, ChainError> {
        let genesis = str::from_utf8(bytes)
            .map_err(|_| ChainError::GenesisError("invalid UTF-8".to_string()))?;
        let genesis: Genesis = serde_json::from_str(genesis)
            .map_err(|e| ChainError::GenesisError(format!("{}", e)))?;
        Ok(genesis)
    }

    pub fn validate(&self) -> Result<Self, ChainError> {
        if self.initial_timestamp.is_empty() {
            return Err(ChainError::GenesisError(
                "missing field: initial_timestamp".to_string(),
            ));
        }
        if self.initial_key.is_empty() {
            return Err(ChainError::GenesisError(
                "missing field: initial_key".to_string(),
            ));
        }
        self.initial_key()?;
        Ok(self.clone())
    }

    pub fn initial_timestamp(&self) -> Result<BlockTimestamp, ChainError> {
        let timestamp = self
            .initial_timestamp
            .parse::<DateTime<Utc>>()
            .map_err(|_| ChainError::GenesisError("invalid timestamp format".to_string()))?;
        Ok(timestamp.into())
    }

    pub fn initial_key(&self) -> Result<PublicKey, ChainError> {
        PublicKey::from_str(&self.initial_key)
    }
}
