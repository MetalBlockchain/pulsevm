use chrono::{DateTime, Utc};
use core::str;
use pulsevm_serialization::Deserialize as PulseDeserialize;
use pulsevm_serialization::Serialize as PulseSerialize;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::{error::Error, fmt};

use crate::chain::error::ChainError;

use super::{PublicKey, block::BlockTimestamp};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct ChainConfig {
    pub max_inline_action_size: u32,
}

impl PulseSerialize for ChainConfig {
    fn serialize(&self, bytes: &mut Vec<u8>) {
        pulsevm_serialization::Serialize::serialize(&self.max_inline_action_size, bytes);
    }
}

impl PulseDeserialize for ChainConfig {
    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let max_inline_action_size = pulsevm_serialization::Deserialize::deserialize(data, pos)?;
        Ok(ChainConfig {
            max_inline_action_size,
        })
    }
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
