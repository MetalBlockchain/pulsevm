use chrono::{DateTime, Utc};
use core::str;
use pulsevm_serialization::Deserialize as PulseDeserialize;
use pulsevm_serialization::Serialize as PulseSerialize;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::{error::Error, fmt};

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

#[derive(Debug)]
pub enum GenesisError {
    InvalidFormat(String),
    MissingField(String),
}

impl Error for GenesisError {}
impl fmt::Display for GenesisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GenesisError::InvalidFormat(field) => write!(f, "Invalid format: {}", field),
            GenesisError::MissingField(field) => write!(f, "Missing field: {}", field),
        }
    }
}

impl Genesis {
    pub fn parse(bytes: &Vec<u8>) -> Result<Self, GenesisError> {
        let genesis = str::from_utf8(bytes)
            .map_err(|_| GenesisError::InvalidFormat("Invalid UTF-8".to_string()))?;
        let genesis: Genesis = serde_json::from_str(genesis)
            .map_err(|e| GenesisError::InvalidFormat(format!("{}", e)))?;
        Ok(genesis)
    }

    pub fn validate(&self) -> Result<Self, GenesisError> {
        if self.initial_timestamp.is_empty() {
            return Err(GenesisError::MissingField("initial_timestamp".to_string()));
        }
        if self.initial_key.is_empty() {
            return Err(GenesisError::MissingField("initial_key".to_string()));
        }
        self.initial_key()?;
        Ok(self.clone())
    }

    pub fn initial_timestamp(&self) -> Result<BlockTimestamp, GenesisError> {
        let timestamp = self
            .initial_timestamp
            .parse::<DateTime<Utc>>()
            .map_err(|_| GenesisError::InvalidFormat("Invalid timestamp format".to_string()))?;
        Ok(timestamp.into())
    }

    pub fn initial_key(&self) -> Result<PublicKey, GenesisError> {
        PublicKey::from_str(&self.initial_key)
            .map_err(|_| GenesisError::InvalidFormat("Invalid public key format".to_string()))
    }
}
