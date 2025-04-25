use core::str;
use std::{error::Error, fmt};
use chrono::{DateTime, Utc};
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};

use super::block::BlockTimestamp;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Genesis {
    initial_timestamp: String,
    initial_key: String,
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
        let genesis = str::from_utf8(bytes).map_err(|_| GenesisError::InvalidFormat("Invalid UTF-8".to_string()))?;
        let genesis: Genesis = serde_json::from_str(genesis).map_err(|_| GenesisError::InvalidFormat("Failed to parse JSON".to_string()))?;
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
        let timestamp = self.initial_timestamp.parse::<DateTime<Utc>>()
            .map_err(|_| GenesisError::InvalidFormat("Invalid timestamp format".to_string()))?;
        Ok(timestamp.into())
    }

    pub fn initial_key(&self) -> Result<PublicKey, GenesisError> {
        let hex_key = hex::decode(&self.initial_key)
            .map_err(|_| GenesisError::InvalidFormat("Invalid hex key".to_string()))?;
        let public_key = PublicKey::from_slice(&hex_key)
            .map_err(|e| GenesisError::InvalidFormat(format!("invalid public key: {}", e)))?;
        Ok(public_key)
    }
}