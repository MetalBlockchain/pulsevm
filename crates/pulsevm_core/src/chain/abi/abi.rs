use pulsevm_error::ChainError;
use pulsevm_proc_macros::{NumBytes, Read, Write};
use serde::{Deserialize, Serialize};

use crate::chain::Name;

#[derive(Debug, Clone, Read, Write, NumBytes, Serialize, Deserialize, PartialEq, Eq)]
pub struct AbiTypeDefinition {
    pub new_type_name: String,
    #[serde(rename = "type")]
    pub type_name: String,
}

#[derive(Debug, Clone, Read, Write, NumBytes, Serialize, Deserialize, PartialEq, Eq)]
pub struct AbiFieldDefinition {
    pub name: String,
    #[serde(rename = "type")]
    pub type_name: String,
}

impl From<(String, String)> for AbiFieldDefinition {
    fn from(item: (String, String)) -> Self {
        AbiFieldDefinition {
            name: item.0,
            type_name: item.1,
        }
    }
}

#[derive(Debug, Clone, Read, Write, NumBytes, Serialize, Deserialize, PartialEq, Eq)]
pub struct AbiStructDefinition {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub base: String,
    #[serde(default)]
    pub fields: Vec<AbiFieldDefinition>,
}

#[derive(Debug, Clone, Read, Write, NumBytes, Serialize, Deserialize, PartialEq, Eq)]
pub struct AbiActionDefinition {
    #[serde(default)]
    pub name: Name,
    #[serde(rename = "type")]
    pub type_name: String,
    #[serde(default)]
    pub ricardian_contract: String,
}

#[derive(Debug, Clone, Read, Write, NumBytes, Serialize, Deserialize, PartialEq, Eq)]
pub struct AbiTableDefinition {
    pub name: Name, // the name of the table
    #[serde(default)]
    pub index_type: String, // the kind of index, i64, i128i128, etc
    #[serde(default)]
    pub key_names: Vec<String>, // names for the keys defined by key_types
    #[serde(default)]
    pub key_types: Vec<String>, // the type of key parameters
    #[serde(default)]
    #[serde(rename = "type")]
    pub type_name: String, // type of binary data stored in this table
}

#[derive(Debug, Clone, Read, Write, NumBytes, Serialize, Deserialize, PartialEq, Eq)]
pub struct AbiClausePair {
    pub id: String,
    pub body: String,
}

#[derive(Debug, Clone, Read, Write, NumBytes, Serialize, Deserialize, PartialEq, Eq)]
pub struct AbiErrorMessage {
    pub error_code: u64,
    pub error_msg: String,
}

#[derive(Debug, Clone, Read, Write, NumBytes, Serialize, Deserialize, PartialEq, Eq)]
pub struct AbiVariantDefinition {
    pub name: String,
    pub types: Vec<String>,
}

#[derive(Debug, Clone, Read, Write, NumBytes, Serialize, Deserialize, PartialEq, Eq)]
pub struct AbiActionResultDefinition {
    pub name: Name,
    pub result_type: String,
}

#[derive(Debug, Clone, Read, Write, NumBytes, Serialize, Deserialize, PartialEq, Eq)]
pub struct AbiDefinition {
    pub version: String,
    #[serde(default)]
    pub types: Vec<AbiTypeDefinition>,
    #[serde(default)]
    pub structs: Vec<AbiStructDefinition>,
    #[serde(default)]
    pub actions: Vec<AbiActionDefinition>,
    #[serde(default)]
    pub tables: Vec<AbiTableDefinition>,
    #[serde(default)]
    pub ricardian_clauses: Vec<AbiClausePair>,
    #[serde(default)]
    pub error_messages: Vec<AbiErrorMessage>,
    #[serde(default)]
    pub abi_extensions: Vec<(u16, Vec<u8>)>,
    #[serde(default)]
    pub variants: Vec<AbiVariantDefinition>,
    #[serde(default)]
    pub action_results: Vec<AbiActionResultDefinition>,
}

impl AbiDefinition {
    pub fn get_table_type(&self, table_name: &Name) -> Result<String, ChainError> {
        for table in &self.tables {
            if &table.name == table_name {
                return Ok(table.type_name.clone());
            }
        }

        Err(ChainError::InvalidArgument(format!("table '{}' not found in ABI", table_name)))
    }
}
