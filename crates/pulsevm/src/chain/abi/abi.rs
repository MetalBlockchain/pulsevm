use pulsevm_proc_macros::{NumBytes, Read, Write};
use serde::{Deserialize, Serialize};

use crate::chain::Name;

#[derive(Debug, Clone, Read, Write, NumBytes, Serialize, Deserialize)]
pub struct AbiTypeDefinition {
    pub new_type_name: String,
    pub type_name: String,
}

#[derive(Debug, Clone, Read, Write, NumBytes, Serialize, Deserialize)]
pub struct AbiFieldDefinition {
    pub name: String,
    pub type_name: String,
}

#[derive(Debug, Clone, Read, Write, NumBytes, Serialize, Deserialize)]
pub struct AbiStructDefinition {
    pub name: String,
    pub base: String,
    pub fields: Vec<AbiFieldDefinition>,
}

#[derive(Debug, Clone, Read, Write, NumBytes, Serialize, Deserialize)]
pub struct AbiActionDefinition {
    pub name: String,
    pub type_name: String,
    pub ricardian_contract: String,
}

#[derive(Debug, Clone, Read, Write, NumBytes, Serialize, Deserialize)]
pub struct AbiTableDefinition {
    pub name: Name,             // the name of the table
    pub index_type: String,     // the kind of index, i64, i128i128, etc
    pub key_names: Vec<String>, // names for the keys defined by key_types
    pub key_types: Vec<String>, // the type of key parameters
    pub type_name: String,      // type of binary data stored in this table
}

#[derive(Debug, Clone, Read, Write, NumBytes, Serialize, Deserialize)]
pub struct AbiClausePair {
    pub id: String,
    pub body: String,
}

#[derive(Debug, Clone, Read, Write, NumBytes, Serialize, Deserialize)]
pub struct AbiErrorMessage {
    pub error_code: u64,
    pub error_msg: String,
}

#[derive(Debug, Clone, Read, Write, NumBytes, Serialize, Deserialize)]
pub struct AbiVariantDefinition {
    pub name: String,
    pub types: Vec<String>,
}

#[derive(Debug, Clone, Read, Write, NumBytes, Serialize, Deserialize)]
pub struct AbiActionResultDefinition {
    pub name: Name,
    pub result_type: String,
}

#[derive(Debug, Clone, Read, Write, NumBytes, Serialize, Deserialize)]
pub struct AbiDefinition {
    pub version: String,
    pub types: Vec<AbiTypeDefinition>,
    pub structs: Vec<AbiStructDefinition>,
    pub actions: Vec<AbiActionDefinition>,
    pub tables: Vec<AbiTableDefinition>,
    pub ricardian_clauses: Vec<AbiClausePair>,
    pub error_messages: Vec<AbiErrorMessage>,
    pub variants: Vec<AbiVariantDefinition>,
    pub action_results: Vec<AbiActionResultDefinition>,
}
