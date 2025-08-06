use anyhow::Chain;
use pulsevm_proc_macros::{NumBytes, Read, Write};
use pulsevm_serialization::Read;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::chain::{Asset, ExtendedAsset, Name, Symbol, SymbolCode, error::ChainError};

#[derive(Debug, Clone, Read, Write, NumBytes, Serialize, Deserialize, PartialEq, Eq)]
pub struct AbiTypeDefinition {
    pub new_type_name: String,
    pub type_name: String,
}

#[derive(Debug, Clone, Read, Write, NumBytes, Serialize, Deserialize, PartialEq, Eq)]
pub struct AbiFieldDefinition {
    pub name: String,
    #[serde(rename = "type")]
    pub type_name: String,
}

#[derive(Debug, Clone, Read, Write, NumBytes, Serialize, Deserialize, PartialEq, Eq)]
pub struct AbiStructDefinition {
    pub name: String,
    pub base: String,
    pub fields: Vec<AbiFieldDefinition>,
}

#[derive(Debug, Clone, Read, Write, NumBytes, Serialize, Deserialize, PartialEq, Eq)]
pub struct AbiActionDefinition {
    pub name: String,
    #[serde(rename = "type")]
    pub type_name: String,
    pub ricardian_contract: String,
}

#[derive(Debug, Clone, Read, Write, NumBytes, Serialize, Deserialize, PartialEq, Eq)]
pub struct AbiTableDefinition {
    pub name: Name,             // the name of the table
    pub index_type: String,     // the kind of index, i64, i128i128, etc
    pub key_names: Vec<String>, // names for the keys defined by key_types
    pub key_types: Vec<String>, // the type of key parameters
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
    pub types: Vec<AbiTypeDefinition>,
    pub structs: Vec<AbiStructDefinition>,
    pub actions: Vec<AbiActionDefinition>,
    pub tables: Vec<AbiTableDefinition>,
    pub ricardian_clauses: Vec<AbiClausePair>,
    pub error_messages: Vec<AbiErrorMessage>,
    pub variants: Vec<AbiVariantDefinition>,
    pub action_results: Vec<AbiActionResultDefinition>,
}

impl AbiDefinition {
    pub fn binary_to_variant(&self, variant_name: &str, data: &[u8]) -> Result<Value, ChainError> {
        let struct_def = self.structs.iter().find(|v| v.name == variant_name);
        let mut variant = Map::new();

        if let Some(struct_def) = struct_def {
            let mut pos = 0;

            for field in &struct_def.fields {
                variant.insert(
                    field.name.clone(),
                    self.parse_type(&field.type_name, data, &mut pos)?,
                );
            }

            return Ok(Value::Object(variant));
        }

        Err(ChainError::ParseError(format!(
            "variant '{}' not found in ABI",
            variant_name
        )))
    }

    fn parse_type(
        &self,
        type_name: &str,
        data: &[u8],
        pos: &mut usize,
    ) -> Result<serde_json::Value, ChainError> {
        match type_name {
            "int8" => Ok(Value::Number(i8::read(data, pos)?.into())),
            "uint8" => Ok(Value::Number(u8::read(data, pos)?.into())),
            "int16" => Ok(Value::Number(i16::read(data, pos)?.into())),
            "uint16" => Ok(Value::Number(u16::read(data, pos)?.into())),
            "int32" => Ok(Value::Number(i32::read(data, pos)?.into())),
            "uint32" => Ok(Value::Number(u32::read(data, pos)?.into())),
            "int64" => Ok(Value::Number(i64::read(data, pos)?.into())),
            "uint64" => Ok(Value::Number(u64::read(data, pos)?.into())),
            "bool" => Ok(Value::Bool(bool::read(data, pos)?.into())),
            "name" => Ok(Value::String(Name::read(data, pos)?.to_string())),
            "string" => Ok(Value::String(String::read(data, pos)?)),
            "symbol" => Ok(Value::String(Symbol::read(data, pos)?.to_string())),
            "symbol_code" => Ok(Value::String(SymbolCode::read(data, pos)?.to_string())),
            "asset" => Ok(Value::String(Asset::read(data, pos)?.to_string())),
            "extended_asset" => Ok(Value::String(ExtendedAsset::read(data, pos)?.to_string())),
            _ => Err(ChainError::ParseError(format!(
                "type '{}' is an invalid type name",
                type_name
            ))),
        }
    }

    pub fn get_table_type(&self, table_name: &Name) -> Result<String, ChainError> {
        for table in &self.tables {
            if &table.name == table_name {
                return Ok(table.type_name.clone());
            }
        }

        Err(ChainError::InvalidArgument(format!(
            "table '{}' not found in ABI",
            table_name
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use pulsevm_serialization::Write;

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes)]
    struct TestStruct {
        field1: i8,
        field2: u8,
        field3: i16,
        field4: u16,
        field5: i32,
        field6: u32,
        field7: i64,
        field8: u64,
        field9: bool,
        field10: Name,
        field11: String,
        field12: Symbol,
        field13: SymbolCode,
        field14: Asset,
        field15: ExtendedAsset,
    }

    #[test]
    fn test_abi_definition() {
        let abi = AbiDefinition {
            version: "pulsevm v1.0".to_string(),
            types: vec![],
            structs: vec![AbiStructDefinition {
                name: "test".to_string(),
                base: "".to_string(),
                fields: vec![
                    AbiFieldDefinition {
                        name: "field1".to_string(),
                        type_name: "int8".to_string(),
                    },
                    AbiFieldDefinition {
                        name: "field2".to_string(),
                        type_name: "uint8".to_string(),
                    },
                    AbiFieldDefinition {
                        name: "field3".to_string(),
                        type_name: "int16".to_string(),
                    },
                    AbiFieldDefinition {
                        name: "field4".to_string(),
                        type_name: "uint16".to_string(),
                    },
                    AbiFieldDefinition {
                        name: "field5".to_string(),
                        type_name: "int32".to_string(),
                    },
                    AbiFieldDefinition {
                        name: "field6".to_string(),
                        type_name: "uint32".to_string(),
                    },
                    AbiFieldDefinition {
                        name: "field7".to_string(),
                        type_name: "int64".to_string(),
                    },
                    AbiFieldDefinition {
                        name: "field8".to_string(),
                        type_name: "uint64".to_string(),
                    },
                    AbiFieldDefinition {
                        name: "field9".to_string(),
                        type_name: "bool".to_string(),
                    },
                    AbiFieldDefinition {
                        name: "field10".to_string(),
                        type_name: "name".to_string(),
                    },
                    AbiFieldDefinition {
                        name: "field11".to_string(),
                        type_name: "string".to_string(),
                    },
                    AbiFieldDefinition {
                        name: "field12".to_string(),
                        type_name: "symbol".to_string(),
                    },
                    AbiFieldDefinition {
                        name: "field13".to_string(),
                        type_name: "symbol_code".to_string(),
                    },
                    AbiFieldDefinition {
                        name: "field14".to_string(),
                        type_name: "asset".to_string(),
                    },
                    AbiFieldDefinition {
                        name: "field15".to_string(),
                        type_name: "extended_asset".to_string(),
                    },
                ],
            }],
            actions: vec![],
            tables: vec![],
            ricardian_clauses: vec![],
            error_messages: vec![],
            variants: vec![],
            action_results: vec![],
        };
        let struct_1 = TestStruct {
            field1: -5,
            field2: 10,
            field3: 1,
            field4: 2,
            field5: 3,
            field6: 4,
            field7: 5,
            field8: 6,
            field9: false,
            field10: Name::from_str("pulsevm").unwrap(),
            field11: "hello world".to_string(),
            field12: Symbol::new_with_code(4, SymbolCode::from_str("EOS").unwrap()),
            field13: SymbolCode::from_str("EOS").unwrap(),
            field14: Asset::new(
                400,
                Symbol::new_with_code(4, SymbolCode::from_str("EOS").unwrap()),
            ),
            field15: ExtendedAsset {
                quantity: Asset::new(
                    500,
                    Symbol::new_with_code(4, SymbolCode::from_str("EOS").unwrap()),
                ),
                contract: Name::from_str("pulsevm").unwrap(),
            },
        };

        assert_eq!(abi.version, "pulsevm v1.0");
        assert_eq!(
            abi.binary_to_variant("test", struct_1.pack().unwrap().as_slice()),
            Ok(json!({
                "field1": -5,
                "field2": 10,
                "field3": 1,
                "field4": 2,
                "field5": 3,
                "field6": 4,
                "field7": 5,
                "field8": 6,
                "field9": false,
                "field10": "pulsevm",
                "field11": "hello world",
                "field12": "4,EOS",
                "field13": "EOS",
                "field14": "0.0400 EOS",
                "field15": "0.0500 EOS@pulsevm"
            }))
        );
    }
}
