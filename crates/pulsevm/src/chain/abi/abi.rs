use anyhow::Chain;
use pulsevm_proc_macros::{NumBytes, Read, Write};
use pulsevm_serialization::Read;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::chain::{Asset, ExtendedAsset, Name, Symbol, SymbolCode, error::ChainError};

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
            abi_extensions: vec![],
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

    #[test]
    fn test_base64() {
        let input = "DmVvc2lvOjphYmkvMS4xACcKbmV3YWNjb3VudAAEB2NyZWF0b3IEbmFtZQZuZXdhY3QEbmFtZQVvd25lcglhdXRob3JpdHkGYWN0aXZlCWF1dGhvcml0eRdwZXJtaXNzaW9uX2xldmVsX3dlaWdodAACCnBlcm1pc3Npb24QcGVybWlzc2lvbl9sZXZlbAZ3ZWlnaHQGdWludDE2C2dsb2JhbHN0YXRlAAMMbWF4X3JhbV9zaXplBnVpbnQ2NBh0b3RhbF9yYW1fYnl0ZXNfcmVzZXJ2ZWQGdWludDY0D3RvdGFsX3JhbV9zdGFrZQVpbnQ2NBlwYWlyX3RpbWVfcG9pbnRfc2VjX2ludDY0AAIDa2V5DnRpbWVfcG9pbnRfc2VjBXZhbHVlBWludDY0DXByb2R1Y2VyaW5mbzIAAwVvd25lcgRuYW1lDXZvdGVwYXlfc2hhcmUHZmxvYXQ2NBlsYXN0X3ZvdGVwYXlfc2hhcmVfdXBkYXRlCnRpbWVfcG9pbnQJdm90ZXJpbmZvAAoFb3duZXIEbmFtZQVwcm94eQRuYW1lCXByb2R1Y2VycwZuYW1lW10Gc3Rha2VkBWludDY0EGxhc3Rfdm90ZV93ZWlnaHQHZmxvYXQ2NBNwcm94aWVkX3ZvdGVfd2VpZ2h0B2Zsb2F0NjQIaXNfcHJveHkEYm9vbAZmbGFnczEGdWludDMyCXJlc2VydmVkMgZ1aW50MzIJcmVzZXJ2ZWQzBWFzc2V0CWF1dGhvcml0eQAECXRocmVzaG9sZAZ1aW50MzIEa2V5cwxrZXlfd2VpZ2h0W10IYWNjb3VudHMZcGVybWlzc2lvbl9sZXZlbF93ZWlnaHRbXQV3YWl0cw13YWl0X3dlaWdodFtdCWJpZHJlZnVuZAACBmJpZGRlcgRuYW1lBmFtb3VudAVhc3NldAZzZXRhYmkAAgRhY250BG5hbWUDYWJpBWJ5dGVzEHhwcnJlZnVuZHJlcXVlc3QAAwVvd25lcgRuYW1lDHJlcXVlc3RfdGltZQ50aW1lX3BvaW50X3NlYwhxdWFudGl0eQVhc3NldAl2b3RlcnN4cHIABwVvd25lcgRuYW1lBnN0YWtlZAZ1aW50NjQLaXNxdWFsaWZpZWQEYm9vbAtjbGFpbWFtb3VudAZ1aW50NjQJbGFzdGNsYWltBnVpbnQ2NApzdGFydHN0YWtlB3VpbnQ2ND8Lc3RhcnRxdWFsaWYFYm9vbD8NcmVmdW5kcmVxdWVzdAAEBW93bmVyBG5hbWUMcmVxdWVzdF90aW1lDnRpbWVfcG9pbnRfc2VjCm5ldF9hbW91bnQFYXNzZXQKY3B1X2Ftb3VudAVhc3NldAt3YWl0X3dlaWdodAACCHdhaXRfc2VjBnVpbnQzMgZ3ZWlnaHQGdWludDE2DXJleHJldHVybnBvb2wABwd2ZXJzaW9uBnVpbnQ2NA5sYXN0X2Rpc3RfdGltZQ50aW1lX3BvaW50X3NlYxNwZW5kaW5nX2J1Y2tldF90aW1lDnRpbWVfcG9pbnRfc2VjEm9sZGVzdF9idWNrZXRfdGltZQ50aW1lX3BvaW50X3NlYxdwZW5kaW5nX2J1Y2tldF9wcm9jZWVkcwVpbnQ2NBhjdXJyZW50X3JhdGVfb2ZfcHJvY2VlZHMFaW50NjQIcHJvY2VlZHMFaW50NjQQcmV4cmV0dXJuYnVja2V0cwACB3ZlcnNpb24FdWludDgOcmV0dXJuX2J1Y2tldHMbcGFpcl90aW1lX3BvaW50X3NlY19pbnQ2NFtdDGdsb2JhbHN0YXRlMgAFEW5ld19yYW1fcGVyX2Jsb2NrBnVpbnQxNhFsYXN0X3JhbV9pbmNyZWFzZRRibG9ja190aW1lc3RhbXBfdHlwZQ5sYXN0X2Jsb2NrX251bRRibG9ja190aW1lc3RhbXBfdHlwZRx0b3RhbF9wcm9kdWNlcl92b3RlcGF5X3NoYXJlB2Zsb2F0NjQIcmV2aXNpb24FdWludDgMZ2xvYmFsc3RhdGVkAA4LdG90YWxzdGFrZWQFaW50NjQMdG90YWxyc3Rha2VkBWludDY0DHRvdGFscnZvdGVycwVpbnQ2NApub3RjbGFpbWVkBWludDY0BHBvb2wFaW50NjQLcHJvY2Vzc3RpbWUFaW50NjQOcHJvY2Vzc3RpbWV1cGQFaW50NjQMaXNwcm9jZXNzaW5nBGJvb2wMcHJvY2Vzc19mcm9tBG5hbWUNcHJvY2Vzc19xdWFudAZ1aW50NjQOcHJvY2Vzc3JzdGFrZWQGdWludDY0CXByb2Nlc3NlZAZ1aW50NjQGc3BhcmUxBWludDY0BnNwYXJlMgVpbnQ2NAdyZXhwb29sAAgHdmVyc2lvbgZ1aW50NjQKdG90YWxfbGVudAVhc3NldAx0b3RhbF91bmxlbnQFYXNzZXQKdG90YWxfcmVudAVhc3NldA50b3RhbF9sZW5kYWJsZQVhc3NldAl0b3RhbF9yZXgFYXNzZXQQbmFtZWJpZF9wcm9jZWVkcwVhc3NldAhsb2FuX251bQZ1aW50NjQMcHJvZHVjZXJpbmZvAAcFb3duZXIEbmFtZQt0b3RhbF92b3RlcwdmbG9hdDY0CWlzX2FjdGl2ZQRib29sA3VybAZzdHJpbmcNdW5wYWlkX2Jsb2NrcwZ1aW50MzIPbGFzdF9jbGFpbV90aW1lCnRpbWVfcG9pbnQIbG9jYXRpb24GdWludDE2Dmdsb2JhbHN0YXRleHByAAgPbWF4X2JwX3Blcl92b3RlBnVpbnQ2NA1taW5fYnBfcmV3YXJkBnVpbnQ2NA51bnN0YWtlX3BlcmlvZAZ1aW50NjQKcHJvY2Vzc19ieQZ1aW50NjQQcHJvY2Vzc19pbnRlcnZhbAZ1aW50NjQVdm90ZXJzX2NsYWltX2ludGVydmFsBnVpbnQ2NAZzcGFyZTEGdWludDY0BnNwYXJlMgZ1aW50NjQKcmV4YmFsYW5jZQAFB3ZlcnNpb24FdWludDgFb3duZXIEbmFtZQp2b3RlX3N0YWtlBWFzc2V0C3JleF9iYWxhbmNlBWFzc2V0C21hdHVyZWRfcmV4BWludDY0DGdsb2JhbHN0YXRlNAADD2NvbnRpbnVvdXNfcmF0ZQdmbG9hdDY0FGluZmxhdGlvbl9wYXlfZmFjdG9yBWludDY0DnZvdGVwYXlfZmFjdG9yBWludDY0DWV4Y2hhbmdlc3RhdGUAAwZzdXBwbHkFYXNzZXQEYmFzZQlDb25uZWN0b3IFcXVvdGUJQ29ubmVjdG9yB3NldGNvZGUABAdhY2NvdW50BG5hbWUGdm10eXBlBXVpbnQ4CXZtdmVyc2lvbgV1aW50OARjb2RlBWJ5dGVzB25hbWViaWQABAhuZXdfbmFtZQRuYW1lC2hpZ2hfYmlkZGVyBG5hbWUIaGlnaF9iaWQFaW50NjQNbGFzdF9iaWRfdGltZQp0aW1lX3BvaW50CmtleV93ZWlnaHQAAgNrZXkKcHVibGljX2tleQZ3ZWlnaHQGdWludDE2B3VzZXJyYW0ABAdhY2NvdW50BG5hbWUDcmFtBnVpbnQ2NAhxdWFudGl0eQVhc3NldAhyYW1saW1pdAZ1aW50NjQNY3VycmVuY3lzdGF0cwADBnN1cHBseQVhc3NldAptYXhfc3VwcGx5BWFzc2V0Bmlzc3VlcgRuYW1lDXVzZXJyZXNvdXJjZXMABAVvd25lcgRuYW1lCm5ldF93ZWlnaHQFYXNzZXQKY3B1X3dlaWdodAVhc3NldAlyYW1fYnl0ZXMFaW50NjQOZ2xvYmFsc3RhdGVyYW0ABRJyYW1fcHJpY2VfcGVyX2J5dGUFYXNzZXQSbWF4X3Blcl91c2VyX2J5dGVzBnVpbnQ2NA9yYW1fZmVlX3BlcmNlbnQGdWludDY0CXRvdGFsX3JhbQZ1aW50NjQJdG90YWxfeHByBnVpbnQ2NAdyZXhmdW5kAAMHdmVyc2lvbgV1aW50OAVvd25lcgRuYW1lB2JhbGFuY2UFYXNzZXQEaW5pdAACB3ZlcnNpb24FdWludDgEY29yZQZzeW1ib2wSZGVsZWdhdGVkYmFuZHdpZHRoAAQEZnJvbQRuYW1lAnRvBG5hbWUKbmV0X3dlaWdodAVhc3NldApjcHVfd2VpZ2h0BWFzc2V0DGRlbGVnYXRlZHhwcgADBGZyb20EbmFtZQJ0bwRuYW1lCHF1YW50aXR5BWFzc2V0B3JleGxvYW4ACAd2ZXJzaW9uBXVpbnQ4BGZyb20EbmFtZQhyZWNlaXZlcgRuYW1lB3BheW1lbnQFYXNzZXQHYmFsYW5jZQVhc3NldAx0b3RhbF9zdGFrZWQFYXNzZXQIbG9hbl9udW0GdWludDY0CmV4cGlyYXRpb24KdGltZV9wb2ludAxnbG9iYWxzdGF0ZTMAAhZsYXN0X3ZwYXlfc3RhdGVfdXBkYXRlCnRpbWVfcG9pbnQcdG90YWxfdnBheV9zaGFyZV9jaGFuZ2VfcmF0ZQdmbG9hdDY0CHJleG9yZGVyAAcHdmVyc2lvbgV1aW50OAVvd25lcgRuYW1lDXJleF9yZXF1ZXN0ZWQFYXNzZXQIcHJvY2VlZHMFYXNzZXQMc3Rha2VfY2hhbmdlBWFzc2V0Cm9yZGVyX3RpbWUKdGltZV9wb2ludAdpc19vcGVuBGJvb2wJY29ubmVjdG9yAAIHYmFsYW5jZQVhc3NldAZ3ZWlnaHQHZmxvYXQ2NAdzZXRwcml2AAIHYWNjb3VudARuYW1lBmlzcHJpdgV1aW50OAUAAABgu1uzwgdzZXRwcml2AABAnpoiZLiaCm5ld2FjY291bnQAAAAAALhjssIGc2V0YWJpAAAAAEAlirLCB3NldGNvZGUAAAAAAACQ3XQEaW5pdAAcAADICl4jpbkDaTY0AAANZXhjaGFuZ2VzdGF0ZQAAADi5o6SZA2k2NAAAB25hbWViaWQAAE5TL3WTOwNpNjQAAAliaWRyZWZ1bmQAAMBXIZ3orQNpNjQAAAxwcm9kdWNlcmluZm8AgMBXIZ3orQNpNjQAAA1wcm9kdWNlcmluZm8yAAAAAOCrMt0DaTY0AAAJdm90ZXJpbmZvAAAAAKt7FdYDaTY0AAANdXNlcnJlc291cmNlcwAAACBNc6JKA2k2NAAAEmRlbGVnYXRlZGJhbmR3aWR0aAAAAACnqZe6A2k2NAAADXJlZnVuZHJlcXVlc3QAAAAA3NqjSgNpNjQAAAxkZWxlZ2F0ZWR4cHIAALi146sy3QNpNjQAAAl2b3RlcnN4cHIAwK0dp6mXugNpNjQAABB4cHJyZWZ1bmRyZXF1ZXN0AMCtHUdzaGQDaTY0AAAOZ2xvYmFsc3RhdGV4cHIAAAAJR3NoZANpNjQAAAxnbG9iYWxzdGF0ZWQAAJDmRnNoZANpNjQAAA5nbG9iYWxzdGF0ZXJhbQAAANJcfBXWA2k2NAAAB3VzZXJyYW0AAAAgUlq7ugNpNjQAAAdyZXhwb29sAAAAIFJas7oDaTY0AAANcmV4cmV0dXJucG9vbAAAzgoifbK6A2k2NAAAEHJleHJldHVybmJ1Y2tldHMAAAAgTb26ugNpNjQAAAdyZXhmdW5kAAAAAERzuroDaTY0AAAKcmV4YmFsYW5jZQAAAGAaGrOaA2k2NAAAB3JleGxvYW4AAABXpUu7ugNpNjQAAAhyZXhvcmRlcgAAAABEc2hkA2k2NAAAC2dsb2JhbHN0YXRlAAAAQERzaGQDaTY0AAAMZ2xvYmFsc3RhdGUyAAAAYERzaGQDaTY0AAAMZ2xvYmFsc3RhdGUzAAAAgERzaGQDaTY0AAAMZ2xvYmFsc3RhdGU0AAAAAACcTcYDaTY0AAANY3VycmVuY3lzdGF0cwAAAAAA";
        let decoded = base64::decode(&input).unwrap();
        let abi: AbiDefinition = AbiDefinition::read(&decoded, &mut 0).unwrap();
        println!("{}", json!(abi));
    }
}
