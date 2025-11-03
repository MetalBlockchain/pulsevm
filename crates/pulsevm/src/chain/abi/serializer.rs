use std::collections::{HashMap, HashSet};

use jsonrpsee::tracing::field;
use pulsevm_crypto::{Bytes, FixedBytes};
use pulsevm_serialization::{Read, ReadError, VarInt32, VarUint32, Write, WriteError};
use pulsevm_time::{TimePoint, TimePointSec};
use serde_json::{Number, Value};

use crate::chain::{
    AbiDefinition, AbiStructDefinition, AbiVariantDefinition, Asset, BlockTimestamp, ExtendedAsset,
    Name, PublicKey, Signature, Symbol, SymbolCode, error::ChainError, pulse_assert,
};

type TypeName = String;
type UnpackFunction = fn(bytes: &[u8], pos: &mut usize) -> Result<Value, ReadError>;
type PackFunction = fn(bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError>;

pub struct AbiSerializer {
    typedefs: HashMap<TypeName, TypeName>,
    structs: HashMap<TypeName, AbiStructDefinition>,
    actions: HashMap<Name, TypeName>,
    tables: HashMap<Name, TypeName>,
    error_messages: HashMap<u64, String>,
    variants: HashMap<TypeName, AbiVariantDefinition>,
    action_results: HashMap<Name, TypeName>,
    built_in_types: HashMap<TypeName, UnpackFunction>,
}
impl AbiSerializer {
    pub fn from_abi(abi: AbiDefinition) -> Result<Self, ChainError> {
        if !abi.version.starts_with("eosio::abi/1.") {
            return Err(ChainError::TransactionError(
                "unsupported ABI version".to_string(),
            ));
        }

        let built_in_types = builtin_types();
        let mut structs: HashMap<TypeName, AbiStructDefinition> =
            HashMap::with_capacity(abi.structs.len());
        let mut typedefs: HashMap<TypeName, TypeName> = HashMap::with_capacity(abi.types.len());
        let mut actions: HashMap<Name, TypeName> = HashMap::with_capacity(abi.actions.len());
        let mut tables: HashMap<Name, TypeName> = HashMap::with_capacity(abi.tables.len());
        let mut error_messages: HashMap<u64, String> =
            HashMap::with_capacity(abi.error_messages.len());
        let mut variants: HashMap<TypeName, AbiVariantDefinition> =
            HashMap::with_capacity(abi.variants.len());
        let mut action_results: HashMap<Name, TypeName> =
            HashMap::with_capacity(abi.action_results.len());

        for s in abi.structs {
            structs.insert(s.name.clone(), s);
        }

        for t in abi.types {
            pulse_assert(
                !is_type(
                    &t.new_type_name,
                    &built_in_types,
                    &typedefs,
                    &structs,
                    &variants,
                ),
                ChainError::TransactionError("type already exists".to_string()),
            )?;
            typedefs.insert(t.new_type_name.clone(), t.type_name.clone());
        }

        for a in abi.actions {
            actions.insert(a.name, a.type_name);
        }

        for t in abi.tables {
            tables.insert(t.name, t.type_name);
        }

        for e in abi.error_messages {
            error_messages.insert(e.error_code, e.error_msg);
        }

        for v in abi.variants {
            variants.insert(v.name.clone(), v);
        }

        for ar in abi.action_results {
            action_results.insert(ar.name, ar.result_type);
        }

        Ok(Self {
            typedefs,
            structs,
            actions,
            tables,
            error_messages,
            variants,
            action_results,
            built_in_types,
        })
    }

    pub fn validate(&self) -> Result<(), ChainError> {
        for t in self.typedefs.iter() {
            pulse_assert(
                is_type(
                    t.1.as_ref(),
                    &self.built_in_types,
                    &self.typedefs,
                    &self.structs,
                    &self.variants,
                ),
                ChainError::TransactionError(format!("type '{}' does not exist", t.1)),
            )?;
        }

        for s in self.structs.iter() {
            for field in s.1.fields.iter() {
                pulse_assert(
                    is_type(
                        remove_bin_extension(field.type_name.as_ref()),
                        &self.built_in_types,
                        &self.typedefs,
                        &self.structs,
                        &self.variants,
                    ),
                    ChainError::TransactionError(format!(
                        "struct field type '{}' does not exist",
                        field.type_name
                    )),
                )?;
            }
        }

        for s in self.variants.iter() {
            for variant_type in s.1.types.iter() {
                pulse_assert(
                    is_type(
                        variant_type.as_ref(),
                        &self.built_in_types,
                        &self.typedefs,
                        &self.structs,
                        &self.variants,
                    ),
                    ChainError::TransactionError(format!(
                        "variant type '{}' does not exist",
                        variant_type
                    )),
                )?;
            }
        }

        for a in self.actions.iter() {
            pulse_assert(
                is_type(
                    a.1.as_ref(),
                    &self.built_in_types,
                    &self.typedefs,
                    &self.structs,
                    &self.variants,
                ),
                ChainError::TransactionError(format!("action type '{}' does not exist", a.1)),
            )?;
        }

        for t in self.tables.iter() {
            pulse_assert(
                is_type(
                    t.1.as_ref(),
                    &self.built_in_types,
                    &self.typedefs,
                    &self.structs,
                    &self.variants,
                ),
                ChainError::TransactionError(format!("table type '{}' does not exist", t.1)),
            )?;
        }

        for r in self.action_results.iter() {
            pulse_assert(
                is_type(
                    r.1.as_ref(),
                    &self.built_in_types,
                    &self.typedefs,
                    &self.structs,
                    &self.variants,
                ),
                ChainError::TransactionError(format!(
                    "action result type '{}' does not exist",
                    r.1
                )),
            )?;
        }

        Ok(())
    }

    pub fn binary_to_variant(
        &self,
        type_name: &str,
        data: &[u8],
        pos: &mut usize,
    ) -> Result<Value, ChainError> {
        let rtype = self.resolve_type(type_name);
        let ftype = fundamental_type(&rtype);

        if let Some(btype) = self.built_in_types.get(ftype) {
            return btype(data, pos).map_err(ChainError::from);
        }

        if is_array(&rtype) {
            let size = usize::read(data, pos)?;
            let mut vars: Vec<Value> = Vec::with_capacity(size);
            for i in 0..size {
                let v = self.binary_to_variant(ftype, data, pos)?;
                vars.insert(i, v);
            }
            return Ok(Value::Array(vars));
        } else if is_optional(&rtype) {
            let is_some = u8::read(data, pos)?;
            if is_some != 0 {
                let v = self.binary_to_variant(ftype, data, pos)?;
                return Ok(v);
            } else {
                return Ok(Value::Null);
            }
        } else if let Some(variant) = self.variants.get(&rtype) {
            let select = usize::read(data, pos)?;
            pulse_assert(
                select < variant.types.len(),
                ChainError::TransactionError("variant index out of range".to_string()),
            )?;
            let v = self.binary_to_variant(&variant.types[select], data, pos)?;
            return Ok(v);
        }

        let mut mvo = serde_json::Map::new();
        self._binary_to_struct(&rtype, data, pos, &mut mvo)?;
        Ok(Value::Object(mvo))
    }

    fn _binary_to_struct(
        &self,
        struct_name: &str,
        data: &[u8],
        pos: &mut usize,
        mvo: &mut serde_json::Map<String, Value>,
    ) -> Result<(), ChainError> {
        let st = match self.structs.get(struct_name) {
            Some(s) => s,
            None => {
                return Err(ChainError::TransactionError(format!(
                    "struct '{}' not found",
                    struct_name
                )));
            }
        };

        if st.base != "" {
            self._binary_to_struct(&self.resolve_type(&st.base), data, pos, mvo)?;
        }

        for field in st.fields.iter() {
            let extension = field.type_name.ends_with('$');

            if *pos >= data.len() {
                if extension {
                    break;
                }
                return Err(ChainError::TransactionError(
                    "not enough data to read struct field".to_string(),
                ));
            }

            let field_type = self.resolve_type(remove_bin_extension(field.type_name.as_ref()));
            let v = self.binary_to_variant(&field_type, data, pos)?;
            mvo.insert(field.name.clone(), v);
        }

        Ok(())
    }

    pub fn resolve_type(&self, type_name: &str) -> String {
        if let Some(t) = self.typedefs.get(type_name) {
            let mut i = self.typedefs.len();
            let mut itr = t.clone();

            while i > 0 {
                // avoid infinite recursion
                if let Some(t2) = self.typedefs.get(itr.as_str()) {
                    itr = t2.clone();
                    i -= 1;
                } else {
                    return itr;
                }
            }
            return itr;
        }
        type_name.to_owned()
    }
}

fn builtin_types() -> HashMap<TypeName, UnpackFunction> {
    let mut m: HashMap<TypeName, UnpackFunction> = HashMap::new();
    m.insert("bool".to_string(), |bytes, pos| {
        let res = u8::read(bytes, pos)?;
        Ok(serde_json::Value::Bool(res != 0))
    });
    m.insert("int8".to_string(), |bytes, pos| {
        let res = i8::read(bytes, pos)?;
        Ok(serde_json::Value::Number(res.into()))
    });
    m.insert("uint8".to_string(), |bytes, pos| {
        let res = u8::read(bytes, pos)?;
        Ok(serde_json::Value::Number(res.into()))
    });
    m.insert("int16".to_string(), |bytes, pos| {
        let res = i16::read(bytes, pos)?;
        Ok(serde_json::Value::Number(res.into()))
    });
    m.insert("uint16".to_string(), |bytes, pos| {
        let res = u16::read(bytes, pos)?;
        Ok(serde_json::Value::Number(res.into()))
    });
    m.insert("int32".to_string(), |bytes, pos| {
        let res = i32::read(bytes, pos)?;
        Ok(serde_json::Value::Number(res.into()))
    });
    m.insert("uint32".to_string(), |bytes, pos| {
        let res = u32::read(bytes, pos)?;
        Ok(serde_json::Value::Number(res.into()))
    });
    m.insert("int64".to_string(), |bytes, pos| {
        let res = i64::read(bytes, pos)?;
        Ok(serde_json::Value::Number(res.into()))
    });
    m.insert("uint64".to_string(), |bytes, pos| {
        let res = u64::read(bytes, pos)?;
        Ok(serde_json::Value::Number(res.into()))
    });
    m.insert("int128".to_string(), |bytes, pos| {
        // TODO: Fix this when we have a int128 implementation
        let res = f64::read(bytes, pos)?;
        match Number::from_f64(res) {
            Some(n) => Ok(Value::Number(n)),
            None => Err(ReadError::ParseError),
        }
    });
    m.insert("uint128".to_string(), |bytes, pos| {
        // TODO: Fix this when we have a uint128 implementation
        let res = f64::read(bytes, pos)?;
        match Number::from_f64(res) {
            Some(n) => Ok(Value::Number(n)),
            None => Err(ReadError::ParseError),
        }
    });
    m.insert("varint32".to_string(), |bytes, pos| {
        let res = VarInt32::read(bytes, pos)?;
        Ok(serde_json::Value::Number(res.0.into()))
    });
    m.insert("varuint32".to_string(), |bytes, pos| {
        let res = VarUint32::read(bytes, pos)?;
        Ok(serde_json::Value::Number(res.0.into()))
    });

    m.insert("float32".to_string(), |bytes, pos| {
        let res = f32::read(bytes, pos)?;
        match Number::from_f64(res as f64) {
            Some(n) => Ok(Value::Number(n)),
            None => Err(ReadError::ParseError),
        }
    });
    m.insert("float64".to_string(), |bytes, pos| {
        let res = f64::read(bytes, pos)?;
        match Number::from_f64(res) {
            Some(n) => Ok(Value::Number(n)),
            None => Err(ReadError::ParseError),
        }
    });
    m.insert("float128".to_string(), |bytes, pos| {
        // TODO: Fix this when we have a float128 implementation
        let res = f64::read(bytes, pos)?;
        match Number::from_f64(res) {
            Some(n) => Ok(Value::Number(n)),
            None => Err(ReadError::ParseError),
        }
    });

    m.insert("time_point".to_string(), |bytes, pos| {
        let res = TimePoint::read(bytes, pos)?;
        Ok(serde_json::Value::String(res.to_string()))
    });
    m.insert("time_point_sec".to_string(), |bytes, pos| {
        let res = TimePointSec::read(bytes, pos)?;
        Ok(serde_json::Value::String(res.to_string()))
    });
    m.insert("block_timestamp_type".to_string(), |bytes, pos| {
        let res = BlockTimestamp::read(bytes, pos)?;
        Ok(serde_json::Value::String(res.to_string()))
    });

    m.insert("name".to_string(), |bytes, pos| {
        let res = Name::read(bytes, pos)?;
        Ok(serde_json::Value::String(res.to_string()))
    });

    m.insert("bytes".to_string(), |bytes, pos| {
        let res = Bytes::read(bytes, pos)?;
        Ok(serde_json::Value::String(res.to_string()))
    });
    m.insert("string".to_string(), |bytes, pos| {
        let res = String::read(bytes, pos)?;
        Ok(serde_json::Value::String(res.to_string()))
    });

    m.insert("checksum160".to_string(), |bytes, pos| {
        let res = FixedBytes::<20>::read(bytes, pos)?;
        Ok(serde_json::Value::String(res.to_string()))
    });
    m.insert("checksum256".to_string(), |bytes, pos| {
        let res = FixedBytes::<32>::read(bytes, pos)?;
        Ok(serde_json::Value::String(res.to_string()))
    });
    m.insert("checksum512".to_string(), |bytes, pos| {
        let res = FixedBytes::<64>::read(bytes, pos)?;
        Ok(serde_json::Value::String(res.to_string()))
    });

    m.insert("public_key".to_string(), |bytes, pos| {
        let res = PublicKey::read(bytes, pos)?;
        Ok(serde_json::Value::String(res.to_string()))
    });
    m.insert("signature".to_string(), |bytes, pos| {
        let res = Signature::read(bytes, pos)?;
        Ok(serde_json::Value::String(res.to_string()))
    });

    m.insert("symbol".to_string(), |bytes, pos| {
        let res = Symbol::read(bytes, pos)?;
        Ok(serde_json::Value::String(res.to_string()))
    });
    m.insert("symbol_code".to_string(), |bytes, pos| {
        let res = SymbolCode::read(bytes, pos)?;
        Ok(serde_json::Value::String(res.to_string()))
    });
    m.insert("asset".to_string(), |bytes, pos| {
        let res = Asset::read(bytes, pos)?;
        Ok(serde_json::Value::String(res.to_string()))
    });
    m.insert("extended_asset".to_string(), |bytes, pos| {
        let res = ExtendedAsset::read(bytes, pos)?;
        Ok(serde_json::Value::String(res.to_string()))
    });

    m
}

fn remove_bin_extension<'a>(ty: &'a str) -> &'a str {
    ty.strip_suffix('$').unwrap_or(ty)
}

fn is_type(
    rtype: &str,
    built_in_types: &HashMap<TypeName, UnpackFunction>,
    typedefs: &HashMap<TypeName, TypeName>,
    structs: &HashMap<TypeName, AbiStructDefinition>,
    variants: &HashMap<TypeName, AbiVariantDefinition>,
) -> bool {
    let actual_type = fundamental_type(rtype);

    if built_in_types.contains_key(actual_type) {
        return true;
    }

    if let Some(resolved_type) = typedefs.get(actual_type) {
        return is_type(resolved_type, built_in_types, typedefs, structs, variants);
    }

    if structs.contains_key(actual_type) {
        return true;
    }

    if variants.contains_key(actual_type) {
        return true;
    }

    return false;
}

fn is_optional(ty: &str) -> bool {
    ty.ends_with("?")
}

fn is_array(ty: &str) -> bool {
    ty.ends_with("[]")
}

fn is_szarray(ty: &str) -> bool {
    let pos1 = match ty.rfind('[') {
        Some(i) => i,
        None => return false,
    };
    let pos2 = match ty.rfind(']') {
        Some(i) => i,
        None => return false,
    };

    let start = pos1 + 1;
    if start == pos2 {
        return false;
    }

    ty[start..pos2].bytes().all(|b| b.is_ascii_digit())
}

fn fundamental_type<'a>(ty: &'a str) -> &'a str {
    if is_array(ty) {
        // trim trailing "[]"
        &ty[..ty.len().saturating_sub(2)]
    } else if is_szarray(ty) {
        // trim everything from the last '['
        match ty.rfind('[') {
            Some(i) => &ty[..i],
            None => ty,
        }
    } else if is_optional(ty) {
        // trim trailing '?'
        &ty[..ty.len().saturating_sub(1)]
    } else {
        ty
    }
}

#[cfg(test)]
mod tests {
    use crate::chain::abi::test_abi::PULSE_ABI;

    use super::*;

    #[test]
    fn test_pulse_system_abi() {
        let abi: AbiDefinition = serde_json::from_str(PULSE_ABI).unwrap();
        let serializer = AbiSerializer::from_abi(abi).unwrap();

        // Validate the ABI
        assert!(serializer.validate().is_ok());

        let packed = 0f64;
        let packed = packed.pack().unwrap();
        let packed = hex::encode(packed);

        let value = serializer
            .binary_to_variant(
                "exchange_state",
                &hex::decode("40e2010000000000045359530000000040e20100000000000453595300000000000000000000000040e201000000000004535953000000000000000000000000").unwrap(),
                &mut 0,
            )
            .unwrap();
    }
}
