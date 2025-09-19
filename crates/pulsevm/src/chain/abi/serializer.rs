use std::collections::{HashMap, HashSet};

use pulsevm_serialization::{Write, WriteError};

use crate::chain::{
    AbiDefinition, AbiStructDefinition, AbiVariantDefinition, Name, error::ChainError, pulse_assert,
};

type TypeName = String;
type PackFunction = fn(bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError>;

pub struct Serializer {
    typedefs: HashMap<TypeName, TypeName>,
    structs: HashMap<TypeName, AbiStructDefinition>,
    actions: HashMap<Name, TypeName>,
    tables: HashMap<Name, TypeName>,
    error_messages: HashMap<u64, String>,
    variants: HashMap<TypeName, AbiVariantDefinition>,
    action_results: HashMap<Name, TypeName>,
    built_in_types: HashSet<TypeName>,
}
impl Serializer {
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
}

fn builtin_types() -> HashSet<TypeName> {
    let mut m: HashSet<TypeName> = HashSet::new();
    m.insert("bool".to_string());
    m.insert("int8".to_string());
    m.insert("uint8".to_string());
    m.insert("int16".to_string());
    m.insert("uint16".to_string());
    m.insert("int32".to_string());
    m.insert("uint32".to_string());
    m.insert("int64".to_string());
    m.insert("uint64".to_string());
    m.insert("int128".to_string());
    m.insert("uint128".to_string());
    m.insert("varint32".to_string());
    m.insert("varuint32".to_string());

    m.insert("float32".to_string());
    m.insert("float64".to_string());
    m.insert("float128".to_string());

    m.insert("time_point".to_string());
    m.insert("time_point_sec".to_string());
    m.insert("block_timestamp_type".to_string());

    m.insert("name".to_string());

    m.insert("bytes".to_string());
    m.insert("string".to_string());

    m.insert("checksum160".to_string());
    m.insert("checksum256".to_string());
    m.insert("checksum512".to_string());

    m.insert("public_key".to_string());
    m.insert("signature".to_string());

    m.insert("symbol".to_string());
    m.insert("symbol_code".to_string());
    m.insert("asset".to_string());
    m.insert("extended_asset".to_string());

    m
}

fn remove_bin_extension<'a>(ty: &'a str) -> &'a str {
    ty.strip_suffix('$').unwrap_or(ty)
}

fn is_type(
    rtype: &str,
    built_in_types: &HashSet<TypeName>,
    typedefs: &HashMap<TypeName, TypeName>,
    structs: &HashMap<TypeName, AbiStructDefinition>,
    variants: &HashMap<TypeName, AbiVariantDefinition>,
) -> bool {
    let actual_type = fundamental_type(rtype);

    if built_in_types.contains(actual_type) {
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
