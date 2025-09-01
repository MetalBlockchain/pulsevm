//! eos-abi-serializer (with variant support)
//! ----------------------------------------
//! A minimal, self-contained reimplementation of EOSIO/Antelope ABI JSON → binary
//! serializer in Rust. It focuses on the common built-in types (name, asset, symbol,
//! checksum256, string/bytes, (u)int* , varuint32, time_point[_sec], arrays and
//! optionals) plus ABI-defined structs/type aliases and **variants** (both named and
//! inline `variant<T1,T2,...>`).
//!
//! # Highlights
//! * Reads an ABI JSON (v1.x) into a `Registry`.
//! * `Serializer::serialize(type_name, json_value)` returns a `Vec<u8>` of packed data.
//! * EOSIO-specific encodings implemented: `name` (base32→u64), `asset` (amount+symbol),
//!   `symbol`/`symbol_code`, `varuint32`, `time_point{,_sec}`.
//! * Zero external chain deps; only `serde`, `hex`, `chrono`, `thiserror`.
//!
//! # Example: pack `eosio.token::transfer`
//! ```rust
//! use serde_json::json;
//! let abi_json = r#"{
//!   "version":"eosio::abi/1.1",
//!   "types":[],
//!   "structs":[
//!     {"name":"transfer","base":"","fields":[
//!       {"name":"from","type":"name"},
//!       {"name":"to","type":"name"},
//!       {"name":"quantity","type":"asset"},
//!       {"name":"memo","type":"string"}
//!     ]}
//!   ],
//!   "actions":[{"name":"transfer","type":"transfer","ricardian_contract":""}],
//!   "tables":[]
//! }"#;
//! let abi: Abi = serde_json::from_str(abi_json).unwrap();
//! let reg = Registry::from_abi(&abi).unwrap();
//! let ser = Serializer::new(reg);
//! let data = json!({
//!   "from":"alice",
//!   "to":"bob",
//!   "quantity":"1.2345 EOS",
//!   "memo":"hi"
//! });
//! let bytes = ser.serialize("transfer", &data).unwrap();
//! assert!(!bytes.is_empty());
//! ```
//!
//! # Notes
//! * `varint32` is implemented with ZigZag + varuint32 packing (as used by eosjs).
//! * Endianness: little-endian for integer/floats, as per chain packing.

use std::{collections::HashMap, str::FromStr};
use std::convert::TryFrom;

use pulsevm_serialization::Write;
use serde::{Deserialize, Serialize};

use crate::chain::Symbol;

// =============== ABI model ===============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiTypeAlias {
    pub new_type_name: String,
    #[serde(rename = "type")]
    pub type_: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiField {
    pub name: String,
    #[serde(rename = "type")]
    pub type_: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiStruct {
    pub name: String,
    pub base: String,
    pub fields: Vec<AbiField>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiVariant {
    pub name: String,
    pub types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiAction {
    pub name: String,
    pub type_: String,
    pub ricardian_contract: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Abi {
    pub version: String,
    #[serde(default)]
    pub types: Vec<AbiTypeAlias>,
    #[serde(default)]
    pub structs: Vec<AbiStruct>,
    #[serde(default)]
    pub variants: Vec<AbiVariant>,
    #[serde(default)]
    pub actions: Vec<AbiAction>,
}

// =============== Registry ===============

#[derive(Debug, Clone)]
pub enum Prim {
    Bool,
    Int8,
    Int16,
    Int32,
    Int64,
    UInt8,
    UInt16,
    UInt32,
    UInt64,
    VarInt32,
    VarUInt32,
    Float32,
    Float64,
    String,
    Bytes,
    Name,
    TimePointSec,
    TimePoint,
    Checksum256,
    Symbol,
    SymbolCode,
    Asset,
}

#[derive(Debug, Clone)]
pub enum TypeDesc {
    Prim(Prim),
    Array(String),    // T[]
    Optional(String), // optional<T>
    Struct(StructDesc),
    Alias(String),        // maps to underlying type name
    Variant(Vec<String>), // variant<Ts...> or named variant
}

#[derive(Debug, Clone)]
pub struct StructField {
    pub name: String,
    pub type_name: String,
}

#[derive(Debug, Clone)]
pub struct StructDesc {
    pub name: String,
    pub fields: Vec<StructField>,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error("Unknown type: {0}")]
    UnknownType(String),
    #[error("Type resolution loop at {0}")]
    TypeLoop(String),
    #[error("Invalid value for type {0}: {1}")]
    InvalidValue(String, String),
    #[error("ABI error: {0}")]
    Abi(String),
    #[error("Unsupported feature: {0}")]
    Unsupported(String),
    #[error("Other: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone)]
pub struct Registry {
    pub types: HashMap<String, TypeDesc>,
}

impl Registry {
    pub fn from_abi(abi: &Abi) -> Result<Self> {
        let mut types: HashMap<String, TypeDesc> = HashMap::new();
        // Built-ins
        let builtins: Vec<(&str, Prim)> = vec![
            ("bool", Prim::Bool),
            ("int8", Prim::Int8),
            ("int16", Prim::Int16),
            ("int32", Prim::Int32),
            ("int64", Prim::Int64),
            ("uint8", Prim::UInt8),
            ("uint16", Prim::UInt16),
            ("uint32", Prim::UInt32),
            ("uint64", Prim::UInt64),
            ("varint32", Prim::VarInt32),
            ("varuint32", Prim::VarUInt32),
            ("float32", Prim::Float32),
            ("float64", Prim::Float64),
            ("string", Prim::String),
            ("bytes", Prim::Bytes),
            ("name", Prim::Name),
            ("time_point_sec", Prim::TimePointSec),
            ("time_point", Prim::TimePoint),
            ("checksum256", Prim::Checksum256),
            ("symbol", Prim::Symbol),
            ("symbol_code", Prim::SymbolCode),
            ("asset", Prim::Asset),
        ];
        for (n, p) in builtins {
            types.insert(n.to_string(), TypeDesc::Prim(p));
        }

        // Aliases
        for a in &abi.types {
            types.insert(a.new_type_name.clone(), TypeDesc::Alias(a.type_.clone()));
        }

        // Structs
        for s in &abi.structs {
            let fields = s
                .fields
                .iter()
                .map(|f| StructField {
                    name: f.name.clone(),
                    type_name: f.type_.clone(),
                })
                .collect();
            types.insert(
                s.name.clone(),
                TypeDesc::Struct(StructDesc {
                    name: s.name.clone(),
                    fields,
                }),
            );
        }

        // Variants (named)
        for v in &abi.variants {
            types.insert(v.name.clone(), TypeDesc::Variant(v.types.clone()));
        }

        Ok(Self { types })
    }

    fn resolve(&self, t: &str) -> Result<&TypeDesc> {
        use std::borrow::Cow;
        let mut cur: Cow<str> = Cow::Borrowed(t);
        let mut seen = std::collections::HashSet::new();
        loop {
            if !seen.insert(cur.to_string()) {
                return Err(Error::TypeLoop(cur.into_owned()));
            }
            if let Some(td) = self.types.get(cur.as_ref()) {
                match td {
                    TypeDesc::Alias(to) => {
                        cur = Cow::Owned(to.clone());
                        continue;
                    }
                    _ => return Ok(td),
                }
            }
            // Only non-container types are resolved here. Containers are handled in `write`.
            return Err(Error::UnknownType(cur.into_owned()));
        }
    }
}

// =============== Serializer ===============

pub struct Serializer {
    reg: Registry,
}
impl Serializer {
    pub fn new(reg: Registry) -> Self {
        Self { reg }
    }
    pub fn serialize(&self, type_name: &str, v: &serde_json::Value) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(64);
        self.write(type_name, v, &mut out)?;
        Ok(out)
    }

    fn write(&self, type_name: &str, v: &serde_json::Value, out: &mut Vec<u8>) -> Result<()> {
        // container sugar
        if let Some(inner) = type_name.strip_suffix("[]") {
            let arr = v
                .as_array()
                .ok_or_else(|| Error::InvalidValue(type_name.into(), "expected array".into()))?;
            self.write_varuint32(u32::try_from(arr.len()).unwrap(), out);
            for x in arr {
                self.write(inner, x, out)?;
            }
            return Ok(());
        }
        if let Some(inner) = type_name
            .strip_prefix("optional<")
            .and_then(|x| x.strip_suffix('>'))
        {
            if v.is_null() {
                out.push(0);
            } else {
                out.push(1);
                self.write(inner, v, out)?;
            }
            return Ok(());
        }
        if let Some(inner) = type_name
            .strip_prefix("variant<")
            .and_then(|x| x.strip_suffix('>'))
        {
            // inline variant
            let alts: Vec<String> = inner.split(',').map(|s| s.trim().to_string()).collect();
            let (idx, ty, val) = select_variant_input(&alts, v)
                .map_err(|e| Error::InvalidValue("variant".into(), e))?;
            self.write_varuint32(idx as u32, out);
            return self.write(ty, val, out);
        }

        match self.reg.resolve(type_name)? {
            TypeDesc::Prim(p) => self.write_prim(p, v, out),
            TypeDesc::Struct(sd) => self.write_struct(sd, v, out),
            TypeDesc::Array(inner) => {
                let arr = v.as_array().ok_or_else(|| {
                    Error::InvalidValue(type_name.into(), "expected array".into())
                })?;
                self.write_varuint32(u32::try_from(arr.len()).unwrap(), out);
                for x in arr {
                    self.write(inner, x, out)?;
                }
                Ok(())
            }
            TypeDesc::Optional(inner) => {
                if v.is_null() {
                    out.push(0);
                } else {
                    out.push(1);
                    self.write(inner, v, out)?;
                }
                Ok(())
            }
            TypeDesc::Alias(to) => self.write(to, v, out),
            TypeDesc::Variant(alts) => {
                let (idx, ty, val) = select_variant_input(alts, v)
                    .map_err(|e| Error::InvalidValue("variant".into(), e))?;
                self.write_varuint32(idx as u32, out);
                self.write(ty, val, out)
            }
        }
    }

    fn write_struct(
        &self,
        sd: &StructDesc,
        v: &serde_json::Value,
        out: &mut Vec<u8>,
    ) -> Result<()> {
        let obj = v
            .as_object()
            .ok_or_else(|| Error::InvalidValue(sd.name.clone(), "expected object".into()))?;
        for f in &sd.fields {
            let fv = obj.get(&f.name).ok_or_else(|| {
                Error::InvalidValue(sd.name.clone(), format!("missing field {}", f.name))
            })?;
            self.write(&f.type_name, fv, out)?;
        }
        Ok(())
    }

    fn write_prim(&self, p: &Prim, v: &serde_json::Value, out: &mut Vec<u8>) -> Result<()> {
        match p {
            Prim::Bool => out.push(
                if v.as_bool()
                    .ok_or_else(|| Error::InvalidValue("bool".into(), "expected bool".into()))?
                {
                    1
                } else {
                    0
                },
            ),
            Prim::Int8 => out.push(
                v.as_i64()
                    .ok_or_else(|| Error::InvalidValue("int8".into(), "expected integer".into()))?
                    as i8 as u8,
            ),
            Prim::UInt8 => {
                out.push(v.as_u64().ok_or_else(|| {
                    Error::InvalidValue("uint8".into(), "expected uinteger".into())
                })? as u8)
            }
            Prim::Int16 => write_le(
                out,
                (v.as_i64()
                    .ok_or_else(|| Error::InvalidValue("int16".into(), "expected integer".into()))?
                    as i16)
                    .to_le_bytes(),
            ),
            Prim::UInt16 => write_le(
                out,
                (v.as_u64().ok_or_else(|| {
                    Error::InvalidValue("uint16".into(), "expected uinteger".into())
                })? as u16)
                    .to_le_bytes(),
            ),
            Prim::Int32 => write_le(
                out,
                (v.as_i64()
                    .ok_or_else(|| Error::InvalidValue("int32".into(), "expected integer".into()))?
                    as i32)
                    .to_le_bytes(),
            ),
            Prim::UInt32 => write_le(
                out,
                (v.as_u64().ok_or_else(|| {
                    Error::InvalidValue("uint32".into(), "expected uinteger".into())
                })? as u32)
                    .to_le_bytes(),
            ),
            Prim::Int64 => write_le(
                out,
                (v.as_i64()
                    .ok_or_else(|| Error::InvalidValue("int64".into(), "expected integer".into()))?
                    as i64)
                    .to_le_bytes(),
            ),
            Prim::UInt64 => write_le(
                out,
                (v.as_u64().ok_or_else(|| {
                    Error::InvalidValue("uint64".into(), "expected uinteger".into())
                })? as u64)
                    .to_le_bytes(),
            ),
            Prim::VarUInt32 => {
                let n = if v.is_string() {
                    v.as_str()
                        .unwrap()
                        .parse::<u64>()
                        .map_err(|e| Error::InvalidValue("varuint32".into(), e.to_string()))?
                        as u32
                } else {
                    v.as_u64().ok_or_else(|| {
                        Error::InvalidValue("varuint32".into(), "expected uinteger".into())
                    })? as u32
                };
                self.write_varuint32(n, out)
            }
            Prim::VarInt32 => {
                let n = if v.is_string() {
                    v.as_str()
                        .unwrap()
                        .parse::<i64>()
                        .map_err(|e| Error::InvalidValue("varint32".into(), e.to_string()))?
                        as i32
                } else {
                    v.as_i64().ok_or_else(|| {
                        Error::InvalidValue("varint32".into(), "expected integer".into())
                    })? as i32
                };
                self.write_varint32(n, out)
            }
            Prim::Float32 => write_le(
                out,
                (v.as_f64().ok_or_else(|| {
                    Error::InvalidValue("float32".into(), "expected number".into())
                })? as f32)
                    .to_le_bytes(),
            ),
            Prim::Float64 => write_le(
                out,
                (v.as_f64().ok_or_else(|| {
                    Error::InvalidValue("float64".into(), "expected number".into())
                })? as f64)
                    .to_le_bytes(),
            ),
            Prim::String => {
                let s = v.as_str().ok_or_else(|| {
                    Error::InvalidValue("string".into(), "expected string".into())
                })?;
                self.write_varuint32(u32::try_from(s.as_bytes().len()).unwrap(), out);
                out.extend_from_slice(s.as_bytes());
            }
            Prim::Bytes => {
                if let Some(s) = v.as_str() {
                    let b = parse_hex(s).map_err(|e| Error::InvalidValue("bytes".into(), e))?;
                    self.write_varuint32(u32::try_from(b.len()).unwrap(), out);
                    out.extend_from_slice(&b);
                } else if let Some(arr) = v.as_array() {
                    let mut b = Vec::with_capacity(arr.len());
                    for x in arr {
                        b.push(
                            u8::try_from(x.as_u64().ok_or_else(|| {
                                Error::InvalidValue("bytes".into(), "expected array of u8".into())
                            })?)
                            .unwrap(),
                        );
                    }
                    self.write_varuint32(u32::try_from(b.len()).unwrap(), out);
                    out.extend_from_slice(&b);
                } else {
                    return Err(Error::InvalidValue(
                        "bytes".into(),
                        "expected hex string or number[]".into(),
                    ));
                }
            }
            Prim::Name => {
                let s = v
                    .as_str()
                    .ok_or_else(|| Error::InvalidValue("name".into(), "expected string".into()))?;
                let n = encode_name(s).map_err(|e| Error::InvalidValue("name".into(), e))?;
                write_le(out, n.to_le_bytes());
            }
            Prim::TimePointSec => {
                let ts = parse_time_point_sec(v)?;
                write_le(out, ts.to_le_bytes());
            }
            Prim::TimePoint => {
                let us = parse_time_point(v)?;
                write_le(out, us.to_le_bytes());
            }
            Prim::Checksum256 => {
                let s = v.as_str().ok_or_else(|| {
                    Error::InvalidValue("checksum256".into(), "expected hex string".into())
                })?;
                let b = parse_hex(s).map_err(|e| Error::InvalidValue("checksum256".into(), e))?;
                if b.len() != 32 {
                    return Err(Error::InvalidValue(
                        "checksum256".into(),
                        "expected 32 bytes hex".into(),
                    ));
                }
                out.extend_from_slice(&b);
            }
            Prim::SymbolCode => {
                let s = v.as_str().ok_or_else(|| {
                    Error::InvalidValue("symbol_code".into(), "expected string".into())
                })?;
                let raw = encode_symbol_code(s)?;
                write_le(out, raw.to_le_bytes());
            }
            Prim::Symbol => {
                // accept "4,EOS" or {code, precision}
                let s = v.as_str().ok_or_else(|| {
                    Error::InvalidValue("symbol".into(), "expected string".into())
                })?;
                let parsed = Symbol::from_str(s).map_err(|e| {
                    Error::InvalidValue("symbol".into(), e.to_string())
                })?;
                let packed = parsed.pack().map_err(|e| {
                    Error::InvalidValue("symbol".into(), e.to_string())
                })?;
                write_le(out, packed);
            }
            Prim::Asset => {
                let s = v.as_str().ok_or_else(|| {
                    Error::InvalidValue("asset".into(), "expected string like '1.2345 EOS'".into())
                })?;
                let (amount, code, prec) = parse_asset(s)?;
                write_le(out, amount.to_le_bytes());
                let raw = encode_symbol_raw(&code, prec)?;
                write_le(out, raw.to_le_bytes());
            }
        }
        Ok(())
    }

    fn write_varuint32(&self, mut n: u32, out: &mut Vec<u8>) {
        loop {
            let mut b = (n & 0x7F) as u8;
            n >>= 7;
            if n > 0 {
                b |= 0x80;
            }
            out.push(b);
            if n == 0 {
                break;
            }
        }
    }
    fn write_varint32(&self, n: i32, out: &mut Vec<u8>) {
        let ux = zigzag_encode32(n);
        self.write_varuint32(ux, out);
    }
}

fn write_le<T: AsRef<[u8]>>(out: &mut Vec<u8>, bytes: T) {
    out.extend_from_slice(bytes.as_ref());
}

// =============== Variant helpers ===============

/// Interpret user JSON for a `variant` value and select which alternative to use.
/// Accepted shapes:
/// 1) { "type": "T", "value": ... }
/// 2) { "T": ... } (single-key object)
/// 3) ["T", ...]
/// 4) { "index": N, "value": ... }
fn select_variant_input<'a>(
    alts: &'a [String],
    v: &'a serde_json::Value,
) -> std::result::Result<(usize, &'a str, &'a serde_json::Value), String> {
    if let Some(obj) = v.as_object() {
        if let (Some(t), Some(val)) = (obj.get("type").and_then(|x| x.as_str()), obj.get("value")) {
            if let Some(idx) = alts.iter().position(|x| x == t) {
                return Ok((idx, alts[idx].as_str(), val));
            } else {
                return Err(format!("unknown variant type '{}'", t));
            }
        }
        if obj.len() == 1 {
            let (k, val) = obj.iter().next().unwrap();
            if let Some(idx) = alts.iter().position(|x| x == k) {
                return Ok((idx, alts[idx].as_str(), val));
            } else {
                return Err(format!("unknown variant type '{}'", k));
            }
        }
        if let (Some(idx_v), Some(val)) = (obj.get("index"), obj.get("value")) {
            let idx = idx_v
                .as_u64()
                .ok_or_else(|| "index must be uinteger".to_string())?
                as usize;
            if idx >= alts.len() {
                return Err("index out of range".into());
            }
            return Ok((idx, alts[idx].as_str(), val));
        }
        return Err(
            "object must contain {type,value}, {index,value}, or single key of the alt name".into(),
        );
    }
    if let Some(arr) = v.as_array() {
        if arr.len() == 2 {
            let t = arr[0]
                .as_str()
                .ok_or_else(|| "first array element must be type string".to_string())?;
            let val = &arr[1];
            if let Some(idx) = alts.iter().position(|x| x == t) {
                return Ok((idx, alts[idx].as_str(), val));
            } else {
                return Err(format!("unknown variant type '{}'", t));
            }
        }
        return Err("array form must be [type, value]".into());
    }
    Err("unsupported JSON for variant".into())
}

// =============== EOS encoders & helpers ===============

fn char_to_symbol(c: u8) -> Option<u8> {
    match c {
        b'.' => Some(0),
        b'1'..=b'5' => Some(c - b'1' + 1),
        b'a'..=b'z' => Some(c - b'a' + 6),
        _ => None,
    }
}

/// Encode EOSIO name into its 64-bit representation.
fn encode_name(name: &str) -> std::result::Result<u64, String> {
    // Validation per EOSIO: up to 13 chars; charset .12345abcdefghijklmnopqrstuvwxyz
    let bytes = name.as_bytes();
    if bytes.len() > 13 {
        return Err("name too long".into());
    }
    for (i, &c) in bytes.iter().enumerate() {
        let ok = if i == 12 {
            matches!(c, b'.'|b'1'..=b'5'|b'a'..=b'j')
        } else {
            matches!(c, b'.'|b'1'..=b'5'|b'a'..=b'z')
        };
        if !ok {
            return Err(format!("invalid character '{}' at pos {}", c as char, i));
        }
    }
    let mut value: u64 = 0;
    for i in 0..12 {
        let c = *bytes.get(i).unwrap_or(&b'.');
        let sym = char_to_symbol(c).ok_or_else(|| format!("invalid char '{}'", c as char))? as u64;
        value <<= 5;
        value |= sym;
    }
    // last char uses 4 bits
    let c = *bytes.get(12).unwrap_or(&b'.');
    let sym = char_to_symbol(c).ok_or_else(|| format!("invalid char '{}'", c as char))? as u64;
    value <<= 4;
    value |= sym & 0x0F;
    Ok(value)
}

fn encode_symbol_code(code: &str) -> Result<u64> {
    if code.is_empty() || code.len() > 7 || !code.chars().all(|c| c.is_ascii_uppercase()) {
        return Err(Error::InvalidValue(
            "symbol_code".into(),
            "must be 1..7 uppercase letters".into(),
        ));
    }
    let mut v: u64 = 0;
    for (i, b) in code.bytes().enumerate() {
        v |= (b as u64) << (8 * (i));
    }
    Ok(v)
}

fn encode_symbol_raw(code: &str, precision: u8) -> Result<u64> {
    // uint64: low byte = precision, remaining bytes = symbol code ASCII
    let sc = encode_symbol_code(code)?;
    Ok((sc << 8) | precision as u64)
}

fn parse_asset(s: &str) -> Result<(i64, String, u8)> {
    // "1.2345 EOS"
    let s = s.trim();
    let mut it = s.rsplitn(2, ' ');
    let code = it
        .next()
        .ok_or_else(|| Error::InvalidValue("asset".into(), "missing symbol code".into()))?;
    let amount = it
        .next()
        .ok_or_else(|| Error::InvalidValue("asset".into(), "missing amount".into()))?;
    if !code.chars().all(|c| c.is_ascii_uppercase()) || code.len() == 0 || code.len() > 7 {
        return Err(Error::InvalidValue(
            "asset".into(),
            "bad symbol code".into(),
        ));
    }
    let (int_part, frac_part, prec): (i128, i128, u8) = if let Some(dot) = amount.find('.') {
        let (i, f) = amount.split_at(dot);
        let f = &f[1..];
        let prec = u8::try_from(f.len()).unwrap();
        let i = i
            .parse::<i128>()
            .map_err(|e| Error::InvalidValue("asset".into(), e.to_string()))?;
        let fnum = f
            .parse::<i128>()
            .map_err(|e| Error::InvalidValue("asset".into(), e.to_string()))?;
        (i, fnum, prec)
    } else {
        (
            amount
                .parse::<i128>()
                .map_err(|e| Error::InvalidValue("asset".into(), e.to_string()))?,
            0,
            0,
        )
    };
    let sign = if int_part < 0 { -1i128 } else { 1i128 };
    let abs_i = int_part.abs();
    let scale = 10i128.pow(prec as u32);
    let mut total = abs_i
        .checked_mul(scale)
        .ok_or_else(|| Error::InvalidValue("asset".into(), "overflow".into()))?
        + frac_part;
    total *= sign;
    let amount_i64 = i64::try_from(total)
        .map_err(|_| Error::InvalidValue("asset".into(), "amount out of range".into()))?;
    Ok((amount_i64, code.to_string(), prec))
}

fn parse_time_point_sec(v: &serde_json::Value) -> Result<u32> {
    if let Some(s) = v.as_str() {
        let t = chrono::DateTime::parse_from_rfc3339(s)
            .map_err(|e| Error::InvalidValue("time_point_sec".into(), e.to_string()))?;
        Ok(t.timestamp() as u32)
    } else if let Some(n) = v.as_u64() {
        Ok(n as u32)
    } else {
        Err(Error::InvalidValue(
            "time_point_sec".into(),
            "expected ISO string or u32".into(),
        ))
    }
}

fn parse_time_point(v: &serde_json::Value) -> Result<i64> {
    if let Some(s) = v.as_str() {
        let t = chrono::DateTime::parse_from_rfc3339(s)
            .map_err(|e| Error::InvalidValue("time_point".into(), e.to_string()))?;
        Ok(t.timestamp_micros())
    } else if let Some(n) = v.as_i64() {
        Ok(n)
    } else {
        Err(Error::InvalidValue(
            "time_point".into(),
            "expected ISO string or i64".into(),
        ))
    }
}

fn zigzag_encode32(n: i32) -> u32 {
    ((n << 1) ^ (n >> 31)) as u32
}

fn parse_hex(s: &str) -> std::result::Result<Vec<u8>, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 {
        return Err("hex length must be even".into());
    }
    hex::decode(s).map_err(|e| e.to_string())
}