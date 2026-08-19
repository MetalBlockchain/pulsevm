//! Pure-Rust reader for Antelope/EOSIO binary ABIs and a `bin_to_json` decoder.
//!
//! The point of this crate is to reproduce, in Rust, exactly the JSON an
//! `fc::abi_serializer` would emit for a contract row so that RPC responses
//! match nodeos. That means we care about fc's rendering quirks, not just the
//! raw values: doubles come out as fixed-precision strings, 64-bit integers
//! that don't fit in an int32 are quoted, `bool` renders as `0`/`1`, and so on.
//! Where this crate and intuition disagree, the C++ output wins.

use std::fmt;

use pulsevm_crypto::{
    K1PublicKey,
    K1Signature,
};
use pulsevm_name::Name;
use serde_json::{
    Map,
    Value,
};

#[derive(Debug)]
pub enum AbiError {
    /// Ran off the end of the input while decoding.
    UnexpectedEnd,
    /// A LEB128 varint was longer than its target width allows.
    VarintOverflow,
    /// A type name resolved to nothing we know how to decode.
    UnknownType(String),
    /// A variant tag pointed past the end of the variant's type list.
    BadVariantTag { variant: String, tag: usize },
    /// Type resolution looped (typedef cycle or pathological nesting).
    ResolutionDepthExceeded,
    /// A built-in we recognize by name but don't (yet) decode.
    UnsupportedBuiltin(String),
    /// A crypto value (key/signature) we can't render, e.g. a non-K1 curve.
    Crypto(String),
    /// UTF-8 that wasn't.
    BadUtf8,
}

impl fmt::Display for AbiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AbiError::UnexpectedEnd => write!(f, "unexpected end of input"),
            AbiError::VarintOverflow => write!(f, "varint overflow"),
            AbiError::UnknownType(t) => write!(f, "unknown type `{t}`"),
            AbiError::BadVariantTag { variant, tag } => {
                write!(f, "variant `{variant}` has no type at index {tag}")
            }
            AbiError::ResolutionDepthExceeded => write!(f, "type resolution depth exceeded"),
            AbiError::UnsupportedBuiltin(t) => write!(f, "unsupported built-in `{t}`"),
            AbiError::Crypto(m) => write!(f, "crypto decode failed: {m}"),
            AbiError::BadUtf8 => write!(f, "invalid utf-8 in string"),
        }
    }
}

impl std::error::Error for AbiError {}

type Reader<'a> = &'a [u8];

fn take<'a>(data: &mut &'a [u8], n: usize) -> Result<&'a [u8], AbiError> {
    if data.len() < n {
        return Err(AbiError::UnexpectedEnd);
    }
    let (head, tail) = data.split_at(n);
    *data = tail;
    Ok(head)
}

fn read_u8(data: &mut &[u8]) -> Result<u8, AbiError> {
    Ok(take(data, 1)?[0])
}

fn read_u16(data: &mut &[u8]) -> Result<u16, AbiError> {
    let b = take(data, 2)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32(data: &mut &[u8]) -> Result<u32, AbiError> {
    let b = take(data, 4)?;
    Ok(u32::from_le_bytes(b.try_into().unwrap()))
}

fn read_u64(data: &mut &[u8]) -> Result<u64, AbiError> {
    let b = take(data, 8)?;
    Ok(u64::from_le_bytes(b.try_into().unwrap()))
}

fn read_varuint32(data: &mut &[u8]) -> Result<u32, AbiError> {
    let mut result: u32 = 0;
    let mut shift = 0;
    loop {
        let byte = read_u8(data)?;
        if shift >= 32 {
            return Err(AbiError::VarintOverflow);
        }
        result |= ((byte & 0x7f) as u32) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    Ok(result)
}

fn read_varint32(data: &mut &[u8]) -> Result<i32, AbiError> {
    // zigzag over the unsigned form
    let u = read_varuint32(data)?;
    Ok(((u >> 1) as i32) ^ -((u & 1) as i32))
}

fn read_string(data: &mut &[u8]) -> Result<String, AbiError> {
    let n = read_varuint32(data)? as usize;
    let bytes = take(data, n)?;
    String::from_utf8(bytes.to_vec()).map_err(|_| AbiError::BadUtf8)
}

/// One `type_def`: an alias `new_type_name -> type`.
struct TypeDef {
    new_type_name: String,
    ty: String,
}

/// A struct with an optional base and ordered fields.
struct StructDef {
    name: String,
    base: String,
    fields: Vec<(String, String)>,
}

/// A `variant`: an ordered list of alternative type names selected by tag.
struct VariantDef {
    name: String,
    types: Vec<String>,
}

/// The portion of a table declaration needed by RPC row queries.
struct TableDef {
    name: u64,
    index_type: String,
    ty: String,
}

pub struct Abi {
    types: Vec<TypeDef>,
    structs: Vec<StructDef>,
    variants: Vec<VariantDef>,
    tables: Vec<TableDef>,
}

impl Abi {
    /// Parse the `fc::raw`-packed `abi_def` bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Abi, AbiError> {
        let mut c: Reader = bytes;

        let _version = read_string(&mut c)?;

        let mut types = Vec::new();
        for _ in 0..read_varuint32(&mut c)? {
            types.push(TypeDef {
                new_type_name: read_string(&mut c)?,
                ty: read_string(&mut c)?,
            });
        }

        let mut structs = Vec::new();
        for _ in 0..read_varuint32(&mut c)? {
            let name = read_string(&mut c)?;
            let base = read_string(&mut c)?;
            let mut fields = Vec::new();
            for _ in 0..read_varuint32(&mut c)? {
                fields.push((read_string(&mut c)?, read_string(&mut c)?));
            }
            structs.push(StructDef { name, base, fields });
        }

        // actions: name(u64) + type + ricardian_contract
        for _ in 0..read_varuint32(&mut c)? {
            let _name = read_u64(&mut c)?;
            let _ty = read_string(&mut c)?;
            let _ricardian = read_string(&mut c)?;
        }

        let mut tables = Vec::new();
        for _ in 0..read_varuint32(&mut c)? {
            let name = read_u64(&mut c)?;
            let index_type = read_string(&mut c)?;
            for _ in 0..read_varuint32(&mut c)? {
                let _key_name = read_string(&mut c)?;
            }
            for _ in 0..read_varuint32(&mut c)? {
                let _key_type = read_string(&mut c)?;
            }
            let ty = read_string(&mut c)?;
            tables.push(TableDef {
                name,
                index_type,
                ty,
            });
        }

        // ricardian_clauses: id + body
        for _ in 0..read_varuint32(&mut c)? {
            let _id = read_string(&mut c)?;
            let _body = read_string(&mut c)?;
        }

        // error_messages: error_code(u64) + error_msg
        for _ in 0..read_varuint32(&mut c)? {
            let _code = read_u64(&mut c)?;
            let _msg = read_string(&mut c)?;
        }

        // abi_extensions: (u16 type, bytes)
        for _ in 0..read_varuint32(&mut c)? {
            let _ext_type = read_u16(&mut c)?;
            let n = read_varuint32(&mut c)? as usize;
            let _payload = take(&mut c, n)?;
        }

        // variants and action_results are `may_not_exist`: present only if the
        // producer emitted them, which we detect by leftover bytes.
        let mut variants = Vec::new();
        if !c.is_empty() {
            for _ in 0..read_varuint32(&mut c)? {
                let name = read_string(&mut c)?;
                let mut vtypes = Vec::new();
                for _ in 0..read_varuint32(&mut c)? {
                    vtypes.push(read_string(&mut c)?);
                }
                variants.push(VariantDef {
                    name,
                    types: vtypes,
                });
            }
        }
        if !c.is_empty() {
            for _ in 0..read_varuint32(&mut c)? {
                let _name = read_u64(&mut c)?;
                let _result_type = read_string(&mut c)?;
            }
        }

        Ok(Abi {
            types,
            structs,
            variants,
            tables,
        })
    }

    /// The row struct type for the table whose name encodes to `table_name`.
    pub fn table_row_type(&self, table_name: u64) -> Option<String> {
        self.tables
            .iter()
            .find(|t| t.name == table_name)
            .map(|t| t.ty.clone())
    }

    /// The ABI-declared primary index type for a table (normally `i64`).
    pub fn table_index_type(&self, table_name: u64) -> Option<&str> {
        self.tables
            .iter()
            .find(|t| t.name == table_name)
            .map(|t| t.index_type.as_str())
    }

    /// Decode one value of `type_name`, advancing `data` past the bytes read.
    pub fn bin_to_json(&self, type_name: &str, data: &mut &[u8]) -> Result<Value, AbiError> {
        self.decode(type_name, data, 0)
    }

    fn typedef_target(&self, name: &str) -> Option<&str> {
        self.types
            .iter()
            .find(|t| t.new_type_name == name)
            .map(|t| t.ty.as_str())
    }

    fn find_variant(&self, name: &str) -> Option<&VariantDef> {
        self.variants.iter().find(|v| v.name == name)
    }

    fn find_struct(&self, name: &str) -> Option<&StructDef> {
        self.structs.iter().find(|s| s.name == name)
    }

    fn decode(&self, type_name: &str, data: &mut &[u8], depth: usize) -> Result<Value, AbiError> {
        if depth > 64 {
            return Err(AbiError::ResolutionDepthExceeded);
        }

        if let Some(inner) = type_name.strip_suffix("[]") {
            let count = read_varuint32(data)? as usize;
            let mut out = Vec::with_capacity(count);
            for _ in 0..count {
                out.push(self.decode(inner, data, depth + 1)?);
            }
            return Ok(Value::Array(out));
        }

        if let Some(inner) = type_name.strip_suffix('?') {
            let present = read_u8(data)?;
            if present == 0 {
                return Ok(Value::Null);
            }
            return self.decode(inner, data, depth + 1);
        }

        if let Some(inner) = type_name.strip_suffix('$') {
            // Binary extension: absent when the stream is already exhausted.
            if data.is_empty() {
                return Ok(Value::Null);
            }
            return self.decode(inner, data, depth + 1);
        }

        if let Some(target) = self.typedef_target(type_name) {
            let target = target.to_string();
            return self.decode(&target, data, depth + 1);
        }

        if let Some(variant) = self.find_variant(type_name) {
            let tag = read_varuint32(data)? as usize;
            let selected = variant
                .types
                .get(tag)
                .ok_or_else(|| AbiError::BadVariantTag {
                    variant: variant.name.clone(),
                    tag,
                })?
                .clone();
            let value = self.decode(&selected, data, depth + 1)?;
            return Ok(Value::Array(vec![Value::String(selected), value]));
        }

        if self.find_struct(type_name).is_some() {
            let mut map = Map::new();
            self.decode_struct(type_name, data, depth, &mut map)?;
            return Ok(Value::Object(map));
        }

        decode_builtin(type_name, data)
    }

    fn decode_struct(
        &self,
        name: &str,
        data: &mut &[u8],
        depth: usize,
        out: &mut Map<String, Value>,
    ) -> Result<(), AbiError> {
        let def = self
            .find_struct(name)
            .ok_or_else(|| AbiError::UnknownType(name.to_string()))?;

        if !def.base.is_empty() {
            self.decode_struct(&def.base, data, depth + 1, out)?;
        }

        for (field_name, field_type) in &def.fields {
            // A binary-extension field with nothing left to read is simply
            // omitted, and once one is absent the rest must be too.
            if field_type.ends_with('$') && data.is_empty() {
                break;
            }
            let value = self.decode(field_type, data, depth + 1)?;
            out.insert(field_name.clone(), value);
        }

        Ok(())
    }
}

/// fc quotes 64-bit signed integers that fall outside the int32 range, so a
/// JS consumer never silently loses precision. Smaller widths always fit.
fn json_i64(v: i64) -> Value {
    if v > i32::MAX as i64 || v < i32::MIN as i64 {
        Value::String(v.to_string())
    } else {
        Value::Number(v.into())
    }
}

fn json_u64(v: u64) -> Value {
    if v > i32::MAX as u64 {
        Value::String(v.to_string())
    } else {
        Value::Number(v.into())
    }
}

/// fc renders doubles as a fixed-point string with 17 fractional digits
/// (`%.17f`), which is what preserves the value across the JSON boundary.
fn json_double(v: f64) -> Value {
    Value::String(format!("{v:.17}"))
}

fn decode_builtin(name: &str, data: &mut &[u8]) -> Result<Value, AbiError> {
    let v = match name {
        // In fc, "bool" packs as a byte and renders as the integer 0/1.
        "bool" => json_u64(read_u8(data)? as u64),
        "int8" => json_i64(read_u8(data)? as i8 as i64),
        "uint8" => json_u64(read_u8(data)? as u64),
        "int16" => json_i64(read_u16(data)? as i16 as i64),
        "uint16" => json_u64(read_u16(data)? as u64),
        "int32" => json_i64(read_u32(data)? as i32 as i64),
        "uint32" => json_u64(read_u32(data)? as u64),
        "int64" => json_i64(read_u64(data)? as i64),
        "uint64" => json_u64(read_u64(data)?),
        "int128" => {
            let b = take(data, 16)?;
            Value::String(i128::from_le_bytes(b.try_into().unwrap()).to_string())
        }
        "uint128" => {
            let b = take(data, 16)?;
            Value::String(u128::from_le_bytes(b.try_into().unwrap()).to_string())
        }
        "varint32" => json_i64(read_varint32(data)? as i64),
        "varuint32" => json_u64(read_varuint32(data)? as u64),
        "float32" => {
            let b = take(data, 4)?;
            json_double(f32::from_le_bytes(b.try_into().unwrap()) as f64)
        }
        "float64" => {
            let b = take(data, 8)?;
            json_double(f64::from_le_bytes(b.try_into().unwrap()))
        }
        "name" => Value::String(Name::new(read_u64(data)?).to_string()),
        "string" => Value::String(read_string(data)?),
        "bytes" => {
            let n = read_varuint32(data)? as usize;
            Value::String(hex::encode(take(data, n)?))
        }
        "checksum160" | "ripemd160" => Value::String(hex::encode(take(data, 20)?)),
        "checksum256" | "sha256" => Value::String(hex::encode(take(data, 32)?)),
        "checksum512" => Value::String(hex::encode(take(data, 64)?)),
        "symbol" => Value::String(format_symbol(read_u64(data)?)),
        "symbol_code" => Value::String(symbol_code_string(read_u64(data)?)),
        "asset" => {
            let amount = read_u64(data)? as i64;
            Value::String(format_asset(amount, read_u64(data)?))
        }
        "extended_asset" => {
            let amount = read_u64(data)? as i64;
            let sym = read_u64(data)?;
            let contract = Name::new(read_u64(data)?);
            let mut m = Map::new();
            m.insert("quantity".into(), Value::String(format_asset(amount, sym)));
            m.insert("contract".into(), Value::String(contract.to_string()));
            Value::Object(m)
        }
        "time_point" => Value::String(format_time_point_micros(read_u64(data)? as i64)),
        "time_point_sec" => Value::String(format_datetime(read_u32(data)? as i64, None)),
        "block_timestamp_type" => {
            // slots of 500ms measured from 2000-01-01T00:00:00 UTC
            const BLOCK_EPOCH_SECONDS: i64 = 946_684_800;
            let slot = read_u32(data)? as i64;
            let micros = BLOCK_EPOCH_SECONDS * 1_000_000 + slot * 500_000;
            Value::String(format_time_point_micros(micros))
        }
        "public_key" => Value::String(decode_public_key(data)?),
        "signature" => Value::String(decode_signature(data)?),
        "float128" => return Err(AbiError::UnsupportedBuiltin(name.to_string())),
        _ => return Err(AbiError::UnknownType(name.to_string())),
    };
    Ok(v)
}

/// The ASCII symbol code sits in the upper 7 bytes of the packed u64, low byte
/// first, terminated by a zero byte.
fn symbol_code_string(packed: u64) -> String {
    let mut code = packed >> 8;
    let mut s = String::new();
    while code & 0xff != 0 {
        s.push((code & 0xff) as u8 as char);
        code >>= 8;
    }
    s
}

/// A bare `symbol` renders as `"<precision>,<CODE>"`.
fn format_symbol(packed: u64) -> String {
    let precision = packed & 0xff;
    format!("{},{}", precision, symbol_code_string(packed))
}

/// `asset` renders as the scaled amount followed by the symbol code, e.g.
/// `"1.0000 SYS"`. Precision 0 has no decimal point (and an empty code still
/// leaves the trailing space, matching fc: `"0 "`).
fn format_asset(amount: i64, symbol: u64) -> String {
    let precision = (symbol & 0xff) as usize;
    let code = symbol_code_string(symbol);

    let negative = amount < 0;
    let magnitude = (amount as i128).unsigned_abs();
    let digits = magnitude.to_string();

    let scaled = if precision == 0 {
        digits
    } else {
        let padded = if digits.len() <= precision {
            format!("{:0>width$}", digits, width = precision + 1)
        } else {
            digits
        };
        let point = padded.len() - precision;
        format!("{}.{}", &padded[..point], &padded[point..])
    };

    let sign = if negative { "-" } else { "" };
    format!("{sign}{scaled} {code}")
}

/// fc's `time_point` string: seconds since the unix epoch plus three-digit
/// milliseconds (the sub-millisecond part is truncated).
fn format_time_point_micros(micros: i64) -> String {
    let seconds = micros.div_euclid(1_000_000);
    let millis = (micros.rem_euclid(1_000_000)) / 1000;
    format_datetime(seconds, Some(millis as u32))
}

/// Render unix `seconds` as ISO-8601 UTC, optionally with a millisecond field.
fn format_datetime(seconds: i64, millis: Option<u32>) -> String {
    let days = seconds.div_euclid(86_400);
    let secs_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;

    let base = format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}");
    match millis {
        Some(ms) => format!("{base}.{ms:03}"),
        None => base,
    }
}

/// Howard Hinnant's civil-from-days: days since 1970-01-01 to (year, month, day).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (year + if month <= 2 { 1 } else { 0 }, month, day)
}

fn decode_public_key(data: &mut &[u8]) -> Result<String, AbiError> {
    // 1 curve-tag byte + 33 compressed bytes for K1; other curves aren't
    // exercised by the RPC golden, so refuse them loudly.
    let tag = read_u8(data)?;
    if tag != 0 {
        return Err(AbiError::Crypto(format!("unsupported key type {tag}")));
    }
    let rest = take(data, 33)?;
    let mut packed = [0u8; 34];
    packed[1..].copy_from_slice(rest);
    K1PublicKey::from_packed(&packed)
        .map(|k| k.to_string())
        .map_err(|e| AbiError::Crypto(format!("{e:?}")))
}

fn decode_signature(data: &mut &[u8]) -> Result<String, AbiError> {
    let tag = read_u8(data)?;
    if tag != 0 {
        return Err(AbiError::Crypto(format!(
            "unsupported signature type {tag}"
        )));
    }
    let rest = take(data, 65)?;
    let mut packed = [0u8; 66];
    packed[1..].copy_from_slice(rest);
    K1Signature::from_packed(&packed)
        .map(|s| s.to_string())
        .map_err(|e| AbiError::Crypto(format!("{e:?}")))
}
