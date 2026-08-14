//! JSON formatting for the node's read-only RPC endpoints.
//!
//! These are the pure output halves of `get_table_rows`, `get_currency_balance`,
//! `get_currency_stats`, `get_table_by_scope` and `get_account`. Each takes
//! values that a caller has already read out of the arena and returns the
//! `serde_json::Value` that nodeos would have produced through `fc::json`. The
//! goal is semantic equality with the C++ output, so the fc rendering quirks
//! (quoted 64-bit ints, `%.17f` doubles, asset strings, empty names printing as
//! `""`) all have to survive the trip. Anything that decodes contract rows is
//! delegated to `pulsevm_abi`, which already reproduces those quirks; the small
//! bits reproduced here (asset and time_point strings) mirror it deliberately.

use pulsevm_abi::{
    Abi,
    AbiError,
};
use pulsevm_name::Name;
use serde_json::{
    Map,
    Value,
    json,
};

#[derive(Debug)]
pub enum RpcError {
    /// An ABI-driven decode of a row failed.
    Abi(AbiError),
    /// A caller asked for JSON rows but supplied no ABI to decode them with.
    MissingAbi,
    /// A raw value was the wrong length for the type it was meant to hold.
    MalformedRow(String),
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcError::Abi(e) => write!(f, "abi decode failed: {e}"),
            RpcError::MissingAbi => write!(f, "json rows requested without an abi"),
            RpcError::MalformedRow(m) => write!(f, "malformed row: {m}"),
        }
    }
}

impl std::error::Error for RpcError {}

impl From<AbiError> for RpcError {
    fn from(e: AbiError) -> Self {
        RpcError::Abi(e)
    }
}

/// One row as `get_table_rows` sees it: the paying account and the raw value.
pub struct TableRow {
    pub payer: u64,
    pub data: Vec<u8>,
}

/// `get_table_rows`: the `{ rows, more, next_key }` envelope.
///
/// With `json_mode` each row's `data` is the ABI-decoded object (which requires
/// `abi` to be present); otherwise it is the lowercase hex of the raw bytes.
pub fn format_table_rows(
    json_mode: bool,
    abi: Option<&Abi>,
    row_type: &str,
    rows: &[TableRow],
    more: bool,
    next_key: &str,
    show_payer: bool,
) -> Result<Value, RpcError> {
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let data = if json_mode {
            let abi = abi.ok_or(RpcError::MissingAbi)?;
            abi.bin_to_json(row_type, &mut &row.data[..])?
        } else {
            Value::String(hex::encode(&row.data))
        };
        if show_payer {
            out.push(json!({
                "data": data,
                "payer": Name::new(row.payer).to_string(),
            }));
        } else {
            out.push(data);
        }
    }

    Ok(json!({
        "rows": out,
        "more": more,
        "next_key": next_key,
    }))
}

/// `get_currency_balance`: an array of asset strings, one per `accounts` row.
///
/// Each row is a single 16-byte `asset` (i64 amount LE, then the 8-byte packed
/// symbol). Row order is preserved into the array.
pub fn format_currency_balance(rows: &[Vec<u8>]) -> Result<Value, RpcError> {
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let (amount, symbol) = read_asset(row)?;
        out.push(Value::String(format_asset(amount, symbol)));
    }
    Ok(Value::Array(out))
}

/// `get_currency_stats`: `{ "<CODE>": { supply, max_supply, issuer } }`.
///
/// Each `stat` row is `asset supply` + `asset max_supply` + `name issuer`, and
/// the object is keyed by the supply symbol's code.
pub fn format_currency_stats(rows: &[Vec<u8>]) -> Result<Value, RpcError> {
    let mut map = Map::new();
    for row in rows {
        if row.len() < 40 {
            return Err(RpcError::MalformedRow(format!(
                "stat row is {} bytes, need 40",
                row.len()
            )));
        }
        let (supply_amount, supply_symbol) = read_asset(&row[0..16])?;
        let (max_amount, max_symbol) = read_asset(&row[16..32])?;
        let issuer = Name::new(u64::from_le_bytes(row[32..40].try_into().unwrap()));

        let code = symbol_code_string(supply_symbol);
        map.insert(
            code,
            json!({
                "supply": format_asset(supply_amount, supply_symbol),
                "max_supply": format_asset(max_amount, max_symbol),
                "issuer": issuer.to_string(),
            }),
        );
    }
    Ok(Value::Object(map))
}

/// One row of `get_table_by_scope`: a `(code, scope, table, payer)` key plus the
/// number of rows the table holds in that scope.
pub struct ScopeRow {
    pub code: u64,
    pub scope: u64,
    pub table: u64,
    pub payer: u64,
    pub count: u32,
}

/// `get_table_by_scope`: `{ rows, more }` where `more` is the next scope's name
/// (or `""` when the listing is exhausted).
pub fn format_table_by_scope(rows: &[ScopeRow], more: &str) -> Value {
    let rows: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "code": Name::new(r.code).to_string(),
                "scope": Name::new(r.scope).to_string(),
                "table": Name::new(r.table).to_string(),
                "payer": Name::new(r.payer).to_string(),
                "count": r.count,
            })
        })
        .collect();

    json!({ "rows": rows, "more": more })
}

/// A single key of an authority.
pub struct KeyWeight {
    /// Already-rendered `PUB_K1_...` string; the caller decodes the key.
    pub key: String,
    pub weight: u16,
}

/// A `(actor, permission)` reference weighted inside an authority.
pub struct PermissionLevelWeight {
    pub actor: u64,
    pub permission: u64,
    pub weight: u16,
}

/// A time-lock entry of an authority.
pub struct WaitWeight {
    pub wait_sec: u32,
    pub weight: u16,
}

pub struct Authority {
    pub threshold: u32,
    pub keys: Vec<KeyWeight>,
    pub accounts: Vec<PermissionLevelWeight>,
    pub waits: Vec<WaitWeight>,
}

pub struct Permission {
    pub perm_name: u64,
    /// Parent permission name; the root (`owner`) has `0`, which prints as `""`.
    pub parent: u64,
    pub required_auth: Authority,
    pub linked_actions: Vec<LinkedAction>,
}

pub struct LinkedAction {
    pub account: u64,
    /// An empty action name is represented by an absent fc optional.
    pub action: Option<u64>,
}

/// A resource (net/cpu) usage window as `get_account` reports it.
pub struct ResourceLimit {
    pub used: i64,
    pub available: i64,
    pub max: i64,
    /// Microseconds since the unix epoch; rendered as a `time_point`.
    pub last_usage_update_time: i64,
    pub current_used: i64,
}

/// Everything `get_account` puts in its response object. The row-derived
/// sub-objects (`total_resources`, `voter_info`, ...) arrive already decoded so
/// this layer only has to place them; absent ones are `Value::Null`.
pub struct AccountInfo {
    pub account_name: u64,
    pub head_block_num: u32,
    /// Microseconds since the unix epoch.
    pub head_block_time: i64,
    pub privileged: bool,
    pub last_code_update: i64,
    pub created: i64,
    /// The core-token balance as an asset string, or `None` when unset.
    pub core_liquid_balance: Option<String>,
    pub ram_quota: i64,
    pub net_weight: i64,
    pub cpu_weight: i64,
    pub net_limit: ResourceLimit,
    pub cpu_limit: ResourceLimit,
    pub ram_usage: i64,
    pub permissions: Vec<Permission>,
    pub total_resources: Value,
    pub self_delegated_bandwidth: Value,
    pub refund_request: Value,
    pub voter_info: Value,
    pub rex_info: Value,
    pub subjective_cpu_bill_limit: ResourceLimit,
    /// Actions linked to `eosio.any`; empty unless the caller fills it in.
    pub eosio_any_linked_actions: Vec<LinkedAction>,
}

/// `get_account`: assemble the full account response object.
pub fn format_account_info(info: &AccountInfo) -> Value {
    let permissions: Vec<Value> = info.permissions.iter().map(format_permission).collect();
    let eosio_any_linked_actions: Vec<Value> = info
        .eosio_any_linked_actions
        .iter()
        .map(format_linked_action)
        .collect();

    let mut value = json!({
        "account_name": Name::new(info.account_name).to_string(),
        "head_block_num": info.head_block_num,
        "head_block_time": format_time_point_micros(info.head_block_time),
        "privileged": info.privileged,
        "last_code_update": format_time_point_micros(info.last_code_update),
        "created": format_time_point_micros(info.created),
        "ram_quota": info.ram_quota,
        "net_weight": info.net_weight,
        "cpu_weight": info.cpu_weight,
        "net_limit": format_resource_limit(&info.net_limit),
        "cpu_limit": format_resource_limit(&info.cpu_limit),
        "ram_usage": info.ram_usage,
        "permissions": permissions,
        "total_resources": info.total_resources,
        "self_delegated_bandwidth": info.self_delegated_bandwidth,
        "refund_request": info.refund_request,
        "voter_info": info.voter_info,
        "rex_info": info.rex_info,
        "subjective_cpu_bill_limit": format_resource_limit(&info.subjective_cpu_bill_limit),
        "eosio_any_linked_actions": eosio_any_linked_actions,
    });
    // `core_liquid_balance` is an fc optional: nodeos omits the property when
    // the token-contract row is absent instead of serializing it as null.
    if let Some(balance) = &info.core_liquid_balance {
        value
            .as_object_mut()
            .unwrap()
            .insert("core_liquid_balance".into(), Value::String(balance.clone()));
    }
    value
}

fn format_permission(p: &Permission) -> Value {
    let keys: Vec<Value> = p
        .required_auth
        .keys
        .iter()
        .map(|k| json!({ "key": k.key, "weight": k.weight }))
        .collect();
    let accounts: Vec<Value> = p
        .required_auth
        .accounts
        .iter()
        .map(|a| {
            json!({
                "permission": {
                    "actor": Name::new(a.actor).to_string(),
                    "permission": Name::new(a.permission).to_string(),
                },
                "weight": a.weight,
            })
        })
        .collect();
    let waits: Vec<Value> = p
        .required_auth
        .waits
        .iter()
        .map(|w| json!({ "wait_sec": w.wait_sec, "weight": w.weight }))
        .collect();

    json!({
        "perm_name": Name::new(p.perm_name).to_string(),
        "parent": Name::new(p.parent).to_string(),
        "required_auth": {
            "threshold": p.required_auth.threshold,
            "keys": keys,
            "accounts": accounts,
            "waits": waits,
        },
        "linked_actions": p.linked_actions.iter().map(format_linked_action).collect::<Vec<_>>(),
    })
}

fn format_linked_action(link: &LinkedAction) -> Value {
    let mut value = json!({
        "account": Name::new(link.account).to_string(),
    });
    if let Some(action) = link.action {
        value.as_object_mut().unwrap().insert(
            "action".into(),
            Value::String(Name::new(action).to_string()),
        );
    }
    value
}

fn format_resource_limit(r: &ResourceLimit) -> Value {
    json!({
        "used": json_i64(r.used),
        "available": json_i64(r.available),
        "max": json_i64(r.max),
        "last_usage_update_time": format_time_point_micros(r.last_usage_update_time),
        "current_used": json_i64(r.current_used),
    })
}

/// fc quotes 64-bit values outside the int32 range in JSON.
fn json_i64(value: i64) -> Value {
    if value > i32::MAX as i64 || value < i32::MIN as i64 {
        Value::String(value.to_string())
    } else {
        Value::Number(value.into())
    }
}

/// Split a 16-byte `asset` into `(amount, packed_symbol)`.
fn read_asset(bytes: &[u8]) -> Result<(i64, u64), RpcError> {
    if bytes.len() < 16 {
        return Err(RpcError::MalformedRow(format!(
            "asset is {} bytes, need 16",
            bytes.len()
        )));
    }
    let amount = i64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let symbol = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    Ok((amount, symbol))
}

/// fc's `time_point` string: unix seconds with a truncated three-digit
/// millisecond field. Mirrors `pulsevm_abi`'s private renderer so RPC times and
/// ABI-decoded times agree.
pub fn format_time_point_micros(micros: i64) -> String {
    let seconds = micros.div_euclid(1_000_000);
    let millis = (micros.rem_euclid(1_000_000)) / 1000;

    let days = seconds.div_euclid(86_400);
    let secs_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}")
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

/// The ASCII symbol code in the upper 7 bytes of a packed symbol, low byte
/// first, zero-terminated.
fn symbol_code_string(packed: u64) -> String {
    let mut code = packed >> 8;
    let mut s = String::new();
    while code & 0xff != 0 {
        s.push((code & 0xff) as u8 as char);
        code >>= 8;
    }
    s
}

/// `asset` as `"<scaled amount> <CODE>"`, matching fc (and `pulsevm_abi`):
/// precision 0 has no decimal point, and an empty code still leaves the space.
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
