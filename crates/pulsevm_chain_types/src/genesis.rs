//! Pure-Rust `genesis_state` parsing.
//!
//! The node receives `genesis.json` from AvalancheGo and needs three things out
//! of it to author the chain's initial state: the initial timestamp, the initial
//! block-signing key, and the initial chain configuration. This mirrors what the
//! C++ `genesis_state` (parsed by fc's reflection) yields, without the bridge:
//!
//!   * the timestamp is an ISO-8601 UTC datetime (optionally with a fractional second), read to
//!     microseconds since the 1970 epoch exactly as `fc::time_point::from_iso_string` does;
//!   * the key is a `PUB_K1_` string;
//!   * `initial_configuration` overlays onto the C++ struct defaults, so a `genesis.json` that
//!     omits `max_transaction_delay` / `deferred_trx_expiration_window` (both value-initialised to
//!     0 in the `genesis_state` aggregate initialiser) leaves them 0.

use pulsevm_crypto::k1::K1PublicKey;
use pulsevm_error::ChainError;
use serde::Deserialize;

use crate::config::ChainConfigV0;

/// The default `max_action_return_value_size` (config.hpp), used when the field
/// is absent — matching the `genesis_state` aggregate initialiser, which sets it.
const DEFAULT_MAX_ACTION_RETURN_VALUE_SIZE: u32 = 256;

/// The subset of `genesis_state` the chain actually consumes at initialization.
#[derive(Clone, Debug)]
pub struct GenesisState {
    /// Microseconds since the 1970 epoch (the fc `time_point` count).
    pub initial_timestamp_micros: i64,
    /// The genesis block-signing / system-account key.
    pub initial_key: K1PublicKey,
    /// The initial chain configuration.
    pub initial_configuration: ChainConfigV0,
    /// `max_action_return_value_size`: not part of `ChainConfigV0` (the runtime
    /// does not track it), but part of the genesis serialization the chain id is
    /// computed over, so it is carried here.
    pub max_action_return_value_size: u32,
}

impl GenesisState {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ChainError> {
        let s = std::str::from_utf8(bytes)
            .map_err(|e| ChainError::ParseError(format!("genesis is not UTF-8: {e}")))?;
        Self::from_json(s)
    }

    pub fn from_json(json: &str) -> Result<Self, ChainError> {
        let raw: RawGenesis = serde_json::from_str(json)
            .map_err(|e| ChainError::ParseError(format!("failed to parse genesis json: {e}")))?;

        let initial_timestamp_micros = iso_to_micros(&raw.initial_timestamp)?;
        let initial_key = K1PublicKey::from_string(&raw.initial_key)
            .map_err(|e| ChainError::GenesisError(format!("invalid genesis key: {e:?}")))?;
        let max_action_return_value_size = raw.initial_configuration.max_action_return_value_size;
        let initial_configuration = raw.initial_configuration.into();

        Ok(GenesisState {
            initial_timestamp_micros,
            initial_key,
            initial_configuration,
            max_action_return_value_size,
        })
    }

    /// The initial key packed to its 34-byte on-chain form.
    pub fn initial_key_packed(&self) -> [u8; 34] {
        self.initial_key.to_packed()
    }

    /// The chain id: `sha256(fc::raw::pack(genesis_state))`, reproducing
    /// `genesis_state::compute_chain_id`. fc packs the reflected members in
    /// declaration order — the timestamp as an i64 microsecond count, the key in
    /// its 34-byte form, then each `chain_config` field as its little-endian
    /// integer (ending with `max_action_return_value_size`).
    pub fn compute_chain_id(&self) -> [u8; 32] {
        let mut buf: Vec<u8> = Vec::with_capacity(34 + 8 + 19 * 4);
        let c = &self.initial_configuration;

        buf.extend_from_slice(&self.initial_timestamp_micros.to_le_bytes());
        buf.extend_from_slice(&self.initial_key.to_packed());

        buf.extend_from_slice(&c.max_block_net_usage.to_le_bytes());
        buf.extend_from_slice(&c.target_block_net_usage_pct.to_le_bytes());
        buf.extend_from_slice(&c.max_transaction_net_usage.to_le_bytes());
        buf.extend_from_slice(&c.base_per_transaction_net_usage.to_le_bytes());
        buf.extend_from_slice(&c.net_usage_leeway.to_le_bytes());
        buf.extend_from_slice(&c.context_free_discount_net_usage_num.to_le_bytes());
        buf.extend_from_slice(&c.context_free_discount_net_usage_den.to_le_bytes());
        buf.extend_from_slice(&c.max_block_cpu_usage.to_le_bytes());
        buf.extend_from_slice(&c.target_block_cpu_usage_pct.to_le_bytes());
        buf.extend_from_slice(&c.max_transaction_cpu_usage.to_le_bytes());
        buf.extend_from_slice(&c.min_transaction_cpu_usage.to_le_bytes());
        buf.extend_from_slice(&c.max_transaction_lifetime.to_le_bytes());
        buf.extend_from_slice(&c.deferred_trx_expiration_window.to_le_bytes());
        buf.extend_from_slice(&c.max_transaction_delay.to_le_bytes());
        buf.extend_from_slice(&c.max_inline_action_size.to_le_bytes());
        buf.extend_from_slice(&c.max_inline_action_depth.to_le_bytes());
        buf.extend_from_slice(&c.max_authority_depth.to_le_bytes());
        buf.extend_from_slice(&self.max_action_return_value_size.to_le_bytes());

        pulsevm_crypto::Digest::hash(&buf).0
    }
}

#[derive(Deserialize)]
struct RawGenesis {
    initial_timestamp: String,
    initial_key: String,
    initial_configuration: RawConfig,
}

/// The genesis `chain_config` fields. Unknown keys (e.g.
/// `max_action_return_value_size`, which the runtime does not track) are ignored;
/// `deferred_trx_expiration_window` and `max_transaction_delay` default to 0 to
/// match the C++ `genesis_state` aggregate initialiser, which omits them.
#[derive(Deserialize)]
struct RawConfig {
    max_block_net_usage: u64,
    target_block_net_usage_pct: u32,
    max_transaction_net_usage: u32,
    base_per_transaction_net_usage: u32,
    net_usage_leeway: u32,
    context_free_discount_net_usage_num: u32,
    context_free_discount_net_usage_den: u32,
    max_block_cpu_usage: u32,
    target_block_cpu_usage_pct: u32,
    max_transaction_cpu_usage: u32,
    min_transaction_cpu_usage: u32,
    max_transaction_lifetime: u32,
    #[serde(default)]
    deferred_trx_expiration_window: u32,
    #[serde(default)]
    max_transaction_delay: u32,
    max_inline_action_size: u32,
    max_inline_action_depth: u16,
    max_authority_depth: u16,
    #[serde(default = "default_max_action_return_value_size")]
    max_action_return_value_size: u32,
}

fn default_max_action_return_value_size() -> u32 {
    DEFAULT_MAX_ACTION_RETURN_VALUE_SIZE
}

impl From<RawConfig> for ChainConfigV0 {
    fn from(c: RawConfig) -> Self {
        ChainConfigV0 {
            max_block_net_usage: c.max_block_net_usage,
            target_block_net_usage_pct: c.target_block_net_usage_pct,
            max_transaction_net_usage: c.max_transaction_net_usage,
            base_per_transaction_net_usage: c.base_per_transaction_net_usage,
            net_usage_leeway: c.net_usage_leeway,
            context_free_discount_net_usage_num: c.context_free_discount_net_usage_num,
            context_free_discount_net_usage_den: c.context_free_discount_net_usage_den,
            max_block_cpu_usage: c.max_block_cpu_usage,
            target_block_cpu_usage_pct: c.target_block_cpu_usage_pct,
            max_transaction_cpu_usage: c.max_transaction_cpu_usage,
            min_transaction_cpu_usage: c.min_transaction_cpu_usage,
            max_transaction_lifetime: c.max_transaction_lifetime,
            deferred_trx_expiration_window: c.deferred_trx_expiration_window,
            max_transaction_delay: c.max_transaction_delay,
            max_inline_action_size: c.max_inline_action_size,
            max_inline_action_depth: c.max_inline_action_depth,
            max_authority_depth: c.max_authority_depth,
        }
    }
}

/// Parse an ISO-8601 UTC datetime (`YYYY-MM-DDTHH:MM:SS`, with an optional
/// `.fraction`) to microseconds since 1970-01-01, matching
/// `fc::time_point::from_iso_string`. No timezone offset is accepted (fc treats
/// the value as UTC), and the fractional part is read to microsecond precision.
fn iso_to_micros(s: &str) -> Result<i64, ChainError> {
    let bad = || ChainError::ParseError(format!("invalid genesis timestamp: {s:?}"));

    let (main, frac) = match s.split_once('.') {
        Some((m, f)) => (m, Some(f)),
        None => (s, None),
    };
    let (date, time) = main.split_once('T').ok_or_else(bad)?;

    let mut d = date.split('-');
    let year: i64 = d.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    let month: i64 = d.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    let day: i64 = d.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    if d.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err(bad());
    }

    let mut t = time.split(':');
    let hour: i64 = t.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    let minute: i64 = t.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    let second: i64 = t.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    if t.next().is_some() || hour >= 24 || minute >= 60 || second >= 61 {
        return Err(bad());
    }

    let days = days_from_civil(year, month, day);
    let secs = days * 86_400 + hour * 3_600 + minute * 60 + second;
    let mut micros = secs.checked_mul(1_000_000).ok_or_else(bad)?;

    if let Some(f) = frac {
        if f.is_empty() || !f.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad());
        }
        // fc keeps microsecond precision: take the first 6 fractional digits and
        // right-pad, so ".5" is 500000us and ".000001" is 1us.
        let mut buf = [b'0'; 6];
        for (i, b) in f.bytes().take(6).enumerate() {
            buf[i] = b;
        }
        let frac_us: i64 = std::str::from_utf8(&buf)
            .unwrap()
            .parse()
            .map_err(|_| bad())?;
        micros += frac_us;
    }

    Ok(micros)
}

/// Days from 1970-01-01 to the given civil date (Howard Hinnant's algorithm),
/// valid for the full proleptic Gregorian range.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_epoch_and_fractions() {
        assert_eq!(iso_to_micros("1970-01-01T00:00:00").unwrap(), 0);
        // 2023-01-01T00:00:00 UTC = 1672531200s.
        assert_eq!(
            iso_to_micros("2023-01-01T00:00:00").unwrap(),
            1_672_531_200_000_000
        );
        assert_eq!(
            iso_to_micros("2023-01-01T00:00:00.500").unwrap(),
            1_672_531_200_500_000
        );
        assert_eq!(
            iso_to_micros("2023-01-01T00:00:00.000001").unwrap(),
            1_672_531_200_000_001
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!(iso_to_micros("not-a-date").is_err());
        assert!(iso_to_micros("2023-13-01T00:00:00").is_err());
        assert!(iso_to_micros("2023-01-01T25:00:00").is_err());
    }

    /// Known-answer for `compute_chain_id`, frozen from the C++
    /// `genesis_state::compute_chain_id` oracle (see
    /// `pulsevm_database/tests/genesis_chain_id_cross_validation.rs`). Guards the
    /// fc-pack layout after the bridge is gone.
    #[test]
    fn chain_id_matches_frozen_oracle() {
        let json = r#"{
            "initial_timestamp": "2023-01-01T00:00:00",
            "initial_key": "PUB_K1_8fsJkG5ka4o1G1wBhySUavHuGqstcjtXMrquxiRWVcYw8ZvZLX",
            "initial_configuration": {
                "max_block_net_usage": 1048576,
                "target_block_net_usage_pct": 1000,
                "max_transaction_net_usage": 524288,
                "base_per_transaction_net_usage": 12,
                "net_usage_leeway": 500,
                "context_free_discount_net_usage_num": 20,
                "context_free_discount_net_usage_den": 100,
                "max_block_cpu_usage": 3000000000,
                "target_block_cpu_usage_pct": 2500,
                "max_transaction_cpu_usage": 1000000000,
                "min_transaction_cpu_usage": 100000,
                "max_transaction_lifetime": 3600,
                "deferred_trx_expiration_window": 600,
                "max_transaction_delay": 3888000,
                "max_inline_action_size": 4096,
                "max_inline_action_depth": 6,
                "max_authority_depth": 6,
                "max_action_return_value_size": 256
            }
        }"#;
        let id = GenesisState::from_json(json).unwrap().compute_chain_id();
        let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "0c880c391f7d695f3d64e57e1ee396c9b26b8e089f440d917493d83a2df9c306"
        );
    }

    #[test]
    fn defaults_omitted_delay_fields_to_zero() {
        let json = r#"{
            "initial_timestamp": "2023-01-01T00:00:00",
            "initial_key": "PUB_K1_8fsJkG5ka4o1G1wBhySUavHuGqstcjtXMrquxiRWVcYw8ZvZLX",
            "initial_configuration": {
                "max_block_net_usage": 1048576,
                "target_block_net_usage_pct": 1000,
                "max_transaction_net_usage": 524288,
                "base_per_transaction_net_usage": 12,
                "net_usage_leeway": 500,
                "context_free_discount_net_usage_num": 20,
                "context_free_discount_net_usage_den": 100,
                "max_block_cpu_usage": 3000000000,
                "target_block_cpu_usage_pct": 2500,
                "max_transaction_cpu_usage": 1000000000,
                "min_transaction_cpu_usage": 100000,
                "max_transaction_lifetime": 4294967295,
                "max_inline_action_size": 4096,
                "max_inline_action_depth": 6,
                "max_authority_depth": 6,
                "max_action_return_value_size": 256
            }
        }"#;
        let g = GenesisState::from_json(json).unwrap();
        assert_eq!(g.initial_configuration.max_transaction_delay, 0);
        assert_eq!(g.initial_configuration.deferred_trx_expiration_window, 0);
        assert_eq!(g.initial_configuration.max_block_cpu_usage, 3_000_000_000);
    }
}
