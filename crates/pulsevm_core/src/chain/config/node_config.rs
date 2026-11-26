use std::str::FromStr;

use pulsevm_name::Name;
use serde::{
    Deserialize,
    Deserializer,
};
use spdlog::{
    Level,
    LevelFilter,
};

use crate::{
    ChainError,
    crypto::PrivateKey,
};

#[derive(Debug, Clone, Deserialize)]
pub struct NodeConfig {
    /// Minimum severity emitted by the PulseVM plugin.
    #[serde(
        default = "default_log_level",
        deserialize_with = "deserialize_log_level"
    )]
    pub log_level: LevelFilter,
    // Root account used by the native system contract.  PulseVM defaults to
    // `pulse`; XPR/Antelope state imports set this to `eosio`.
    #[serde(default = "default_system_account")]
    pub system_account: Name,
    // Whether PulseVM's native system handlers should be used when the root
    // account receives an action. Imported XPR state should set this false so
    // its deployed eosio.system WASM remains authoritative.
    #[serde(default = "default_native_system_contract")]
    pub native_system_contract: bool,
    /// Validate and produce block signatures using Antelope's block-header
    /// state digest (header + blockroot merkle + pending schedule hash). This is
    /// required for canonical XPR history replay; Pulse migration chains leave
    /// it disabled because they start a new block-signing domain.
    #[serde(default)]
    pub antelope_block_signatures: bool,
    /// Emit per-block trace and chain-state SHiP logs. Nodes enable this by
    /// default; one-shot migration replays may disable it because the canonical
    /// source history already exists and only the final Arena state is needed.
    /// Keep this setting fixed for a data directory: enabling it after skipped
    /// blocks requires rebasing the state-history logs at the current revision.
    #[serde(default = "default_state_history_enabled")]
    pub state_history_enabled: bool,
    /// Allow a replay process to truncate accepted block-log entries newer
    /// than its durable Arena revision and replay those blocks from its source.
    /// This is only for explicit offline/follow replay jobs; normal nodes keep
    /// strict block-log and database revision matching.
    #[serde(default)]
    pub allow_replay_recovery: bool,
    // Name of the block producer, must be a valid EOSIO name (up to 12 characters, a-z, 1-5)
    pub producer_name: Name,
    // Private key of the block producer, used for signing blocks and transactions
    pub producer_key: PrivateKey,
    // Size of the memory mapped database in bytes
    #[serde(default = "default_db_size")]
    pub db_size: u64,
    /// Optional Pulse Arena snapshot produced by the XPR migration tool. When
    /// supplied, it is restored before controller startup and normal Arena
    /// genesis authoring is skipped.
    #[serde(default)]
    pub migration_checkpoint: Option<String>,
    /// Manifest emitted beside `migration_checkpoint`. It binds the checkpoint
    /// bytes and revision to the source state-history export.
    #[serde(default)]
    pub migration_manifest: Option<String>,
    // Wall-clock ceiling on how long a single transaction may spend executing
    // before it is abandoned, in milliseconds. This is a SUBJECTIVE, node-local
    // guard (it depends on this machine's speed, not the transaction's result), so
    // it protects against a native/host code path that the deterministic op
    // metering can't bound; it never affects consensus. Measured against raw
    // wall-clock, which includes module compilation. Generous by default (matching
    // the 30s deadline the C++ layer uses) so it only catches genuine runaways, not
    // a slow-but-legitimate compile of a large contract on a slow machine; a
    // producer would tune it down.
    #[serde(default = "default_max_transaction_time_ms")]
    pub max_transaction_time_ms: u32,
    /// Maximum number of `(code, scope, table, payer)` RAM usage series exposed
    /// through the VM metrics endpoint. Zero disables continuous monitoring.
    /// The database applies a hard upper bound to prevent unbounded labels.
    #[serde(default)]
    pub ram_usage_monitor_max_series: usize,
}

impl NodeConfig {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ChainError> {
        serde_json::from_slice(bytes)
            .map_err(|e| ChainError::ParseError(format!("failed to parse node config JSON: {e}")))
    }
}

fn default_log_level() -> LevelFilter {
    LevelFilter::MoreSevereEqual(Level::Info)
}

fn deserialize_log_level<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<LevelFilter, D::Error> {
    let value = String::deserialize(deserializer)?;
    if value.eq_ignore_ascii_case("off") {
        return Ok(LevelFilter::Off);
    }
    value
        .parse::<Level>()
        .map(LevelFilter::MoreSevereEqual)
        .map_err(|_| {
            serde::de::Error::custom(
                "invalid log_level: expected trace, debug, info, warn, error, critical, or off",
            )
        })
}

fn default_db_size() -> u64 {
    20 * 1024 * 1024 * 1024 // 20 GB
}

fn default_system_account() -> Name {
    Name::from_str("pulse").expect("pulse is a valid system account name")
}

fn default_native_system_contract() -> bool {
    true
}

fn default_state_history_enabled() -> bool {
    true
}

fn default_max_transaction_time_ms() -> u32 {
    30_000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_account_defaults_to_pulse() {
        let cfg: NodeConfig = serde_json::from_str(
            r#"{"producer_name":"pulse","producer_key":"PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez"}"#,
        )
        .unwrap();
        assert_eq!(cfg.system_account, Name::from_str("pulse").unwrap());
        assert_eq!(cfg.log_level, LevelFilter::MoreSevereEqual(Level::Info));
        assert!(cfg.native_system_contract);
        assert!(cfg.state_history_enabled);
        assert!(!cfg.allow_replay_recovery);
        assert_eq!(cfg.ram_usage_monitor_max_series, 0);
    }

    #[test]
    fn log_level_accepts_severities_and_off_and_rejects_typos() {
        let mut config = serde_json::json!({
            "producer_name": "pulse",
            "producer_key": PrivateKey::random().to_string(),
        });
        for (value, expected) in [
            ("DEBUG", LevelFilter::MoreSevereEqual(Level::Debug)),
            ("warn", LevelFilter::MoreSevereEqual(Level::Warn)),
            ("off", LevelFilter::Off),
        ] {
            config["log_level"] = value.into();
            let parsed = NodeConfig::from_bytes(&serde_json::to_vec(&config).unwrap()).unwrap();
            assert_eq!(parsed.log_level, expected);
        }
        config["log_level"] = "verbose".into();
        let error = NodeConfig::from_bytes(&serde_json::to_vec(&config).unwrap()).unwrap_err();
        assert!(error.to_string().contains("invalid log_level"));
        assert!(!error.to_string().contains("producer_key"));
    }

    #[test]
    fn replay_recovery_is_opt_in() {
        let cfg: NodeConfig = serde_json::from_str(
            r#"{"producer_name":"pulse","producer_key":"PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez","allow_replay_recovery":true}"#,
        )
        .unwrap();
        assert!(cfg.allow_replay_recovery);
    }

    #[test]
    fn ram_usage_monitor_series_limit_is_configurable() {
        let cfg: NodeConfig = serde_json::from_str(
            r#"{"producer_name":"pulse","producer_key":"PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez","ram_usage_monitor_max_series":512}"#,
        )
        .unwrap();
        assert_eq!(cfg.ram_usage_monitor_max_series, 512);
    }
}
