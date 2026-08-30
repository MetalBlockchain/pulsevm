use std::str::FromStr;

use pulsevm_name::Name;
use serde::Deserialize;

use crate::crypto::PrivateKey;

#[derive(Debug, Clone, Deserialize)]
pub struct NodeConfig {
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
        assert!(cfg.native_system_contract);
    }
}
