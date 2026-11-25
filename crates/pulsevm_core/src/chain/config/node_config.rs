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
    /// Checkpoint hash this operator derived itself, by converting its own
    /// Leap snapshot at H (`xpr_import_check --leap-snapshot`). A migration
    /// restore refuses to start unless it equals the genesis pin and the
    /// manifest hash, so a checkpoint delivered by anyone else is only
    /// trusted once it matches what this operator derived independently.
    /// Required for a migration restore.
    #[serde(default)]
    pub migration_local_checkpoint_sha256: Option<String>,
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
    /// Size at which the arena's write-ahead log is folded into a new
    /// checkpoint. The log is what lets a node killed between clean shutdowns
    /// restart at its last accepted block; the checkpoint rewrites all state,
    /// so this is the one place a long-running node pauses to write it. Lower
    /// it to bound crash-recovery replay, raise it to checkpoint less often.
    #[serde(default = "default_arena_wal_max_bytes")]
    pub arena_wal_max_bytes: u64,
    /// A state summary no more than this many blocks ahead of this node's last
    /// accepted block is skipped, and the node catches up by fetching those blocks
    /// instead. A snapshot install rebases the block log onto the synced tip and
    /// drops its history (a node 5 blocks behind lost 78 MB of it), and it is the
    /// path on which a restart can stall, so it is kept for a node that is far
    /// behind. Zero syncs whenever any summary is ahead.
    #[serde(default = "default_state_sync_min_blocks_behind")]
    pub state_sync_min_blocks_behind: u64,

    /// A state summary is built for every block whose height is a multiple of this
    /// (when that block is accepted), and offered to peers that need to state-sync.
    /// The host takes a summary only if over half the validator weight returns the
    /// same one for the same height in one vote, so every validator has to offer the
    /// same heights; a summary of whatever the tip happens to be never agrees. Each
    /// build stops the node for as long as it takes to copy the state (about a second
    /// at mainnet size) on every validator at once, so this is large: 4096 blocks is
    /// about half an hour at two blocks a second. Zero turns summaries off. A node
    /// that joins when no summary is old enough catches up by fetching blocks.
    #[serde(default = "default_state_summary_interval")]
    pub state_summary_interval: u64,

    /// A summary is offered only once it is this many blocks below the tip, so a
    /// peer that picks it is not racing the head.
    #[serde(default = "default_state_summary_min_age")]
    pub state_summary_min_age: u64,
    /// Log the arena state root at info level every this many blocks. Zero (the
    /// default) logs none. The root hashes all state, so it costs time in
    /// proportion to it; it exists so the nodes of a test network can be
    /// compared with each other. It is a setting here and not an environment
    /// variable because a host such as MetalGo starts the plugin with a minimal
    /// environment of its own.
    #[serde(default)]
    pub state_root_log_every: u64,
    /// Shut this process down cleanly if it accepts no blocks for this many
    /// seconds. Zero disables the watchdog. This is a node-local operational
    /// safeguard for rehearsals and deliberately halted chains; it does not
    /// affect block validity or consensus.
    #[serde(default)]
    pub dead_chain_shutdown_after_secs: u64,
    /// Log threshold: `trace`, `debug`, `info` (the default), `warn` or `error`.
    /// At debug the controller also hashes all state after every block to print
    /// it. Set here for the same reason as above.
    #[serde(default)]
    pub log_level: Option<String>,
}

fn default_state_summary_interval() -> u64 {
    4096
}

fn default_state_summary_min_age() -> u64 {
    8
}

fn default_state_sync_min_blocks_behind() -> u64 {
    1024
}

fn default_arena_wal_max_bytes() -> u64 {
    pulsevm_database::DEFAULT_ARENA_WAL_MAX_BYTES
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
        assert!(cfg.native_system_contract);
        assert!(cfg.state_history_enabled);
        assert!(!cfg.allow_replay_recovery);
        assert_eq!(cfg.ram_usage_monitor_max_series, 0);
        assert_eq!(
            cfg.arena_wal_max_bytes,
            pulsevm_database::DEFAULT_ARENA_WAL_MAX_BYTES
        );
        assert_eq!(cfg.state_root_log_every, 0);
        assert_eq!(cfg.dead_chain_shutdown_after_secs, 0);
        assert_eq!(cfg.log_level, None);
        assert_eq!(cfg.state_sync_min_blocks_behind, 1024);
        assert_eq!(cfg.state_summary_interval, 4096);
        assert_eq!(cfg.state_summary_min_age, 8);
    }

    #[test]
    fn dead_chain_shutdown_timeout_is_opt_in() {
        let cfg: NodeConfig = serde_json::from_str(
            r#"{"producer_name":"pulse","producer_key":"PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez","dead_chain_shutdown_after_secs":3600}"#,
        )
        .unwrap();
        assert_eq!(cfg.dead_chain_shutdown_after_secs, 3600);
    }

    #[test]
    fn the_state_sync_threshold_is_configurable() {
        let cfg: NodeConfig = serde_json::from_str(
            r#"{"producer_name":"pulse","producer_key":"PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez","state_sync_min_blocks_behind":20}"#,
        )
        .unwrap();
        assert_eq!(cfg.state_sync_min_blocks_behind, 20);
    }

    #[test]
    fn logging_is_set_in_the_chain_config() {
        let cfg: NodeConfig = serde_json::from_str(
            r#"{"producer_name":"pulse","producer_key":"PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez","state_root_log_every":1,"log_level":"debug"}"#,
        )
        .unwrap();
        assert_eq!(cfg.state_root_log_every, 1);
        assert_eq!(cfg.log_level.as_deref(), Some("debug"));
    }

    #[test]
    fn wal_checkpoint_threshold_is_configurable() {
        let cfg: NodeConfig = serde_json::from_str(
            r#"{"producer_name":"pulse","producer_key":"PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez","arena_wal_max_bytes":1048576}"#,
        )
        .unwrap();
        assert_eq!(cfg.arena_wal_max_bytes, 1_048_576);
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
