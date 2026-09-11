//! Opt-in phase and action-family timing for offline replay optimization.
//!
//! This module is observation-only and disabled by default. It deliberately
//! reports aggregated intervals rather than logging every action, keeping the
//! profiling overhead small enough to measure representative Mainnet windows.

use std::{
    cmp::Reverse,
    collections::BTreeMap,
    sync::{
        LazyLock,
        Mutex,
    },
    time::Duration,
};

use spdlog::info;

use crate::chain::name::Name;

static ENABLED: LazyLock<bool> =
    LazyLock::new(|| std::env::var_os("PULSEVM_REPLAY_PROFILE").is_some());
static REPORT_INTERVAL: LazyLock<u32> = LazyLock::new(|| {
    std::env::var("PULSEVM_REPLAY_PROFILE_INTERVAL")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(1_000)
});
static PROFILE: LazyLock<Mutex<ReplayProfile>> =
    LazyLock::new(|| Mutex::new(ReplayProfile::default()));

#[derive(Clone, Copy, Debug, Default)]
pub struct WasmTiming {
    pub total: Duration,
    pub module: Duration,
    pub store: Duration,
    pub reset: Duration,
    pub instantiate: Duration,
    pub apply: Duration,
    pub compiled: bool,
    pub reused_instance: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockTiming {
    pub total: Duration,
    pub expired: Duration,
    pub onblock: Duration,
    pub transactions: Duration,
    pub native_flush: Duration,
    pub merkle: Duration,
    pub resources: Duration,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NativeBotTiming {
    pub total: Duration,
    pub admission: Duration,
    pub metadata: Duration,
    pub decode: Duration,
    pub cache_clone: Duration,
    pub bot_rows: Duration,
    pub oracle_rows: Duration,
    pub cache_commit: Duration,
    pub inline_auth: Duration,
    pub transaction_and_ram: Duration,
    pub receipts: Duration,
    pub resources: Duration,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NativeOnblockTiming {
    pub total: Duration,
    pub metadata: Duration,
    pub state_transition: Duration,
    pub account_usage: Duration,
    pub receipt: Duration,
    pub resources: Duration,
}

#[derive(Clone, Copy, Debug, Default)]
struct TimingStats {
    calls: u64,
    nanos: u128,
}

impl TimingStats {
    fn add(&mut self, duration: Duration) {
        self.calls += 1;
        self.nanos += duration.as_nanos();
    }

    fn milliseconds(self) -> f64 {
        self.nanos as f64 / 1_000_000.0
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct WasmStats {
    calls: u64,
    compiled: u64,
    reused: u64,
    total: u128,
    module: u128,
    store: u128,
    reset: u128,
    instantiate: u128,
    apply: u128,
}

impl WasmStats {
    fn add(&mut self, timing: WasmTiming) {
        self.calls += 1;
        self.compiled += u64::from(timing.compiled);
        self.reused += u64::from(timing.reused_instance);
        self.total += timing.total.as_nanos();
        self.module += timing.module.as_nanos();
        self.store += timing.store.as_nanos();
        self.reset += timing.reset.as_nanos();
        self.instantiate += timing.instantiate.as_nanos();
        self.apply += timing.apply.as_nanos();
    }
}

#[derive(Debug, Default)]
struct ReplayProfile {
    blocks: u64,
    block: BlockTimingNanos,
    transaction_paths: BTreeMap<&'static str, TimingStats>,
    native_declines: BTreeMap<&'static str, u64>,
    native_code_declines: BTreeMap<([u8; 32], [u8; 32]), u64>,
    wasm: BTreeMap<(u64, u64, [u8; 32]), WasmStats>,
    native_bot: NativeBotTimingNanos,
    native_onblock: NativeOnblockTimingNanos,
    read_only_wasm: ReadOnlyWasmCacheStats,
}

#[derive(Clone, Copy, Debug, Default)]
struct ReadOnlyWasmCacheStats {
    hits: u64,
    misses: u64,
    promotions: u64,
    inline_declines: u64,
    mutation_declines: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct NativeBotTimingNanos {
    calls: u64,
    total: u128,
    admission: u128,
    metadata: u128,
    decode: u128,
    cache_clone: u128,
    bot_rows: u128,
    oracle_rows: u128,
    cache_commit: u128,
    inline_auth: u128,
    transaction_and_ram: u128,
    receipts: u128,
    resources: u128,
}

#[derive(Clone, Copy, Debug, Default)]
struct NativeOnblockTimingNanos {
    calls: u64,
    total: u128,
    metadata: u128,
    state_transition: u128,
    account_usage: u128,
    receipt: u128,
    resources: u128,
}

#[derive(Clone, Copy, Debug, Default)]
struct BlockTimingNanos {
    total: u128,
    expired: u128,
    onblock: u128,
    transactions: u128,
    native_flush: u128,
    merkle: u128,
    resources: u128,
}

pub fn enabled() -> bool {
    *ENABLED
}

pub fn record_transaction(path: &'static str, duration: Duration) {
    if !enabled() {
        return;
    }
    if let Ok(mut profile) = PROFILE.lock() {
        profile
            .transaction_paths
            .entry(path)
            .or_default()
            .add(duration);
    }
}

pub fn record_native_decline(reason: &'static str) {
    if !enabled() {
        return;
    }
    if let Ok(mut profile) = PROFILE.lock() {
        *profile.native_declines.entry(reason).or_default() += 1;
    }
}

pub fn record_native_code_decline(bot_code_hash: [u8; 32], oracle_code_hash: [u8; 32]) {
    if !enabled() {
        return;
    }
    if let Ok(mut profile) = PROFILE.lock() {
        *profile
            .native_code_declines
            .entry((bot_code_hash, oracle_code_hash))
            .or_default() += 1;
    }
}

pub fn record_wasm(account: u64, action: u64, code_hash: [u8; 32], timing: WasmTiming) {
    if !enabled() {
        return;
    }
    if let Ok(mut profile) = PROFILE.lock() {
        profile
            .wasm
            .entry((account, action, code_hash))
            .or_default()
            .add(timing);
    }
}

pub fn record_native_bot(timing: NativeBotTiming) {
    if !enabled() {
        return;
    }
    if let Ok(mut profile) = PROFILE.lock() {
        let stats = &mut profile.native_bot;
        stats.calls += 1;
        stats.total += timing.total.as_nanos();
        stats.admission += timing.admission.as_nanos();
        stats.metadata += timing.metadata.as_nanos();
        stats.decode += timing.decode.as_nanos();
        stats.cache_clone += timing.cache_clone.as_nanos();
        stats.bot_rows += timing.bot_rows.as_nanos();
        stats.oracle_rows += timing.oracle_rows.as_nanos();
        stats.cache_commit += timing.cache_commit.as_nanos();
        stats.inline_auth += timing.inline_auth.as_nanos();
        stats.transaction_and_ram += timing.transaction_and_ram.as_nanos();
        stats.receipts += timing.receipts.as_nanos();
        stats.resources += timing.resources.as_nanos();
    }
}

pub fn record_native_onblock(timing: NativeOnblockTiming) {
    if !enabled() {
        return;
    }
    if let Ok(mut profile) = PROFILE.lock() {
        let stats = &mut profile.native_onblock;
        stats.calls += 1;
        stats.total += timing.total.as_nanos();
        stats.metadata += timing.metadata.as_nanos();
        stats.state_transition += timing.state_transition.as_nanos();
        stats.account_usage += timing.account_usage.as_nanos();
        stats.receipt += timing.receipt.as_nanos();
        stats.resources += timing.resources.as_nanos();
    }
}

pub fn record_read_only_wasm_probe(hit: bool) {
    if !enabled() {
        return;
    }
    if let Ok(mut profile) = PROFILE.lock() {
        if hit {
            profile.read_only_wasm.hits += 1;
        } else {
            profile.read_only_wasm.misses += 1;
        }
    }
}

pub fn record_read_only_wasm_finish(promoted: bool, scheduled_inline: bool) {
    if !enabled() {
        return;
    }
    if let Ok(mut profile) = PROFILE.lock() {
        if promoted {
            profile.read_only_wasm.promotions += 1;
        } else if scheduled_inline {
            profile.read_only_wasm.inline_declines += 1;
        } else {
            profile.read_only_wasm.mutation_declines += 1;
        }
    }
}

pub fn record_block(block_num: u32, timing: BlockTiming) {
    if !enabled() {
        return;
    }
    let Ok(mut profile) = PROFILE.lock() else {
        return;
    };
    profile.blocks += 1;
    profile.block.total += timing.total.as_nanos();
    profile.block.expired += timing.expired.as_nanos();
    profile.block.onblock += timing.onblock.as_nanos();
    profile.block.transactions += timing.transactions.as_nanos();
    profile.block.native_flush += timing.native_flush.as_nanos();
    profile.block.merkle += timing.merkle.as_nanos();
    profile.block.resources += timing.resources.as_nanos();

    if !block_num.is_multiple_of(*REPORT_INTERVAL) {
        return;
    }

    let snapshot = std::mem::take(&mut *profile);
    drop(profile);
    let ms = |nanos: u128| nanos as f64 / 1_000_000.0;
    info!(
        "replay profile block={} blocks={} total_ms={:.3} expired_ms={:.3} onblock_ms={:.3} transactions_ms={:.3} native_flush_ms={:.3} merkle_ms={:.3} resources_ms={:.3}",
        block_num,
        snapshot.blocks,
        ms(snapshot.block.total),
        ms(snapshot.block.expired),
        ms(snapshot.block.onblock),
        ms(snapshot.block.transactions),
        ms(snapshot.block.native_flush),
        ms(snapshot.block.merkle),
        ms(snapshot.block.resources),
    );
    for (path, stats) in snapshot.transaction_paths {
        info!(
            "replay profile path={} calls={} total_ms={:.3} mean_us={:.3}",
            path,
            stats.calls,
            stats.milliseconds(),
            stats.nanos as f64 / stats.calls.max(1) as f64 / 1_000.0,
        );
    }
    let bot = snapshot.native_bot;
    if bot.calls > 0 {
        info!(
            "replay profile native_bot calls={} total_ms={:.3} mean_us={:.3} admission_ms={:.3} metadata_ms={:.3} decode_ms={:.3} cache_clone_ms={:.3} bot_rows_ms={:.3} oracle_rows_ms={:.3} cache_commit_ms={:.3} inline_auth_ms={:.3} transaction_ram_ms={:.3} receipts_ms={:.3} resources_ms={:.3}",
            bot.calls,
            ms(bot.total),
            bot.total as f64 / bot.calls as f64 / 1_000.0,
            ms(bot.admission),
            ms(bot.metadata),
            ms(bot.decode),
            ms(bot.cache_clone),
            ms(bot.bot_rows),
            ms(bot.oracle_rows),
            ms(bot.cache_commit),
            ms(bot.inline_auth),
            ms(bot.transaction_and_ram),
            ms(bot.receipts),
            ms(bot.resources),
        );
    }
    let onblock = snapshot.native_onblock;
    if onblock.calls > 0 {
        info!(
            "replay profile native_onblock calls={} total_ms={:.3} mean_us={:.3} metadata_ms={:.3} transition_ms={:.3} account_usage_ms={:.3} receipt_ms={:.3} resources_ms={:.3}",
            onblock.calls,
            ms(onblock.total),
            onblock.total as f64 / onblock.calls as f64 / 1_000.0,
            ms(onblock.metadata),
            ms(onblock.state_transition),
            ms(onblock.account_usage),
            ms(onblock.receipt),
            ms(onblock.resources),
        );
    }
    let read_only = snapshot.read_only_wasm;
    if read_only.hits + read_only.misses > 0 {
        info!(
            "replay profile read_only_wasm_cache hits={} misses={} promotions={} inline_declines={} mutation_declines={}",
            read_only.hits,
            read_only.misses,
            read_only.promotions,
            read_only.inline_declines,
            read_only.mutation_declines,
        );
    }
    for (reason, calls) in snapshot.native_declines {
        info!("replay profile native_decline={} calls={}", reason, calls,);
    }
    for ((bot_code_hash, oracle_code_hash), calls) in snapshot.native_code_declines {
        info!(
            "replay profile native_code_decline bot_hash={} oracle_hash={} calls={}",
            hex::encode(bot_code_hash),
            hex::encode(oracle_code_hash),
            calls,
        );
    }
    let mut wasm = snapshot.wasm.into_iter().collect::<Vec<_>>();
    wasm.sort_unstable_by_key(|(_, stats)| Reverse(stats.total));
    for ((account, action, code_hash), stats) in wasm.into_iter().take(12) {
        info!(
            "replay profile wasm={}::{} code_hash={} calls={} compiled={} reused={} total_ms={:.3} module_ms={:.3} store_ms={:.3} reset_ms={:.3} instantiate_ms={:.3} apply_ms={:.3}",
            Name::new(account),
            Name::new(action),
            hex::encode(code_hash),
            stats.calls,
            stats.compiled,
            stats.reused,
            ms(stats.total),
            ms(stats.module),
            ms(stats.store),
            ms(stats.reset),
            ms(stats.instantiate),
            ms(stats.apply),
        );
    }
}
