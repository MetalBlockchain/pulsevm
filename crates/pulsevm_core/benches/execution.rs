//! Execution benchmark and per-stage profiler.
//!
//! Part A profiles where a single `execute_transaction` spends its time
//! (signature recovery / authority check / WASM setup / WASM exec / finalize) —
//! the breakdown that tells us whether the remaining optimization bets target a
//! stage that actually costs anything. The per-stage numbers require the
//! `profiling` feature; without it only the aggregate throughput prints.
//!
//! Part B drives the block lifecycle (build then accept the same block) so the
//! re-execution cost — build executes, accept re-executes — is visible at the
//! block level.
//!
//! Run:
//!   cargo bench -p pulsevm_core --bench execution --features profiling
//!
//! (`cargo bench` builds in release, which is what makes the numbers meaningful.)

use chrono::Utc;
use pulsevm_core::{
    ACTIVE_NAME, PULSE_NAME,
    asset::{Asset, Symbol},
    block::BlockStatus,
    controller::Controller,
    crypto::PrivateKey,
    id::Id,
    mempool::Mempool,
    profiling::{self, Group},
    pulse_contract::{NewAccount, SetCode},
    transaction::{Action, PackedTransaction, Transaction, TransactionHeader},
};
use pulsevm_ffi::{Authority, KeyWeight, PermissionLevel, TimePointSec};
use pulsevm_name::Name;
use pulsevm_proc_macros::{NumBytes, Read, Write};
use pulsevm_serialization::Write;
use serde_json::json;
use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};
use tempfile::env::temp_dir;

// Warm up before profiling so we measure steady state (module already compiled
// and cached), not the one-off LLVM compile of the contract.
const WARMUP_TXS: usize = 50;
const PROFILE_TXS: usize = 3000;
const BLOCK_TXS: usize = 300;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes)]
struct Issue {
    to: Name,
    quantity: Asset,
    memo: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes)]
struct Transfer {
    from: Name,
    to: Name,
    quantity: Asset,
    memo: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes)]
struct Create {
    issuer: Name,
    max_supply: Asset,
}

fn main() {
    println!("=== PulseVM execution benchmark ===");
    let profiled = !profiling::snapshot().is_empty();
    if !profiled {
        println!(
            "(per-stage profile disabled — rebuild with `--features profiling` for the breakdown)\n"
        );
    }

    // Part A — profile a transfer against progressively larger chainbase state.
    // Extra accounts bloat the account/permission indices every tx must search,
    // so this shows whether the FFI find/lookup cost grows with state size (the
    // premise behind state-delta / FFI batching) or stays flat.
    let sizes = account_sizes();
    println!(
        "Part A — transfer profile vs state size (extra accounts: {:?})",
        sizes
    );
    let mut results = Vec::new();
    for &n in &sizes {
        results.push(run_size(n));
    }
    print_scaling(&results, profiled);

    // Detailed per-stage/per-op breakdown at the largest state.
    if profiled {
        if let Some(last) = results.last() {
            println!(
                "\nPart A detail — {} extra accounts ({:.0} tx/s):",
                last.n_extra, last.tps
            );
            print_profile(last.wall, last.txs);
        }
    }

    println!();
    lifecycle_throughput();
}

struct SizeResult {
    n_extra: usize,
    txs: usize,
    wall: Duration,
    tps: f64,
    // per-op nanos and ops/tx for the two read/write categories, plus FFI share.
    find_ns: f64,
    find_per_tx: f64,
    modify_ns: f64,
    ffi_ops_per_tx: f64,
    ffi_pct: f64,
}

/// Set up a fresh chain, create `n_extra` throwaway accounts to grow the state,
/// then profile a steady-state alice->bob transfer.
fn run_size(n_extra: usize) -> SizeResult {
    let (mut controller, private_key) = setup();
    let ts = controller.last_accepted_block().timestamp().clone();
    let status = BlockStatus::Benchmarking;
    let chain_id = controller.chain_id().clone();

    for i in 0..n_extra {
        controller
            .execute_transaction(&create_account(&private_key, nth_name(i), chain_id), &ts, &status)
            .unwrap();
    }

    for i in 0..WARMUP_TXS {
        controller
            .execute_transaction(&transfer_tx(&private_key, &chain_id, i), &ts, &status)
            .unwrap();
    }

    profiling::reset();
    let start = Instant::now();
    for i in 0..PROFILE_TXS {
        controller
            .execute_transaction(&transfer_tx(&private_key, &chain_id, WARMUP_TXS + i), &ts, &status)
            .unwrap();
    }
    let wall = start.elapsed();

    let snap = profiling::snapshot();
    let stat = |m: profiling::Metric| snap.iter().find(|(x, _)| *x == m).map(|(_, s)| *s).unwrap_or_default();
    let per_op_ns = |s: profiling::MetricStat| if s.calls > 0 { s.total.as_nanos() as f64 / s.calls as f64 } else { 0.0 };
    let find = stat(profiling::Metric::DbFind);
    let modify = stat(profiling::Metric::DbModify);
    let ffi_sum: Duration = snap
        .iter()
        .filter(|(m, _)| profiling::group(*m) == Group::FfiState)
        .map(|(_, s)| s.total)
        .sum();
    let ffi_calls: u64 = snap
        .iter()
        .filter(|(m, _)| profiling::group(*m) == Group::FfiState)
        .map(|(_, s)| s.calls)
        .sum();

    SizeResult {
        n_extra,
        txs: PROFILE_TXS,
        wall,
        tps: PROFILE_TXS as f64 / wall.as_secs_f64(),
        find_ns: per_op_ns(find),
        find_per_tx: find.calls as f64 / PROFILE_TXS as f64,
        modify_ns: per_op_ns(modify),
        ffi_ops_per_tx: ffi_calls as f64 / PROFILE_TXS as f64,
        ffi_pct: ffi_sum.as_secs_f64() / wall.as_secs_f64() * 100.0,
    }
}

fn print_scaling(results: &[SizeResult], profiled: bool) {
    println!(
        "  {:>12}  {:>10}  {:>10}",
        "extra accts", "tx/s", "µs/tx"
    );
    for r in results {
        println!(
            "  {:>12}  {:>10.0}  {:>10.2}",
            r.n_extra,
            r.tps,
            r.wall.as_secs_f64() * 1e6 / r.txs as f64,
        );
    }
    if profiled {
        println!(
            "  {:>12}  {:>12}  {:>12}  {:>12}  {:>8}",
            "extra accts", "find ns/op", "find/tx", "modify ns/op", "ffi %"
        );
        for r in results {
            println!(
                "  {:>12}  {:>12.0}  {:>12.1}  {:>12.0}  {:>7.1}%",
                r.n_extra, r.find_ns, r.find_per_tx, r.modify_ns, r.ffi_pct,
            );
        }
        println!(
            "  (if find ns/op climbs with state, the FFI/state boundary matters at scale;\n   if it stays flat, execution-side costs dominate regardless of state size)"
        );
    }
}

fn account_sizes() -> Vec<usize> {
    // override with e.g. BENCH_ACCOUNTS=0,50000,500000
    if let Ok(v) = std::env::var("BENCH_ACCOUNTS") {
        let parsed: Vec<usize> = v.split(',').filter_map(|s| s.trim().parse().ok()).collect();
        if !parsed.is_empty() {
            return parsed;
        }
    }
    vec![0, 20_000, 100_000]
}

/// Part B — build a block of transfers, then accept it. On this baseline the
/// accept re-executes what build already ran; the two timings show that gap.
fn lifecycle_throughput() {
    let (mut controller, private_key) = setup();
    let chain_id = controller.chain_id().clone();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    // Warm the module cache so build doesn't pay the one-time LLVM compile that
    // accept would then skip — otherwise accept looks artificially cheaper.
    let ts = controller.last_accepted_block().timestamp().clone();
    for i in 0..WARMUP_TXS {
        controller
            .execute_transaction(&transfer_tx(&private_key, &chain_id, 10_000_000 + i), &ts, &BlockStatus::Benchmarking)
            .unwrap();
    }

    let mut mempool = Mempool::new();
    for i in 0..BLOCK_TXS {
        mempool.add_transaction(transfer_tx(&private_key, &chain_id, i));
    }

    let build_start = Instant::now();
    let block = match rt.block_on(controller.build_block(&mut mempool)) {
        Ok(b) => b,
        Err(e) => {
            println!("Part B — skipped (build_block failed: {e})");
            return;
        }
    };
    let build_elapsed = build_start.elapsed();
    let n = block.transactions.len();

    let accept_start = Instant::now();
    if let Err(e) = controller.accept_block(&block.id().unwrap(), &mut mempool) {
        println!("Part B — build measured, accept failed: {e}");
        return;
    }
    let accept_elapsed = accept_start.elapsed();

    println!("Part B — block lifecycle ({n} transfers/block)");
    println!(
        "  build : {:.3?}  =>  {:.0} tx/s",
        build_elapsed,
        n as f64 / build_elapsed.as_secs_f64()
    );
    println!(
        "  accept: {:.3?}  =>  {:.0} tx/s   (re-executes the block on this baseline)",
        accept_elapsed,
        n as f64 / accept_elapsed.as_secs_f64()
    );
    let total = build_elapsed + accept_elapsed;
    println!(
        "  total : {:.3?}  =>  {:.0} tx/s effective   (accept/build = {:.2}x)",
        total,
        n as f64 / total.as_secs_f64(),
        accept_elapsed.as_secs_f64() / build_elapsed.as_secs_f64().max(f64::MIN_POSITIVE),
    );
}

fn print_profile(total_wall: Duration, txs: usize) {
    let snap = profiling::snapshot();
    if snap.is_empty() {
        return;
    }
    let txs = txs as f64;

    // Execution stages partition the wall time; FFI/state ops are a lens *into*
    // the wasm-exec stage (host calls happen during it), so they are reported
    // separately rather than summed with the stages.
    let exec: Vec<_> = snap.iter().filter(|(m, _)| profiling::group(*m) == Group::Execution).collect();
    let ffi: Vec<_> = snap.iter().filter(|(m, _)| profiling::group(*m) == Group::FfiState).collect();

    let exec_sum: Duration = exec.iter().map(|(_, s)| s.total).sum();
    println!(
        "  execution stages (sum {:.3?} = {:.0}% of wall):",
        exec_sum,
        exec_sum.as_secs_f64() / total_wall.as_secs_f64() * 100.0
    );
    for (m, s) in &exec {
        print_row(profiling::metric_name(*m), s.total, exec_sum, s.calls, txs);
    }

    let ffi_sum: Duration = ffi.iter().map(|(_, s)| s.total).sum();
    let ffi_calls: u64 = ffi.iter().map(|(_, s)| s.calls).sum();
    println!(
        "  FFI/state boundary (sum {:.3?} = {:.0}% of wall, {:.1} ops/tx):",
        ffi_sum,
        ffi_sum.as_secs_f64() / total_wall.as_secs_f64() * 100.0,
        ffi_calls as f64 / txs,
    );
    for (m, s) in &ffi {
        print_row(profiling::metric_name(*m), s.total, ffi_sum, s.calls, txs);
    }
    println!(
        "  note: object field accessors (get_payer/get_value/...) are cxx calls not yet counted;"
    );
    println!("        the FFI figures are lock-guarded Database ops only.");
}

fn print_row(name: &str, total: Duration, group_sum: Duration, calls: u64, txs: f64) {
    let pct = if group_sum.as_nanos() > 0 {
        total.as_nanos() as f64 / group_sum.as_nanos() as f64 * 100.0
    } else {
        0.0
    };
    let per_call = if calls > 0 {
        total / calls as u32
    } else {
        Duration::ZERO
    };
    println!(
        "    {:<34} {:>5.1}%  {:>10.3?}  ({:>5.1}/tx, {:.2?}/call)",
        name,
        pct,
        total,
        calls as f64 / txs,
        per_call,
    );
}

// --- setup: a controller with pulse.token deployed and alice funded ---

fn setup() -> (Controller, PrivateKey) {
    let chain_id =
        Id::from_str("c8c4a47932fc0a938972f48f32489e7e91f024697e498ceb3d3c3afcf28f68b6").unwrap();
    let private_key =
        PrivateKey::from_str("PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez").unwrap();
    let mut controller = Controller::new();
    let config_bytes = json!({ "producer_name": "pulse", "producer_key": private_key.to_string() })
        .to_string()
        .into_bytes();
    let genesis_bytes = generate_genesis();
    let temp_path = get_temp_dir().to_str().unwrap().to_string();
    controller
        .initialize(&chain_id, &config_bytes, &genesis_bytes, &temp_path)
        .unwrap();

    let ts = controller.last_accepted_block().timestamp().clone();
    let status = BlockStatus::Benchmarking;
    let mut exec = |tx: PackedTransaction| controller.execute_transaction(&tx, &ts, &status).unwrap();

    let token = Name::from_str("pulse.token").unwrap();
    let alice = Name::from_str("alice").unwrap();
    let bob = Name::from_str("bob").unwrap();
    let eos = Symbol::from_str("4,EOS").unwrap();

    exec(create_account(&private_key, token, chain_id));
    exec(create_account(&private_key, alice, chain_id));
    exec(create_account(&private_key, bob, chain_id));
    exec(set_code(&private_key, token, load_token_wasm(), chain_id));
    exec(call(
        &private_key,
        token,
        Name::from_str("create").unwrap(),
        &Create { issuer: token, max_supply: Asset::new(1_000_000_000, eos) },
        chain_id,
        token,
    ));
    exec(call(
        &private_key,
        token,
        Name::from_str("issue").unwrap(),
        &Issue { to: token, quantity: Asset::new(1_000_000_000, eos), memo: "i".into() },
        chain_id,
        token,
    ));
    // Fund alice so she can pay for every transfer in the benchmark.
    exec(call(
        &private_key,
        token,
        Name::from_str("transfer").unwrap(),
        &Transfer { from: token, to: alice, quantity: Asset::new(900_000_000, eos), memo: "f".into() },
        chain_id,
        token,
    ));
    drop(exec);

    (controller, private_key)
}

/// A distinct alice->bob transfer; the memo carries `nonce` so each tx has a
/// unique id (the dedup record rejects identical transactions).
fn transfer_tx(private_key: &PrivateKey, chain_id: &Id, nonce: usize) -> PackedTransaction {
    let token = Name::from_str("pulse.token").unwrap();
    let alice = Name::from_str("alice").unwrap();
    let bob = Name::from_str("bob").unwrap();
    call(
        private_key,
        token,
        Name::from_str("transfer").unwrap(),
        &Transfer {
            from: alice,
            to: bob,
            quantity: Asset::new(1, Symbol::from_str("4,EOS").unwrap()),
            memo: format!("t{nonce}"),
        },
        *chain_id,
        alice,
    )
}

/// Distinct valid account names (a-z only): a 'z' prefix plus five base-26
/// digits, so `i` up to 26^5 gives a unique 6-char name that never collides with
/// alice/bob/pulse.
fn nth_name(i: usize) -> Name {
    let mut bytes = [b'z'; 6];
    let mut n = i;
    for slot in bytes[1..].iter_mut() {
        *slot = b'a' + (n % 26) as u8;
        n /= 26;
    }
    Name::from_str(std::str::from_utf8(&bytes).unwrap()).unwrap()
}

fn load_token_wasm() -> Vec<u8> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap();
    fs::read(root.join("reference_contracts/pulse_token.wasm")).unwrap()
}

fn call<T: Write>(
    private_key: &PrivateKey,
    account: Name,
    action: Name,
    data: &T,
    chain_id: Id,
    authorizer: Name,
) -> PackedTransaction {
    let trx = Transaction::new(
        TransactionHeader::new(TimePointSec::new(u32::MAX), 0, 0, 0u32.into(), 0, 0u32.into()),
        vec![],
        vec![Action::new(
            account,
            action,
            data.pack().unwrap(),
            vec![PermissionLevel::new(authorizer.as_u64(), ACTIVE_NAME.as_u64())],
        )],
    )
    .sign(private_key, &chain_id)
    .unwrap();
    PackedTransaction::from_signed_transaction(trx).unwrap()
}

fn create_account(private_key: &PrivateKey, account: Name, chain_id: Id) -> PackedTransaction {
    let authority = Authority::new(
        1,
        vec![KeyWeight::new(private_key.get_public_key().inner().clone(), 1)],
        vec![],
        vec![],
    );
    let trx = Transaction::new(
        TransactionHeader::new(TimePointSec::new(u32::MAX), 0, 0, 0u32.into(), 0, 0u32.into()),
        vec![],
        vec![Action::new(
            Name::from_str("pulse").unwrap(),
            Name::from_str("newaccount").unwrap(),
            NewAccount { creator: Name::from_str("pulse").unwrap(), name: account, owner: authority.clone(), active: authority }
                .pack()
                .unwrap(),
            vec![PermissionLevel::new(PULSE_NAME.as_u64(), ACTIVE_NAME.as_u64())],
        )],
    )
    .sign(private_key, &chain_id)
    .unwrap();
    PackedTransaction::from_signed_transaction(trx).unwrap()
}

fn set_code(private_key: &PrivateKey, account: Name, wasm: Vec<u8>, chain_id: Id) -> PackedTransaction {
    let trx = Transaction::new(
        TransactionHeader::new(TimePointSec::new(u32::MAX), 0, 0, 0u32.into(), 0, 0u32.into()),
        vec![],
        vec![Action::new(
            Name::from_str("pulse").unwrap(),
            Name::from_str("setcode").unwrap(),
            SetCode { account, vm_type: 0, vm_version: 0, code: Arc::new(wasm.into()) }.pack().unwrap(),
            vec![PermissionLevel::new(account.as_u64(), ACTIVE_NAME.as_u64())],
        )],
    )
    .sign(private_key, &chain_id)
    .unwrap();
    PackedTransaction::from_signed_transaction(trx).unwrap()
}

fn get_temp_dir() -> PathBuf {
    temp_dir().join(format!("db_{}_bench.pulsevm", Utc::now().format("%Y%m%d%H%M%S%f")))
}

fn generate_genesis() -> Vec<u8> {
    json!({
        "initial_timestamp": "2023-01-01T00:00:00",
        "initial_key": "PUB_K1_8XeW7H2JhKFP8Wjw31cv4j4Bpw4in8MVMrtmfUunJV4gSVBzqZ",
        "initial_configuration": {
            "max_block_net_usage": 1048576,
            "target_block_net_usage_pct": 1000,
            "max_transaction_net_usage": 524288,
            "base_per_transaction_net_usage": 12,
            "net_usage_leeway": 500,
            "context_free_discount_net_usage_num": 20,
            "context_free_discount_net_usage_den": 100,
            "max_block_cpu_usage": 200000,
            "target_block_cpu_usage_pct": 2500,
            "max_transaction_cpu_usage": 150000,
            "min_transaction_cpu_usage": 100,
            // wide so the far-future test expiration is accepted at real-clock build time
            "max_transaction_lifetime": 4294967295u32,
            "max_inline_action_size": 4096,
            "max_inline_action_depth": 6,
            "max_authority_depth": 6,
            "max_action_return_value_size": 256
        }
    })
    .to_string()
    .into_bytes()
}
