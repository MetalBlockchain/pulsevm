//! Mixed-workload stress fixture for a running PulseVM network.
//!
//! Where `pulsevm-e2e-admission-soak` sends one kind of transaction to one
//! node, this drives thousands of transactions of many kinds from hundreds of
//! independently keyed accounts at *every* node, in waves with different shapes
//! (steady, burst, hot-key contention, out-of-order oracle writes, atomic
//! bundles, multi-signature swaps, replays, invalid traffic, optional mempool
//! saturation). It records what it sent and what the chain should now hold, and
//! prints that as JSON. The surrounding Go test owns every assertion: it walks
//! the blocks on each node and reads the state back over RPC.
//!
//! Progress goes to stderr; stdout carries only the final report.
//!
//! Usage:
//!   pulsevm-e2e-stress --url <node-rpc-url>... --private-key <PVT_K1_...> \
//!       --token-wasm <pulse_token.wasm> --token-abi <pulse_token.abi> \
//!       [--users 300] [--scale 1.0] [--seed N] [--saturate 0]

mod contracts;
mod runner;
mod traffic;

use std::{
    str::FromStr,
    sync::Arc,
    time::{
        Duration,
        Instant,
    },
};

use anyhow::{
    Context,
    Result,
    bail,
};
use pulsevm_api_client::PulseVmClient;
use pulsevm_api_types::TransactionStatus;
use pulsevm_core::{
    ACTIVE_NAME,
    CODE_NAME,
    OWNER_NAME,
    PULSE_NAME,
    abi::AbiDefinition,
    authority::{
        Authority,
        KeyWeight,
        PermissionLevel,
        PermissionLevelWeight,
    },
    config::{
        NEWACCOUNT_NAME,
        SETABI_NAME,
        SETCODE_NAME,
        UPDATEAUTH_NAME,
    },
    crypto::PrivateKey,
    id::Id,
    mempool::DEFAULT_MEMPOOL_TRANSACTION_TTL_SECS,
    name::Name,
    pulse_contract::{
        NewAccount,
        SetAbi,
        SetCode,
        UpdateAuth,
    },
    time::TimePointSec,
    transaction::Action,
};
use pulsevm_crypto::Bytes;
use pulsevm_proc_macros::{
    NumBytes,
    Read,
    Write,
};
use pulsevm_serialization::Write as _;
use runner::{
    Ctx,
    RPC_TIMEOUT,
    WaveOpts,
    WaveOutcome,
    run_wave,
};
use serde_json::{
    Value,
    json,
};
use tokio::time::{
    sleep,
    timeout,
};
use traffic::{
    AMM_RESERVE,
    CREATOR,
    FUND_UNITS,
    PAIRS,
    SYM_A,
    SYM_B,
    TOKEN,
    World,
    asset,
};

#[derive(Debug, Clone, Read, Write, NumBytes)]
struct CreateToken {
    issuer: Name,
    maximum_supply: pulsevm_core::asset::Asset,
}

#[derive(Debug, Clone, Read, Write, NumBytes)]
struct IssueToken {
    to: Name,
    quantity: pulsevm_core::asset::Asset,
    memo: String,
}

struct Args {
    urls: Vec<String>,
    private_key: String,
    token_wasm: String,
    token_abi: String,
    users: usize,
    scale: f64,
    seed: u64,
    saturate: usize,
}

fn parse_args() -> Result<Args> {
    let mut urls = Vec::new();
    let (mut private_key, mut token_wasm, mut token_abi) = (None, None, None);
    let (mut users, mut scale, mut seed, mut saturate) = (300usize, 1.0f64, 0x5eed_u64, 0usize);
    let mut argv = std::env::args().skip(1);
    while let Some(flag) = argv.next() {
        let mut take = || argv.next().context(format!("{flag} requires a value"));
        match flag.as_str() {
            "--url" => urls.push(take()?),
            "--private-key" => private_key = Some(take()?),
            "--token-wasm" => token_wasm = Some(take()?),
            "--token-abi" => token_abi = Some(take()?),
            "--users" => users = take()?.parse().context("invalid --users")?,
            "--scale" => scale = take()?.parse().context("invalid --scale")?,
            "--seed" => seed = take()?.parse().context("invalid --seed")?,
            "--saturate" => saturate = take()?.parse().context("invalid --saturate")?,
            other => bail!("unknown argument: {other}"),
        }
    }
    if urls.is_empty() {
        bail!("at least one --url is required");
    }
    if users < 30 {
        bail!("--users must be at least 30 so feeders, sinks and counterparties are distinct");
    }
    if scale <= 0.0 {
        bail!("--scale must be positive");
    }
    Ok(Args {
        urls,
        private_key: private_key.context("--private-key is required")?,
        token_wasm: token_wasm.context("--token-wasm is required")?,
        token_abi: token_abi.context("--token-abi is required")?,
        users,
        scale,
        seed,
        saturate,
    })
}

fn name(s: &str) -> Result<Name> {
    Name::from_str(s).map_err(|e| anyhow::anyhow!("encoding name {s}: {e}"))
}

fn act(account: Name, action: Name, actor: Name, data: Vec<u8>) -> Action {
    Action::new(
        account,
        action,
        data,
        vec![PermissionLevel::new(actor.as_u64(), ACTIVE_NAME.as_u64())],
    )
}

fn named(account: &str, action: &str, actor: Name, data: Vec<u8>) -> Result<Action> {
    Ok(act(name(account)?, name(action)?, actor, data))
}

fn new_account(creator: Name, account: Name, key: &PrivateKey) -> Result<Action> {
    let authority = Authority::new(
        1,
        vec![KeyWeight::new(key.get_public_key().into_k1(), 1)],
        vec![],
        vec![],
    );
    let data = NewAccount {
        creator,
        name: account,
        owner: authority.clone(),
        active: authority,
    }
    .pack()
    .context("packing newaccount")?;
    Ok(act(PULSE_NAME, NEWACCOUNT_NAME, creator, data))
}

fn set_code(account: Name, wasm: Vec<u8>) -> Result<Action> {
    let data = SetCode {
        account: account.into(),
        vm_type: 0,
        vm_version: 0,
        code: Arc::new(Bytes::new(wasm)),
    }
    .pack()
    .map_err(|e| anyhow::anyhow!("packing setcode: {e}"))?;
    Ok(act(PULSE_NAME, SETCODE_NAME, account, data))
}

fn set_abi(account: Name, abi_json: &[u8]) -> Result<Action> {
    let abi: AbiDefinition = serde_json::from_slice(abi_json).context("parsing ABI JSON")?;
    let packed = abi
        .pack()
        .map_err(|e| anyhow::anyhow!("packing ABI: {e}"))?;
    let data = SetAbi {
        account: account.into(),
        abi: Arc::new(Bytes::new(packed)),
    }
    .pack()
    .map_err(|e| anyhow::anyhow!("packing setabi: {e}"))?;
    Ok(act(PULSE_NAME, SETABI_NAME, account, data))
}

/// Setup transaction: signed by the genesis key, sent to node 0, and awaited.
/// Setup is sequential and not part of the measured load.
async fn push_wait(ctx: &Ctx, what: &str, actions: Vec<Action>) -> Result<()> {
    let tx = traffic::build_tx(
        &ctx.chain_id,
        actions,
        &[&ctx.genesis_key],
        TimePointSec::now() + DEFAULT_MEMPOOL_TRANSACTION_TTL_SECS,
    )?;
    let response = timeout(RPC_TIMEOUT, ctx.clients[0].issue_tx(&tx))
        .await
        .with_context(|| format!("submitting setup step {what} timed out"))?
        .with_context(|| format!("submitting setup step {what}"))?;
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let status = timeout(
            RPC_TIMEOUT,
            ctx.clients[0].get_transaction_status(&response.tx_id),
        )
        .await
        .with_context(|| format!("polling setup step {what} timed out"))?
        .with_context(|| format!("polling setup step {what}"))?;
        match status.status {
            TransactionStatus::Included => {
                eprintln!(
                    "stress: setup {what}: block {}",
                    status.block_num.unwrap_or(0)
                );
                return Ok(());
            }
            TransactionStatus::ExecutionFailed => bail!(
                "setup step {what} failed during execution: {}",
                status.error.unwrap_or_default()
            ),
            _ => {}
        }
        if Instant::now() >= deadline {
            bail!("setup step {what} was not included within 90s");
        }
        sleep(Duration::from_millis(100)).await;
    }
}

async fn setup(ctx: &Ctx, args: &Args, world: &mut World) -> Result<()> {
    let genesis = &ctx.genesis_key;
    let creator = name(CREATOR)?;
    let token = name(TOKEN)?;
    let amm = name(contracts::AMM)?;
    let oracle = name(contracts::ORACLE)?;
    let router = name(contracts::ROUTER)?;

    push_wait(
        ctx,
        "accounts",
        [creator, token, amm, oracle, router]
            .into_iter()
            .map(|account| new_account(PULSE_NAME, account, genesis))
            .collect::<Result<_>>()?,
    )
    .await?;

    let token_wasm =
        std::fs::read(&args.token_wasm).with_context(|| format!("reading {}", args.token_wasm))?;
    let token_abi =
        std::fs::read(&args.token_abi).with_context(|| format!("reading {}", args.token_abi))?;
    push_wait(
        ctx,
        "token contract",
        vec![set_code(token, token_wasm)?, set_abi(token, &token_abi)?],
    )
    .await?;
    push_wait(
        ctx,
        "oracle contract",
        vec![
            set_code(oracle, contracts::oracle_wasm()?)?,
            set_abi(oracle, contracts::oracle_abi().as_bytes())?,
        ],
    )
    .await?;
    push_wait(
        ctx,
        "amm contract",
        vec![
            set_code(amm, contracts::amm_wasm()?)?,
            set_abi(amm, contracts::amm_abi().as_bytes())?,
        ],
    )
    .await?;
    push_wait(
        ctx,
        "router contract",
        vec![set_code(router, contracts::router_wasm(TOKEN)?)?],
    )
    .await?;

    // Let the router's inline actions run under its own authority: its `active`
    // permission gains `router@pulse.code`, keeping the genesis key as well.
    let router_active = Authority::new(
        1,
        vec![KeyWeight::new(genesis.get_public_key().into_k1(), 1)],
        vec![PermissionLevelWeight::new(
            PermissionLevel::new(router.as_u64(), CODE_NAME.as_u64()),
            1,
        )],
        vec![],
    );
    push_wait(
        ctx,
        "router pulse.code permission",
        vec![act(
            PULSE_NAME,
            UPDATEAUTH_NAME,
            router,
            UpdateAuth {
                account: router,
                permission: ACTIVE_NAME,
                parent: OWNER_NAME,
                auth: router_active,
            }
            .pack()
            .context("packing updateauth")?,
        )],
    )
    .await?;

    // Enough supply to fund every user and leave the treasury with a remainder.
    let issued = FUND_UNITS * args.users as i64 + 5_000_000;
    let max_supply = issued * 10;
    let mut token_actions = Vec::new();
    for sym in [SYM_A, SYM_B] {
        token_actions.push(named(
            TOKEN,
            "create",
            token,
            CreateToken {
                issuer: token,
                maximum_supply: asset(max_supply, sym)?,
            }
            .pack()
            .context("packing create")?,
        )?);
    }
    for sym in [SYM_A, SYM_B] {
        token_actions.push(named(
            TOKEN,
            "issue",
            token,
            IssueToken {
                to: token,
                quantity: asset(issued, sym)?,
                memo: "stress supply".into(),
            }
            .pack()
            .context("packing issue")?,
        )?);
    }
    push_wait(ctx, "token create and issue", token_actions).await?;
    world.model.supply = [issued, issued];
    world
        .model
        .balances
        .insert(TOKEN.to_string(), [issued, issued]);

    push_wait(
        ctx,
        "amm pool",
        vec![named(
            contracts::AMM,
            "init",
            amm,
            contracts::pack_u64s(&[AMM_RESERVE, AMM_RESERVE]),
        )?],
    )
    .await?;
    Ok(())
}

#[derive(Default)]
struct Totals {
    waves: Vec<Value>,
    good: Vec<String>,
    bad: Vec<String>,
    failures: Vec<String>,
}

impl Totals {
    fn add(&mut self, wave: WaveOutcome) {
        self.waves.push(wave.report);
        self.good.extend(wave.good_ids);
        self.bad.extend(wave.bad_ids);
        self.failures.extend(wave.failures);
    }
}

fn scaled(base: usize, scale: f64) -> usize {
    ((base as f64 * scale).round() as usize).max(1)
}

fn model_json(world: &World) -> Result<Value> {
    let mut balances = serde_json::Map::new();
    for (account, [a, b]) in &world.model.balances {
        balances.insert(
            account.clone(),
            json!({ SYM_A: asset(*a, SYM_A)?.to_string(), SYM_B: asset(*b, SYM_B)?.to_string() }),
        );
    }
    let mut feeds = serde_json::Map::new();
    for ((pair, feeder), (price, seq)) in &world.model.feeds {
        feeds
            .entry(pair.clone())
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .context("feed map is an object")?
            .insert(feeder.clone(), json!({ "price": price, "seq": seq }));
    }
    let mut aggregates = serde_json::Map::new();
    for pair in PAIRS {
        let (sum, count) = world.model.aggregate_for(pair);
        if count > 0 {
            aggregates.insert(
                pair.to_string(),
                json!({ "sum": sum, "count": count, "avg": sum / count }),
            );
        }
    }
    Ok(json!({
        "token": TOKEN,
        "symbols": [SYM_A, SYM_B],
        "balances": balances,
        "supply": {
            SYM_A: asset(world.model.supply[0], SYM_A)?.to_string(),
            SYM_B: asset(world.model.supply[1], SYM_B)?.to_string(),
        },
        "amm": {
            "account": contracts::AMM,
            "init_a": AMM_RESERVE,
            "init_b": AMM_RESERVE,
            "faucet_each_side": world.model.amm_faucet,
            "swaps": world.model.amm_swaps,
            "traders": world.model.amm_traders,
        },
        "oracle": {
            "account": contracts::ORACLE,
            "updates": world.model.oracle_updates,
            "pairs": PAIRS,
            "feeds": feeds,
            "aggregates": aggregates,
        },
    }))
}

#[tokio::main(flavor = "multi_thread", worker_threads = 6)]
async fn main() -> Result<()> {
    let args = parse_args()?;
    let genesis_key = PrivateKey::from_str(&args.private_key).context("invalid --private-key")?;
    let clients: Vec<_> = args.urls.iter().map(|u| PulseVmClient::new(u)).collect();
    let info = clients[0].get_info().await.context("getting chain info")?;
    let chain_id = Id::from_str(&info.chain_id).context("invalid chain id from endpoint")?;
    let ctx = Arc::new(Ctx::new(clients, chain_id, genesis_key));
    let mut world = World::new(ctx.clone(), args.users, args.seed)?;
    eprintln!(
        "stress: {} nodes, {} users, scale {}, seed {}",
        args.urls.len(),
        args.users,
        args.scale,
        args.seed
    );

    setup(&ctx, &args, &mut world).await?;
    let start_block = ctx.head().await?;
    // The Go test starts its concurrent RPC readers on this line: every
    // contract and the token exist from here on.
    eprintln!("STRESS_READY");

    let s = args.scale;
    let mut totals = Totals::default();
    let mut aborted = None;
    let started = Instant::now();

    macro_rules! wave {
        ($name:expr, $jobs:expr, $opts:expr, $critical:expr) => {
            if aborted.is_none() {
                let jobs = $jobs?;
                let outcome = run_wave(&ctx, $name, jobs, $opts).await?;
                if $critical && !outcome.failures.is_empty() {
                    aborted = Some($name);
                }
                totals.add(outcome);
            }
        };
    }

    let wide = WaveOpts::default();
    wave!("onboard", world.onboard(), wide, true);
    wave!("fund", world.fund(), wide, true);
    wave!(
        "steady",
        world.steady(scaled(900, s)),
        WaveOpts {
            pace_per_sec: Some(75),
            concurrency: 32,
            ..wide
        },
        false
    );
    wave!(
        "burst",
        world.burst(scaled(1_800, s)),
        WaveOpts {
            concurrency: 256,
            ..wide
        },
        false
    );
    wave!("hot_key", world.hot_key(), wide, false);
    wave!("oracle", world.oracle(scaled(14, s)), wide, false);
    wave!(
        "bundles",
        world.bundles(scaled(160, s), scaled(120, s), scaled(60, s)),
        wide,
        false
    );
    wave!(
        "chaos",
        world.chaos(scaled(1_600, s)),
        WaveOpts {
            concurrency: 192,
            ..wide
        },
        false
    );
    if args.saturate > 0 {
        // One node, far more than its mempool holds. Backpressure is expected
        // and retried; every transaction must still land eventually.
        wave!(
            "saturate",
            world.saturate(args.saturate),
            WaveOpts {
                concurrency: 512,
                pin_node: Some(0),
                settle_timeout: Duration::from_secs(600),
                ..wide
            },
            false
        );
    }
    wave!("final_aggregates", world.final_aggregates(), wide, false);

    let end_block = ctx.head().await?;
    println!(
        "{}",
        json!({
            "chain_id": info.chain_id,
            "seed": args.seed,
            "users": args.users,
            "nodes": args.urls.len(),
            "start_block": start_block,
            "end_block": end_block,
            "elapsed_secs": started.elapsed().as_secs_f64(),
            "aborted_after": aborted,
            "waves": totals.waves,
            "good_ids": totals.good,
            "bad_ids": totals.bad,
            "failure_count": totals.failures.len(),
            "failures": totals.failures.iter().take(60).collect::<Vec<_>>(),
            "model": model_json(&world)?,
        })
    );
    Ok(())
}
