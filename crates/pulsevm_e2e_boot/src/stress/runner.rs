//! Submission and settlement machinery shared by every wave.
//!
//! A wave is a batch of independently signed transactions pushed at the
//! network with a chosen concurrency and pacing, then polled until each one
//! reaches a terminal state. The runner never decides whether the chain was
//! *right*: it records what happened and returns it, and the Go test asserts.

use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{
            AtomicU64,
            AtomicUsize,
            Ordering,
        },
    },
    time::{
        Duration,
        Instant,
    },
};

use anyhow::{
    Context,
    Result,
};
use pulsevm_api_client::{
    ClientError,
    PulseVmClient,
};
use pulsevm_api_types::TransactionStatus;
use pulsevm_core::{
    crypto::PrivateKey,
    id::Id,
    transaction::PackedTransaction,
};
use tokio::{
    sync::Semaphore,
    task::JoinSet,
    time::{
        MissedTickBehavior,
        interval,
        sleep,
        timeout,
    },
};

/// Upper bound on any single RPC. The client sets none of its own, so without
/// this one wedged node would hang the whole run instead of failing it.
pub const RPC_TIMEOUT: Duration = Duration::from_secs(30);

/// What the chain is expected to do with a transaction.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Expect {
    /// Valid and funded: must be admitted and end up in exactly one block.
    Included,
    /// Invalid or doomed to fail: must never appear in a block. Rejecting it at
    /// admission or failing it at execution are both acceptable.
    Never,
    /// A repeat of a transaction that is also submitted as `Included`. Any
    /// admission outcome is fine; it must not be executed twice.
    Resubmit,
}

pub struct Job {
    pub kind: &'static str,
    pub expect: Expect,
    pub tx: PackedTransaction,
}

/// Process-wide handles shared by setup and every wave.
pub struct Ctx {
    pub clients: Vec<PulseVmClient>,
    pub chain_id: Id,
    pub genesis_key: PrivateKey,
    nonce: AtomicU64,
    next: AtomicUsize,
}

impl Ctx {
    pub fn new(clients: Vec<PulseVmClient>, chain_id: Id, genesis_key: PrivateKey) -> Self {
        Self {
            clients,
            chain_id,
            genesis_key,
            nonce: AtomicU64::new(1),
            next: AtomicUsize::new(0),
        }
    }

    /// A value unique across the whole run, used to keep transaction ids distinct.
    pub fn nonce(&self) -> u64 {
        self.nonce.fetch_add(1, Ordering::Relaxed)
    }

    pub fn next_node(&self) -> usize {
        self.next.fetch_add(1, Ordering::Relaxed) % self.clients.len()
    }

    pub async fn head(&self) -> Result<u32> {
        Ok(timeout(RPC_TIMEOUT, self.clients[0].get_info())
            .await
            .context("getting chain head timed out")?
            .context("getting chain head")?
            .head_block_num)
    }
}

#[derive(Clone, Copy)]
pub struct WaveOpts {
    pub concurrency: usize,
    /// Submissions per second; `None` fires as fast as the concurrency allows.
    pub pace_per_sec: Option<u32>,
    /// Send everything to one node instead of round-robin across all of them.
    pub pin_node: Option<usize>,
    pub settle_timeout: Duration,
}

impl Default for WaveOpts {
    fn default() -> Self {
        Self {
            concurrency: 128,
            pace_per_sec: None,
            pin_node: None,
            settle_timeout: Duration::from_secs(180),
        }
    }
}

enum Admission {
    Admitted,
    Rejected(String),
    /// A transaction that had to be admitted was not, even after retries.
    Failed(String),
}

struct Record {
    id: String,
    kind: &'static str,
    expect: Expect,
    node: usize,
    admission: Admission,
    admit_ms: u128,
    retries: u32,
    submitted: Instant,
}

/// Everything a wave produced that the final report needs.
pub struct WaveOutcome {
    pub report: serde_json::Value,
    pub good_ids: Vec<String>,
    pub bad_ids: Vec<String>,
    pub failures: Vec<String>,
}

const MAX_ADMISSION_ATTEMPTS: u32 = 14;

async fn submit(ctx: &Ctx, job: Job, node: usize) -> Record {
    let id = job.tx.id().to_string();
    let started = Instant::now();
    let mut retries = 0;
    let admission = loop {
        let result = timeout(RPC_TIMEOUT, ctx.clients[node].issue_tx(&job.tx))
            .await
            .unwrap_or_else(|_| Err(ClientError::Http("request timed out".into())));
        match result {
            Ok(response) => {
                if response.tx_id.to_string() != id {
                    break Admission::Failed(format!(
                        "issue_tx returned id {} for signed transaction {id}",
                        response.tx_id
                    ));
                }
                break Admission::Admitted;
            }
            Err(error) => {
                let message = error.to_string();
                // Only transactions that must land are worth retrying. A doomed
                // one that is refused has already told us what we wanted to know.
                if job.expect != Expect::Included {
                    break Admission::Rejected(message);
                }
                retries += 1;
                if retries >= MAX_ADMISSION_ATTEMPTS {
                    break Admission::Failed(message);
                }
                // Backpressure (a full mempool, a busy node) is expected under
                // load; back off instead of hammering it.
                sleep(Duration::from_millis((25u64 << retries.min(6)).min(1500))).await;
            }
        }
    };
    Record {
        id,
        kind: job.kind,
        expect: job.expect,
        node,
        admission,
        admit_ms: started.elapsed().as_millis(),
        retries,
        submitted: started,
    }
}

pub fn percentile(values: &[u128], pct: f64) -> u128 {
    if values.is_empty() {
        return 0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    sorted[((sorted.len() - 1) as f64 * pct).ceil() as usize]
}

/// Terminal observation for one transaction.
enum Seen {
    Included(u32),
    ExecutionFailed(String),
    /// Still `Admitted` when the timeout hit.
    Stuck,
    /// The node has no record of it.
    Unknown,
}

async fn poll_all(
    ctx: &Arc<Ctx>,
    records: &[Record],
    timeout: Duration,
) -> Vec<Option<(Seen, u128)>> {
    let mut results: Vec<Option<(Seen, u128)>> = (0..records.len()).map(|_| None).collect();
    let mut pending: Vec<usize> = records
        .iter()
        .enumerate()
        .filter(|(_, r)| matches!(r.admission, Admission::Admitted) && r.expect != Expect::Resubmit)
        .map(|(i, _)| i)
        .collect();
    let deadline = Instant::now() + timeout;
    let gate = Arc::new(Semaphore::new(48));
    let mut last_status: BTreeMap<usize, Seen> = BTreeMap::new();

    while !pending.is_empty() {
        let mut round = JoinSet::new();
        for &index in &pending {
            let ctx = ctx.clone();
            let gate = gate.clone();
            let id = records[index].id.clone();
            let node = records[index].node;
            round.spawn(async move {
                let _permit = gate.acquire_owned().await.ok();
                let parsed = id.parse::<Id>();
                let status = match parsed {
                    Ok(tx_id) => tokio::time::timeout(
                        RPC_TIMEOUT,
                        ctx.clients[node].get_transaction_status(&tx_id),
                    )
                    .await
                    .ok()
                    .and_then(|response| response.ok()),
                    Err(_) => None,
                };
                (index, status)
            });
        }
        let mut still = Vec::new();
        while let Some(done) = round.join_next().await {
            let Ok((index, status)) = done else { continue };
            let elapsed = records[index].submitted.elapsed().as_millis();
            match status {
                Some(s) => match s.status {
                    TransactionStatus::Included => {
                        results[index] = Some((Seen::Included(s.block_num.unwrap_or(0)), elapsed));
                    }
                    TransactionStatus::ExecutionFailed => {
                        results[index] =
                            Some((Seen::ExecutionFailed(s.error.unwrap_or_default()), elapsed));
                    }
                    TransactionStatus::Admitted => {
                        last_status.insert(index, Seen::Stuck);
                        still.push(index);
                    }
                    TransactionStatus::Unknown => {
                        last_status.insert(index, Seen::Unknown);
                        still.push(index);
                    }
                },
                // A transient RPC failure is retried rather than counted; a
                // persistent one surfaces as Stuck at the deadline.
                None => {
                    last_status.insert(index, Seen::Stuck);
                    still.push(index);
                }
            }
        }
        pending = still;
        if pending.is_empty() {
            break;
        }
        if Instant::now() >= deadline {
            for index in &pending {
                let seen = last_status.remove(index).unwrap_or(Seen::Stuck);
                results[*index] = Some((seen, records[*index].submitted.elapsed().as_millis()));
            }
            break;
        }
        sleep(Duration::from_millis(250)).await;
    }
    results
}

pub async fn run_wave(
    ctx: &Arc<Ctx>,
    name: &str,
    jobs: Vec<Job>,
    opts: WaveOpts,
) -> Result<WaveOutcome> {
    let total = jobs.len();
    let start_block = ctx.head().await?;
    eprintln!(
        "stress: wave {name}: submitting {total} transactions (concurrency {})",
        opts.concurrency
    );
    let wall = Instant::now();

    let gate = Arc::new(Semaphore::new(opts.concurrency.max(1)));
    let mut pending = JoinSet::new();
    let mut ticker = opts.pace_per_sec.map(|rate| {
        let mut t = interval(Duration::from_secs_f64(1.0 / f64::from(rate.max(1))));
        t.set_missed_tick_behavior(MissedTickBehavior::Delay);
        t
    });
    for job in jobs {
        if let Some(t) = ticker.as_mut() {
            t.tick().await;
        }
        let permit = gate
            .clone()
            .acquire_owned()
            .await
            .context("wave gate closed")?;
        let node = opts.pin_node.unwrap_or_else(|| ctx.next_node());
        let ctx = ctx.clone();
        pending.spawn(async move {
            let record = submit(&ctx, job, node).await;
            drop(permit);
            record
        });
    }
    let mut records = Vec::with_capacity(total);
    while let Some(done) = pending.join_next().await {
        records.push(done.context("submission task panicked")?);
    }
    let submit_secs = wall.elapsed().as_secs_f64();

    let settled = poll_all(ctx, &records, opts.settle_timeout).await;
    let wall_secs = wall.elapsed().as_secs_f64();
    let end_block = ctx.head().await?;

    let mut failures = Vec::new();
    let mut good_ids = Vec::new();
    let mut bad_ids = Vec::new();
    let mut by_kind: BTreeMap<&'static str, [u64; 4]> = BTreeMap::new(); // submitted, included, rejected, exec_failed
    let (mut rejected, mut exec_failed, mut dropped, mut resubmit_admitted, mut resubmit_rejected) =
        (0u64, 0u64, 0u64, 0u64, 0u64);
    let mut admit_latencies = Vec::new();
    let mut inclusion_latencies = Vec::new();
    let mut retries = 0u64;
    let mut per_block: BTreeMap<u32, u64> = BTreeMap::new();
    let mut sample_rejections: BTreeMap<String, u64> = BTreeMap::new();

    for (index, record) in records.iter().enumerate() {
        let tally = by_kind.entry(record.kind).or_default();
        tally[0] += 1;
        retries += u64::from(record.retries);
        admit_latencies.push(record.admit_ms);
        match record.expect {
            Expect::Included => good_ids.push(record.id.clone()),
            Expect::Never => bad_ids.push(record.id.clone()),
            Expect::Resubmit => {}
        }
        match (&record.admission, record.expect) {
            (Admission::Failed(why), _) => failures.push(format!(
                "{} {}: not admitted after {} attempts: {why}",
                record.kind, record.id, record.retries
            )),
            (Admission::Rejected(why), Expect::Resubmit) => {
                resubmit_rejected += 1;
                *sample_rejections
                    .entry(why.chars().take(120).collect())
                    .or_default() += 1;
            }
            (Admission::Rejected(why), _) => {
                rejected += 1;
                tally[2] += 1;
                *sample_rejections
                    .entry(why.chars().take(120).collect())
                    .or_default() += 1;
            }
            (Admission::Admitted, Expect::Resubmit) => resubmit_admitted += 1,
            (Admission::Admitted, expect) => match settled[index].as_ref() {
                Some((Seen::Included(block), latency)) => {
                    if expect == Expect::Never {
                        failures.push(format!(
                            "{} {} must never be included but was in block {block}",
                            record.kind, record.id
                        ));
                    } else {
                        tally[1] += 1;
                        *per_block.entry(*block).or_default() += 1;
                        inclusion_latencies.push(*latency);
                    }
                }
                Some((Seen::ExecutionFailed(why), _)) => {
                    if expect == Expect::Included {
                        failures.push(format!(
                            "{} {} failed during block execution: {why}",
                            record.kind, record.id
                        ));
                    } else {
                        exec_failed += 1;
                        tally[3] += 1;
                    }
                }
                Some((Seen::Stuck, _)) => failures.push(format!(
                    "{} {} still admitted (never executed or dropped) after {:?}",
                    record.kind, record.id, opts.settle_timeout
                )),
                Some((Seen::Unknown, _)) => {
                    if expect == Expect::Included {
                        failures.push(format!(
                            "{} {} vanished: admitted, then unknown to its node",
                            record.kind, record.id
                        ));
                    } else {
                        dropped += 1;
                    }
                }
                None => failures.push(format!("{} {} was never polled", record.kind, record.id)),
            },
        }
    }

    let max_per_block = per_block.values().copied().max().unwrap_or(0);
    let report = serde_json::json!({
        "name": name,
        "submitted": total,
        "start_block": start_block,
        "end_block": end_block,
        "blocks_with_included": per_block.len(),
        "max_included_per_block": max_per_block,
        "submit_secs": submit_secs,
        "wall_secs": wall_secs,
        "submit_rps": if submit_secs > 0.0 { total as f64 / submit_secs } else { 0.0 },
        "included": by_kind.values().map(|v| v[1]).sum::<u64>(),
        "rejected_at_admission": rejected,
        "failed_in_execution": exec_failed,
        "dropped_unknown": dropped,
        "resubmit_admitted": resubmit_admitted,
        "resubmit_rejected": resubmit_rejected,
        "admission_retries": retries,
        "admit_ms": {
            "p50": percentile(&admit_latencies, 0.50),
            "p95": percentile(&admit_latencies, 0.95),
            "max": percentile(&admit_latencies, 1.0),
        },
        "inclusion_ms": {
            "p50": percentile(&inclusion_latencies, 0.50),
            "p95": percentile(&inclusion_latencies, 0.95),
            "max": percentile(&inclusion_latencies, 1.0),
        },
        "kinds": by_kind
            .iter()
            .map(|(k, v)| (k.to_string(), serde_json::json!({
                "submitted": v[0], "included": v[1], "rejected": v[2], "exec_failed": v[3],
            })))
            .collect::<serde_json::Map<_, _>>(),
        "rejection_reasons": sample_rejections,
        "failures": failures.len(),
    });
    eprintln!(
        "stress: wave {name}: {total} tx, blocks {start_block}..{end_block}, {} failures",
        failures.len()
    );
    Ok(WaveOutcome {
        report,
        good_ids,
        bad_ids,
        failures,
    })
}
