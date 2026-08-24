//! Sends a bounded burst of independently signed transactions to a running
//! PulseVM endpoint, then proves every accepted transaction was applied.
//!
//! It is an end-to-end fixture rather than a benchmark: the surrounding Go
//! test runs it against a five-node tmpnet, so the requests traverse HTTP,
//! mempool admission, gossip, production, verification, and acceptance.

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
use pulsevm_core::{
    ACTIVE_NAME,
    PULSE_NAME,
    authority::{
        Authority,
        KeyWeight,
        PermissionLevel,
    },
    config::NEWACCOUNT_NAME,
    crypto::PrivateKey,
    id::Id,
    mempool::DEFAULT_MEMPOOL_TRANSACTION_TTL_SECS,
    name::Name,
    pulse_contract::NewAccount,
    time::TimePointSec,
    transaction::{
        Action,
        PackedTransaction,
        Transaction,
    },
};
use pulsevm_serialization::Write;
use tokio::task::JoinSet;

const DEFAULT_TRANSACTIONS: usize = 128;
const DEFAULT_CONCURRENCY: usize = 32;
const INCLUSION_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const ACCOUNT_NAME_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz12345";

struct Args {
    url: String,
    private_key: String,
    transactions: usize,
    concurrency: usize,
}

fn parse_args() -> Result<Args> {
    let (mut url, mut private_key) = (None, None);
    let mut transactions = DEFAULT_TRANSACTIONS;
    let mut concurrency = DEFAULT_CONCURRENCY;
    let mut argv = std::env::args().skip(1);
    while let Some(flag) = argv.next() {
        let mut take = || argv.next().context(format!("{flag} requires a value"));
        match flag.as_str() {
            "--url" => url = Some(take()?),
            "--private-key" => private_key = Some(take()?),
            "--transactions" => transactions = take()?.parse().context("invalid --transactions")?,
            "--concurrency" => concurrency = take()?.parse().context("invalid --concurrency")?,
            other => bail!("unknown argument: {other}"),
        }
    }
    if transactions == 0 {
        bail!("--transactions must be positive");
    }
    if concurrency == 0 {
        bail!("--concurrency must be positive");
    }
    Ok(Args {
        url: url.context("--url is required")?,
        private_key: private_key.context("--private-key is required")?,
        transactions,
        concurrency,
    })
}

fn new_account_transaction(
    key: &PrivateKey,
    chain_id: &Id,
    account: Name,
) -> Result<PackedTransaction> {
    let public_key = key.get_public_key().into_k1();
    let authority = Authority::new(1, vec![KeyWeight::new(public_key, 1)], vec![], vec![]);
    let action = Action::new(
        PULSE_NAME,
        NEWACCOUNT_NAME,
        NewAccount {
            creator: PULSE_NAME,
            name: account,
            owner: authority.clone(),
            active: authority,
        }
        .pack()
        .context("packing newaccount")?,
        vec![PermissionLevel::new(
            PULSE_NAME.as_u64(),
            ACTIVE_NAME.as_u64(),
        )],
    );
    let mut transaction = Transaction::default();
    transaction.header.expiration = TimePointSec::now() + DEFAULT_MEMPOOL_TRANSACTION_TTL_SECS;
    transaction.actions = vec![action];
    let signed = transaction
        .sign(key, chain_id)
        .map_err(|e| anyhow::anyhow!("signing transaction: {e}"))?;
    PackedTransaction::from_signed_transaction(signed)
        .map_err(|e| anyhow::anyhow!("packing transaction: {e}"))
}

fn soak_account_name(mut index: usize) -> Result<Name> {
    let mut suffix = [b'a'; 11];
    for character in suffix.iter_mut().rev() {
        *character = ACCOUNT_NAME_CHARS[index % ACCOUNT_NAME_CHARS.len()];
        index /= ACCOUNT_NAME_CHARS.len();
    }
    Name::from_str(&format!("s{}", std::str::from_utf8(&suffix)?))
        .context("generating valid soak account name")
}

fn percentile_ms(latencies: &mut [u128], percentile: f64) -> u128 {
    latencies.sort_unstable();
    let index = ((latencies.len() - 1) as f64 * percentile).ceil() as usize;
    latencies[index]
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    let args = parse_args()?;
    let key = PrivateKey::from_str(&args.private_key).context("invalid --private-key")?;
    let client = Arc::new(PulseVmClient::new(&args.url));
    let info = client.get_info().await.context("getting chain info")?;
    let chain_id = Id::from_str(&info.chain_id).context("invalid chain id from endpoint")?;

    // A fresh tmpnet is used for each run. The twelve-character names use the
    // chain's `a-z1-5` alphabet and avoid collisions with the boot test's named
    // accounts.
    let accounts: Vec<Name> = (0..args.transactions)
        .map(soak_account_name)
        .collect::<Result<_>>()?;
    let transactions: Vec<_> = accounts
        .iter()
        .copied()
        .map(|account| new_account_transaction(&key, &chain_id, account))
        .collect::<Result<_>>()?;

    let mut remaining = transactions.into_iter();
    let mut pending = JoinSet::new();
    for _ in 0..args.concurrency.min(args.transactions) {
        let transaction = remaining.next().expect("initial work count is bounded");
        let client = client.clone();
        pending.spawn(async move {
            let started = Instant::now();
            client.issue_tx(&transaction).await?;
            Ok::<_, pulsevm_api_client::ClientError>(started.elapsed().as_millis())
        });
    }

    let mut latencies = Vec::with_capacity(args.transactions);
    while let Some(result) = pending.join_next().await {
        latencies.push(result.context("admission task panicked")??);
        if let Some(transaction) = remaining.next() {
            let client = client.clone();
            pending.spawn(async move {
                let started = Instant::now();
                client.issue_tx(&transaction).await?;
                Ok::<_, pulsevm_api_client::ClientError>(started.elapsed().as_millis())
            });
        }
    }

    let deadline = Instant::now() + INCLUSION_TIMEOUT;
    loop {
        let mut missing = 0;
        for account in &accounts {
            if client.get_account(account, &None).await.is_err() {
                missing += 1;
            }
        }
        if missing == 0 {
            break;
        }
        if Instant::now() >= deadline {
            bail!(
                "{missing} of {} admitted transactions were not applied within {:?}",
                args.transactions,
                INCLUSION_TIMEOUT
            );
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    let mut p50_values = latencies.clone();
    let mut p95_values = latencies.clone();
    let p50_ms = percentile_ms(&mut p50_values, 0.50);
    let p95_ms = percentile_ms(&mut p95_values, 0.95);
    let max_ms = latencies.iter().copied().max().unwrap_or_default();
    println!(
        "{}",
        serde_json::json!({
            "submitted": args.transactions,
            "included": accounts.len(),
            "p50_admission_ms": p50_ms,
            "p95_admission_ms": p95_ms,
            "max_admission_ms": max_ms,
        })
    );
    Ok(())
}
