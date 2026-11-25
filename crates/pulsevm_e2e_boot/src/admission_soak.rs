//! Sends a bounded burst of independently signed transactions to a running
//! PulseVM endpoint, checks admission and status RPCs, then proves every
//! accepted transaction was applied.
//!
//! It is an end-to-end fixture rather than a benchmark: the surrounding Go
//! test runs it against a five-node tmpnet, so the requests traverse HTTP,
//! mempool admission/status, gossip, production, verification, and acceptance.

use std::{
    collections::BTreeSet,
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
const ADMISSION_STATUS_TIMEOUT: Duration = Duration::from_secs(5);
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
    creator: Name,
    account: Name,
) -> Result<PackedTransaction> {
    let public_key = key.get_public_key().into_k1();
    let authority = Authority::new(1, vec![KeyWeight::new(public_key, 1)], vec![], vec![]);
    let action = Action::new(
        PULSE_NAME,
        NEWACCOUNT_NAME,
        NewAccount {
            creator,
            name: account,
            owner: authority.clone(),
            active: authority,
        }
        .pack()
        .context("packing newaccount")?,
        vec![PermissionLevel::new(creator.as_u64(), ACTIVE_NAME.as_u64())],
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

async fn admitted_or_included_status(
    client: &PulseVmClient,
    tx_id: &Id,
) -> Result<TransactionStatus> {
    let deadline = Instant::now() + ADMISSION_STATUS_TIMEOUT;
    loop {
        let response = client
            .get_transaction_status(tx_id)
            .await
            .context("querying transaction status after admission")?;
        match response.status {
            TransactionStatus::Admitted | TransactionStatus::Included => {
                return Ok(response.status);
            }
            TransactionStatus::ExecutionFailed => bail!(
                "transaction {tx_id} failed during block execution: {}",
                response.error.unwrap_or_else(|| "no error detail".into())
            ),
            TransactionStatus::Unknown => {
                if Instant::now() >= deadline {
                    bail!("transaction {tx_id} remained unknown after successful admission");
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    let args = parse_args()?;
    let key = PrivateKey::from_str(&args.private_key).context("invalid --private-key")?;
    let client = Arc::new(PulseVmClient::new(&args.url));
    let info = client.get_info().await.context("getting chain info")?;
    let chain_id = Id::from_str(&info.chain_id).context("invalid chain id from endpoint")?;

    // Exercise the reported ordinary-creator case: pulse creates `test` with
    // the same key, then all soak transactions are authorized by test rather
    // than by the privileged system account.
    let creator = Name::from_str("test").context("encoding test creator account")?;
    let creator_setup = new_account_transaction(&key, &chain_id, PULSE_NAME, creator)?;
    client
        .issue_tx(&creator_setup)
        .await
        .context("submitting the test creator account")?;
    let creator_deadline = Instant::now() + INCLUSION_TIMEOUT;
    loop {
        if client.get_account(&creator, &None).await.is_ok() {
            break;
        }
        if Instant::now() >= creator_deadline {
            bail!("test creator account was not created within {INCLUSION_TIMEOUT:?}");
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    let start_block_num = client
        .get_info()
        .await
        .context("getting chain head after creator setup")?
        .head_block_num;

    // A fresh tmpnet is used for each run. The twelve-character names use the
    // chain's `a-z1-5` alphabet and avoid collisions with the boot test's named
    // accounts. They are created by the ordinary `test` account above.
    let accounts: Vec<Name> = (0..args.transactions)
        .map(soak_account_name)
        .collect::<Result<_>>()?;
    let transactions: Vec<_> = accounts
        .iter()
        .copied()
        .map(|account| new_account_transaction(&key, &chain_id, creator, account))
        .collect::<Result<_>>()?;
    let expected_transaction_ids: BTreeSet<_> = transactions
        .iter()
        .map(|transaction| transaction.id().to_string())
        .collect();

    let mut remaining = transactions.into_iter();
    let mut pending = JoinSet::new();
    for _ in 0..args.concurrency.min(args.transactions) {
        let transaction = remaining.next().expect("initial work count is bounded");
        let client = client.clone();
        pending.spawn(async move {
            let started = Instant::now();
            let response = client.issue_tx(&transaction).await?;
            if response.status != TransactionStatus::Admitted {
                bail!("issue_tx returned unexpected status {:?}", response.status);
            }
            let status = admitted_or_included_status(&client, &response.tx_id).await?;
            Ok::<_, anyhow::Error>((
                started.elapsed().as_millis(),
                response.tx_id.to_string(),
                status,
            ))
        });
    }

    let mut latencies = Vec::with_capacity(args.transactions);
    let mut admitted_transaction_ids = BTreeSet::new();
    while let Some(result) = pending.join_next().await {
        let (latency, transaction_id, status) = result.context("admission task panicked")??;
        latencies.push(latency);
        admitted_transaction_ids.insert(transaction_id);
        if !matches!(
            status,
            TransactionStatus::Admitted | TransactionStatus::Included
        ) {
            bail!("status query did not observe the transaction in the mempool or a block");
        }
        if let Some(transaction) = remaining.next() {
            let client = client.clone();
            pending.spawn(async move {
                let started = Instant::now();
                let response = client.issue_tx(&transaction).await?;
                if response.status != TransactionStatus::Admitted {
                    bail!("issue_tx returned unexpected status {:?}", response.status);
                }
                let status = admitted_or_included_status(&client, &response.tx_id).await?;
                Ok::<_, anyhow::Error>((
                    started.elapsed().as_millis(),
                    response.tx_id.to_string(),
                    status,
                ))
            });
        }
    }
    if admitted_transaction_ids != expected_transaction_ids {
        bail!("issue_tx returned transaction IDs that differ from the signed transactions");
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

    // Account state proves the actions executed; require the RPC status API to
    // report the corresponding accepted receipt and block height as well.
    for transaction_id in &admitted_transaction_ids {
        let transaction_id = Id::from_str(transaction_id).context("invalid transaction ID")?;
        let status = client.get_transaction_status(&transaction_id).await?;
        if status.status != TransactionStatus::Included || status.block_num.is_none() {
            bail!(
                "transaction {transaction_id} finished without included status and block number: {:?}",
                status.status
            );
        }
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
            "included_statuses": admitted_transaction_ids.len(),
            "start_block_num": start_block_num,
            "transaction_ids": admitted_transaction_ids,
            "p50_admission_ms": p50_ms,
            "p95_admission_ms": p95_ms,
            "max_admission_ms": max_ms,
        })
    );
    Ok(())
}
