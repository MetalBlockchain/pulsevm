//! Append verified-source XPR blocks fetched from public chain APIs to a Leap
//! v3 block log. PulseVM's regular replay process consumes the appended log and
//! independently validates every block before applying it.

use std::{
    collections::BTreeMap,
    env,
    fs::{
        File,
        OpenOptions,
    },
    io::{
        Read as IoRead,
        Seek,
        SeekFrom,
        Write as IoWrite,
    },
    path::{
        Path,
        PathBuf,
    },
    str::FromStr,
    time::Duration,
};

use anyhow::{
    Context,
    Result,
    bail,
};
use chrono::NaiveDateTime;
use pulsevm_core::{
    block::{
        BlockHeader,
        SignedBlock,
        SignedBlockHeader,
    },
    crypto::Signature,
    id::Id,
    producer_schedule::ProducerSchedule,
    transaction::{
        PackedTransaction,
        TransactionCompression,
        TransactionReceipt,
        TransactionReceiptHeader,
        TransactionStatus,
    },
};
use pulsevm_crypto::Digest;
use pulsevm_database::BlockTimestamp;
use pulsevm_serialization::{
    Read as PulseRead,
    VarUint32,
    Write as PulseWrite,
};
use reqwest::Client;
use serde_json::Value;

const CHAIN_ID: &str = "384da888112027f0321850a169f737c33e53b388aad48b5adace4bab97f437e0";
const MAX_BLOCK_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
const DEFAULT_CONCURRENCY: usize = 32;
const DEFAULT_APIS: &[&str] = &[
    "https://api.protonnz.com",
    "https://proton.eosusa.io",
    "https://proton.cryptolions.io",
    "https://api-xprnetwork-main.saltant.io",
    "https://proton.eu.eosamsterdam.net",
    "https://mainnet.brotonbp.com",
];

struct BlockLogWriter {
    log: File,
    index: File,
    blocks: u32,
    tip: SignedBlock,
}

impl BlockLogWriter {
    fn open(dir: &Path) -> Result<Self> {
        let log_path = dir.join("blocks.log");
        let index_path = dir.join("blocks.index");
        let mut log = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&log_path)
            .with_context(|| format!("open {}", log_path.display()))?;
        let mut index = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&index_path)
            .with_context(|| format!("open {}", index_path.display()))?;
        let index_len = index.metadata()?.len();
        if index_len == 0 || index_len % 8 != 0 {
            bail!("{} is empty or has a partial offset", index_path.display());
        }
        let blocks = u32::try_from(index_len / 8).context("block index exceeds uint32")?;
        index.seek(SeekFrom::Start(index_len - 8))?;
        let mut offset_bytes = [0; 8];
        index.read_exact(&mut offset_bytes)?;
        let last_offset = u64::from_le_bytes(offset_bytes);
        let log_len = log.metadata()?.len();
        let tail_len = log_len
            .checked_sub(last_offset)
            .context("last block index points beyond blocks.log")?;
        if tail_len == 0 || tail_len > MAX_BLOCK_RESPONSE_BYTES as u64 + 8 {
            bail!("last block record has invalid size {tail_len}");
        }
        log.seek(SeekFrom::Start(last_offset))?;
        let mut tail = vec![0; tail_len as usize];
        log.read_exact(&mut tail)?;
        let mut position = 0;
        let tip = SignedBlock::read(&tail, &mut position)
            .map_err(|error| anyhow::anyhow!("decode block-log tip: {error}"))?;
        if tip.block_num() != blocks {
            bail!(
                "last indexed record is block {}, expected {blocks}",
                tip.block_num()
            );
        }
        if position + 8 > tail.len() {
            bail!("last block record is missing its position trailer");
        }
        let trailer = u64::from_le_bytes(tail[position..position + 8].try_into()?);
        if trailer != last_offset {
            bail!("last block trailer points to {trailer}, expected {last_offset}");
        }
        // A crash after appending block bytes but before the index entry leaves
        // an uncommitted tail. Drop it before any new record is appended.
        log.set_len(last_offset + position as u64 + 8)?;
        log.seek(SeekFrom::End(0))?;
        index.seek(SeekFrom::End(0))?;
        Ok(Self {
            log,
            index,
            blocks,
            tip,
        })
    }

    fn append(&mut self, block: &SignedBlock, packed: &[u8]) -> Result<()> {
        let expected = self
            .blocks
            .checked_add(1)
            .context("block height overflow")?;
        if block.block_num() != expected {
            bail!("received block {}, expected {expected}", block.block_num());
        }
        if block.previous_id() != &self.tip.id()? {
            bail!("block {expected} does not extend the current block-log tip");
        }
        let offset = self.log.stream_position()?;
        self.log.write_all(packed)?;
        self.log.write_all(&offset.to_le_bytes())?;
        self.log.sync_data()?;
        self.index.write_all(&offset.to_le_bytes())?;
        self.index.sync_data()?;
        self.blocks = expected;
        self.tip = block.clone();
        Ok(())
    }
}

fn parse_digest(value: &Value, field: &str) -> Result<Digest> {
    let text = value
        .get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("block field {field} is missing"))?;
    let bytes = hex::decode(text).with_context(|| format!("decode {field}"))?;
    Ok(Digest(bytes.try_into().map_err(|_| {
        anyhow::anyhow!("{field} must be 32 bytes")
    })?))
}

fn parse_u64(value: &Value, field: &str) -> Result<u64> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .with_context(|| format!("block field {field} is missing or invalid"))
}

fn parse_extensions(value: Option<&Value>, field: &str) -> Result<Vec<(u16, Vec<u8>)>> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(Vec::new());
    };
    let entries = value
        .as_array()
        .with_context(|| format!("{field} is not an array"))?;
    entries
        .iter()
        .map(|entry| {
            let pair = entry
                .as_array()
                .filter(|pair| pair.len() == 2)
                .with_context(|| format!("{field} entry is not a pair"))?;
            let id = pair[0]
                .as_u64()
                .context("extension id is not an integer")?
                .try_into()
                .context("extension id does not fit uint16")?;
            let bytes = pair[1]
                .as_str()
                .context("extension payload is not hexadecimal")?;
            Ok((id, hex::decode(bytes)?))
        })
        .collect()
}

fn parse_slot(value: &str) -> Result<u32> {
    let format = if value.contains('.') {
        "%Y-%m-%dT%H:%M:%S%.f"
    } else {
        "%Y-%m-%dT%H:%M:%S"
    };
    let timestamp = NaiveDateTime::parse_from_str(value.trim_end_matches('Z'), format)?;
    let epoch = NaiveDateTime::parse_from_str("2000-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S")?;
    let milliseconds = (timestamp - epoch).num_milliseconds();
    if milliseconds < 0 || milliseconds % 500 != 0 {
        bail!("timestamp is before the Antelope epoch or not slot aligned");
    }
    u32::try_from(milliseconds / 500).context("timestamp slot exceeds uint32")
}

fn parse_status(value: &str) -> Result<TransactionStatus> {
    match value {
        "executed" => Ok(TransactionStatus::Executed),
        "soft_fail" => Ok(TransactionStatus::SoftFail),
        "hard_fail" => Ok(TransactionStatus::HardFail),
        "delayed" => Ok(TransactionStatus::Delayed),
        "expired" => Ok(TransactionStatus::Expired),
        other => bail!("unknown transaction status {other}"),
    }
}

fn parse_block(value: &Value, expected_num: u32) -> Result<SignedBlock> {
    let timestamp = value
        .get("timestamp")
        .and_then(Value::as_str)
        .context("block timestamp is missing")?;
    let producer = value
        .get("producer")
        .and_then(Value::as_str)
        .context("block producer is missing")?;
    let previous = value
        .get("previous")
        .and_then(Value::as_str)
        .context("block previous id is missing")?;
    let producer_signature = value
        .get("producer_signature")
        .and_then(Value::as_str)
        .context("producer signature is missing")?;
    let schedule_version = u32::try_from(parse_u64(value, "schedule_version")?)?;
    let new_producers = match value.get("new_producers") {
        None | Some(Value::Null) => None,
        Some(schedule) => Some(serde_json::from_value::<ProducerSchedule>(
            schedule.clone(),
        )?),
    };
    let header = BlockHeader {
        timestamp: BlockTimestamp::new(parse_slot(timestamp)?),
        producer: pulsevm_core::name::Name::from_str(producer)?,
        confirmed: u16::try_from(parse_u64(value, "confirmed")?)?,
        previous: Id::from_str(previous)?,
        transaction_mroot: parse_digest(value, "transaction_mroot")?,
        action_mroot: parse_digest(value, "action_mroot")?,
        schedule_version,
        new_producers,
        header_extensions: parse_extensions(value.get("header_extensions"), "header_extensions")?,
    };
    let signature = Signature::from_str(producer_signature)?;
    let mut transactions = std::collections::VecDeque::new();
    for transaction in value
        .get("transactions")
        .and_then(Value::as_array)
        .context("block transactions are missing")?
    {
        let status = transaction
            .get("status")
            .and_then(Value::as_str)
            .context("transaction status is missing")?;
        let cpu = u32::try_from(parse_u64(transaction, "cpu_usage_us")?)?;
        let net = u32::try_from(parse_u64(transaction, "net_usage_words")?)?;
        let receipt_header =
            TransactionReceiptHeader::new(parse_status(status)?, cpu, VarUint32(net));
        let trx = transaction
            .get("trx")
            .context("transaction receipt is missing")?;
        if let Some(id) = trx.as_str() {
            transactions.push_back(TransactionReceipt::for_id(
                receipt_header,
                Id::from_str(id)?,
            ));
            continue;
        }
        let signatures = trx
            .get("signatures")
            .and_then(Value::as_array)
            .context("packed transaction signatures are missing")?
            .iter()
            .map(|signature| {
                Signature::from_str(
                    signature
                        .as_str()
                        .context("packed transaction signature is not a string")?,
                )
                .context("parse packed transaction signature")
            })
            .collect::<Result<Vec<_>>>()?;
        let compression = match trx
            .get("compression")
            .and_then(Value::as_str)
            .context("packed transaction compression is missing")?
        {
            "none" | "0" => TransactionCompression::None,
            "zlib" | "1" => TransactionCompression::Zlib,
            other => bail!("unknown transaction compression {other}"),
        };
        let packed_trx = decode_hex_field(trx, "packed_trx")?;
        let context_free_data = decode_hex_field(trx, "packed_context_free_data")?;
        let packed = PackedTransaction::new(
            signatures,
            compression,
            context_free_data.into(),
            packed_trx.into(),
        )?;
        transactions.push_back(TransactionReceipt::new(receipt_header, packed));
    }
    let block = SignedBlock {
        signed_block_header: SignedBlockHeader { header, signature },
        transactions,
        block_extensions: parse_extensions(value.get("block_extensions"), "block_extensions")?,
    };
    if block.block_num() != expected_num {
        bail!(
            "API returned block {}, expected {expected_num}",
            block.block_num()
        );
    }
    if let Some(remote_id) = value.get("id").and_then(Value::as_str) {
        let local_id = block.id()?.to_string();
        if remote_id != local_id {
            bail!("reconstructed block id {local_id} disagrees with API id {remote_id}");
        }
    }
    Ok(block)
}

fn decode_hex_field(value: &Value, field: &str) -> Result<Vec<u8>> {
    let text = value
        .get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("packed transaction field {field} is missing"))?;
    hex::decode(text).with_context(|| format!("decode packed transaction field {field}"))
}

async fn post_json(client: &Client, api: &str, route: &str, body: &Value) -> Result<Value> {
    let response = client
        .post(format!("{api}{route}"))
        .json(body)
        .send()
        .await
        .with_context(|| format!("request {api}{route}"))?
        .error_for_status()
        .with_context(|| format!("HTTP error from {api}{route}"))?;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_BLOCK_RESPONSE_BYTES as u64)
    {
        bail!("response from {api}{route} exceeds the response size limit");
    }
    let mut response = response;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len().saturating_add(chunk.len()) > MAX_BLOCK_RESPONSE_BYTES {
            bail!("response from {api}{route} exceeds the response size limit");
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).with_context(|| format!("parse JSON from {api}{route}"))
}

async fn fetch_info(client: &Client, apis: &[String]) -> Result<(u32, usize)> {
    let mut errors = Vec::new();
    for (index, api) in apis.iter().enumerate() {
        match post_json(client, api, "/v1/chain/get_info", &serde_json::json!({})).await {
            Ok(info) => {
                let chain_id = info
                    .get("chain_id")
                    .and_then(Value::as_str)
                    .context("get_info omitted chain_id")?;
                if chain_id != CHAIN_ID {
                    bail!("API {api} returned unexpected chain id {chain_id}");
                }
                let lib = u32::try_from(
                    info.get("last_irreversible_block_num")
                        .and_then(Value::as_u64)
                        .context("get_info omitted irreversible block height")?,
                )?;
                return Ok((lib, index));
            }
            Err(error) => errors.push(format!("{api}: {error}")),
        }
    }
    bail!("all mainnet APIs failed: {}", errors.join("; "))
}

async fn fetch_block(
    client: &Client,
    apis: &[String],
    preferred: usize,
    block_num: u32,
) -> Result<(u32, SignedBlock, Vec<u8>)> {
    let body = serde_json::json!({ "block_num_or_id": block_num });
    let mut errors = Vec::new();
    for step in 0..apis.len() {
        let index = (preferred + step) % apis.len();
        let api = &apis[index];
        match post_json(client, api, "/v1/chain/get_block", &body).await {
            Ok(value) => match parse_block(&value, block_num) {
                Ok(block) => {
                    let packed = block.pack()?;
                    return Ok((block_num, block, packed));
                }
                Err(error) => errors.push(format!("{api} block {block_num}: {error}")),
            },
            Err(error) => errors.push(format!("{api} block {block_num}: {error}")),
        }
    }
    bail!(
        "could not fetch block {block_num} from any API: {}",
        errors.join("; ")
    )
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = env::args_os();
    let program = args.next().unwrap_or_default();
    let Some(source_dir) = args.next() else {
        bail!(
            "usage: {} <source-blocks-dir> [concurrency]",
            PathBuf::from(program).display()
        );
    };
    let concurrency = args
        .next()
        .map(|value| {
            value
                .to_string_lossy()
                .parse::<usize>()
                .context("invalid concurrency")
        })
        .transpose()?
        .unwrap_or(DEFAULT_CONCURRENCY);
    if concurrency == 0 || concurrency > 256 {
        bail!("concurrency must be between 1 and 256");
    }
    if args.next().is_some() {
        bail!("too many arguments");
    }
    let source_dir = PathBuf::from(source_dir);
    let mut writer = BlockLogWriter::open(&source_dir)?;
    let apis = DEFAULT_APIS
        .iter()
        .map(|api| (*api).to_owned())
        .collect::<Vec<_>>();
    let client = Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(concurrency.min(32))
        .user_agent("pulsevm-xpr-api-block-feed/1.0")
        .build()?;

    eprintln!(
        "following XPR block APIs from {} (tip {}) with concurrency {concurrency}",
        source_dir.display(),
        writer.blocks
    );
    loop {
        let (lib, preferred_api) = fetch_info(&client, &apis).await?;
        if lib <= writer.blocks {
            tokio::time::sleep(Duration::from_secs(2)).await;
            continue;
        }
        let first = writer
            .blocks
            .checked_add(1)
            .context("block height overflow")?;
        let end = first
            .saturating_add(u32::try_from(concurrency - 1).unwrap_or(u32::MAX))
            .min(lib);
        let mut tasks = tokio::task::JoinSet::new();
        for block_num in first..=end {
            let client = client.clone();
            let apis = apis.clone();
            tasks.spawn(async move {
                fetch_block(
                    &client,
                    &apis,
                    (preferred_api + block_num as usize) % apis.len(),
                    block_num,
                )
                .await
            });
        }
        let mut completed = BTreeMap::new();
        while let Some(result) = tasks.join_next().await {
            let (block_num, block, packed) = result.context("block fetch task panicked")??;
            completed.insert(block_num, (block, packed));
        }
        for block_num in first..=end {
            let (block, packed) = completed
                .remove(&block_num)
                .with_context(|| format!("fetch batch omitted block {block_num}"))?;
            writer.append(&block, &packed)?;
        }
        if writer.blocks % 1000 < concurrency as u32 || writer.blocks == lib {
            eprintln!(
                "appended block {} through irreversible height {lib}",
                writer.blocks
            );
        }
    }
}
