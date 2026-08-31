//! Replay canonical packed XPR blocks from a Leap `blocks.log`/`blocks.index`.
//!
//! This intentionally consumes the binary block bytes rather than JSON RPC
//! responses: signatures, transaction variants, schedules, and extensions must
//! all reach the production `verify_block` -> `accept_block` path unchanged.

use std::{
    env,
    fs::{
        self,
        File,
    },
    io::{
        Read as IoRead,
        Seek,
        SeekFrom,
    },
    path::{
        Path,
        PathBuf,
    },
    str::FromStr,
    time::Instant,
};

use anyhow::{
    Context,
    Result,
    bail,
};
use pulsevm_core::{
    block::SignedBlock,
    controller::Controller,
    id::Id,
    mempool::Mempool,
};
use pulsevm_serialization::Read as PulseRead;
use serde_json::json;

const XPR_CHAIN_ID: &str = "384da888112027f0321850a169f737c33e53b388aad48b5adace4bab97f437e0";
const XPR_BLOCK_ONE_ID: &str = "000000018421bd47ce23d4c47706e0bb98604157afedc67d56d05c82d5aa10c5";
const UNUSED_PRODUCER_KEY: &str = "PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez";
const XPR_V3_FIRST_BLOCK_OFFSET: u64 = 126;
const PARTIAL_SCAN_WINDOW: usize = 4 * 1024 * 1024;

struct BlockLog {
    log: File,
    offsets: Vec<u64>,
    packed_ends: Vec<u64>,
}

impl BlockLog {
    fn open(dir: &Path) -> Result<Self> {
        let log_path = dir.join("blocks.log");
        let index_path = dir.join("blocks.index");
        let log = File::open(&log_path)
            .with_context(|| format!("open source block log {}", log_path.display()))?;
        let log_len = log.metadata()?.len();
        let (offsets, effective_log_len): (Vec<u64>, u64) = match fs::read(&index_path) {
            Ok(index) if !index.is_empty() && index.len() % 8 == 0 => (
                index
                    .chunks_exact(8)
                    .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
                    .collect(),
                log_len,
            ),
            Ok(_) => bail!(
                "{} is empty or not a sequence of uint64 offsets",
                index_path.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Self::scan_partial_offsets(&log_path)?
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("read source block index {}", index_path.display()));
            }
        };
        if offsets.windows(2).any(|pair| pair[0] >= pair[1]) {
            bail!("{} contains non-increasing offsets", index_path.display());
        }
        if offsets.last().copied().unwrap() + 8 > effective_log_len {
            bail!(
                "{} points beyond the end of blocks.log",
                index_path.display()
            );
        }
        let packed_ends = offsets
            .iter()
            .enumerate()
            .map(|(index, _)| {
                if index + 1 < offsets.len() {
                    offsets[index + 1]
                        .checked_sub(8)
                        .context("source block-log offsets overlap")
                } else {
                    effective_log_len
                        .checked_sub(8)
                        .context("source blocks.log has no position trailer")
                }
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            log,
            offsets,
            packed_ends,
        })
    }

    /// A downloaded archive prefix has no blocks.index and ends in a partial
    /// block. Scan complete packed blocks from the fixed XPR v3 log header and
    /// ignore only that incomplete tail, allowing parity work to begin while
    /// the full archive is still downloading.
    fn scan_partial_offsets(log_path: &Path) -> Result<(Vec<u64>, u64)> {
        let bytes = fs::read(log_path)
            .with_context(|| format!("read archive prefix {}", log_path.display()))?;
        if bytes.len() < XPR_V3_FIRST_BLOCK_OFFSET as usize {
            bail!("indexless source is shorter than the XPR block-log header");
        }
        let header = &bytes[..8];
        if u32::from_le_bytes(header[..4].try_into().unwrap()) != 3
            || u32::from_le_bytes(header[4..].try_into().unwrap()) != 1
        {
            bail!("an indexless source must be an XPR v3 block log starting at block 1");
        }

        let mut offsets = Vec::new();
        let mut start = XPR_V3_FIRST_BLOCK_OFFSET as usize;
        while start < bytes.len() {
            let mut end = start;
            let Ok(block) = SignedBlock::read(&bytes, &mut end) else {
                if bytes.len() - start > PARTIAL_SCAN_WINDOW {
                    bail!("could not decode a complete block at source offset {start}");
                }
                break;
            };
            let expected_num = u32::try_from(offsets.len() + 1)?;
            if block.block_num() != expected_num {
                bail!(
                    "source offset {start} decoded as block {}, expected {expected_num}",
                    block.block_num()
                );
            }
            if end + 8 > bytes.len() {
                break;
            }
            let trailer: [u8; 8] = bytes[end..end + 8].try_into().unwrap();
            if u64::from_le_bytes(trailer) != start as u64 {
                bail!("source block {expected_num} has an invalid position trailer");
            }
            offsets.push(start as u64);
            start = end + 8;
        }
        if offsets.is_empty() {
            bail!("indexless source contains no complete blocks");
        }
        eprintln!(
            "scanned {} complete blocks from indexless archive prefix",
            offsets.len()
        );
        Ok((offsets, start as u64))
    }

    fn last_block_num(&self) -> Result<u32> {
        u32::try_from(self.offsets.len()).context("source block log exceeds uint32 height")
    }

    fn packed_block(&mut self, block_num: u32) -> Result<Vec<u8>> {
        if block_num == 0 || block_num as usize > self.offsets.len() {
            bail!("block {block_num} is outside the source block-log range");
        }
        let index = block_num as usize - 1;
        let start = self.offsets[index];
        let end = self.packed_ends[index];
        if end <= start {
            bail!("source block {block_num} has invalid byte range {start}..{end}");
        }
        let length = usize::try_from(end - start).context("packed block is too large")?;
        let mut bytes = vec![0; length];
        self.log.seek(SeekFrom::Start(start))?;
        self.log.read_exact(&mut bytes)?;

        self.log.seek(SeekFrom::Start(end))?;
        let mut trailer = [0; 8];
        self.log.read_exact(&mut trailer)?;
        let recorded_start = u64::from_le_bytes(trailer);
        if recorded_start != start {
            bail!("source block {block_num} trailer points to {recorded_start}, expected {start}");
        }
        Ok(bytes)
    }
}

fn usage(program: &str) {
    eprintln!(
        "Usage: {program} <source-blocks-dir> <arena-dir> [last-block]\n\
         Replays canonical XPR blocks and resumes at the Arena tip when possible."
    );
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = env::args();
    let program = args.next().unwrap_or_else(|| "xpr_blocklog_replay".into());
    let Some(source_dir) = args.next() else {
        usage(&program);
        bail!("missing source-blocks-dir");
    };
    let Some(arena_dir) = args.next() else {
        usage(&program);
        bail!("missing arena-dir");
    };
    let requested_last = args
        .next()
        .map(|value| value.parse::<u32>().context("last-block must be a uint32"))
        .transpose()?;
    if args.next().is_some() {
        usage(&program);
        bail!("too many arguments");
    }
    let debug_block = env::var("XPR_REPLAY_DEBUG_BLOCK")
        .ok()
        .map(|value| {
            value
                .parse::<u32>()
                .context("XPR_REPLAY_DEBUG_BLOCK must be a uint32")
        })
        .transpose()?;
    let inspect_schedules = env::var_os("XPR_REPLAY_INSPECT_SCHEDULES").is_some();

    let source_dir = PathBuf::from(source_dir);
    let arena_dir = PathBuf::from(arena_dir);
    let mut source = BlockLog::open(&source_dir)?;
    let source_last = source.last_block_num()?;
    let last = requested_last.unwrap_or(source_last).min(source_last);
    if last < 1 {
        bail!("source block log has no genesis block");
    }

    let chain_id = Id::from_str(XPR_CHAIN_ID).expect("constant XPR chain id is valid");
    let config = serde_json::to_vec(&json!({
        "system_account": "eosio",
        "native_system_contract": false,
        "antelope_block_signatures": true,
        "producer_name": "eosio",
        // Replay validates source signatures against the on-chain schedule; this
        // local key is required by NodeConfig but is never used to alter them.
        "producer_key": UNUSED_PRODUCER_KEY,
        "db_size": 48_u64 * 1024 * 1024 * 1024,
        "max_transaction_time_ms": 300_000
    }))?;
    let genesis =
        include_bytes!("../../../tools/xpr-chainbase-export/xpr-mainnet-genesis.json").to_vec();
    fs::create_dir_all(&arena_dir)?;

    let mut controller = Controller::new();
    controller.initialize(
        &chain_id,
        &config,
        &genesis,
        arena_dir
            .to_str()
            .context("arena directory is not valid UTF-8")?,
    )?;
    let local_tip = controller.last_accepted_block();
    if local_tip.block_num() == 1 && local_tip.id()?.to_string() != XPR_BLOCK_ONE_ID {
        bail!(
            "authored genesis id {} is not canonical XPR block 1",
            local_tip.id()?
        );
    }

    let source_genesis_bytes = source.packed_block(1)?;
    let source_genesis = controller
        .parse_block(&source_genesis_bytes)
        .map_err(|error| anyhow::anyhow!("decode source block 1: {error}"))?;
    if source_genesis.id()?.to_string() != XPR_BLOCK_ONE_ID {
        bail!(
            "source block 1 id {} differs from canonical genesis {XPR_BLOCK_ONE_ID}",
            source_genesis.id()?
        );
    }

    if inspect_schedules {
        let mut previous = None;
        for block_num in 1..=last {
            let block = controller
                .parse_block(&source.packed_block(block_num)?)
                .map_err(|error| anyhow::anyhow!("decode source block {block_num}: {error}"))?;
            let header = &block.signed_block_header.header;
            let state = (header.schedule_version, header.confirmed, header.producer);
            if previous != Some(state) || header.new_producers.is_some() {
                eprintln!(
                    "schedule block {block_num}: producer={} confirmed={} active_version={} new={:?}",
                    header.producer,
                    header.confirmed,
                    header.schedule_version,
                    header.new_producers
                );
            }
            previous = Some(state);
        }
    }

    let start = controller
        .last_accepted_block()
        .block_num()
        .saturating_add(1);
    if start > last {
        println!(
            "XPR replay already complete at block {} (requested last {last}, source head {source_last})",
            start - 1
        );
        return Ok(());
    }

    println!(
        "replaying canonical XPR blocks {start}..={last} from {} into {}",
        source_dir.display(),
        arena_dir.display()
    );
    let started = Instant::now();
    let mut mempool = Mempool::new();
    for block_num in start..=last {
        let packed = source.packed_block(block_num)?;
        let block = controller
            .parse_block(&packed)
            .map_err(|error| anyhow::anyhow!("decode source block {block_num}: {error}"))?;
        if block.block_num() != block_num {
            bail!(
                "source index entry {block_num} decoded as block {}",
                block.block_num()
            );
        }
        if debug_block == Some(block_num) {
            eprintln!(
                "canonical source block {block_num}: {} transactions, header extensions {:?}, block extensions {:?}",
                block.transactions.len(),
                block.signed_block_header.header.header_extensions,
                block.block_extensions
            );
            for (receipt_index, receipt) in block.transactions.iter().enumerate() {
                eprintln!(
                    "  receipt {receipt_index}: id={} status={:?} cpu={} net_words={}",
                    receipt.transaction_id(),
                    receipt.status(),
                    receipt.cpu_usage_us(),
                    receipt.net_usage_words()
                );
                if let Some(packed) = receipt.packed_trx() {
                    let transaction = packed.get_transaction();
                    for (action_index, action) in transaction
                        .context_free_actions
                        .iter()
                        .chain(&transaction.actions)
                        .enumerate()
                    {
                        eprintln!(
                            "    action {action_index}: {}::{} auth={:?} data_bytes={}",
                            action.account(),
                            action.name(),
                            action.authorization(),
                            action.data().len()
                        );
                    }
                }
            }
        }
        let block_id = block.id()?;
        controller
            .verify_block(&block, &mut mempool)
            .await
            .with_context(|| {
                format!("XPR parity divergence verifying block {block_num} {block_id}")
            })?;
        controller
            .accept_block(&block_id, &mut mempool)
            .with_context(|| {
                format!("XPR parity divergence accepting block {block_num} {block_id}")
            })?;

        if block_num % 10_000 == 0 || block_num == last {
            controller.database().close()?;
            let elapsed = started.elapsed().as_secs_f64();
            let count = u64::from(block_num - start + 1);
            println!(
                "accepted block {block_num}/{last} ({:.0} blocks/s, id {block_id})",
                count as f64 / elapsed.max(0.001)
            );
        }
    }

    println!(
        "XPR replay passed through block {last} in {:.1}s",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}
