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
        BufReader,
        Read as IoRead,
        Seek,
        SeekFrom,
    },
    path::{
        Path,
        PathBuf,
    },
    str::FromStr,
    sync::mpsc::sync_channel,
    thread,
    time::Instant,
};

use anyhow::{
    Context,
    Result,
    bail,
};
use pulsevm_core::{
    block::SignedBlock,
    controller::{
        AuthenticatedMigrationBlock,
        Controller,
    },
    id::Id,
    mempool::Mempool,
    name::Name,
};
use pulsevm_serialization::Read as PulseRead;
use serde_json::json;

const XPR_CHAIN_ID: &str = "384da888112027f0321850a169f737c33e53b388aad48b5adace4bab97f437e0";
const XPR_BLOCK_ONE_ID: &str = "000000018421bd47ce23d4c47706e0bb98604157afedc67d56d05c82d5aa10c5";
const UNUSED_PRODUCER_KEY: &str = "PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez";
const XPR_V3_FIRST_BLOCK_OFFSET: u64 = 126;
const PARTIAL_SCAN_WINDOW: usize = 4 * 1024 * 1024;
const SIGNATURE_BATCH_SIZE: usize = 256;
const SIGNATURE_PIPELINE_BATCHES: usize = 4;
const ONLY_LINK_TO_EXISTING_PERMISSION_FEATURE_DIGEST: [u8; 32] = [
    0x1a, 0x99, 0xa5, 0x9d, 0x87, 0xe0, 0x6e, 0x09, 0xec, 0x5b, 0x02, 0x8a, 0x9c, 0xbb, 0x77, 0x49,
    0xb4, 0xa5, 0xad, 0x88, 0x19, 0x00, 0x43, 0x65, 0xd0, 0x2d, 0xc4, 0x37, 0x9a, 0x8b, 0x72, 0x41,
];

struct BlockLog {
    log: BufReader<File>,
    offsets: BlockOffsets,
    effective_log_len: u64,
    next_offset: Option<u64>,
}

enum BlockOffsets {
    /// Leap's index is already a dense array of little-endian offsets. Keep a
    /// buffered cursor over it instead of expanding 400M entries into two
    /// multi-gigabyte `Vec<u64>` allocations.
    Indexed {
        reader: BufReader<File>,
        blocks: u32,
        cached: Option<(u32, u64)>,
    },
    /// Indexless partial downloads still need the offsets discovered while
    /// scanning, because there is no on-disk index to stream.
    Scanned(Vec<u64>),
}

impl BlockOffsets {
    fn len(&self) -> u32 {
        match self {
            Self::Indexed { blocks, .. } => *blocks,
            Self::Scanned(offsets) => u32::try_from(offsets.len()).unwrap_or(u32::MAX),
        }
    }

    fn pair(&mut self, block_num: u32, effective_log_len: u64) -> Result<(u64, u64)> {
        if block_num == 0 || block_num > self.len() {
            bail!("block {block_num} is outside the source block-log range");
        }

        let (start, next) = match self {
            Self::Indexed {
                reader,
                blocks,
                cached,
            } => {
                let start = match cached.take() {
                    Some((cached_block, offset)) if cached_block == block_num => offset,
                    _ => {
                        reader.seek(SeekFrom::Start(u64::from(block_num - 1) * 8))?;
                        read_index_offset(reader)?
                    }
                };
                let next = if block_num < *blocks {
                    let next = read_index_offset(reader)?;
                    *cached = Some((block_num + 1, next));
                    next
                } else {
                    effective_log_len
                };
                (start, next)
            }
            Self::Scanned(offsets) => {
                let index = block_num as usize - 1;
                let start = offsets[index];
                let next = offsets.get(index + 1).copied().unwrap_or(effective_log_len);
                (start, next)
            }
        };
        let end = next
            .checked_sub(8)
            .context("source block-log offsets overlap")?;
        if end <= start {
            bail!("source block {block_num} has invalid byte range {start}..{end}");
        }
        Ok((start, end))
    }
}

fn read_index_offset(reader: &mut impl IoRead) -> Result<u64> {
    let mut bytes = [0; 8];
    reader.read_exact(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

#[cfg(test)]
mod block_offset_tests {
    use super::*;
    use std::io::Write;

    fn indexed(offsets: &[u64]) -> BlockOffsets {
        let mut file = tempfile::tempfile().unwrap();
        for offset in offsets {
            file.write_all(&offset.to_le_bytes()).unwrap();
        }
        file.seek(SeekFrom::Start(0)).unwrap();
        BlockOffsets::Indexed {
            reader: BufReader::with_capacity(16, file),
            blocks: offsets.len() as u32,
            cached: None,
        }
    }

    #[test]
    fn indexed_offsets_support_sequential_and_random_reads() {
        let mut offsets = indexed(&[126, 200, 300]);
        assert_eq!(offsets.pair(1, 400).unwrap(), (126, 192));
        assert_eq!(offsets.pair(2, 400).unwrap(), (200, 292));
        assert_eq!(offsets.pair(1, 400).unwrap(), (126, 192));
        assert_eq!(offsets.pair(3, 400).unwrap(), (300, 392));
        assert_eq!(offsets.pair(2, 400).unwrap(), (200, 292));
    }

    #[test]
    fn indexed_offsets_reject_overlaps_lazily() {
        let mut offsets = indexed(&[126, 100]);
        assert!(offsets.pair(1, 400).is_err());
    }

    #[test]
    fn scanned_offsets_use_the_effective_partial_tail() {
        let mut offsets = BlockOffsets::Scanned(vec![126, 200]);
        assert_eq!(offsets.pair(2, 275).unwrap(), (200, 267));
    }
}

impl BlockLog {
    fn open(dir: &Path) -> Result<Self> {
        let log_path = dir.join("blocks.log");
        let index_path = dir.join("blocks.index");
        let log = File::open(&log_path)
            .with_context(|| format!("open source block log {}", log_path.display()))?;
        let log_len = log.metadata()?.len();
        let (offsets, effective_log_len) = match File::open(&index_path) {
            Ok(mut index) => {
                let index_len = index.metadata()?.len();
                if index_len == 0 || index_len % 8 != 0 {
                    bail!(
                        "{} is empty or not a sequence of uint64 offsets",
                        index_path.display()
                    );
                }
                let blocks = u32::try_from(index_len / 8)
                    .context("source block index exceeds uint32 height")?;
                let first = read_index_offset(&mut index)?;
                index.seek(SeekFrom::Start(index_len - 8))?;
                let last = read_index_offset(&mut index)?;
                if first >= log_len || last.checked_add(8).is_none_or(|end| end > log_len) {
                    bail!(
                        "{} points beyond the source block log",
                        index_path.display()
                    );
                }
                index.seek(SeekFrom::Start(0))?;
                (
                    BlockOffsets::Indexed {
                        reader: BufReader::with_capacity(PARTIAL_SCAN_WINDOW, index),
                        blocks,
                        cached: None,
                    },
                    log_len,
                )
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let (offsets, effective_log_len) = Self::scan_partial_offsets(&log_path)?;
                (BlockOffsets::Scanned(offsets), effective_log_len)
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("read source block index {}", index_path.display()));
            }
        };
        Ok(Self {
            log: BufReader::with_capacity(PARTIAL_SCAN_WINDOW, log),
            offsets,
            effective_log_len,
            next_offset: None,
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
        Ok(self.offsets.len())
    }

    fn packed_block(&mut self, block_num: u32) -> Result<Vec<u8>> {
        let (start, end) = self.offsets.pair(block_num, self.effective_log_len)?;
        let length = usize::try_from(end - start).context("packed block is too large")?;
        let record_length = length
            .checked_add(8)
            .context("packed block record is too large")?;
        let mut bytes = vec![0; record_length];
        if self.next_offset != Some(start) {
            self.log.seek(SeekFrom::Start(start))?;
        }
        self.log.read_exact(&mut bytes)?;

        let trailer: [u8; 8] = bytes[length..].try_into().unwrap();
        let recorded_start = u64::from_le_bytes(trailer);
        if recorded_start != start {
            bail!("source block {block_num} trailer points to {recorded_start}, expected {start}");
        }
        bytes.truncate(length);
        self.next_offset = Some(
            end.checked_add(8)
                .context("source block record offset overflow")?,
        );
        Ok(bytes)
    }
}

fn dump_block(block_num: u32, block: &SignedBlock) {
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
                    "    action {action_index}: {}::{} auth={:?} data_bytes={} data_hex={}",
                    action.account(),
                    action.name(),
                    action.authorization(),
                    action.data().len(),
                    hex::encode(action.data())
                );
            }
        }
    }
}

fn block_mentions_account(block: &SignedBlock, account: Name) -> bool {
    let encoded = account.as_u64().to_le_bytes();
    block.transactions.iter().any(|receipt| {
        receipt.packed_trx().is_some_and(|packed| {
            let transaction = packed.get_transaction();
            transaction
                .context_free_actions
                .iter()
                .chain(&transaction.actions)
                .any(|action| {
                    action.account() == &account
                        || action
                            .authorization()
                            .iter()
                            .any(|level| level.actor == account)
                        || action
                            .data()
                            .windows(encoded.len())
                            .any(|window| window == encoded)
                })
        })
    })
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
    let checkpoint_interval = env::var("XPR_REPLAY_CHECKPOINT_INTERVAL")
        .ok()
        .map(|value| {
            value
                .parse::<u32>()
                .context("XPR_REPLAY_CHECKPOINT_INTERVAL must be a uint32")
        })
        .transpose()?
        .unwrap_or(1_000_000);
    if checkpoint_interval == 0 {
        bail!("XPR_REPLAY_CHECKPOINT_INTERVAL must be greater than zero");
    }

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
        // The importer needs canonical execution and final Arena state, not a
        // second copy of source history-derived SHiP traces and table deltas.
        "state_history_enabled": false,
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

    if env::var_os("XPR_REPLAY_INSPECT_ONLY").is_some() {
        let block_num = debug_block
            .context("XPR_REPLAY_INSPECT_ONLY requires XPR_REPLAY_DEBUG_BLOCK=<height>")?;
        let first_block = env::var("XPR_REPLAY_INSPECT_FROM")
            .ok()
            .map(|value| {
                value
                    .parse::<u32>()
                    .context("XPR_REPLAY_INSPECT_FROM must be a uint32")
            })
            .transpose()?
            .unwrap_or(block_num);
        if first_block > block_num {
            bail!("XPR_REPLAY_INSPECT_FROM must not exceed XPR_REPLAY_DEBUG_BLOCK");
        }
        let inspect_account = env::var("XPR_REPLAY_INSPECT_ACCOUNT")
            .ok()
            .map(|value| Name::from_str(&value).context("invalid XPR_REPLAY_INSPECT_ACCOUNT"))
            .transpose()?;
        for inspected_block in first_block..=block_num {
            let block = controller
                .parse_block(&source.packed_block(inspected_block)?)
                .map_err(|error| {
                    anyhow::anyhow!("decode source block {inspected_block}: {error}")
                })?;
            if inspect_account.is_none_or(|account| block_mentions_account(&block, account)) {
                dump_block(inspected_block, &block);
            }
        }
        let database = controller.database();
        let read = database.read()?;
        let eosio = Name::from_str("eosio")?;
        let committee = Name::from_str("committee")?;
        eprintln!(
            "Arena state at block {}: ONLY_LINK_TO_EXISTING_PERMISSION={} eosio@committee={:?} activated_features={:?}",
            controller.last_accepted_block().block_num(),
            database.protocol_feature_activated(ONLY_LINK_TO_EXISTING_PERMISSION_FEATURE_DIGEST),
            read.find_permission_info(eosio.as_u64(), committee.as_u64())?,
            database.activated_protocol_features()?
        );
        return Ok(());
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
    let mut authenticator = controller.migration_block_authenticator()?;
    let (signature_sender, signature_receiver) =
        sync_channel::<Result<Vec<AuthenticatedMigrationBlock>>>(SIGNATURE_PIPELINE_BATCHES);
    let signature_worker = thread::Builder::new()
        .name("xpr-signature-prefetch".to_string())
        .spawn(move || {
            let result = (|| -> Result<()> {
                let mut batch = Vec::with_capacity(SIGNATURE_BATCH_SIZE);
                for block_num in start..=last {
                    let packed = source.packed_block(block_num)?;
                    let block = SignedBlock::read(&packed, &mut 0).map_err(|error| {
                        anyhow::anyhow!("decode source block {block_num}: {error}")
                    })?;
                    if block.block_num() != block_num {
                        bail!(
                            "source index entry {block_num} decoded as block {}",
                            block.block_num()
                        );
                    }
                    let authenticated = authenticator.authenticate(block).with_context(|| {
                        format!("authenticate canonical source block {block_num}")
                    })?;
                    batch.push(authenticated);
                    if batch.len() == SIGNATURE_BATCH_SIZE {
                        if signature_sender.send(Ok(batch)).is_err() {
                            return Ok(());
                        }
                        batch = Vec::with_capacity(SIGNATURE_BATCH_SIZE);
                    }
                }
                if !batch.is_empty() {
                    let _ = signature_sender.send(Ok(batch));
                }
                Ok(())
            })();
            if let Err(error) = result {
                let _ = signature_sender.send(Err(error));
            }
        })?;

    let mut block_num = start;
    while block_num <= last {
        let batch = signature_receiver
            .recv()
            .context("signature prefetch worker stopped before the replay completed")??;
        for authenticated in batch {
            let block = authenticated.block();
            if block.block_num() != block_num {
                bail!(
                    "signature pipeline yielded block {}, expected {block_num}",
                    block.block_num()
                );
            }
            if debug_block == Some(block_num) {
                dump_block(block_num, block);
            }
            let block_id = block.id()?;
            controller
                .verify_authenticated_migration_block(&authenticated, &mut mempool)
                .await
                .with_context(|| {
                    format!("XPR parity divergence verifying block {block_num} {block_id}")
                })?;
            controller
                .accept_block(&block_id, &mut mempool)
                .with_context(|| {
                    format!("XPR parity divergence accepting block {block_num} {block_id}")
                })?;

            if block_num % checkpoint_interval == 0 || block_num == last {
                // Bulk replay defers the per-block block-log durability barrier.
                // Sync history first, then persist Arena state: after a crash the
                // log can be ahead of the checkpoint (and safely rewound), never
                // behind a state revision that depends on it.
                controller.sync_accepted_logs()?;
                controller.database().close()?;
            }
            if block_num % 10_000 == 0 || block_num == last {
                let elapsed = started.elapsed().as_secs_f64();
                let count = u64::from(block_num - start + 1);
                println!(
                    "accepted block {block_num}/{last} ({:.0} blocks/s, id {block_id})",
                    count as f64 / elapsed.max(0.001)
                );
            }
            block_num = block_num
                .checked_add(1)
                .context("canonical block height overflow")?;
        }
    }
    signature_worker
        .join()
        .map_err(|_| anyhow::anyhow!("signature prefetch worker panicked"))?;

    println!(
        "XPR replay passed through block {last} in {:.1}s",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}
