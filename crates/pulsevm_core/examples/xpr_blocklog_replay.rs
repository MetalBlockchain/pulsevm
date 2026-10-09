//! Replay canonical packed XPR blocks from a Leap `blocks.log`/`blocks.index`.
//!
//! This intentionally consumes the binary block bytes rather than JSON RPC
//! responses: signatures, transaction variants, schedules, and extensions must
//! all reach the production `verify_block` -> `accept_block` path unchanged.

use base64::Engine;
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
    sync::{
        Arc,
        mpsc::sync_channel,
    },
    thread,
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
use jsonrpsee::{
    RpcModule,
    server::ServerBuilder,
    types::{
        ErrorObjectOwned,
        Params,
    },
};
use pulsevm_core::{
    abi::AbiDefinition,
    block::SignedBlock,
    controller::{
        AuthenticatedMigrationBlock,
        Controller,
        MigrationBlockAuthenticator,
        PreparedMigrationBlock,
    },
    id::Id,
    mempool::Mempool,
    name::Name,
    protocol_features::PROTOCOL_VERSION,
    state_history::StateHistoryServer,
    transaction::{
        Action,
        TransactionStatus,
    },
};
use pulsevm_crypto::Digest as PulseDigest;
use pulsevm_serialization::Read as PulseRead;
use serde_json::json;
use sha2::{
    Digest,
    Sha256,
};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

const XPR_CHAIN_ID: &str = "384da888112027f0321850a169f737c33e53b388aad48b5adace4bab97f437e0";
const XPR_BLOCK_ONE_ID: &str = "000000018421bd47ce23d4c47706e0bb98604157afedc67d56d05c82d5aa10c5";
const XPR_V3_FIRST_BLOCK_OFFSET: u64 = 126;
const PARTIAL_SCAN_WINDOW: usize = 4 * 1024 * 1024;
const SIGNATURE_BATCH_SIZE: usize = 256;
const SIGNATURE_PIPELINE_BATCHES: usize = 4;
const MAX_DEFAULT_SIGNATURE_THREADS: usize = 8;
const REPLAY_SEMANTICS_VERSION: u32 = 4;
// Version 4 preserves `last_updated` when schedule promotion maintains the
// producer permissions, as Leap does. Every older persisted replay checkpoint
// is unsafe to resume; version 3 added chainbase's reserved permission id 0,
// while earlier versions also predate secondary-index and deferred fixes.
const REPLAY_SEMANTICS_FILE: &str = "xpr_replay_semantics_version";
const ONLY_LINK_TO_EXISTING_PERMISSION_FEATURE_DIGEST: [u8; 32] = [
    0x1a, 0x99, 0xa5, 0x9d, 0x87, 0xe0, 0x6e, 0x09, 0xec, 0x5b, 0x02, 0x8a, 0x9c, 0xbb, 0x77, 0x49,
    0xb4, 0xa5, 0xad, 0x88, 0x19, 0x00, 0x43, 0x65, 0xd0, 0x2d, 0xc4, 0x37, 0x9a, 0x8b, 0x72, 0x41,
];

type ReplayController = Arc<RwLock<Controller>>;

fn replay_rpc_error(code: i32, message: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(code, "replay_rpc_error", Some(message.into()))
}

fn params_object(
    params: Params<'_>,
) -> Result<serde_json::Map<String, serde_json::Value>, ErrorObjectOwned> {
    let value: serde_json::Value = params
        .parse()
        .map_err(|error| replay_rpc_error(400, format!("invalid parameters: {error}")))?;
    match value {
        serde_json::Value::Null => Ok(serde_json::Map::new()),
        serde_json::Value::Object(object) => Ok(object),
        _ => Err(replay_rpc_error(400, "parameters must be a JSON object")),
    }
}

fn parameter_string(
    params: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<String, ErrorObjectOwned> {
    let value = params
        .get(key)
        .ok_or_else(|| replay_rpc_error(400, format!("missing parameter {key}")))?;
    match value {
        serde_json::Value::String(value) => Ok(value.clone()),
        serde_json::Value::Number(value) => Ok(value.to_string()),
        _ => Err(replay_rpc_error(
            400,
            format!("parameter {key} must be a string or number"),
        )),
    }
}

fn parameter_name(
    params: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<Name, ErrorObjectOwned> {
    let value = parameter_string(params, key)?;
    Name::from_str(&value)
        .map_err(|error| replay_rpc_error(400, format!("invalid {key} {value}: {error}")))
}

fn optional_string(
    params: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<Option<String>, ErrorObjectOwned> {
    match params.get(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(replay_rpc_error(
            400,
            format!("parameter {key} must be a string"),
        )),
    }
}

fn optional_bool(
    params: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    default: bool,
) -> Result<bool, ErrorObjectOwned> {
    match params.get(key) {
        None | Some(serde_json::Value::Null) => Ok(default),
        Some(value) => value
            .as_bool()
            .ok_or_else(|| replay_rpc_error(400, format!("parameter {key} must be a boolean"))),
    }
}

fn optional_u32(
    params: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    default: u32,
) -> Result<u32, ErrorObjectOwned> {
    match params.get(key) {
        None | Some(serde_json::Value::Null) => Ok(default),
        Some(serde_json::Value::Number(value)) => value
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| replay_rpc_error(400, format!("parameter {key} must be a uint32"))),
        Some(serde_json::Value::String(value)) => value
            .parse::<u32>()
            .map_err(|error| replay_rpc_error(400, format!("invalid {key}: {error}"))),
        Some(_) => Err(replay_rpc_error(
            400,
            format!("parameter {key} must be a uint32"),
        )),
    }
}

async fn replay_get_info(
    controller: &ReplayController,
) -> Result<serde_json::Value, ErrorObjectOwned> {
    let controller = controller.read().await;
    let head = controller.last_accepted_block();
    let database = controller.database();
    let head_id = head
        .id()
        .map_err(|error| replay_rpc_error(500, error.to_string()))?;
    let next_protocol_upgrade = controller
        .next_protocol_upgrade(head.block_num())
        .map(|upgrade| {
            json!({
                "protocol_version": upgrade.protocol_version,
                "activation_height": upgrade.activation_height,
            })
        });

    Ok(json!({
        "server_version": "pulsevm-replay",
        "protocol_version": controller.protocol_version(head.block_num()),
        "supported_protocol_version": PROTOCOL_VERSION,
        "protocol_upgrade_schedule_hash": hex::encode(controller.protocol_upgrade_schedule_hash()),
        "next_protocol_upgrade": next_protocol_upgrade,
        "server_time": head.timestamp(),
        "chain_id": controller.chain_id(),
        "head_block_num": head.block_num(),
        "last_irreversible_block_num": head.block_num(),
        "last_irreversible_block_id": head_id,
        "head_block_id": head_id,
        "head_block_time": head.timestamp(),
        "head_block_producer": head.signed_block_header.header.producer,
        "virtual_block_cpu_limit": database.get_virtual_block_cpu_limit().map_err(|error| replay_rpc_error(500, error.to_string()))?,
        "virtual_block_net_limit": database.get_virtual_block_net_limit().map_err(|error| replay_rpc_error(500, error.to_string()))?,
        "block_cpu_limit": database.get_block_cpu_limit().map_err(|error| replay_rpc_error(500, error.to_string()))?,
        "block_net_limit": database.get_block_net_limit().map_err(|error| replay_rpc_error(500, error.to_string()))?,
        "server_version_string": "v5.0.3",
        "fork_db_head_block_num": head.block_num(),
        "fork_db_head_block_id": head_id,
        "server_full_version_string": "v5.0.3-pulsevm-replay",
        "total_cpu_weight": database.get_total_cpu_weight().map_err(|error| replay_rpc_error(500, error.to_string()))?,
        "total_net_weight": database.get_total_net_weight().map_err(|error| replay_rpc_error(500, error.to_string()))?,
        "earliest_available_block_num": 1,
        "last_irreversible_block_time": head.timestamp(),
    }))
}

async fn replay_get_block(
    controller: &ReplayController,
    params: Params<'_>,
) -> Result<serde_json::Value, ErrorObjectOwned> {
    let params = params_object(params)?;
    let identifier = parameter_string(&params, "block_num_or_id")?;
    let controller = controller.read().await;
    let block = if let Ok(block_num) = identifier.parse::<u32>() {
        controller
            .get_block_by_height(block_num)
            .map_err(|error| replay_rpc_error(500, error.to_string()))?
            .ok_or_else(|| replay_rpc_error(404, format!("block {block_num} not found")))?
    } else {
        let id = Id::from_str(&identifier)
            .map_err(|error| replay_rpc_error(400, format!("invalid block identifier: {error}")))?;
        controller
            .get_block(id)
            .map_err(|error| replay_rpc_error(500, error.to_string()))?
            .ok_or_else(|| replay_rpc_error(404, format!("block {identifier} not found")))?
    };
    serde_json::to_value(block).map_err(|error| replay_rpc_error(500, error.to_string()))
}

async fn replay_get_account(
    controller: &ReplayController,
    params: Params<'_>,
) -> Result<serde_json::Value, ErrorObjectOwned> {
    let params = params_object(params)?;
    let account = parameter_name(&params, "account_name")?;
    let expected_core_symbol = optional_string(&params, "expected_core_symbol")?;
    let controller = controller.read().await;
    let database = controller.database();
    let head_num = controller.last_accepted_block().block_num();
    let head_time = controller.last_accepted_block().timestamp().to_time_point();
    let response = match expected_core_symbol {
        Some(symbol) => database.get_account_info_with_core_symbol(
            account.as_u64(),
            &symbol,
            head_num,
            &head_time,
        ),
        None => {
            database.get_account_info_without_core_symbol(account.as_u64(), head_num, &head_time)
        }
    }
    .map_err(|error| replay_rpc_error(404, error.to_string()))?;
    serde_json::from_str(&response).map_err(|error| replay_rpc_error(500, error.to_string()))
}

async fn replay_get_table_rows(
    controller: &ReplayController,
    params: Params<'_>,
) -> Result<serde_json::Value, ErrorObjectOwned> {
    let params = params_object(params)?;
    let json_mode = optional_bool(&params, "json", true)?;
    let code = parameter_name(&params, "code")?;
    let scope = parameter_string(&params, "scope")?;
    let table = parameter_name(&params, "table")?;
    let table_key = optional_string(&params, "table_key")?.unwrap_or_default();
    let lower_bound = optional_string(&params, "lower_bound")?.unwrap_or_default();
    let upper_bound = optional_string(&params, "upper_bound")?.unwrap_or_default();
    let limit = optional_u32(&params, "limit", 10)?;
    let key_type = optional_string(&params, "key_type")?.unwrap_or_default();
    let index_position = optional_u32(&params, "index_position", 1)?;
    let encode_type = optional_string(&params, "encode_type")?.unwrap_or_else(|| "dec".to_string());
    let reverse = optional_bool(&params, "reverse", false)?;
    let show_payer = optional_bool(&params, "show_payer", false)?;
    let controller = controller.read().await;
    let response = controller
        .database()
        .get_table_rows(
            json_mode,
            code.as_u64(),
            &scope,
            table.as_u64(),
            &table_key,
            &lower_bound,
            &upper_bound,
            limit,
            &key_type,
            &index_position.to_string(),
            &encode_type,
            reverse,
            show_payer,
        )
        .map_err(|error| replay_rpc_error(500, error.to_string()))?;
    serde_json::from_str(&response).map_err(|error| replay_rpc_error(500, error.to_string()))
}

async fn replay_get_table_by_scope(
    controller: &ReplayController,
    params: Params<'_>,
) -> Result<serde_json::Value, ErrorObjectOwned> {
    let params = params_object(params)?;
    let code = parameter_name(&params, "code")?;
    let table = parameter_name(&params, "table")?;
    let lower_bound = optional_string(&params, "lower_bound")?.unwrap_or_default();
    let upper_bound = optional_string(&params, "upper_bound")?.unwrap_or_default();
    let limit = optional_u32(&params, "limit", 10)?;
    let reverse = optional_bool(&params, "reverse", false)?;
    let controller = controller.read().await;
    let response = controller
        .database()
        .get_table_by_scope(
            code.as_u64(),
            table.as_u64(),
            &lower_bound,
            &upper_bound,
            limit,
            reverse,
        )
        .map_err(|error| replay_rpc_error(500, error.to_string()))?;
    serde_json::from_str(&response).map_err(|error| replay_rpc_error(500, error.to_string()))
}

async fn replay_get_currency_balance(
    controller: &ReplayController,
    params: Params<'_>,
) -> Result<serde_json::Value, ErrorObjectOwned> {
    let params = params_object(params)?;
    let code = parameter_name(&params, "code")?;
    let account = parameter_name(&params, "account")?;
    let symbol = optional_string(&params, "symbol")?;
    let controller = controller.read().await;
    let response = match symbol {
        Some(symbol) => controller.database().get_currency_balance_with_symbol(
            code.as_u64(),
            account.as_u64(),
            &symbol,
        ),
        None => controller
            .database()
            .get_currency_balance_without_symbol(code.as_u64(), account.as_u64()),
    }
    .map_err(|error| replay_rpc_error(500, error.to_string()))?;
    serde_json::from_str(&response).map_err(|error| replay_rpc_error(500, error.to_string()))
}

async fn replay_get_currency_stats(
    controller: &ReplayController,
    params: Params<'_>,
) -> Result<serde_json::Value, ErrorObjectOwned> {
    let params = params_object(params)?;
    let code = parameter_name(&params, "code")?;
    let symbol = parameter_string(&params, "symbol")?;
    let controller = controller.read().await;
    let response = controller
        .database()
        .get_currency_stats(code.as_u64(), &symbol)
        .map_err(|error| replay_rpc_error(500, error.to_string()))?;
    serde_json::from_str(&response).map_err(|error| replay_rpc_error(500, error.to_string()))
}

async fn replay_get_raw_abi(
    controller: &ReplayController,
    params: Params<'_>,
) -> Result<serde_json::Value, ErrorObjectOwned> {
    let params = params_object(params)?;
    let account = parameter_name(&params, "account_name")?;
    let controller = controller.read().await;
    let database = controller.database();
    let abi = database
        .arena_account_abi_bytes(account.as_u64())
        .unwrap_or_default();
    let (code_hash, _, _) = database
        .account_code_hash_vm(account.as_u64())
        .map_err(|error| replay_rpc_error(404, error.to_string()))?;
    let abi_hash = if abi.is_empty() {
        PulseDigest::default()
    } else {
        PulseDigest::hash(&abi)
    };
    Ok(json!({
        "account_name": account,
        "code_hash": Id::new(code_hash),
        "abi_hash": abi_hash,
        "abi": base64::engine::general_purpose::STANDARD.encode(abi),
    }))
}

async fn replay_get_abi(
    controller: &ReplayController,
    params: Params<'_>,
) -> Result<serde_json::Value, ErrorObjectOwned> {
    let params = params_object(params)?;
    let account = parameter_name(&params, "account_name")?;
    let controller = controller.read().await;
    let abi = controller
        .database()
        .arena_account_abi_bytes(account.as_u64())
        .ok_or_else(|| replay_rpc_error(404, format!("account {account} not found")))?;
    let abi = AbiDefinition::read(abi.as_slice(), &mut 0)
        .map_err(|error| replay_rpc_error(400, error.to_string()))?;
    serde_json::to_value(abi).map_err(|error| replay_rpc_error(500, error.to_string()))
}

async fn replay_get_producers(
    controller: &ReplayController,
    params: Params<'_>,
) -> Result<serde_json::Value, ErrorObjectOwned> {
    let params = params_object(params)?;
    let json_mode = optional_bool(&params, "json", true)?;
    let controller = controller.read().await;
    let schedule = controller.active_producer_schedule();
    let eosio =
        Name::from_str("eosio").map_err(|error| replay_rpc_error(500, error.to_string()))?;
    let producers =
        Name::from_str("producers").map_err(|error| replay_rpc_error(500, error.to_string()))?;
    let response = controller
        .database()
        .get_table_rows(
            json_mode,
            eosio.as_u64(),
            "eosio",
            producers.as_u64(),
            "",
            "",
            "",
            125,
            "",
            "1",
            "dec",
            false,
            false,
        )
        .map_err(|error| replay_rpc_error(500, error.to_string()))?;
    let table = serde_json::from_str::<serde_json::Value>(&response)
        .map_err(|error| replay_rpc_error(500, error.to_string()))?;
    let table_rows = table
        .get("rows")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let rows = schedule
        .producers
        .iter()
        .filter_map(|producer| {
            let owner = producer.producer_name.to_string();
            table_rows
                .iter()
                .find(|row| {
                    row.get("owner").and_then(serde_json::Value::as_str) == Some(owner.as_str())
                })
                .cloned()
        })
        .collect::<Vec<_>>();
    Ok(json!({
        // The deployed Bloks frontend expects its PulseVM producer adapter
        // to receive the same shape as its paginated producer API. Keep the
        // SHiP/table-compatible fields as well for existing callers.
        "producers": rows,
        "count": schedule.producers.len(),
        "rows": rows,
        "total": schedule.producers.len(),
        "more": "",
        "schedule_version": schedule.version,
    }))
}

async fn start_replay_rpc(
    controller: ReplayController,
    bind: &str,
) -> Result<jsonrpsee::server::ServerHandle> {
    let address = bind
        .parse::<std::net::SocketAddr>()
        .with_context(|| format!("invalid XPR_REPLAY_RPC_BIND {bind}"))?;
    let server = ServerBuilder::default().build(address).await?;
    let mut module = RpcModule::new(controller);
    module.register_async_method("pulsevm.getInfo", |_, controller, _| async move {
        replay_get_info(controller.as_ref()).await
    })?;
    module.register_async_method("pulsevm.getBlock", |params, controller, _| async move {
        replay_get_block(controller.as_ref(), params).await
    })?;
    module.register_async_method("pulsevm.getRawBlock", |params, controller, _| async move {
        replay_get_block(controller.as_ref(), params).await
    })?;
    module.register_async_method("pulsevm.getAccount", |params, controller, _| async move {
        replay_get_account(controller.as_ref(), params).await
    })?;
    module.register_async_method("pulsevm.getTableRows", |params, controller, _| async move {
        replay_get_table_rows(controller.as_ref(), params).await
    })?;
    module.register_async_method(
        "pulsevm.getTableByScope",
        |params, controller, _| async move {
            replay_get_table_by_scope(controller.as_ref(), params).await
        },
    )?;
    module.register_async_method(
        "pulsevm.getCurrencyBalance",
        |params, controller, _| async move {
            replay_get_currency_balance(controller.as_ref(), params).await
        },
    )?;
    module.register_async_method(
        "pulsevm.getCurrencyStats",
        |params, controller, _| async move {
            replay_get_currency_stats(controller.as_ref(), params).await
        },
    )?;
    module.register_async_method("pulsevm.getRawABI", |params, controller, _| async move {
        replay_get_raw_abi(controller.as_ref(), params).await
    })?;
    module.register_async_method("pulsevm.getABI", |params, controller, _| async move {
        replay_get_abi(controller.as_ref(), params).await
    })?;
    module.register_async_method("pulsevm.getProducers", |params, controller, _| async move {
        replay_get_producers(controller.as_ref(), params).await
    })?;
    Ok(server.start(module))
}

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

fn verify_replay_checkpoint_semantics(
    arena_dir: &Path,
    revision: u32,
    initialized_fresh: bool,
) -> Result<()> {
    let path = arena_dir.join(REPLAY_SEMANTICS_FILE);
    match fs::read_to_string(&path) {
        Ok(value) => {
            let version = value
                .trim()
                .parse::<u32>()
                .with_context(|| format!("invalid replay semantics marker {}", path.display()))?;
            if version != REPLAY_SEMANTICS_VERSION {
                bail!(
                    "Arena checkpoint uses XPR replay semantics version {version}, but this binary requires {REPLAY_SEMANTICS_VERSION}"
                );
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let trusted = env::var("XPR_REPLAY_TRUST_LEGACY_CHECKPOINT").as_deref() == Ok("1");
            if revision > 0 && !initialized_fresh && !trusted {
                bail!(
                    "unmarked Arena checkpoint at block {revision} may contain incorrect producer-permission timestamps, omit reserved permission id 0, or contain state produced before secondary-index billing and deferred-transaction retirement were fixed; restart from an empty Arena, or set XPR_REPLAY_TRUST_LEGACY_CHECKPOINT=1 only after independent state validation"
                );
            }
            fs::write(&path, format!("{REPLAY_SEMANTICS_VERSION}\n"))
                .with_context(|| format!("write replay semantics marker {}", path.display()))?;
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("read replay semantics marker {}", path.display()));
        }
    }
    Ok(())
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

    /// Refresh a growing Leap block log. Leap publishes complete block-log
    /// records before appending their offsets; ignore a partial trailing index
    /// word while the producer is writing it, then expose only complete entries.
    fn refresh(&mut self) -> Result<u32> {
        self.effective_log_len = self.log.get_ref().metadata()?.len();
        let BlockOffsets::Indexed {
            reader,
            blocks,
            cached,
        } = &mut self.offsets
        else {
            bail!("follow mode requires Leap's append-only blocks.index");
        };
        let index_len = reader.get_ref().metadata()?.len();
        let complete_len = index_len / 8 * 8;
        let new_blocks =
            u32::try_from(complete_len / 8).context("source block index exceeds uint32 height")?;
        if new_blocks < *blocks {
            bail!("source block index shrank from {} to {new_blocks}", *blocks);
        }
        if new_blocks > *blocks {
            *blocks = new_blocks;
            *cached = None;
        }
        Ok(new_blocks)
    }

    fn packed_block(&mut self, block_num: u32) -> Result<Vec<u8>> {
        let (start, mut end) = self.offsets.pair(block_num, self.effective_log_len)?;
        let mut length = usize::try_from(end - start).context("packed block is too large")?;
        if block_num == self.offsets.len() {
            // A live Leap writer can append bytes for the next block before its
            // index entry appears. Decode the indexed block to find its exact
            // record boundary instead of treating the current file tail as its
            // end.
            let available = usize::try_from(self.effective_log_len - start)
                .context("live source tail is too large")?;
            let mut tail = vec![0; available];
            if self.next_offset != Some(start) {
                self.log.seek(SeekFrom::Start(start))?;
            }
            self.log.read_exact(&mut tail)?;
            // The tail read advances the buffered cursor to EOF. Force the
            // record read below to seek back to this block's start.
            self.next_offset = None;
            let mut cursor = 0;
            let block = SignedBlock::read(&tail, &mut cursor).map_err(|error| {
                anyhow::anyhow!("decode live source block {block_num}: {error}")
            })?;
            if block.block_num() != block_num {
                bail!(
                    "live source offset {start} decoded as block {}, expected {block_num}",
                    block.block_num()
                );
            }
            length = cursor;
            end = start
                .checked_add(u64::try_from(length).context("packed block is too large")?)
                .context("source block record offset overflow")?;
        }
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

fn action_mentions_account(action: &Action, account: Name) -> bool {
    let encoded = account.as_u64().to_le_bytes();
    action.account() == &account
        || action
            .authorization()
            .iter()
            .any(|level| level.actor == account)
        || action
            .data()
            .windows(encoded.len())
            .any(|window| window == encoded)
}

fn block_mentions_account(block: &SignedBlock, account: Name) -> bool {
    block.transactions.iter().any(|receipt| {
        receipt.packed_trx().is_some_and(|packed| {
            let transaction = packed.get_transaction();
            transaction
                .context_free_actions
                .iter()
                .chain(&transaction.actions)
                .any(|action| action_mentions_account(action, account))
        })
    })
}

fn dump_matching_actions(block_num: u32, block: &SignedBlock, account: Name) {
    for (receipt_index, receipt) in block.transactions.iter().enumerate() {
        let Some(packed) = receipt.packed_trx() else {
            continue;
        };
        let transaction = packed.get_transaction();
        for (action_index, action) in transaction
            .context_free_actions
            .iter()
            .chain(&transaction.actions)
            .enumerate()
        {
            if action_mentions_account(action, account) {
                eprintln!(
                    "source block {block_num} receipt {receipt_index} action {action_index}: {}::{} auth={:?} data_bytes={} data_hex={}",
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

fn setcode_payload(data: &[u8]) -> Option<(Name, u8, u8, &[u8])> {
    let account = Name::new(u64::from_le_bytes(data.get(..8)?.try_into().ok()?));
    let vm_type = *data.get(8)?;
    let vm_version = *data.get(9)?;
    let mut position = 10;
    let mut length = 0usize;
    let mut shift = 0u32;
    loop {
        let byte = *data.get(position)?;
        position += 1;
        length |= usize::from(byte & 0x7f).checked_shl(shift)?;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 32 {
            return None;
        }
    }
    let code = data.get(position..position.checked_add(length)?)?;
    (position + length == data.len()).then_some((account, vm_type, vm_version, code))
}

fn authenticate_signature_batch(
    batch: Vec<PreparedMigrationBlock>,
    thread_count: usize,
) -> Result<Vec<AuthenticatedMigrationBlock>> {
    let worker_count = thread_count.min(batch.len()).max(1);
    let chunk_size = batch.len().div_ceil(worker_count);
    let mut batch = batch.into_iter();
    let chunks: Vec<Vec<_>> = (0..worker_count)
        .map(|_| batch.by_ref().take(chunk_size).collect())
        .filter(|chunk: &Vec<_>| !chunk.is_empty())
        .collect();

    thread::scope(|scope| {
        let workers: Vec<_> = chunks
            .into_iter()
            .map(|chunk| {
                scope.spawn(move || {
                    chunk
                        .into_iter()
                        .map(MigrationBlockAuthenticator::authenticate_prepared)
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let mut authenticated = Vec::with_capacity(SIGNATURE_BATCH_SIZE);
        for worker in workers {
            let recovered = worker
                .join()
                .map_err(|_| anyhow::anyhow!("signature recovery worker panicked"))?;
            for block in recovered {
                authenticated.push(block?);
            }
        }
        Ok(authenticated)
    })
}

fn usage(program: &str) {
    eprintln!(
        "Usage: {program} <source-blocks-dir> <arena-dir> [last-block]\n\
         Replays canonical XPR blocks and resumes at the Arena tip when possible."
    );
}

fn read_indexed_height(path: &Path) -> Result<Option<u32>> {
    match fs::read_to_string(path) {
        Ok(value) => Ok(Some(value.trim().parse::<u32>().with_context(|| {
            format!(
                "invalid Hyperion indexed-height watermark {}",
                path.display()
            )
        })?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error)
            .with_context(|| format!("read Hyperion indexed-height watermark {}", path.display())),
    }
}

async fn wait_for_hyperion_capacity(
    next_block: u32,
    watermark_path: &Path,
    max_lag: u32,
) -> Result<u32> {
    loop {
        let indexed = read_indexed_height(watermark_path)?.unwrap_or(0);
        if next_block <= indexed.saturating_add(max_lag) {
            return Ok(indexed);
        }
        eprintln!(
            "replay waiting for Hyperion: next_block={next_block} indexed={indexed} max_lag={max_lag}"
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
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
    let follow = env::var("XPR_REPLAY_FOLLOW").as_deref() == Ok("1");
    if follow && requested_last.is_some() {
        bail!("follow mode does not accept a fixed last-block argument");
    }
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
    let trace_ram_account = env::var("XPR_REPLAY_TRACE_RAM_ACCOUNT")
        .ok()
        .map(|value| Name::from_str(&value).context("invalid XPR_REPLAY_TRACE_RAM_ACCOUNT"))
        .transpose()?;
    let audit_ram_account = env::var("XPR_REPLAY_AUDIT_RAM_ACCOUNT")
        .ok()
        .map(|value| Name::from_str(&value).context("invalid XPR_REPLAY_AUDIT_RAM_ACCOUNT"))
        .transpose()?;
    let profile_replay = env::var_os("XPR_REPLAY_PROFILE").is_some();
    let ship_enabled = env::var("XPR_REPLAY_SHIP_ENABLED").as_deref() == Ok("1");
    let ship_bind =
        env::var("XPR_REPLAY_SHIP_BIND").unwrap_or_else(|_| "127.0.0.1:9090".to_string());
    let indexed_height_path = env::var_os("XPR_REPLAY_INDEXED_HEIGHT_FILE").map(PathBuf::from);
    let ship_max_lag = env::var("XPR_REPLAY_SHIP_MAX_LAG")
        .ok()
        .map(|value| {
            value
                .parse::<u32>()
                .context("XPR_REPLAY_SHIP_MAX_LAG must be a uint32")
        })
        .transpose()?
        .unwrap_or(100_000);
    let ship_retained_blocks = env::var("XPR_REPLAY_SHIP_RETAIN_BLOCKS")
        .ok()
        .map(|value| {
            value
                .parse::<u32>()
                .context("XPR_REPLAY_SHIP_RETAIN_BLOCKS must be a uint32")
        })
        .transpose()?
        .unwrap_or(20_000);
    let rpc_bind = env::var("XPR_REPLAY_RPC_BIND").ok();
    if ship_enabled {
        if ship_max_lag == 0 {
            bail!("XPR_REPLAY_SHIP_MAX_LAG must be greater than zero");
        }
        if ship_retained_blocks == 0 || ship_retained_blocks >= ship_max_lag {
            bail!(
                "XPR_REPLAY_SHIP_RETAIN_BLOCKS must be greater than zero and smaller than XPR_REPLAY_SHIP_MAX_LAG"
            );
        }
        if indexed_height_path.is_none() {
            bail!("XPR_REPLAY_INDEXED_HEIGHT_FILE is required when SHiP replay is enabled");
        }
    }
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
    let signature_threads = env::var("XPR_REPLAY_SIGNATURE_THREADS")
        .ok()
        .map(|value| {
            value
                .parse::<usize>()
                .context("XPR_REPLAY_SIGNATURE_THREADS must be a positive integer")
        })
        .transpose()?
        .unwrap_or_else(|| {
            thread::available_parallelism()
                .map(|count| count.get().saturating_sub(1))
                .unwrap_or(1)
                .clamp(1, MAX_DEFAULT_SIGNATURE_THREADS)
        });
    if signature_threads == 0 {
        bail!("XPR_REPLAY_SIGNATURE_THREADS must be greater than zero");
    }

    let source_dir = PathBuf::from(source_dir);
    let arena_dir = PathBuf::from(arena_dir);
    let mut source = BlockLog::open(&source_dir)?;
    let source_last = source.last_block_num()?;
    let last = requested_last.unwrap_or(source_last).min(source_last);
    if last < 1 {
        bail!("source block log has no genesis block");
    }

    // Scan top-level deployment actions directly from packed blocks, without
    // opening an Arena database. Indirect setcode actions (for example an
    // eosio.msig::exec inline action) are not present in the packed transaction;
    // pair this output with the code object's first_block_used metadata.
    if let Ok(account_list) = env::var("XPR_REPLAY_SCAN_SETCODE") {
        let final_block = debug_block
            .context("XPR_REPLAY_SCAN_SETCODE requires XPR_REPLAY_DEBUG_BLOCK=<height>")?;
        let first_block = env::var("XPR_REPLAY_INSPECT_FROM")
            .ok()
            .map(|value| {
                value
                    .parse::<u32>()
                    .context("invalid XPR_REPLAY_INSPECT_FROM")
            })
            .transpose()?
            .unwrap_or(1);
        if first_block > final_block || final_block > source_last {
            bail!("requested setcode scan is outside the source block log");
        }
        let accounts = account_list
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(Name::from_str)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let eosio = Name::from_str("eosio")?;
        let setcode = Name::from_str("setcode")?;
        let output_directory = env::var_os("XPR_REPLAY_SETCODE_DIR").map(PathBuf::from);
        eprintln!(
            "scanning executed top-level setcode actions; indirect/deferred deployments require code-object metadata"
        );
        if let Some(directory) = &output_directory {
            fs::create_dir_all(directory)?;
        }
        for block_num in first_block..=final_block {
            let packed = source.packed_block(block_num)?;
            let block = SignedBlock::read(&packed, &mut 0)
                .map_err(|error| anyhow::anyhow!("decode source block {block_num}: {error}"))?;
            for receipt in &block.transactions {
                // Only an executed receipt can mutate the deployed code. Failed
                // setcode attempts remain in packed block history but must not
                // become native-accelerator activation boundaries.
                if receipt.status() != &TransactionStatus::Executed {
                    continue;
                }
                let Some(transaction) = receipt.packed_trx().map(|packed| packed.get_transaction())
                else {
                    continue;
                };
                for action in &transaction.actions {
                    if action.account() != &eosio || action.name() != &setcode {
                        continue;
                    }
                    let action_data = action.data();
                    let Some((account, vm_type, vm_version, code)) =
                        setcode_payload(action_data.as_ref())
                    else {
                        bail!("malformed eosio::setcode payload at block {block_num}");
                    };
                    if accounts.is_empty() || accounts.contains(&account) {
                        let code_hash = hex::encode(Sha256::digest(code));
                        println!(
                            "block={block_num} account={account} vm_type={vm_type} vm_version={vm_version} code_bytes={} code_hash={}",
                            code.len(),
                            code_hash
                        );
                        if let Some(directory) = &output_directory {
                            fs::write(
                                directory.join(format!("{block_num}-{account}-{code_hash}.wasm")),
                                code,
                            )?;
                        }
                    }
                }
            }
        }
        return Ok(());
    }

    // Decode packed source blocks without constructing a controller or scanning
    // its accepted history. This keeps workload inspection cheap enough to use
    // while profiling a long replay checkpoint.
    if env::var_os("XPR_REPLAY_DECODE_ONLY").is_some() {
        let final_block = debug_block
            .context("XPR_REPLAY_DECODE_ONLY requires XPR_REPLAY_DEBUG_BLOCK=<height>")?;
        let first_block = env::var("XPR_REPLAY_INSPECT_FROM")
            .ok()
            .map(|value| {
                value
                    .parse::<u32>()
                    .context("XPR_REPLAY_INSPECT_FROM must be a uint32")
            })
            .transpose()?
            .unwrap_or(final_block);
        if first_block > final_block || final_block > source_last {
            bail!("requested decode range is outside the source block log");
        }
        for block_num in first_block..=final_block {
            let packed = source.packed_block(block_num)?;
            let block = SignedBlock::read(&packed, &mut 0)
                .map_err(|error| anyhow::anyhow!("decode source block {block_num}: {error}"))?;
            dump_block(block_num, &block);
        }
        return Ok(());
    }

    // Scan only packed transaction data and avoid opening the multi-gigabyte
    // Arena checkpoint. This is suitable for parallel historical audits where
    // each worker owns a disjoint block range.
    if let Ok(account) = env::var("XPR_REPLAY_SCAN_ACCOUNT") {
        let account = Name::from_str(&account).context("invalid XPR_REPLAY_SCAN_ACCOUNT")?;
        let final_block = debug_block
            .context("XPR_REPLAY_SCAN_ACCOUNT requires XPR_REPLAY_DEBUG_BLOCK=<height>")?;
        let first_block = env::var("XPR_REPLAY_INSPECT_FROM")
            .ok()
            .map(|value| {
                value
                    .parse::<u32>()
                    .context("XPR_REPLAY_INSPECT_FROM must be a uint32")
            })
            .transpose()?
            .unwrap_or(final_block);
        if first_block > final_block || final_block > source_last {
            bail!("requested account scan is outside the source block log");
        }
        for block_num in first_block..=final_block {
            let packed = source.packed_block(block_num)?;
            let block = SignedBlock::read(&packed, &mut 0)
                .map_err(|error| anyhow::anyhow!("decode source block {block_num}: {error}"))?;
            dump_matching_actions(block_num, &block, account);
        }
        return Ok(());
    }

    let chain_id = Id::from_str(XPR_CHAIN_ID).expect("constant XPR chain id is valid");
    let producer_key = env::var("XPR_REPLAY_PRODUCER_KEY")
        .context("XPR_REPLAY_PRODUCER_KEY must contain a local replay signing key")?;
    let config = serde_json::to_vec(&json!({
        "system_account": "eosio",
        "native_system_contract": false,
        "antelope_block_signatures": true,
        // A full-history Hyperion audit emits SHiP data while replay runs. The
        // ordinary state migration keeps it disabled to avoid derived history.
        "state_history_enabled": ship_enabled,
        "bulk_replay": true,
        "producer_name": "eosio",
        // Required by NodeConfig, but replay never signs or produces blocks.
        "producer_key": producer_key,
        "db_size": 48_u64 * 1024 * 1024 * 1024,
        "max_transaction_time_ms": 300_000
    }))?;
    let genesis =
        include_bytes!("../../../tools/xpr-chainbase-export/xpr-mainnet-genesis.json").to_vec();
    let initialized_fresh = !arena_dir.join("arena_state.bin").exists();
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
    if env::var("PULSEVM_XPR_NATIVE_REPLAY").as_deref() == Ok("1") {
        controller.database().enable_xpr_native_replay();
        eprintln!("XPR native replay accelerators enabled");
    }
    let local_tip = controller.last_accepted_block();
    verify_replay_checkpoint_semantics(&arena_dir, local_tip.block_num(), initialized_fresh)?;
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
        let matches_only = env::var_os("XPR_REPLAY_INSPECT_MATCHES_ONLY").is_some();
        for inspected_block in first_block..=block_num {
            let block = controller
                .parse_block(&source.packed_block(inspected_block)?)
                .map_err(|error| {
                    anyhow::anyhow!("decode source block {inspected_block}: {error}")
                })?;
            if matches_only && let Some(account) = inspect_account {
                dump_matching_actions(inspected_block, &block, account);
            } else if inspect_account.is_none_or(|account| block_mentions_account(&block, account))
            {
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
    if start > last && !follow {
        println!(
            "XPR replay already complete at block {} (requested last {last}, source head {source_last})",
            start - 1
        );
        return Ok(());
    }

    println!(
        "{} canonical XPR blocks beginning at {start} from {} into {}",
        if follow { "following" } else { "replaying" },
        source_dir.display(),
        arena_dir.display()
    );
    let started = Instant::now();
    let mut mempool = Mempool::new();
    let mut authenticator = controller.migration_block_authenticator()?;
    let mut traced_ram_usage = trace_ram_account.and_then(|account| {
        controller
            .database()
            .arena_account_ram_usage(account.as_u64())
    });
    let initial_ram_residual = audit_ram_account
        .map(|account| -> Result<i64> {
            let stored = controller
                .database()
                .get_account_ram_usage(account.as_u64())?;
            let represented = controller
                .database()
                .account_ram_billing_breakdown(account.as_u64())?
                .total()?;
            let residual = stored - represented;
            eprintln!("RAM inventory baseline recorded at block {}", start - 1);
            Ok(residual)
        })
        .transpose()?;
    let controller = Arc::new(RwLock::new(controller));
    let _rpc_handle = if let Some(bind) = rpc_bind.as_deref() {
        Some(start_replay_rpc(controller.clone(), bind).await?)
    } else {
        None
    };
    let ship_cancel = CancellationToken::new();
    let ship_handle = if ship_enabled {
        let server = StateHistoryServer::new(controller.clone());
        let bind = ship_bind.clone();
        let cancel = ship_cancel.clone();
        Some(tokio::spawn(async move {
            server.run_ws_server(&bind, false, cancel).await
        }))
    } else {
        None
    };
    let (signature_sender, signature_receiver) =
        sync_channel::<Result<Vec<AuthenticatedMigrationBlock>>>(SIGNATURE_PIPELINE_BATCHES);
    let signature_worker = thread::Builder::new()
        .name("xpr-signature-prefetch".to_string())
        .spawn(move || {
            let result = (|| -> Result<()> {
                let mut batch = Vec::with_capacity(SIGNATURE_BATCH_SIZE);
                let mut block_num = start;
                loop {
                    let available = source.refresh()?;
                    if block_num > available {
                        if !batch.is_empty() {
                            let pending = std::mem::replace(
                                &mut batch,
                                Vec::with_capacity(SIGNATURE_BATCH_SIZE),
                            );
                            let authenticated =
                                authenticate_signature_batch(pending, signature_threads)?;
                            if signature_sender.send(Ok(authenticated)).is_err() {
                                return Ok(());
                            }
                        }
                        if !follow {
                            break;
                        }
                        thread::sleep(Duration::from_millis(250));
                        continue;
                    }
                    let packed = source.packed_block(block_num)?;
                    let prepared = authenticator
                        .prepare_packed(packed)
                        .with_context(|| format!("prepare canonical source block {block_num}"))?;
                    if prepared.block_num() != block_num {
                        bail!(
                            "source index entry {block_num} decoded as block {}",
                            prepared.block_num()
                        );
                    }
                    batch.push(prepared);
                    if batch.len() == SIGNATURE_BATCH_SIZE {
                        let authenticated = authenticate_signature_batch(batch, signature_threads)?;
                        if signature_sender.send(Ok(authenticated)).is_err() {
                            return Ok(());
                        }
                        batch = Vec::with_capacity(SIGNATURE_BATCH_SIZE);
                    }
                    block_num = block_num
                        .checked_add(1)
                        .context("canonical block height overflow")?;
                }
                if !batch.is_empty() {
                    let authenticated = authenticate_signature_batch(batch, signature_threads)?;
                    let _ = signature_sender.send(Ok(authenticated));
                }
                Ok(())
            })();
            if let Err(error) = result {
                let _ = signature_sender.send(Err(error));
            }
        })?;

    let mut block_num = start;
    let mut empty_blocks = 0u64;
    let mut transaction_receipts = 0u64;
    let mut signature_wait_time = Duration::ZERO;
    let mut verify_time = Duration::ZERO;
    let mut accept_time = Duration::ZERO;

    while follow || block_num <= last {
        let signature_wait_started = Instant::now();
        let batch = signature_receiver
            .recv()
            .context("signature prefetch worker stopped before the replay completed")??;
        if profile_replay {
            signature_wait_time += signature_wait_started.elapsed();
        }
        controller
            .read()
            .await
            .schedule_migration_wasm_precompiles(&batch);
        for authenticated in batch {
            if let Some(path) = indexed_height_path.as_deref() {
                wait_for_hyperion_capacity(block_num, path, ship_max_lag).await?;
            }
            let block = authenticated.block();
            if block.transactions.is_empty() {
                empty_blocks += 1;
            }
            transaction_receipts += block.transactions.len() as u64;
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
            let verify_started = Instant::now();
            let mut controller = controller.write().await;
            controller
                .verify_authenticated_migration_block(&authenticated, &mut mempool)
                .await
                .with_context(|| {
                    format!("XPR parity divergence verifying block {block_num} {block_id}")
                })?;
            if profile_replay {
                verify_time += verify_started.elapsed();
            }
            let accept_started = Instant::now();
            controller
                .accept_authenticated_migration_block(&authenticated, &mut mempool)
                .with_context(|| {
                    format!("XPR parity divergence accepting block {block_num} {block_id}")
                })?;
            if profile_replay {
                accept_time += accept_started.elapsed();
            }

            if let Some(account) = trace_ram_account {
                let current = controller
                    .database()
                    .arena_account_ram_usage(account.as_u64());
                if current != traced_ram_usage {
                    eprintln!("RAM trace observed a change at block {block_num} {block_id}");
                    traced_ram_usage = current;
                }
            }

            if block_num % checkpoint_interval == 0 || (!follow && block_num == last) {
                if let Some(account) = audit_ram_account {
                    let stored = controller
                        .database()
                        .get_account_ram_usage(account.as_u64())?;
                    let represented = controller
                        .database()
                        .account_ram_billing_breakdown(account.as_u64())?
                        .total()?;
                    let residual = stored - represented;
                    eprintln!("RAM inventory audit completed at block {block_num}");
                    if Some(residual) != initial_ram_residual {
                        bail!("RAM inventory residual changed at or before block {block_num}");
                    }
                }
                // Bulk replay defers the per-block block-log durability barrier.
                // Sync history first, then persist Arena state: after a crash the
                // log can be ahead of the checkpoint (and safely rewound), never
                // behind a state revision that depends on it.
                controller.sync_accepted_logs()?;
                controller.database().close()?;
                controller.persist_migration_header_state()?;
                if let Some(path) = indexed_height_path.as_deref()
                    && let Some(indexed) = read_indexed_height(path)?
                {
                    let first_to_keep = indexed
                        .saturating_sub(ship_retained_blocks)
                        .max(1)
                        .min(block_num);
                    controller.block_log()?.prune_from(first_to_keep)?;
                    if let Some(log) = controller.trace_log() {
                        log.prune_from(first_to_keep)?;
                    }
                    if let Some(log) = controller.chain_state_log() {
                        log.prune_from(first_to_keep)?;
                    }
                }
            }
            if block_num % 10_000 == 0 || (!follow && block_num == last) {
                let elapsed = started.elapsed().as_secs_f64();
                let count = u64::from(block_num - start + 1);
                println!(
                    "accepted block {block_num}/{} ({:.0} blocks/s, id {block_id})",
                    if follow {
                        "LIVE".to_string()
                    } else {
                        last.to_string()
                    },
                    count as f64 / elapsed.max(0.001)
                );
                if profile_replay {
                    println!(
                        "XPR replay profile: signature_wait={:.3}s, verify={:.3}s, accept={:.3}s",
                        signature_wait_time.as_secs_f64(),
                        verify_time.as_secs_f64(),
                        accept_time.as_secs_f64(),
                    );
                    signature_wait_time = Duration::ZERO;
                    verify_time = Duration::ZERO;
                    accept_time = Duration::ZERO;
                }
            }
            block_num = block_num
                .checked_add(1)
                .context("canonical block height overflow")?;
        }
    }
    signature_worker
        .join()
        .map_err(|_| anyhow::anyhow!("signature prefetch worker panicked"))?;

    if !follow && let Some(path) = indexed_height_path.as_deref() {
        while read_indexed_height(path)?.unwrap_or(0) < last {
            let indexed = read_indexed_height(path)?.unwrap_or(0);
            eprintln!("replay complete; waiting for Hyperion to index {indexed}/{last}");
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
    ship_cancel.cancel();
    if let Some(handle) = ship_handle {
        handle
            .await
            .context("state-history server task panicked")??;
    }

    println!(
        "XPR replay passed through block {last} in {:.1}s ({empty_blocks} empty blocks, {transaction_receipts} transaction receipts)",
        started.elapsed().as_secs_f64(),
    );
    if profile_replay {
        let blocks = u64::from(last - start + 1);
        let micros_per_block = |duration: Duration| duration.as_micros() as f64 / blocks as f64;
        println!(
            "XPR replay profile: signature_wait={:.3}s ({:.1} us/block), verify={:.3}s ({:.1} us/block), accept={:.3}s ({:.1} us/block)",
            signature_wait_time.as_secs_f64(),
            micros_per_block(signature_wait_time),
            verify_time.as_secs_f64(),
            micros_per_block(verify_time),
            accept_time.as_secs_f64(),
            micros_per_block(accept_time),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks_a_fresh_arena() {
        let temp = tempfile::tempdir().unwrap();
        verify_replay_checkpoint_semantics(temp.path(), 1, true).unwrap();
        assert_eq!(
            fs::read_to_string(temp.path().join(REPLAY_SEMANTICS_FILE)).unwrap(),
            format!("{REPLAY_SEMANTICS_VERSION}\n")
        );
    }

    #[test]
    fn rejects_any_unversioned_persisted_checkpoint() {
        let temp = tempfile::tempdir().unwrap();
        let error = verify_replay_checkpoint_semantics(temp.path(), 1, false).unwrap_err();
        assert!(error.to_string().contains("omit reserved permission id 0"));
    }

    #[test]
    fn rejects_a_checkpoint_from_another_semantics_version() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join(REPLAY_SEMANTICS_FILE), "0\n").unwrap();
        let error = verify_replay_checkpoint_semantics(temp.path(), 1, false).unwrap_err();
        assert!(
            error
                .to_string()
                .contains(&format!("requires {REPLAY_SEMANTICS_VERSION}"))
        );
    }

    #[test]
    fn setcode_payload_parser_is_bounded_and_exact() {
        let account = Name::from_str("oracles").unwrap();
        let mut payload = account.as_u64().to_le_bytes().to_vec();
        payload.extend_from_slice(&[0, 0, 3, 1, 2, 3]);
        let (decoded, vm_type, vm_version, code) = setcode_payload(&payload).unwrap();
        assert_eq!(decoded, account);
        assert_eq!((vm_type, vm_version), (0, 0));
        assert_eq!(code, [1, 2, 3]);

        let mut trailing = payload.clone();
        trailing.push(4);
        assert!(setcode_payload(&trailing).is_none());

        payload[10] = 4;
        assert!(setcode_payload(&payload).is_none());
    }
}
