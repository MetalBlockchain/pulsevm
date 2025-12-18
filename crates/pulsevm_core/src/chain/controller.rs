use core::fmt;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::Path,
    sync::{Arc, LazyLock},
};

use crate::{
    OWNER_NAME, PULSE_NAME,
    account::CodeObject,
    authority::{Permission, PermissionLink},
    chain::{
        ACTIVE_NAME,
        account::{Account, AccountMetadata},
        apply_context::ApplyContext,
        authority::{Authority, KeyWeight},
        authorization_manager::AuthorizationManager,
        block::{BlockHeader, BlockTimestamp, SignedBlock},
        config::{
            BLOCK_CPU_USAGE_AVERAGE_WINDOW_MS, BLOCK_INTERVAL_MS, BLOCK_SIZE_AVERAGE_WINDOW_MS,
            DELETEAUTH_NAME, GlobalPropertyObject, LINKAUTH_NAME,
            MAXIMUM_ELASTIC_RESOURCE_MULTIPLIER, NEWACCOUNT_NAME, SETABI_NAME, SETCODE_NAME,
            UNLINKAUTH_NAME, UPDATEAUTH_NAME, eos_percent,
        },
        error::ChainError,
        genesis::{ChainConfig, Genesis},
        id::Id,
        mempool::Mempool,
        name::Name,
        pulse_contract::{
            deleteauth, get_pulse_contract_abi, linkauth, newaccount, setabi, setcode, unlinkauth,
            updateauth,
        },
        resource::ElasticLimitParameters,
        resource_limits::ResourceLimitsManager,
        state_history::StateHistoryLog,
        transaction::{PackedTransaction, TransactionReceipt, TransactionTrace},
        transaction_context::{TransactionContext, TransactionResult},
        utils::make_ratio,
        wasm_runtime::WasmRuntime,
    },
    config::DynamicGlobalPropertyObject,
    resource::{ResourceLimits, ResourceLimitsConfig, ResourceLimitsState, ResourceUsage},
    table::{KeyValue, Table},
    utils::prepare_db_object,
};

use pulsevm_chainbase::{Database, UndoSession};
use pulsevm_crypto::{Digest, merkle};
use pulsevm_serialization::{Read, Write};
use spdlog::info;
use tokio::sync::RwLock as AsyncRwLock;

pub type ApplyHandlerFn = fn(&mut ApplyContext) -> Result<(), ChainError>;
pub type ApplyHandlerMap = HashMap<
    (Name, Name, Name), // (receiver, contract, action)
    ApplyHandlerFn,
>;

pub static APPLY_HANDLERS: LazyLock<ApplyHandlerMap> = LazyLock::new(|| {
    let mut m: ApplyHandlerMap = HashMap::new();
    m.insert((PULSE_NAME, PULSE_NAME, NEWACCOUNT_NAME), newaccount);
    m.insert((PULSE_NAME, PULSE_NAME, SETCODE_NAME), setcode);
    m.insert((PULSE_NAME, PULSE_NAME, SETABI_NAME), setabi);
    m.insert((PULSE_NAME, PULSE_NAME, UPDATEAUTH_NAME), updateauth);
    m.insert((PULSE_NAME, PULSE_NAME, DELETEAUTH_NAME), deleteauth);
    m.insert((PULSE_NAME, PULSE_NAME, LINKAUTH_NAME), linkauth);
    m.insert((PULSE_NAME, PULSE_NAME, UNLINKAUTH_NAME), unlinkauth);
    m
});

pub struct Controller {
    wasm_runtime: WasmRuntime,
    config: Arc<ChainConfig>,

    last_accepted_block: SignedBlock,
    preferred_id: Id,
    db: Database,
    verified_blocks: HashMap<Id, SignedBlock>,
    chain_id: Id,

    trace_log: Option<StateHistoryLog>,
    chain_state_log: Option<StateHistoryLog>,
}

#[derive(Debug)]
pub enum ControllerError {
    GenesisError(String),
}

impl fmt::Display for ControllerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ControllerError::GenesisError(msg) => write!(f, "Genesis error: {}", msg),
        }
    }
}

impl Controller {
    pub fn new() -> Self {
        // Create a temporary database
        let db = Database::new(Path::new("temp")).unwrap();
        let wasm_runtime = WasmRuntime::new().unwrap();
        let controller = Controller {
            wasm_runtime,
            config: Arc::new(ChainConfig::default()),

            last_accepted_block: SignedBlock::default(),
            preferred_id: Id::default(),
            db: db,
            verified_blocks: HashMap::new(),
            chain_id: Id::default(),

            trace_log: None,
            chain_state_log: None,
        };

        controller
    }

    pub fn initialize(&mut self, genesis_bytes: &Vec<u8>, db_path: &str) -> Result<(), ChainError> {
        info!("initializing controller with DB path: {}", db_path);
        self.db = Database::new(Path::new(&db_path)).map_err(|e| {
            ChainError::InternalError(Some(format!("failed to open database: {}", e)))
        })?;
        // Parse genesis bytes
        let genesis = Genesis::parse(genesis_bytes)
            .map_err(|e| ChainError::ParseError(format!("failed to parse genesis: {}", e)))?
            .validate()?;
        self.config = Arc::new(genesis.initial_configuration().clone());
        self.chain_id = genesis.compute_chain_id()?;
        self.trace_log = Some(StateHistoryLog::open(&db_path, "trace_log").map_err(|e| {
            ChainError::InternalError(Some(format!("failed to open trace log: {}", e)))
        })?);
        self.chain_state_log = Some(StateHistoryLog::open(&db_path, "chain_state_log").map_err(
            |e| ChainError::InternalError(Some(format!("failed to open chain state log: {}", e))),
        )?);

        // Set our last accepted block to the genesis block
        self.last_accepted_block = SignedBlock::new(
            Id::default(),
            genesis.initial_timestamp().clone(),
            VecDeque::new(),
            Digest::default(),
        );

        let mut session = self.db.undo_session()?;

        // Prep partition handles for faster access
        prepare_db_object::<Account>(&self.db)?;
        prepare_db_object::<AccountMetadata>(&self.db)?;
        prepare_db_object::<SignedBlock>(&self.db)?;
        prepare_db_object::<CodeObject>(&self.db)?;
        prepare_db_object::<DynamicGlobalPropertyObject>(&self.db)?;
        prepare_db_object::<GlobalPropertyObject>(&self.db)?;
        prepare_db_object::<Permission>(&self.db)?;
        prepare_db_object::<PermissionLink>(&self.db)?;
        prepare_db_object::<ResourceUsage>(&self.db)?;
        prepare_db_object::<ResourceLimits>(&self.db)?;
        prepare_db_object::<ResourceLimitsConfig>(&self.db)?;
        prepare_db_object::<ResourceLimitsState>(&self.db)?;
        prepare_db_object::<Table>(&self.db)?;
        prepare_db_object::<KeyValue>(&self.db)?;

        // Do we have the genesis block in our DB?
        let genesis_block = session.find::<SignedBlock>(1).map_err(|e| {
            ChainError::GenesisError(format!("failed to find genesis block: {}", e))
        })?;

        if genesis_block.is_none() {
            session.insert(&self.last_accepted_block).map_err(|e| {
                ChainError::GenesisError(format!("failed to insert genesis block: {}", e))
            })?;
            let default_key = genesis.initial_key();
            info!(
                "initializing pulse account with default key: {}",
                default_key
            );
            let default_authority = Authority::new(
                1,
                vec![KeyWeight::new(default_key.clone(), 1)],
                vec![],
                vec![],
            );
            // Create the pulse@owner permission
            let owner_permission = AuthorizationManager::create_permission(
                &mut session,
                PULSE_NAME,
                OWNER_NAME,
                0,
                default_authority.clone(),
            )
            .map_err(|e| {
                ChainError::GenesisError(format!("failed to create pulse@owner permission: {}", e))
            })?;
            // Create the pulse@active permission
            AuthorizationManager::create_permission(
                &mut session,
                PULSE_NAME,
                ACTIVE_NAME,
                owner_permission.id(),
                default_authority.clone(),
            )
            .map_err(|e| {
                ChainError::GenesisError(format!("failed to create pulse@owner permission: {}", e))
            })?;
            let abi = get_pulse_contract_abi().pack().map_err(|e| {
                ChainError::GenesisError(format!("failed to pack pulse abi: {}", e))
            })?;
            session
                .insert(&Account::new(
                    PULSE_NAME,
                    self.last_accepted_block().timestamp(),
                    abi,
                ))
                .map_err(|e| {
                    ChainError::GenesisError(format!("failed to insert pulse account: {}", e))
                })?;
            session
                .insert(&AccountMetadata::new(PULSE_NAME, true))
                .map_err(|e| {
                    ChainError::GenesisError(format!(
                        "failed to insert pulse account metadata: {}",
                        e
                    ))
                })?;
            session.insert(&GlobalPropertyObject {
                chain_id: self.chain_id.clone(),
                configuration: genesis.initial_configuration().clone(),
            })?;
            ResourceLimitsManager::initialize_database(&mut session)?;
            ResourceLimitsManager::initialize_account(&mut session, PULSE_NAME).map_err(|e| {
                ChainError::GenesisError(format!(
                    "failed to initialize resource limits for pulse account: {}",
                    e
                ))
            })?;
            session.commit()?;
        }

        Ok(())
    }

    pub async fn build_block(&mut self, mempool: &mut Mempool) -> Result<SignedBlock, ChainError> {
        let mut undo_session = self.db.undo_session()?;
        let mut transaction_receipts: VecDeque<TransactionReceipt> = VecDeque::new();
        let timestamp = BlockTimestamp::now();

        // Get transactions from the mempool
        loop {
            if let Some(transaction) = mempool.pop_transaction() {
                let transaction_result =
                    self.execute_transaction(&mut undo_session, &transaction, &timestamp)?;
                let receipt =
                    TransactionReceipt::new(transaction_result.trace.receipt, transaction);

                // Add the transaction to the block
                transaction_receipts.push_back(receipt);
            } else {
                break;
            };
        }

        // Don't build a block if we have no transactions
        if transaction_receipts.len() == 0 {
            return Err(ChainError::NetworkError(format!(
                "built block has no transactions"
            )));
        }

        // Create a new block
        let transaction_mroot = self.calculate_trx_merkle(&transaction_receipts)?;
        let block = SignedBlock::new(
            self.preferred_id,
            timestamp,
            transaction_receipts,
            transaction_mroot,
        );

        // We built this block so no need to verify it again
        self.verified_blocks.insert(
            block.signed_block_header.block.calculate_id().unwrap(),
            block.clone(),
        );

        Ok(block)
    }

    pub async fn verify_block(
        &mut self,
        block: &SignedBlock,
        mempool: Arc<AsyncRwLock<Mempool>>,
    ) -> Result<(), ChainError> {
        if self.verified_blocks.contains_key(&block.id()) {
            return Ok(());
        }

        // Verify the block
        let mut session = self.db.undo_session()?;
        let mut mempool = mempool.write().await;
        self.execute_block(block, &mut session, &mut mempool)
            .await?;
        self.verified_blocks.insert(block.id(), block.clone());

        Ok(())
    }

    pub async fn accept_block(
        &mut self,
        block_id: &Id,
        mempool: Arc<AsyncRwLock<Mempool>>,
    ) -> Result<(), ChainError> {
        let block = {
            self.verified_blocks
                .get(block_id)
                .cloned()
                .ok_or(ChainError::NetworkError(format!(
                    "block with id {} not verified",
                    block_id
                )))?
        };
        let mut session = self.db.undo_session()?;
        let mut mempool = mempool.write().await;
        let transaction_traces = self
            .execute_block(&block, &mut session, &mut mempool)
            .await?;
        let packed_transaction_traces = transaction_traces.pack().map_err(|e| {
            ChainError::TransactionError(format!(
                "failed to pack transaction traces for block {}: {}",
                block_id, e
            ))
        })?;
        self.trace_log
            .as_ref()
            .map(|log| log.append(block_id.clone(), packed_transaction_traces.as_slice()));
        self.chain_state_log
            .as_ref()
            .map(|log| log.append(block_id.clone(), block.id().as_bytes()));
        session
            .commit()
            .map_err(|e| ChainError::TransactionError(format!("failed to commit block: {}", e)))?;
        self.verified_blocks.remove(block_id);
        self.last_accepted_block = block;

        Ok(())
    }

    pub async fn execute_block(
        &mut self,
        block: &SignedBlock,
        session: &mut UndoSession,
        mempool: &mut Mempool,
    ) -> Result<Vec<TransactionTrace>, ChainError> {
        // Make sure we don't have the block already
        let existing_block = session
            .find::<SignedBlock>(block.block_num())
            .map_err(|e| ChainError::TransactionError(format!("failed to find block: {}", e)))?;

        if existing_block.is_some() {
            return Ok(Vec::new());
        }

        let mut transaction_traces: Vec<TransactionTrace> = Vec::new();

        for receipt in &block.transactions {
            // Verify the transaction
            let result = self.execute_transaction(
                session,
                receipt.trx(),
                &block.signed_block_header.block.timestamp,
            )?;

            // Add trace to traces
            transaction_traces.push(result.trace);

            // Remove from mempool if we have it
            mempool.remove_transaction(receipt.trx().id());
        }

        session
            .insert(block)
            .map_err(|e| ChainError::TransactionError(format!("failed to insert block: {}", e)))?;

        // Update resource limits
        let chain_config = &self.config;
        let cpu_target = eos_percent(
            chain_config.max_block_cpu_usage as u64,
            chain_config.target_block_cpu_usage_pct,
        );
        let cpu_elastic_parameters = ElasticLimitParameters::new(
            cpu_target,
            chain_config.max_block_cpu_usage as u64,
            BLOCK_CPU_USAGE_AVERAGE_WINDOW_MS / BLOCK_INTERVAL_MS,
            MAXIMUM_ELASTIC_RESOURCE_MULTIPLIER,
            make_ratio(99, 100),
            make_ratio(1000, 999),
        );
        let net_elastic_parameters = ElasticLimitParameters::new(
            eos_percent(
                chain_config.max_block_net_usage,
                chain_config.target_block_net_usage_pct,
            ),
            chain_config.max_block_net_usage as u64,
            BLOCK_SIZE_AVERAGE_WINDOW_MS / BLOCK_INTERVAL_MS,
            MAXIMUM_ELASTIC_RESOURCE_MULTIPLIER,
            make_ratio(99, 100),
            make_ratio(1000, 999),
        );
        ResourceLimitsManager::process_account_limit_updates(session)?;
        ResourceLimitsManager::set_block_parameters(
            session,
            cpu_elastic_parameters,
            net_elastic_parameters,
        )?;

        Ok(transaction_traces)
    }

    // This function will execute a transaction and roll it back instantly
    // This is useful for checking if a transaction is valid
    pub fn push_transaction(
        &mut self,
        transaction: &PackedTransaction,
        pending_block_timestamp: &BlockTimestamp,
    ) -> Result<TransactionResult, ChainError> {
        let db = &self.db;
        let mut undo_session = db.undo_session()?;
        let result =
            self.execute_transaction(&mut undo_session, transaction, pending_block_timestamp);

        return result;
    }

    // This function will execute a transaction and commit it to the database
    // This is useful for applying a transaction to the blockchain
    pub fn execute_transaction(
        &mut self,
        undo_session: &mut UndoSession,
        packed_transaction: &PackedTransaction,
        pending_block_timestamp: &BlockTimestamp,
    ) -> Result<TransactionResult, ChainError> {
        let signed_transaction = packed_transaction.get_signed_transaction();

        {
            // Verify authority
            AuthorizationManager::check_authorization(
                &self.config,
                undo_session,
                &signed_transaction.transaction().actions,
                &signed_transaction.recovered_keys(&self.chain_id)?,
                &HashSet::new(),
                &HashSet::new(),
            )?;
        }

        let mut trx_context = TransactionContext::new(
            undo_session.clone(),
            self.config.clone(),
            self.wasm_runtime.clone(),
            self.last_accepted_block().block_num() + 1,
            pending_block_timestamp.clone(),
            packed_transaction.id(),
        );

        let trx = packed_transaction.get_transaction();
        trx_context.init_for_input_trx(
            trx,
            packed_transaction.get_unprunable_size()?,
            packed_transaction.get_prunable_size()?,
        )?;
        trx_context.exec(trx)?;
        let result = trx_context.finalize()?;

        Ok(result)
    }

    pub fn last_accepted_block(&self) -> &SignedBlock {
        &self.last_accepted_block
    }

    pub fn get_block_by_height(&self, height: u32) -> Result<Option<SignedBlock>, ChainError> {
        if height == self.last_accepted_block.block_num() {
            return Ok(Some(self.last_accepted_block.clone()));
        }

        // Query DB
        let block = self.db.undo_session()?.find::<SignedBlock>(height)?;

        Ok(block)
    }

    pub fn get_block_id_for_num(&self, height: u32) -> Result<Option<Id>, ChainError> {
        let block = self.get_block_by_height(height)?;

        Ok(block.map(|b| b.id()))
    }

    pub fn get_block(&self, id: Id) -> Result<Option<SignedBlock>, ChainError> {
        self.db
            .undo_session()?
            .find::<SignedBlock>(BlockHeader::num_from_id(&id))
            .map_err(|e| ChainError::TransactionError(format!("failed to find block: {}", e)))
    }

    pub fn parse_block(&self, bytes: &Vec<u8>) -> Result<SignedBlock, ControllerError> {
        let mut pos = 0;
        let block = SignedBlock::read(bytes, &mut pos)
            .map_err(|e| ControllerError::GenesisError(format!("Failed to parse block: {}", e)))?;
        Ok(block)
    }

    pub fn set_preferred_id(&mut self, id: Id) {
        self.preferred_id = id;
    }

    pub fn find_apply_handler(receiver: Name, scope: Name, act: Name) -> Option<ApplyHandlerFn> {
        if let Some(handler) = APPLY_HANDLERS.get(&(receiver, scope, act)) {
            return Some(*handler);
        }
        None
    }

    pub fn create_undo_session(&mut self) -> Result<UndoSession, ChainError> {
        self.db.undo_session().map_err(|e| {
            ChainError::TransactionError(format!("failed to create undo session: {}", e))
        })
    }

    pub fn get_wasm_runtime(&self) -> &WasmRuntime {
        &self.wasm_runtime
    }

    pub fn get_global_properties(
        session: &mut UndoSession,
    ) -> Result<GlobalPropertyObject, ChainError> {
        session.get::<GlobalPropertyObject>(0).map_err(|e| {
            ChainError::TransactionError(format!("failed to get global properties: {}", e))
        })
    }

    pub fn database(&self) -> Database {
        self.db.clone()
    }

    pub fn chain_id(&self) -> Id {
        self.chain_id
    }

    pub fn calculate_trx_merkle(
        &self,
        receipts: &VecDeque<TransactionReceipt>,
    ) -> Result<Digest, ChainError> {
        let mut trx_digests = VecDeque::new();

        for receipt in receipts {
            let digest = receipt.digest().map_err(|e| {
                ChainError::TransactionError(format!(
                    "failed to calculate transaction digest: {}",
                    e
                ))
            })?;
            trx_digests.push_back(digest);
        }

        Ok(merkle(trx_digests))
    }

    pub fn trace_log(&self) -> Option<&StateHistoryLog> {
        self.trace_log.as_ref()
    }

    pub fn chain_state_log(&self) -> Option<&StateHistoryLog> {
        self.chain_state_log.as_ref()
    }

    pub async fn get_block_id(&self, block_num: u32) -> Result<Option<Id>, ChainError> {
        let trace_log = self.trace_log();
        let chain_state_log = self.chain_state_log();

        if let Some(log) = trace_log {
            if let Some(entry) = log.get_block_id(block_num).ok() {
                return Ok(Some(entry));
            }
        }

        if let Some(log) = chain_state_log {
            if let Some(entry) = log.get_block_id(block_num).ok() {
                return Ok(Some(entry));
            }
        }

        let session = self.db.undo_session()?;
        let block = session.find::<SignedBlock>(block_num)?;
        if let Some(block) = block {
            return Ok(Some(block.id()));
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, str::FromStr, vec};

    use pulsevm_proc_macros::{NumBytes, Read, Write};
    use pulsevm_serialization::Write;
    use pulsevm_time::TimePointSec;
    use serde_json::json;
    use tempfile::TempDir;
    use tokio::runtime;

    use crate::chain::{
        asset::{Asset, Symbol},
        authority::PermissionLevel,
        pulse_contract::{NewAccount, SetCode},
        secp256k1::PrivateKey,
        transaction::{Action, Transaction, TransactionHeader},
    };

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes)]
    struct Create {
        issuer: Name,
        max_supply: Asset,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes)]
    struct Transfer {
        from: Name,
        to: Name,
        quantity: Asset,
        memo: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes)]
    struct Issue {
        to: Name,
        quantity: Asset,
        memo: String,
    }

    fn get_temp_dir() -> TempDir {
        tempfile::tempdir().expect("failed to create temp dir")
    }

    fn generate_genesis(private_key: &PrivateKey) -> Vec<u8> {
        let genesis = json!(
        {
            "initial_timestamp": "2023-01-01T00:00:00Z",
            "initial_key": private_key.public_key().to_string(),
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
                "max_inline_action_size": 4096,
                "max_inline_action_depth": 6,
                "max_authority_depth": 6,
                "max_action_return_value_size": 256
            }
        });
        genesis.to_string().into_bytes()
    }

    fn create_account(
        private_key: &PrivateKey,
        account: Name,
        chain_id: Id,
    ) -> Result<PackedTransaction, ChainError> {
        let trx = Transaction::new(
            TransactionHeader::new(TimePointSec::new(0), 0, 0, 0u32.into(), 0, 0u32.into()),
            vec![],
            vec![Action::new(
                Name::from_str("pulse").unwrap(),
                Name::from_str("newaccount").unwrap(),
                NewAccount {
                    creator: Name::from_str("pulse").unwrap(),
                    name: account,
                    owner: Authority::new(
                        1,
                        vec![KeyWeight::new(private_key.public_key(), 1)],
                        vec![],
                        vec![],
                    ),
                    active: Authority::new(
                        1,
                        vec![KeyWeight::new(private_key.public_key(), 1)],
                        vec![],
                        vec![],
                    ),
                }
                .pack()
                .unwrap(),
                vec![PermissionLevel::new(
                    Name::from_str("pulse").unwrap(),
                    Name::from_str("active").unwrap(),
                )],
            )],
        )
        .sign(&private_key, &chain_id)?;
        let packed_trx = PackedTransaction::from_signed_transaction(trx)?;
        Ok(packed_trx)
    }

    fn set_code(
        private_key: &PrivateKey,
        account: Name,
        wasm_bytes: Vec<u8>,
        chain_id: Id,
    ) -> Result<PackedTransaction, ChainError> {
        let trx = Transaction::new(
            TransactionHeader::new(TimePointSec::new(0), 0, 0, 0u32.into(), 0, 0u32.into()),
            vec![],
            vec![Action::new(
                Name::from_str("pulse").unwrap(),
                Name::from_str("setcode").unwrap(),
                SetCode {
                    account,
                    vm_type: 0,
                    vm_version: 0,
                    code: Arc::new(wasm_bytes.into()),
                }
                .pack()
                .unwrap(),
                vec![PermissionLevel::new(
                    account,
                    Name::from_str("active").unwrap(),
                )],
            )],
        )
        .sign(&private_key, &chain_id)?;
        let packed_trx = PackedTransaction::from_signed_transaction(trx)?;
        Ok(packed_trx)
    }

    fn call_contract<T: Write>(
        private_key: &PrivateKey,
        account: Name,
        action: Name,
        action_data: &T,
        chain_id: Id,
    ) -> Result<PackedTransaction, ChainError> {
        let trx = Transaction::new(
            TransactionHeader::new(TimePointSec::new(0), 0, 0, 0u32.into(), 0, 0u32.into()),
            vec![],
            vec![Action::new(
                account,
                action,
                action_data.pack().unwrap(),
                vec![PermissionLevel::new(
                    account,
                    Name::from_str("active").unwrap(),
                )],
            )],
        )
        .sign(&private_key, &chain_id)?;
        let packed_trx = PackedTransaction::from_signed_transaction(trx)?;
        Ok(packed_trx)
    }

    #[test]
    fn test_initialize() -> Result<(), ChainError> {
        let private_key = PrivateKey::random();
        let mut controller = Controller::new();
        let genesis_bytes = generate_genesis(&private_key);
        let temp_path = get_temp_dir();
        controller.initialize(&genesis_bytes.to_vec(), temp_path.path().to_str().unwrap())?;
        assert_eq!(controller.last_accepted_block().block_num(), 1);
        let pending_block_timestamp = controller.last_accepted_block().timestamp();
        let mut undo_session = controller.create_undo_session()?;
        let chain_id = controller.chain_id();
        controller.execute_transaction(
            &mut undo_session,
            &create_account(&private_key, Name::from_str("glenn")?, chain_id)?,
            &pending_block_timestamp,
        )?;
        controller.execute_transaction(
            &mut undo_session,
            &create_account(&private_key, Name::from_str("marshall")?, chain_id)?,
            &pending_block_timestamp,
        )?;

        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let pulse_token_contract =
            fs::read(root.join(Path::new("reference_contracts/pulse_token.wasm"))).unwrap();
        controller.execute_transaction(
            &mut undo_session,
            &set_code(
                &private_key,
                Name::from_str("glenn")?,
                pulse_token_contract,
                chain_id,
            )?,
            &pending_block_timestamp,
        )?;

        controller.execute_transaction(
            &mut undo_session,
            &call_contract(
                &private_key,
                Name::from_str("glenn")?,
                Name::from_str("create")?,
                &Create {
                    issuer: Name::from_str("glenn")?,
                    max_supply: Asset::new(1000000, Symbol(1162826500)),
                },
                chain_id,
            )?,
            &pending_block_timestamp,
        )?;

        controller.execute_transaction(
            &mut undo_session,
            &call_contract(
                &private_key,
                Name::from_str("glenn")?,
                Name::from_str("issue")?,
                &Issue {
                    to: Name::from_str("glenn")?,
                    quantity: Asset {
                        amount: 1000000,
                        symbol: Symbol(1162826500), // "PLUS" in ASCII
                    },
                    memo: "Initial transfer".to_string(),
                },
                chain_id,
            )?,
            &pending_block_timestamp,
        )?;

        controller.execute_transaction(
            &mut undo_session,
            &call_contract(
                &private_key,
                Name::from_str("glenn")?,
                Name::from_str("transfer")?,
                &Transfer {
                    from: Name::from_str("glenn")?,
                    to: Name::from_str("marshall")?,
                    quantity: Asset {
                        amount: 5000,
                        symbol: Symbol(1162826500), // "PLUS" in ASCII
                    },
                    memo: "Initial transfer".to_string(),
                },
                chain_id,
            )?,
            &pending_block_timestamp,
        )?;

        Ok(())
    }

    #[test]
    fn test_api_db() -> Result<(), ChainError> {
        let runtime = runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _guard = runtime.enter();
        let private_key = PrivateKey::random();
        let mut controller = Controller::new();
        let genesis_bytes = generate_genesis(&private_key);
        let temp_path = get_temp_dir();
        controller.initialize(&genesis_bytes.to_vec(), temp_path.path().to_str().unwrap())?;
        let pending_block_timestamp = controller.last_accepted_block().timestamp();
        let mut undo_session = controller.create_undo_session()?;
        let chain_id = controller.chain_id();
        controller.execute_transaction(
            &mut undo_session,
            &create_account(&private_key, Name::from_str("glenn")?, chain_id)?,
            &pending_block_timestamp,
        )?;
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let contract =
            fs::read(root.join(Path::new("reference_contracts/test_api_db.wasm"))).unwrap();
        controller.execute_transaction(
            &mut undo_session,
            &set_code(&private_key, Name::from_str("glenn")?, contract, chain_id)?,
            &pending_block_timestamp,
        )?;

        controller.execute_transaction(
            &mut undo_session,
            &call_contract(
                &private_key,
                Name::from_str("glenn")?,
                Name::from_str("pg")?,
                &Vec::<u8>::new(),
                chain_id,
            )?,
            &pending_block_timestamp,
        )?;
        controller.execute_transaction(
            &mut undo_session,
            &call_contract(
                &private_key,
                Name::from_str("glenn")?,
                Name::from_str("pl")?,
                &Vec::<u8>::new(),
                chain_id,
            )?,
            &pending_block_timestamp,
        )?;
        controller.execute_transaction(
            &mut undo_session,
            &call_contract(
                &private_key,
                Name::from_str("glenn")?,
                Name::from_str("pu")?,
                &Vec::<u8>::new(),
                chain_id,
            )?,
            &pending_block_timestamp,
        )?;

        Ok(())
    }
}