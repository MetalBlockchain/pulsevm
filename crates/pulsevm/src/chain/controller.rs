use core::fmt;
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    path::Path,
    rc::Rc,
    sync::{Arc, LazyLock, RwLock},
};

use crate::{
    chain::{ACTIVE_NAME, Account, AccountMetadata},
    mempool::Mempool,
};

use super::{
    AuthorizationManager, Genesis, Id, Name, OWNER_NAME, PULSE_NAME, TransactionContext,
    apply_context::ApplyContext,
    authority::{Authority, KeyWeight},
    block::{Block, BlockByHeightIndex, BlockTimestamp},
    error::ChainError,
    pulse_contract::{newaccount, setabi, setcode, updateauth},
    resource_limits::ResourceLimitsManager,
    transaction::{self, Transaction},
    wasm_runtime::WasmRuntime,
};
use chrono::{DateTime, Utc};
use pulsevm_chainbase::{Database, UndoSession};
use pulsevm_proc_macros::name;
use pulsevm_serialization::Deserialize;
use spdlog::info;
use tokio::sync::RwLock as AsyncRwLock;

pub type ApplyHandlerFn = fn(&mut ApplyContext) -> Result<(), ChainError>;
pub type ApplyHandlerMap = HashMap<
    (Name, Name, Name), // (receiver, contract, action)
    ApplyHandlerFn,
>;

pub static APPLY_HANDLERS: LazyLock<ApplyHandlerMap> = LazyLock::new(|| {
    let mut m: ApplyHandlerMap = HashMap::new();
    m.insert(
        (PULSE_NAME, PULSE_NAME, Name::new(name!("newaccount"))),
        newaccount,
    );
    m.insert(
        (PULSE_NAME, PULSE_NAME, Name::new(name!("setcode"))),
        setcode,
    );
    m.insert((PULSE_NAME, PULSE_NAME, Name::new(name!("setabi"))), setabi);
    m.insert(
        (PULSE_NAME, PULSE_NAME, Name::new(name!("updateauth"))),
        updateauth,
    );
    m
});

pub struct Controller {
    authorization_manager: AuthorizationManager,
    resource_limits_manager: ResourceLimitsManager,
    wasm_runtime: Arc<RwLock<WasmRuntime>>,

    last_accepted_block: Block,
    preferred_id: Id,
    db: Database,
    verified_blocks: HashMap<Id, Block>,
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
        let db = Database::temporary(Path::new("temp")).unwrap();
        let controller = Controller {
            authorization_manager: AuthorizationManager::new(),
            resource_limits_manager: ResourceLimitsManager::new(),
            wasm_runtime: Arc::new(RwLock::new(WasmRuntime::new())), // TODO: Handle error properly

            last_accepted_block: Block::default(),
            preferred_id: Id::default(),
            db: db,
            verified_blocks: HashMap::new(),
        };

        controller
    }

    pub fn initialize(
        &mut self,
        genesis_bytes: &Vec<u8>,
        db_path: String,
    ) -> Result<(), ControllerError> {
        self.db = Database::new(Path::new(&db_path)).map_err(|e| {
            ControllerError::GenesisError(format!("failed to open database: {}", e))
        })?;
        // Parse genesis bytes
        let genesis = Genesis::parse(genesis_bytes)
            .map_err(|e| ControllerError::GenesisError(format!("failed to parse genesis: {}", e)))?
            .validate()
            .map_err(|e| ControllerError::GenesisError(format!("invalid genesis: {}", e)))?;

        // Set our last accepted block to the genesis block
        self.last_accepted_block = Block::new(
            Id::default(),
            genesis.initial_timestamp().unwrap(),
            0,
            Vec::new(),
        );

        // Do we have the genesis block in our DB?
        let genesis_block = self
            .db
            .find_by_secondary::<Block, BlockByHeightIndex>(self.last_accepted_block.height)
            .map_err(|e| {
                ControllerError::GenesisError(format!("failed to find genesis block: {}", e))
            })?;

        if genesis_block.is_none() {
            // If not, insert it
            let session = self.db.undo_session().map_err(|e| {
                ControllerError::GenesisError(format!("failed to create undo session: {}", e))
            })?;
            let session = Rc::new(RefCell::new(session));
            session
                .borrow_mut()
                .insert(&self.last_accepted_block)
                .map_err(|e| {
                    ControllerError::GenesisError(format!("failed to insert genesis block: {}", e))
                })?;
            let default_key = genesis.initial_key().map_err(|e| {
                ControllerError::GenesisError(format!("failed to get initial key: {}", e))
            })?;
            info!(
                "initializing pulse account with default key: {}",
                default_key.0
            );
            let default_authority = Authority::new(1, vec![KeyWeight::new(default_key, 1)], vec![]);
            // Create the pulse@owner permission
            let owner_permission = self
                .authorization_manager
                .create_permission(
                    session.clone(),
                    PULSE_NAME,
                    OWNER_NAME,
                    0,
                    default_authority.clone(),
                )
                .map_err(|e| {
                    ControllerError::GenesisError(format!(
                        "failed to create pulse@owner permission: {}",
                        e
                    ))
                })?;
            // Create the pulse@active permission
            self.authorization_manager
                .create_permission(
                    session.clone(),
                    PULSE_NAME,
                    ACTIVE_NAME,
                    owner_permission.id(),
                    default_authority.clone(),
                )
                .map_err(|e| {
                    ControllerError::GenesisError(format!(
                        "failed to create pulse@owner permission: {}",
                        e
                    ))
                })?;
            session
                .borrow_mut()
                .insert(&Account::new(PULSE_NAME, 0, vec![]))
                .map_err(|e| {
                    ControllerError::GenesisError(format!("failed to insert pulse account: {}", e))
                })?;
            session
                .borrow_mut()
                .insert(&AccountMetadata::new(PULSE_NAME))
                .map_err(|e| {
                    ControllerError::GenesisError(format!(
                        "failed to insert pulse account metadata: {}",
                        e
                    ))
                })?;
            Rc::try_unwrap(session)
                .map_err(|_| ControllerError::GenesisError("failed to unwrap session".to_string()))?
                .into_inner()
                .commit();
        }

        Ok(())
    }

    pub async fn build_block(
        &self,
        mempool: Arc<AsyncRwLock<Mempool>>,
    ) -> Result<Block, ChainError> {
        let mempool = mempool.clone();
        let mut mempool = mempool.write().await;
        let undo_session = Rc::new(RefCell::new(self.db.undo_session().unwrap()));
        let mut transactions: Vec<Transaction> = Vec::new();

        // Get transactions from the mempool
        loop {
            let transaction = mempool.pop_transaction();

            if transaction.is_none() {
                break;
            }
            let transaction = transaction.unwrap();
            let result = self.execute_transaction(undo_session.clone(), &transaction);
            // TODO: Handle rollback behavior
            if result.is_err() {
                return Err(ChainError::TransactionError(format!(
                    "failed to execute transaction: {}",
                    result.unwrap_err()
                )));
            }

            // Add the transaction to the block
            transactions.push(transaction.clone());
        }

        // Create a new block
        let timestamp = BlockTimestamp::new(Utc::now());
        let block = Block::new(
            self.preferred_id,
            timestamp,
            self.last_accepted_block.height + 1,
            transactions,
        );
        Ok(block)
    }

    pub async fn verify_block(&mut self, block: &Block) -> Result<(), ChainError> {
        if self.verified_blocks.contains_key(&block.id()) {
            return Ok(());
        }

        // Verify the block
        let session = self.db.undo_session().map_err(|e| {
            ChainError::TransactionError(format!("failed to create undo session: {}", e))
        })?;
        let session = Rc::new(RefCell::new(session));

        // Make sure we don't have the block already
        let existing_block = self
            .db
            .find::<Block>(block.id())
            .map_err(|e| ChainError::TransactionError(format!("failed to find block: {}", e)))?;

        if existing_block.is_some() {
            return Ok(());
        }

        for transaction in &block.transactions {
            // Verify the transaction
            self.execute_transaction(session.clone(), transaction)?;
        }

        session
            .borrow_mut()
            .insert(block)
            .map_err(|e| ChainError::TransactionError(format!("failed to insert block: {}", e)))?;

        Rc::try_unwrap(session)
            .map_err(|_| ChainError::TransactionError("failed to unwrap session".to_string()))?
            .into_inner()
            .commit();

        self.verified_blocks.insert(block.id(), block.clone());

        Ok(())
    }

    pub async fn accept_block(&mut self, block_id: &Id) -> Result<(), ChainError> {
        let existing_block = self
            .db
            .find::<Block>(block_id.clone())
            .map_err(|e| ChainError::TransactionError(format!("failed to find block: {}", e)))?;

        if existing_block.is_none() {
            return Err(ChainError::TransactionError(format!(
                "block not found in database: {}",
                block_id
            )));
        }

        self.verified_blocks.remove(block_id);
        self.last_accepted_block = existing_block.unwrap();

        Ok(())
    }

    // This function will execute a transaction and roll it back instantly
    // This is useful for checking if a transaction is valid
    pub fn push_transaction(&self, transaction: &Transaction) -> Result<(), ChainError> {
        let db = &self.db;
        let undo_session = db.undo_session().map_err(|e| {
            ChainError::TransactionError(format!("failed to create undo session: {}", e))
        })?;
        let undo_session = Rc::new(RefCell::new(undo_session));

        let result = self.execute_transaction(undo_session, transaction);

        return result;
    }

    // This function will execute a transaction and commit it to the database
    // This is useful for applying a transaction to the blockchain
    pub fn execute_transaction(
        &self,
        undo_session: Rc<RefCell<UndoSession>>,
        transaction: &Transaction,
    ) -> Result<(), ChainError> {
        // Verify authority
        self.authorization_manager.check_authorization(
            undo_session.clone(),
            &transaction.unsigned_tx.actions,
            &transaction.recovered_keys()?,
            &HashSet::new(),
            &HashSet::new(),
        )?;

        let mut trx_context =
            TransactionContext::new(undo_session.clone(), self.wasm_runtime.clone());

        return trx_context.exec(transaction);
    }

    pub fn last_accepted_block(&self) -> &Block {
        &self.last_accepted_block
    }

    pub fn get_block_by_height(&self, height: u64) -> Result<Option<Block>, ControllerError> {
        if height == self.last_accepted_block.height {
            return Ok(Some(self.last_accepted_block.clone()));
        }

        // Query DB
        let block = self
            .db
            .find_by_secondary::<Block, BlockByHeightIndex>(height)
            .map_err(|e| {
                ControllerError::GenesisError(format!("Failed to find block by height: {}", e))
            })?;

        Ok(block)
    }

    pub fn get_block(&self, id: Id) -> Result<Option<Block>, ControllerError> {
        // Query DB
        let block = self.db.find::<Block>(id).map_err(|e| {
            ControllerError::GenesisError(format!("Failed to find block by ID: {}", e))
        })?;

        Ok(block)
    }

    pub fn parse_block(&self, bytes: &Vec<u8>) -> Result<Block, ControllerError> {
        let mut pos = 0;
        let block = Block::deserialize(bytes, &mut pos)
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

    pub fn get_authorization_manager(&self) -> &AuthorizationManager {
        &self.authorization_manager
    }

    pub fn get_resource_limits_manager(&self) -> &ResourceLimitsManager {
        &self.resource_limits_manager
    }

    pub fn create_undo_session(&mut self) -> Result<UndoSession, ChainError> {
        self.db.undo_session().map_err(|e| {
            ChainError::TransactionError(format!("failed to create undo session: {}", e))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initialize() {
        let mut controller = Controller::new();
        let genesis_bytes = b"{\"initial_timestamp\": \"2023-01-01T00:00:00Z\", \"initial_key\": \"02c66e7d8966b5c555af5805989da9fbf8db95e15631ce358c3a1710c962679063\"}".to_vec();
        controller
            .initialize(&genesis_bytes, "database".to_owned())
            .unwrap();
        assert_eq!(controller.last_accepted_block().height, 0);
    }
}
