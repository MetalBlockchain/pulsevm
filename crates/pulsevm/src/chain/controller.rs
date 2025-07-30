use core::fmt;
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    path::Path,
    rc::Rc,
    sync::{Arc, LazyLock, RwLock},
};

use crate::{
    chain::{
        ACTIVE_NAME, Account, AccountMetadata, Asset, BlockTimestamp, config::GlobalPropertyObject,
    },
    mempool::Mempool,
};

use super::{
    AuthorizationManager, Genesis, Id, Name, OWNER_NAME, PULSE_NAME, TransactionContext,
    apply_context::ApplyContext,
    authority::{Authority, KeyWeight},
    block::{Block, BlockByHeightIndex},
    error::ChainError,
    pulse_contract::{newaccount, setabi, setcode, updateauth},
    transaction::Transaction,
    wasm_runtime::WasmRuntime,
};
use chrono::Utc;
use pulsevm_chainbase::{Database, UndoSession};
use pulsevm_proc_macros::name;
use pulsevm_serialization::Read;
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
    wasm_runtime: Arc<RwLock<WasmRuntime>>,
    genesis: Option<Genesis>,

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
        let wasm_runtime = WasmRuntime::new().unwrap();
        let controller = Controller {
            wasm_runtime: Arc::new(RwLock::new(wasm_runtime)), // TODO: Handle error properly
            genesis: None,

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
    ) -> Result<(), ChainError> {
        self.db = Database::new(Path::new(&db_path)).map_err(|e| {
            ChainError::InternalError(Some(format!("failed to open database: {}", e)))
        })?;
        // Parse genesis bytes
        self.genesis = Some(
            Genesis::parse(genesis_bytes)
                .map_err(|e| ChainError::ParseError(format!("failed to parse genesis: {}", e)))?
                .validate()?,
        );

        // Set our last accepted block to the genesis block
        self.last_accepted_block = Block::new(
            Id::default(),
            self.genesis.clone().unwrap().initial_timestamp().unwrap(),
            0,
            Vec::new(),
        );

        // Do we have the genesis block in our DB?
        let genesis_block = self
            .db
            .find_by_secondary::<Block, BlockByHeightIndex>(self.last_accepted_block.height)
            .map_err(|e| {
                ChainError::GenesisError(format!("failed to find genesis block: {}", e))
            })?;

        if genesis_block.is_none() {
            // If not, insert it
            let mut session = self.db.undo_session().map_err(|e| {
                ChainError::GenesisError(format!("failed to create undo session: {}", e))
            })?;
            session.insert(&self.last_accepted_block).map_err(|e| {
                ChainError::GenesisError(format!("failed to insert genesis block: {}", e))
            })?;
            let default_key = self.genesis.clone().unwrap().initial_key().map_err(|e| {
                ChainError::GenesisError(format!("failed to get initial key: {}", e))
            })?;
            info!(
                "initializing pulse account with default key: {}",
                default_key.0
            );
            let default_authority = Authority::new(1, vec![KeyWeight::new(default_key, 1)], vec![]);
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
            session
                .insert(&Account::new(
                    PULSE_NAME,
                    self.last_accepted_block().timestamp,
                    vec![],
                ))
                .map_err(|e| {
                    ChainError::GenesisError(format!("failed to insert pulse account: {}", e))
                })?;
            session
                .insert(&AccountMetadata::new(PULSE_NAME))
                .map_err(|e| {
                    ChainError::GenesisError(format!(
                        "failed to insert pulse account metadata: {}",
                        e
                    ))
                })?;
            session.commit()?;
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
        let timestamp = BlockTimestamp::new(Utc::now());

        // Get transactions from the mempool
        loop {
            let transaction = mempool.pop_transaction();

            if transaction.is_none() {
                break;
            }
            let transaction = transaction.unwrap();
            let result = self.execute_transaction(undo_session.clone(), &transaction, timestamp);
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
            self.execute_transaction(session.clone(), transaction, block.timestamp)?;
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
    pub fn push_transaction(
        &self,
        transaction: &Transaction,
        pending_block_timestamp: BlockTimestamp,
    ) -> Result<(), ChainError> {
        let db = &self.db;
        let undo_session = db.undo_session().map_err(|e| {
            ChainError::TransactionError(format!("failed to create undo session: {}", e))
        })?;
        let undo_session = Rc::new(RefCell::new(undo_session));

        let result = self.execute_transaction(undo_session, transaction, pending_block_timestamp);

        return result;
    }

    // This function will execute a transaction and commit it to the database
    // This is useful for applying a transaction to the blockchain
    pub fn execute_transaction(
        &self,
        undo_session: Rc<RefCell<UndoSession>>,
        transaction: &Transaction,
        pending_block_timestamp: BlockTimestamp,
    ) -> Result<(), ChainError> {
        {
            // Verify authority
            AuthorizationManager::check_authorization(
                &mut undo_session.borrow_mut(),
                &transaction.unsigned_tx.actions,
                &transaction.recovered_keys()?,
                &HashSet::new(),
                &HashSet::new(),
            )?;
        }

        let mut trx_context = TransactionContext::new(
            undo_session.clone(),
            self.wasm_runtime.clone(),
            pending_block_timestamp,
        );

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
        let block = Block::read(bytes, &mut pos)
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

    pub fn get_wasm_runtime(&self) -> Arc<RwLock<WasmRuntime>> {
        self.wasm_runtime.clone()
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
}

#[cfg(test)]
mod tests {
    use std::{env::temp_dir, fs, path::PathBuf, str::FromStr, vec};

    use pulsevm_proc_macros::{NumBytes, Read, Write};
    use pulsevm_serialization::Write;
    use serde_json::json;

    use crate::chain::{
        Action, NewAccount, PrivateKey, SetCode, Symbol, UnsignedTransaction,
        authority::{Permission, PermissionLevel},
    };

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes)]
    struct Create {
        issuer: Name,
        max_supply: Asset,
    }

    impl Create {
        pub fn new(issuer: Name, max_supply: Asset) -> Self {
            Create { issuer, max_supply }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes)]
    struct Transfer {
        from: Name,
        to: Name,
        quantity: Asset,
        memo: String,
    }

    impl Transfer {
        pub fn new(from: Name, to: Name, quantity: Asset, memo: String) -> Self {
            Transfer {
                from,
                to,
                quantity,
                memo,
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes)]
    struct Issue {
        to: Name,
        quantity: Asset,
        memo: String,
    }

    impl Issue {
        pub fn new(to: Name, quantity: Asset, memo: String) -> Self {
            Issue { to, quantity, memo }
        }
    }

    fn get_temp_dir() -> PathBuf {
        let temp_dir_name = format!("db_{}.pulsevm", Utc::now().format("%Y%m%d%H%M%S"));
        temp_dir().join(Path::new(&temp_dir_name))
    }

    fn generate_genesis(private_key: &PrivateKey) -> Vec<u8> {
        let genesis = json!(
        {
            "initial_timestamp": "2023-01-01T00:00:00Z",
            "initial_key": private_key.public_key().to_string(),
            "initial_configuration": {
                "max_inline_action_size": 4096,
                "max_action_return_value_size": 256,
            }
        });
        genesis.to_string().into_bytes()
    }

    fn create_account(private_key: &PrivateKey, account: Name) -> Transaction {
        Transaction::new(
            0,
            UnsignedTransaction::new(
                Id::default(),
                vec![Action::new(
                    Name::from_str("pulse").unwrap(),
                    Name::from_str("newaccount").unwrap(),
                    NewAccount::new(
                        Name::from_str("pulse").unwrap(),
                        account,
                        Authority::new(
                            1,
                            vec![KeyWeight::new(private_key.public_key(), 1)],
                            vec![],
                        ),
                        Authority::new(
                            1,
                            vec![KeyWeight::new(private_key.public_key(), 1)],
                            vec![],
                        ),
                    )
                    .pack()
                    .unwrap(),
                    vec![PermissionLevel::new(
                        Name::from_str("pulse").unwrap(),
                        Name::from_str("active").unwrap(),
                    )],
                )],
            ),
        )
        .sign(&private_key)
    }

    fn set_code(private_key: &PrivateKey, account: Name, wasm_bytes: Vec<u8>) -> Transaction {
        Transaction::new(
            0,
            UnsignedTransaction::new(
                Id::default(),
                vec![Action::new(
                    Name::from_str("pulse").unwrap(),
                    Name::from_str("setcode").unwrap(),
                    SetCode::new(account, 0, 0, wasm_bytes).pack().unwrap(),
                    vec![PermissionLevel::new(
                        account,
                        Name::from_str("active").unwrap(),
                    )],
                )],
            ),
        )
        .sign(&private_key)
    }

    fn call_contract<T: Write>(
        private_key: &PrivateKey,
        account: Name,
        action: Name,
        action_data: &T,
    ) -> Transaction {
        Transaction::new(
            0,
            UnsignedTransaction::new(
                Id::default(),
                vec![Action::new(
                    account,
                    action,
                    action_data.pack().unwrap(),
                    vec![PermissionLevel::new(
                        account,
                        Name::from_str("active").unwrap(),
                    )],
                )],
            ),
        )
        .sign(&private_key)
    }

    #[test]
    fn test_initialize() -> Result<(), ChainError> {
        let private_key = PrivateKey::random();
        let mut controller = Controller::new();
        let genesis_bytes = generate_genesis(&private_key);
        let temp_path = get_temp_dir().to_str().unwrap().to_string();
        controller.initialize(&genesis_bytes.to_vec(), temp_path)?;
        assert_eq!(controller.last_accepted_block().height, 0);
        let pending_block_timestamp = controller.last_accepted_block().timestamp;
        let undo_session = Rc::new(RefCell::new(controller.create_undo_session()?));
        controller.execute_transaction(
            undo_session.clone(),
            &create_account(&private_key, Name::from_str("glenn")?),
            pending_block_timestamp
        )?;
        controller.execute_transaction(
            undo_session.clone(),
            &create_account(&private_key, Name::from_str("marshall")?),
            pending_block_timestamp
        )?;

        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let pulse_token_contract =
            fs::read(root.join(Path::new("reference_contracts/pulse_token.wasm"))).unwrap();
        controller.execute_transaction(
            undo_session.clone(),
            &set_code(&private_key, Name::from_str("glenn")?, pulse_token_contract),
            pending_block_timestamp
        )?;

        controller.execute_transaction(
            undo_session.clone(),
            &call_contract(
                &private_key,
                Name::from_str("glenn")?,
                Name::from_str("create")?,
                &Create {
                    issuer: Name::from_str("glenn")?,
                    max_supply: Asset::new(1000000, Symbol(1162826500)),
                },
            ),
            pending_block_timestamp
        )?;

        controller.execute_transaction(
            undo_session.clone(),
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
            ),
            pending_block_timestamp
        )?;

        controller.execute_transaction(
            undo_session.clone(),
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
            ),
            pending_block_timestamp
        )?;

        Ok(())
    }

    #[test]
    fn test_api_db() -> Result<(), ChainError> {
        let private_key = PrivateKey::random();
        let mut controller = Controller::new();
        let genesis_bytes = generate_genesis(&private_key);
        let temp_path = get_temp_dir().to_str().unwrap().to_string();
        controller.initialize(&genesis_bytes.to_vec(), temp_path)?;
        assert_eq!(controller.last_accepted_block().height, 0);
        let pending_block_timestamp = controller.last_accepted_block().timestamp;
        let undo_session = Rc::new(RefCell::new(controller.create_undo_session()?));
        controller.execute_transaction(
            undo_session.clone(),
            &create_account(&private_key, Name::from_str("glenn")?),
            pending_block_timestamp
        )?;
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let contract =
            fs::read(root.join(Path::new("reference_contracts/test_api_db.wasm"))).unwrap();
        controller.execute_transaction(
            undo_session.clone(),
            &set_code(&private_key, Name::from_str("glenn")?, contract),
            pending_block_timestamp
        )?;

        controller.execute_transaction(
            undo_session.clone(),
            &call_contract(
                &private_key,
                Name::from_str("glenn")?,
                Name::from_str("pg")?,
                &Vec::<u8>::new(),
            ),
            pending_block_timestamp
        )?;
        controller.execute_transaction(
            undo_session.clone(),
            &call_contract(
                &private_key,
                Name::from_str("glenn")?,
                Name::from_str("pl")?,
                &Vec::<u8>::new(),
            ),
            pending_block_timestamp
        )?;
        controller.execute_transaction(
            undo_session.clone(),
            &call_contract(
                &private_key,
                Name::from_str("glenn")?,
                Name::from_str("pu")?,
                &Vec::<u8>::new(),
            ),
            pending_block_timestamp
        )?;

        Ok(())
    }
}
