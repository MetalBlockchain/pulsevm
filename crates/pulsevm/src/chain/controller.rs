use core::fmt;
use std::{
    collections::{HashMap, HashSet},
    iter::Map,
    path::Path,
    str::FromStr,
};

use crate::chain::{ACTIVE_NAME, Account, AccountMetadata};

use super::{
    AuthorizationManager, Genesis, Id, Name, OWNER_NAME, PULSE_NAME, TransactionContext,
    apply_context::ApplyContext,
    authority::{Authority, KeyWeight},
    block::{Block, BlockByHeightIndex},
    error::ChainError,
    pulse_contract::newaccount,
    resource_limits::ResourceLimitsManager,
    transaction::Transaction,
};
use pulsevm_chainbase::{Database, UndoSession};
use pulsevm_proc_macros::name;
use pulsevm_serialization::Deserialize;
use spdlog::info;

pub struct Controller {
    authorization_manager: AuthorizationManager,
    resource_limits_manager: ResourceLimitsManager,

    last_accepted_block: Block,
    preferred_id: Id,
    db: Database,
    apply_handlers: HashMap<
        Name,
        HashMap<(Name, Name), fn(&mut ApplyContext, &mut UndoSession) -> Result<(), ChainError>>,
    >,
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
        let mut controller = Controller {
            authorization_manager: AuthorizationManager::new(),
            resource_limits_manager: ResourceLimitsManager::new(),

            last_accepted_block: Block::default(),
            preferred_id: Id::default(),
            db: db,
            apply_handlers: HashMap::new(),
        };

        controller.set_apply_handler(
            PULSE_NAME,
            PULSE_NAME,
            Name::new(name!("newaccount")),
            newaccount,
        );

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
            let mut session = self.db.undo_session().map_err(|e| {
                ControllerError::GenesisError(format!("failed to create undo session: {}", e))
            })?;
            session.insert(&self.last_accepted_block).map_err(|e| {
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
                    &mut session,
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
                    &mut session,
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
                .insert(&Account::new(PULSE_NAME, 0, vec![]))
                .map_err(|e| {
                    ControllerError::GenesisError(format!("failed to insert pulse account: {}", e))
                })?;
            session
                .insert(&AccountMetadata::new(PULSE_NAME))
                .map_err(|e| {
                    ControllerError::GenesisError(format!(
                        "failed to insert pulse account metadata: {}",
                        e
                    ))
                })?;
            session.commit();
        }

        Ok(())
    }

    // This function will execute a transaction and roll it back instantly
    // This is useful for checking if a transaction is valid
    pub fn push_transaction(&self, transaction: &Transaction) -> Result<(), ChainError> {
        // Execute the transaction
        let mut undo_session = self.db.undo_session().unwrap();
        self.execute_transaction(&mut undo_session, transaction)
    }

    // This function will execute a transaction and commit it to the database
    // This is useful for applying a transaction to the blockchain
    pub fn execute_transaction(
        &self,
        undo_session: &mut UndoSession,
        transaction: &Transaction,
    ) -> Result<(), ChainError> {
        // Verify authority
        self.authorization_manager.check_authorization(
            undo_session,
            &transaction.unsigned_tx.actions,
            &transaction.recovered_keys()?,
            &HashSet::new(),
            &HashSet::new(),
        )?;

        let mut trx_context = TransactionContext::new(self, transaction);
        trx_context.exec(undo_session)?;
        Ok(())
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

    pub fn set_apply_handler(
        &mut self,
        receiver: Name,
        contract: Name,
        action: Name,
        apply_handler: fn(&mut ApplyContext, &mut UndoSession) -> Result<(), ChainError>,
    ) {
        self.apply_handlers
            .entry(receiver)
            .or_insert_with(HashMap::new)
            .insert((contract, action), apply_handler);
    }

    pub fn find_apply_handler(
        &self,
        receiver: Name,
        scope: Name,
        act: Name,
    ) -> Option<fn(&mut ApplyContext, &mut UndoSession) -> Result<(), ChainError>> {
        if let Some(handlers) = self.apply_handlers.get(&receiver) {
            if let Some(handler) = handlers.get(&(scope, act)) {
                return Some(*handler);
            }
        }
        None
    }

    pub fn get_authorization_manager(&self) -> &AuthorizationManager {
        &self.authorization_manager
    }

    pub fn get_resource_limits_manager(&self) -> &ResourceLimitsManager {
        &self.resource_limits_manager
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
