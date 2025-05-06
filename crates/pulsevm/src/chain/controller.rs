use core::fmt;
use std::path::Path;

use pulsevm_chainbase::Database;
use pulsevm_serialization::Deserialize;
use super::{block::{Block, BlockByHeightIndex}, transaction::Transaction, Genesis, Id, TransactionContext};

pub struct Controller {
    last_accepted_block: Block,
    preferred_id: Id,
    db: Option<Database>,
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
        Controller {
            last_accepted_block: Block::default(),
            preferred_id: Id::default(),
            db: None,
        }
    }

    pub fn initialize(&mut self, genesis_bytes: &Vec<u8>, db_path: String) -> Result<(), ControllerError> {
        self.db = Some(Database::new(Path::new(&db_path))
            .map_err(|e| ControllerError::GenesisError(format!("Failed to open database: {}", e)))?);
        // Parse genesis bytes
        let genesis = Genesis::parse(genesis_bytes)
            .map_err(|e| ControllerError::GenesisError(format!("Failed to parse genesis: {}", e)))?
            .validate()
            .map_err(|e| ControllerError::GenesisError(format!("Invalid genesis: {}", e)))?;

        // Set our last accepted block to the genesis block
        self.last_accepted_block = Block::new(Id::default(), genesis.initial_timestamp().unwrap(), 0, Vec::new());

        // Do we have the genesis block in our DB?
        let db = self.db.as_ref().unwrap();
        let genesis_block = db.find_by_secondary::<Block, BlockByHeightIndex>(self.last_accepted_block.height)
            .map_err(|e| ControllerError::GenesisError(format!("Failed to find genesis block: {}", e)))?;

        if genesis_block.is_none() {
            // If not, insert it
            let mut session = db.undo_session()
                .map_err(|e| ControllerError::GenesisError(format!("Failed to create undo session: {}", e)))?;
            session.insert(&self.last_accepted_block)
                .map_err(|e| ControllerError::GenesisError(format!("Failed to insert genesis block: {}", e)))?;
            session.commit();
        }

        Ok(())
    }

    pub fn execute_transaction(&mut self, transaction: &Transaction) -> Result<(), ControllerError> {
        let trx_context = TransactionContext::new(transaction);
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
        let db = self.db.as_ref().unwrap();
        let block = db.find_by_secondary::<Block, BlockByHeightIndex>(height)
            .map_err(|e| ControllerError::GenesisError(format!("Failed to find block by height: {}", e)))?;
        
        Ok(block)
    }

    pub fn get_block(&self, id: Id) -> Result<Option<Block>, ControllerError> {
        // Query DB
        let db = self.db.as_ref().unwrap();
        let block = db.find_by_primary::<Block>(id)
            .map_err(|e| ControllerError::GenesisError(format!("Failed to find block by ID: {}", e)))?;
        
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initialize() {
        let mut controller = Controller::new();
        let genesis_bytes = b"{\"initial_timestamp\": \"2023-01-01T00:00:00Z\", \"initial_key\": \"02c66e7d8966b5c555af5805989da9fbf8db95e15631ce358c3a1710c962679063\"}".to_vec();
        controller.initialize(&genesis_bytes, "database".to_owned()).unwrap();
        assert_eq!(controller.last_accepted_block().height, 0);
    }
}