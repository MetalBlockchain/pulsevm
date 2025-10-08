use tokio::sync::broadcast::Receiver;

use crate::chain::{Controller, SignedBlock, error::ChainError};

pub struct HistoryPlugin {
    on_accepted_block: Receiver<SignedBlock>,
    on_accepted_block_handle: Option<tokio::task::JoinHandle<()>>,
}

impl HistoryPlugin {
    pub fn new(on_accepted_block: Receiver<SignedBlock>) -> Self {
        Self {
            on_accepted_block,
            on_accepted_block_handle: None,
        }
    }

    fn initialize(&mut self) -> Result<(), ChainError> {
        self.on_accepted_block_handle = Some(tokio::spawn({
            let mut on_accepted_block = self.on_accepted_block.resubscribe();

            async move {
                while let Ok(block) = on_accepted_block.recv().await {
                    // Handle the accepted block
                    // For example, log it or store it in a database
                    println!("Accepted block: {}", block.block_num());
                }
            }
        }));
        Ok(())
    }
}
