use std::collections::{HashSet, VecDeque};
use tokio::sync::Mutex;

use crate::chain::{id::Id, transaction::PackedTransaction};

#[derive(Debug, Clone)]
pub enum MempoolError {
    InternalError(String),
}

impl std::fmt::Display for MempoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MempoolError::InternalError(msg) => write!(f, "internal error: {}", msg),
        }
    }
}

pub struct Mempool {
    transactions_list: VecDeque<PackedTransaction>,
    transactions_map: HashSet<Id>,
    request_block_mutex: Mutex<()>,
}

impl Mempool {
    pub fn new() -> Self {
        Self {
            transactions_list: VecDeque::new(),
            transactions_map: HashSet::new(),
            request_block_mutex: Mutex::new(()),
        }
    }

    pub fn add_transaction(&mut self, transaction: &PackedTransaction) {
        if self.transactions_map.contains(transaction.id()) {
            return; // Transaction already exists in the mempool
        }

        self.transactions_list.push_back(transaction.clone());
        self.transactions_map.insert(transaction.id().clone());
    }

    pub fn pop_transaction(&mut self) -> Option<PackedTransaction> {
        if let Some(transaction) = self.transactions_list.pop_front() {
            self.transactions_map.remove(transaction.id());
            return Some(transaction.clone());
        }

        return None;
    }

    pub fn remove_transaction(&mut self, tx_id: &Id) {
        if let Some(index) = self.transactions_list.iter().position(|x| x.id() == tx_id) {
            self.transactions_list.remove(index);
            self.transactions_map.remove(tx_id);
        }
    }

    pub fn has_transactions(&self) -> bool {
        self.transactions_list.len() > 0
    }
}
