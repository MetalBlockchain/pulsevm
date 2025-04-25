use std::{collections::VecDeque};

use tokio::sync::mpsc::{self, error::SendError, Receiver, Sender};

use crate::chain::Transaction;

pub struct Mempool {
    transactions: VecDeque<Transaction>,
    build_channel_tx: Sender<()>,
    build_channel_rx: Receiver<()>,
}

impl Mempool {
    pub fn new() -> Self {
        let (build_channel_tx, build_channel_rx) = mpsc::channel(1);

        Self {
            transactions: VecDeque::new(),
            build_channel_tx,
            build_channel_rx,
        }
    }

    pub fn add_transaction(&mut self, transaction: Transaction) {
        self.transactions.push_back(transaction);
    }

    pub fn pop_transaction(&mut self) -> Option<Transaction> {
        self.transactions.pop_front()
    }
}