use std::collections::{
    HashSet,
    VecDeque,
};

use crate::chain::{
    id::Id,
    transaction::PackedTransaction,
};

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
}

pub const MAX_MEMPOOL_SIZE: usize = 10000;

impl Mempool {
    pub fn new() -> Self {
        Self {
            transactions_list: VecDeque::new(),
            transactions_map: HashSet::new(),
        }
    }

    pub fn add_transaction(&mut self, transaction: PackedTransaction) -> bool {
        if self.transactions_list.len() >= MAX_MEMPOOL_SIZE {
            return false; // mempool is full
        }
        if !self.transactions_map.insert(transaction.id().clone()) {
            return false; // already present
        }
        self.transactions_list.push_back(transaction);
        true
    }

    pub fn pop_transaction(&mut self) -> Option<PackedTransaction> {
        if let Some(transaction) = self.transactions_list.pop_front() {
            self.transactions_map.remove(transaction.id());
            return Some(transaction);
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

    pub fn contains(&self, tx_id: &Id) -> bool {
        self.transactions_map.contains(tx_id)
    }

    // Prune transactions that are included in a new block or expired
    pub fn prune(&mut self, pending_ids: &HashSet<Id>) {
        self.transactions_list
            .retain(|tx| !pending_ids.contains(tx.id()));
        for tx_id in pending_ids {
            self.transactions_map.remove(tx_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::transaction::{
        Transaction,
        TransactionCompression,
        TransactionHeader,
    };
    use pulsevm_database::TimePointSec;
    use pulsevm_serialization::Write;

    // A distinct, unsigned transaction per `seed`. The mempool keys on the
    // transaction id (its digest), so varying the header is enough to get a
    // different id; no signing or execution is involved.
    fn tx(seed: u16) -> PackedTransaction {
        let trx = Transaction::new(
            TransactionHeader::new(
                TimePointSec::maximum(),
                seed,
                0,
                0u32.into(),
                0,
                0u32.into(),
            ),
            vec![],
            vec![],
        );
        PackedTransaction::new(
            std::collections::BTreeSet::new(),
            TransactionCompression::None,
            pulsevm_crypto::Bytes::default(),
            trx.pack().unwrap().into(),
        )
        .unwrap()
    }

    #[test]
    fn add_transaction_reports_newly_added_then_duplicate() {
        let mut mempool = Mempool::new();
        let t = tx(1);
        // First insert is new; the caller relays on this signal.
        assert!(mempool.add_transaction(t.clone()));
        // The same transaction (re-gossiped) is a duplicate and must not relay.
        assert!(!mempool.add_transaction(t.clone()));
        // A different transaction is new again.
        assert!(mempool.add_transaction(tx(2)));
    }

    #[test]
    fn contains_tracks_membership() {
        let mut mempool = Mempool::new();
        let t = tx(7);
        assert!(!mempool.contains(t.id()));
        mempool.add_transaction(t.clone());
        assert!(mempool.contains(t.id()));
    }

    #[test]
    fn pop_transaction_allows_readmission() {
        let mut mempool = Mempool::new();
        let t = tx(3);
        mempool.add_transaction(t.clone());
        let popped = mempool.pop_transaction().unwrap();
        assert_eq!(popped.id(), t.id());
        // Popping clears the id, so the same transaction can be admitted again.
        assert!(!mempool.contains(t.id()));
        assert!(mempool.add_transaction(t.clone()));
    }

    #[test]
    fn remove_transaction_clears_membership() {
        let mut mempool = Mempool::new();
        let t = tx(4);
        mempool.add_transaction(t.clone());
        mempool.remove_transaction(t.id());
        assert!(!mempool.contains(t.id()));
        assert!(!mempool.has_transactions());
    }

    #[test]
    fn prune_removes_included_transactions() {
        let mut mempool = Mempool::new();
        let kept = tx(5);
        let included = tx(6);
        mempool.add_transaction(kept.clone());
        mempool.add_transaction(included.clone());

        let mut ids = HashSet::new();
        ids.insert(included.id().clone());
        mempool.prune(&ids);

        assert!(!mempool.contains(included.id()));
        assert!(mempool.contains(kept.id()));
    }

    #[test]
    fn add_transaction_rejects_when_full() {
        let mut mempool = Mempool::new();
        for i in 0..MAX_MEMPOOL_SIZE {
            assert!(mempool.add_transaction(tx(i as u16)));
        }
        // A new, distinct transaction is refused once the mempool is full.
        assert!(!mempool.add_transaction(tx(MAX_MEMPOOL_SIZE as u16)));
    }
}
