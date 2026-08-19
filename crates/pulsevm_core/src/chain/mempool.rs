use std::collections::{
    BTreeMap,
    HashMap,
    HashSet,
    VecDeque,
};

use crate::chain::{
    id::Id,
    time::{TimePoint, TimePointSec},
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
    // The local removal deadline for each transaction. It is the earlier of
    // the signed expiration and the first-seen time plus the local TTL.
    expiration_by_id: HashMap<Id, u32>,
    // Counted by deadline so checking for due entries and removing a
    // transaction during block building are both cheap even when many entries
    // share the same five-minute deadline.
    expiration_counts: BTreeMap<u32, usize>,
}

pub const MAX_MEMPOOL_SIZE: usize = 10000;
pub const DEFAULT_MEMPOOL_TRANSACTION_TTL_SECS: u32 = 300;

impl Mempool {
    pub fn new() -> Self {
        Self {
            transactions_list: VecDeque::new(),
            transactions_map: HashSet::new(),
            expiration_by_id: HashMap::new(),
            expiration_counts: BTreeMap::new(),
        }
    }

    pub fn add_transaction(&mut self, transaction: PackedTransaction) -> bool {
        self.add_transaction_at(transaction, TimePointSec::now())
    }

    fn add_transaction_at(
        &mut self,
        transaction: PackedTransaction,
        received_at: TimePointSec,
    ) -> bool {
        if self.transactions_list.len() >= MAX_MEMPOOL_SIZE {
            return false; // mempool is full
        }
        if !self.transactions_map.insert(transaction.id().clone()) {
            return false; // already present
        }
        let signed_expiration = transaction
            .get_transaction()
            .header
            .expiration()
            .sec_since_epoch();
        let expiration = signed_expiration.min(
            received_at
                .sec_since_epoch()
                .saturating_add(DEFAULT_MEMPOOL_TRANSACTION_TTL_SECS),
        );
        self.expiration_by_id
            .insert(transaction.id().clone(), expiration);
        self.transactions_list.push_back(transaction);
        self.record_expiration(expiration);
        true
    }

    pub fn pop_transaction(&mut self) -> Option<PackedTransaction> {
        if let Some(transaction) = self.transactions_list.pop_front() {
            self.transactions_map.remove(transaction.id());
            let expiration = self.expiration_by_id.remove(transaction.id());
            if let Some(expiration) = expiration {
                self.remove_expiration(expiration);
            }
            return Some(transaction);
        }

        return None;
    }

    pub fn remove_transaction(&mut self, tx_id: &Id) {
        if let Some(index) = self.transactions_list.iter().position(|x| x.id() == tx_id) {
            let transaction = self.transactions_list.remove(index).unwrap();
            self.transactions_map.remove(tx_id);
            let expiration = self.expiration_by_id.remove(transaction.id());
            if let Some(expiration) = expiration {
                self.remove_expiration(expiration);
            }
        }
    }

    pub fn has_transactions(&self) -> bool {
        self.transactions_list.len() > 0
    }

    pub fn contains(&self, tx_id: &Id) -> bool {
        self.transactions_map.contains(tx_id)
    }

    /// Remove transactions whose effective mempool lifetime is before `now`.
    ///
    /// A transaction is retained only until the earlier of its signed
    /// expiration and [`DEFAULT_MEMPOOL_TRANSACTION_TTL_SECS`] after it first
    /// arrived. This prevents an excessively long signed expiration from
    /// holding capacity indefinitely. The comparison has second precision, so
    /// a transaction remains eligible for its entire expiration second.
    pub fn prune_expired(&mut self, now: &TimePoint) -> usize {
        let now = now.sec_since_epoch();
        if self
            .expiration_counts
            .first_key_value()
            .map_or(true, |(expiration, _)| *expiration >= now)
        {
            return 0;
        }

        let old_len = self.transactions_list.len();
        let expiration_by_id = &self.expiration_by_id;
        self.transactions_list.retain(|tx| {
            expiration_by_id
                .get(tx.id())
                .is_some_and(|expiration| *expiration >= now)
        });
        self.refresh_index();
        old_len - self.transactions_list.len()
    }

    // Prune transactions that are included in a new block.
    pub fn prune(&mut self, pending_ids: &HashSet<Id>) {
        self.transactions_list
            .retain(|tx| !pending_ids.contains(tx.id()));
        self.refresh_index();
    }

    fn refresh_index(&mut self) {
        self.transactions_map = self
            .transactions_list
            .iter()
            .map(|tx| tx.id().clone())
            .collect();
        self.expiration_by_id
            .retain(|id, _| self.transactions_map.contains(id));
        self.expiration_counts.clear();
        let expirations: Vec<u32> = self.expiration_by_id.values().copied().collect();
        for expiration in expirations {
            self.record_expiration(expiration);
        }
    }

    fn record_expiration(&mut self, expiration: u32) {
        *self.expiration_counts.entry(expiration).or_default() += 1;
    }

    fn remove_expiration(&mut self, expiration: u32) {
        if let Some(count) = self.expiration_counts.get_mut(&expiration) {
            if *count > 1 {
                *count -= 1;
            } else {
                self.expiration_counts.remove(&expiration);
            }
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
    use pulsevm_serialization::Write;

    // A distinct, unsigned transaction per `seed`. The mempool keys on the
    // transaction id (its digest), so varying the header is enough to get a
    // different id; no signing or execution is involved.
    fn tx_with_expiration(expiration: TimePointSec, seed: u16) -> PackedTransaction {
        let trx = Transaction::new(
            TransactionHeader::new(
                expiration,
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

    fn tx(seed: u16) -> PackedTransaction {
        tx_with_expiration(TimePointSec::maximum(), seed)
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
    fn prune_expired_removes_only_transactions_past_their_signed_expiration() {
        let mut mempool = Mempool::new();
        let expired = tx_with_expiration(TimePointSec::new(9), 8);
        let current = tx_with_expiration(TimePointSec::new(10), 9);
        let future = tx_with_expiration(TimePointSec::new(11), 10);
        let received_at = TimePointSec::new(0);
        mempool.add_transaction_at(expired.clone(), received_at);
        mempool.add_transaction_at(current.clone(), received_at);
        mempool.add_transaction_at(future.clone(), received_at);

        // Expirations have second precision. A transaction remains eligible for
        // the entire second named by its expiration, matching block execution.
        let now = TimePoint::new(pulsevm_database::Microseconds::new(10_999_999));
        assert_eq!(mempool.prune_expired(&now), 1);
        assert!(!mempool.contains(expired.id()));
        assert!(mempool.contains(current.id()));
        assert!(mempool.contains(future.id()));
    }

    #[test]
    fn prune_expired_caps_an_excessively_long_signed_lifetime() {
        let mut mempool = Mempool::new();
        let long_lived = tx_with_expiration(TimePointSec::maximum(), 11);
        mempool.add_transaction_at(long_lived.clone(), TimePointSec::new(100));

        let before_ttl: TimePoint = TimePointSec::new(100 + DEFAULT_MEMPOOL_TRANSACTION_TTL_SECS).into();
        assert_eq!(mempool.prune_expired(&before_ttl), 0);

        let after_ttl: TimePoint =
            TimePointSec::new(101 + DEFAULT_MEMPOOL_TRANSACTION_TTL_SECS).into();
        assert_eq!(mempool.prune_expired(&after_ttl), 1);
        assert!(!mempool.contains(long_lived.id()));
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
