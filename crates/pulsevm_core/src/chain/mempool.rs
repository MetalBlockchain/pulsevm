use std::collections::{
    BTreeMap,
    HashMap,
    HashSet,
    VecDeque,
};

use crate::chain::{
    id::Id,
    time::{
        TimePoint,
        TimePointSec,
    },
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
    // Ids currently owned by a detached build/verification batch. Reservations
    // keep the configured bound and duplicate suppression in force while the
    // batch executes outside this mempool's async lock.
    reserved_ids: HashSet<Id>,
    // The local removal deadline for each transaction. It is the earlier of
    // the signed expiration and the first-seen time plus the local TTL.
    expiration_by_id: HashMap<Id, u32>,
    // Counted by deadline so checking for due entries and removing a
    // transaction during block building are both cheap even when many entries
    // share the same five-minute deadline.
    expiration_counts: BTreeMap<u32, usize>,
}

/// Transactions detached from the live pool for block construction or
/// verification. `reservations` remains in the live pool until this batch is
/// finished, so concurrent admission cannot overfill the pool or re-admit an
/// in-flight transaction.
pub struct MempoolBatch {
    transactions: Mempool,
    reservations: HashSet<Id>,
}

impl MempoolBatch {
    pub fn transactions_mut(&mut self) -> &mut Mempool {
        &mut self.transactions
    }
}

pub const MAX_MEMPOOL_SIZE: usize = 10000;
/// Local, non-consensus retention bound. See `docs/mempool-admission.md` §6.
pub const DEFAULT_MEMPOOL_TRANSACTION_TTL_SECS: u32 = 300;

impl Mempool {
    pub fn new() -> Self {
        Self {
            transactions_list: VecDeque::new(),
            transactions_map: HashSet::new(),
            reserved_ids: HashSet::new(),
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
        if self.transactions_list.len() + self.reserved_ids.len() >= MAX_MEMPOOL_SIZE {
            return false; // mempool is full
        }
        if self.reserved_ids.contains(transaction.id())
            || !self.transactions_map.insert(transaction.id().clone())
        {
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
        self.transactions_map.contains(tx_id) || self.reserved_ids.contains(tx_id)
    }

    /// Whether any transaction has passed its effective local expiry. This is
    /// intentionally read-only so routine admission and timer checks can share
    /// the pool lock; callers only need an exclusive lock when this is true.
    pub fn has_expired(&self, now: &TimePoint) -> bool {
        self.expiration_counts
            .first_key_value()
            .is_some_and(|(expiration, _)| *expiration < now.sec_since_epoch())
    }

    /// Move the current queue into an independent batch. Producers and
    /// validators can execute that batch without holding the shared mempool
    /// lock, allowing new transactions to be admitted concurrently.
    pub fn take_all(&mut self) -> MempoolBatch {
        let transactions = Mempool {
            transactions_list: std::mem::take(&mut self.transactions_list),
            transactions_map: std::mem::take(&mut self.transactions_map),
            reserved_ids: HashSet::new(),
            expiration_by_id: std::mem::take(&mut self.expiration_by_id),
            expiration_counts: std::mem::take(&mut self.expiration_counts),
        };
        let reservations = transactions.transactions_map.clone();
        self.reserved_ids.extend(reservations.iter().cloned());
        MempoolBatch {
            transactions,
            reservations,
        }
    }

    /// Put transactions from an older, detached batch ahead of transactions
    /// admitted while that batch was executing. Existing ids win, so a
    /// re-gossiped transaction cannot be duplicated. The original local expiry
    /// deadline is retained instead of extending its TTL on every merge.
    fn prepend_missing(&mut self, mut older: Self) {
        while let Some(transaction) = older.transactions_list.pop_back() {
            let id = transaction.id().clone();
            // A detached batch can race with block acceptance removing an
            // already-considered transaction. Do not let a stale auxiliary
            // expiry index panic the consensus worker; reconstruct a bounded
            // deadline for the surviving transaction instead.
            let expiration = older.expiration_by_id.remove(&id).unwrap_or_else(|| {
                let now = TimePointSec::now().sec_since_epoch();
                transaction
                    .get_transaction()
                    .header
                    .expiration()
                    .sec_since_epoch()
                    .min(now.saturating_add(DEFAULT_MEMPOOL_TRANSACTION_TTL_SECS))
            });
            if self.transactions_list.len() + self.reserved_ids.len() < MAX_MEMPOOL_SIZE
                && self.transactions_map.insert(id)
            {
                self.transactions_list.push_front(transaction);
                self.record_expiration(expiration);
            }
        }
    }

    /// Complete a detached batch. Releasing its reservations before merging
    /// restores the capacity consumed by the same transactions, so deferred
    /// entries return without being silently displaced by arrivals that occurred
    /// during execution.
    pub fn finish_batch(&mut self, batch: MempoolBatch) {
        for id in &batch.reservations {
            self.reserved_ids.remove(id);
        }
        self.prepend_missing(batch.transactions);
    }

    /// Remove transactions whose effective mempool lifetime is before `now`.
    ///
    /// A transaction is retained only until the earlier of its signed
    /// expiration and [`DEFAULT_MEMPOOL_TRANSACTION_TTL_SECS`] after it first
    /// arrived. This prevents an excessively long signed expiration from
    /// holding capacity indefinitely. The comparison has second precision, so
    /// a transaction remains eligible for its entire expiration second.
    pub fn prune_expired(&mut self, now: &TimePoint) -> usize {
        if !self.has_expired(now) {
            return 0;
        }
        let now = now.sec_since_epoch();

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
            TransactionHeader::new(expiration, seed, 0, 0u32.into(), 0, 0u32.into()),
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

        let before_ttl: TimePoint =
            TimePointSec::new(100 + DEFAULT_MEMPOOL_TRANSACTION_TTL_SECS).into();
        assert_eq!(mempool.prune_expired(&before_ttl), 0);

        let after_ttl: TimePoint =
            TimePointSec::new(101 + DEFAULT_MEMPOOL_TRANSACTION_TTL_SECS).into();
        assert_eq!(mempool.prune_expired(&after_ttl), 1);
        assert!(!mempool.contains(long_lived.id()));
    }

    #[test]
    fn detached_batch_merges_before_new_arrivals_without_extending_ttl() {
        let mut mempool = Mempool::new();
        let older = tx_with_expiration(TimePointSec::maximum(), 12);
        mempool.add_transaction_at(older.clone(), TimePointSec::new(100));

        let detached = mempool.take_all();
        assert!(!mempool.has_transactions());
        assert!(mempool.contains(older.id()));

        let newer = tx(13);
        // The detached transaction still reserves capacity and its id, while
        // unrelated arrivals consume only unused capacity.
        assert!(mempool.add_transaction(newer.clone()));
        mempool.finish_batch(detached);

        assert_eq!(mempool.pop_transaction().unwrap().id(), older.id());
        assert_eq!(mempool.pop_transaction().unwrap().id(), newer.id());

        // The detached transaction's effective deadline was 400, not five
        // minutes after it was merged back into the live pool.
        let mut mempool = Mempool::new();
        mempool.add_transaction_at(older.clone(), TimePointSec::new(100));
        let detached = mempool.take_all();
        mempool.finish_batch(detached);
        let after_original_ttl: TimePoint =
            TimePointSec::new(101 + DEFAULT_MEMPOOL_TRANSACTION_TTL_SECS).into();
        assert_eq!(mempool.prune_expired(&after_original_ttl), 1);
    }

    #[test]
    fn detached_batch_reserves_its_capacity_and_transaction_ids() {
        let mut mempool = Mempool::new();
        let detached_transaction = tx(0);
        assert!(mempool.add_transaction(detached_transaction.clone()));
        let batch = mempool.take_all();

        // Re-gossip cannot re-admit a transaction that is currently being
        // considered by the block builder.
        assert!(!mempool.add_transaction(detached_transaction.clone()));
        for index in 1..MAX_MEMPOOL_SIZE {
            assert!(mempool.add_transaction(tx(index as u16)));
        }
        assert!(!mempool.add_transaction(tx(MAX_MEMPOOL_SIZE as u16)));

        // Releasing the batch's reservation makes exactly enough space for its
        // deferred transaction; it is not silently dropped or displaced.
        mempool.finish_batch(batch);
        assert!(mempool.contains(detached_transaction.id()));
        assert!(!mempool.add_transaction(tx(MAX_MEMPOOL_SIZE as u16)));
    }

    #[test]
    fn detached_batch_recovers_from_a_missing_expiry_entry() {
        let mut mempool = Mempool::new();
        let transaction = tx_with_expiration(TimePointSec::maximum(), 99);
        assert!(mempool.add_transaction(transaction.clone()));
        let mut batch = mempool.take_all();
        batch.transactions.expiration_by_id.clear();

        mempool.finish_batch(batch);

        assert!(mempool.contains(transaction.id()));
        assert_eq!(mempool.pop_transaction().unwrap().id(), transaction.id());
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
