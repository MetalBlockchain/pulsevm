//! Default-off, transaction-private speculation primitives.
//!
//! A [`SpeculativeWave`] borrows the canonical [`Database`] mutably, which
//! establishes the controller-side freeze boundary. Read snapshots expose only
//! immutable operations, while each worker records primary-table mutations as
//! logical keys and values. Nothing assigns Arena object ids until ordered
//! apply invokes the canonical database APIs.

use std::{
    collections::{
        BTreeMap,
        BTreeSet,
    },
    sync::atomic::{
        AtomicU64,
        Ordering,
    },
};

use pulsevm_error::ChainError;

use super::Database;
use crate::dependency::{
    ContractIndex,
    ContractRowKey,
    DependencyKey,
    DependencyTracker,
    TransactionDependencies,
};

/// Stable version of the canonical state frozen for one speculative wave.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotVersion {
    /// Arena undo revision at the block-prefix boundary.
    pub revision: i64,
    /// Intra-revision logical mutation epoch.
    pub mutation_epoch: u64,
}

/// Logical identity of one contract primary row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ContractPrimaryKey {
    pub code: u64,
    pub scope: u64,
    pub table: u64,
    pub primary: u64,
}

impl ContractPrimaryKey {
    pub const fn new(code: u64, scope: u64, table: u64, primary: u64) -> Self {
        Self {
            code,
            scope,
            table,
            primary,
        }
    }

    fn dependency_key(self) -> DependencyKey {
        DependencyKey::Contract(ContractRowKey::new(
            self.code,
            self.scope,
            self.table,
            ContractIndex::Primary,
            self.primary,
        ))
    }

    fn table_dependency_key(self) -> DependencyKey {
        DependencyKey::Contract(ContractRowKey::table(self.code, self.scope, self.table))
    }
}

/// Why a speculative result must be re-executed by the serial executor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpeculativeFallbackReason {
    SnapshotMismatch,
    MutationEpochAdvanced,
    DependencyConflict,
    UnsupportedMutation,
    SpeculativeExecutionFailed(String),
    ApplyFailed(String),
    SerialFallbackRequired,
    WaveInvalidated,
}

/// Result of ordered validation and apply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpeculativeCommitOutcome {
    Applied,
    RetrySerial(SpeculativeFallbackReason),
}

/// Read-only view of the canonical block-prefix state.
///
/// The backing Arena is shared, not copied. Immutability is enforced by the
/// wave's exclusive controller borrow and by checking the shared mutation epoch
/// both before and after every read. A stale snapshot never returns a value.
#[derive(Clone)]
pub struct BlockReadSnapshot {
    database: Database,
    version: SnapshotVersion,
}

impl BlockReadSnapshot {
    pub fn version(&self) -> SnapshotVersion {
        self.version
    }

    pub fn transaction(&self) -> ContractPrimaryOverlay {
        ContractPrimaryOverlay {
            snapshot: self.clone(),
            visible: BTreeMap::new(),
            operations: Vec::new(),
            tracker: DependencyTracker::new(),
            invalid: None,
        }
    }

    fn mutation_epoch(&self) -> u64 {
        self.database
            .speculation_epoch
            .get()
            .expect("speculative snapshot always installs an epoch")
            .load(Ordering::Acquire)
    }

    fn primary_get(
        &self,
        key: ContractPrimaryKey,
    ) -> Result<Option<Vec<u8>>, SpeculativeFallbackReason> {
        if self.mutation_epoch() != self.version.mutation_epoch {
            return Err(SpeculativeFallbackReason::MutationEpochAdvanced);
        }
        let value = self
            .database
            .arena_kv_get(key.code, key.scope, key.table, key.primary);
        if self.mutation_epoch() != self.version.mutation_epoch {
            return Err(SpeculativeFallbackReason::MutationEpochAdvanced);
        }
        Ok(value)
    }
}

#[derive(Clone, Debug)]
enum LogicalOperation {
    Create {
        key: ContractPrimaryKey,
        payer: u64,
        value: Vec<u8>,
    },
    Update {
        key: ContractPrimaryKey,
        payer: u64,
        value: Vec<u8>,
    },
    Remove {
        key: ContractPrimaryKey,
    },
}

/// Transaction-private primary-table overlay.
///
/// Only this closed CRUD surface can produce a complete report. Future
/// adapters must call [`Self::mark_unsupported_mutation`] before falling back
/// when execution reaches a system table, secondary index, or other operation
/// that is not represented here.
pub struct ContractPrimaryOverlay {
    snapshot: BlockReadSnapshot,
    visible: BTreeMap<ContractPrimaryKey, Option<Vec<u8>>>,
    operations: Vec<LogicalOperation>,
    tracker: DependencyTracker,
    invalid: Option<SpeculativeFallbackReason>,
}

impl ContractPrimaryOverlay {
    pub fn get(
        &mut self,
        key: ContractPrimaryKey,
    ) -> Result<Option<Vec<u8>>, SpeculativeFallbackReason> {
        self.tracker.recorder().exact_read(key.dependency_key());
        if let Some(value) = self.visible.get(&key) {
            return Ok(value.clone());
        }
        match self.snapshot.primary_get(key) {
            Ok(value) => Ok(value),
            Err(reason) => {
                self.invalid.get_or_insert_with(|| reason.clone());
                Err(reason)
            }
        }
    }

    pub fn create(
        &mut self,
        key: ContractPrimaryKey,
        payer: u64,
        value: Vec<u8>,
    ) -> Result<(), ChainError> {
        if self.get(key).map_err(Self::snapshot_error)?.is_some() {
            return self.execution_error(format!(
                "speculative create found existing primary row {key:?}"
            ));
        }
        self.record_write(key, true);
        self.visible.insert(key, Some(value.clone()));
        self.operations
            .push(LogicalOperation::Create { key, payer, value });
        Ok(())
    }

    pub fn update(
        &mut self,
        key: ContractPrimaryKey,
        payer: u64,
        value: Vec<u8>,
    ) -> Result<(), ChainError> {
        if self.get(key).map_err(Self::snapshot_error)?.is_none() {
            return self.execution_error(format!(
                "speculative update did not find primary row {key:?}"
            ));
        }
        self.record_write(key, false);
        self.visible.insert(key, Some(value.clone()));
        self.operations
            .push(LogicalOperation::Update { key, payer, value });
        Ok(())
    }

    pub fn remove(&mut self, key: ContractPrimaryKey) -> Result<(), ChainError> {
        if self.get(key).map_err(Self::snapshot_error)?.is_none() {
            return self.execution_error(format!(
                "speculative remove did not find primary row {key:?}"
            ));
        }
        self.record_write(key, true);
        self.visible.insert(key, None);
        self.operations.push(LogicalOperation::Remove { key });
        Ok(())
    }

    pub fn mark_unsupported_mutation(&mut self) {
        self.invalid
            .get_or_insert(SpeculativeFallbackReason::UnsupportedMutation);
    }

    pub fn finish(self) -> SpeculativeTransaction {
        if self.invalid.is_none() {
            self.tracker.recorder().mark_complete();
        }
        SpeculativeTransaction {
            version: self.snapshot.version,
            operations: self.operations,
            dependencies: self.tracker.snapshot(),
            invalid: self.invalid,
        }
    }

    fn record_write(&self, key: ContractPrimaryKey, changes_table_metadata: bool) {
        let recorder = self.tracker.recorder();
        if changes_table_metadata {
            recorder.write(key.table_dependency_key());
        }
        recorder.write(key.dependency_key());
    }

    fn snapshot_error(reason: SpeculativeFallbackReason) -> ChainError {
        ChainError::DatabaseError(format!("speculative snapshot is stale: {reason:?}"))
    }

    fn execution_error<T>(&mut self, message: String) -> Result<T, ChainError> {
        self.invalid.get_or_insert_with(|| {
            SpeculativeFallbackReason::SpeculativeExecutionFailed(message.clone())
        });
        Err(ChainError::DatabaseError(message))
    }
}

/// Finished worker result awaiting canonical-order validation.
pub struct SpeculativeTransaction {
    version: SnapshotVersion,
    operations: Vec<LogicalOperation>,
    dependencies: TransactionDependencies,
    invalid: Option<SpeculativeFallbackReason>,
}

impl SpeculativeTransaction {
    pub fn version(&self) -> SnapshotVersion {
        self.version
    }

    pub fn dependencies(&self) -> &TransactionDependencies {
        &self.dependencies
    }
}

/// Exclusive canonical commit boundary for a speculative block wave.
pub struct SpeculativeWave<'db> {
    canonical: &'db mut Database,
    snapshot: BlockReadSnapshot,
    expected_epoch: u64,
    prior_writes: BTreeSet<DependencyKey>,
    awaiting_serial_fallback: bool,
    invalidated: bool,
}

impl Database {
    /// Freeze the controller's canonical handle and begin a default-off wave.
    pub fn begin_speculative_wave(&mut self) -> Result<SpeculativeWave<'_>, ChainError> {
        self.speculation_freeze
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                ChainError::DatabaseError("a speculative wave is already active".into())
            })?;
        let epoch = self
            .speculation_epoch
            .get_or_init(|| AtomicU64::new(0))
            .load(Ordering::Acquire);
        let version = SnapshotVersion {
            revision: self.revision(),
            mutation_epoch: epoch,
        };
        let mut read_database = self.clone();
        read_database.dependency_recorder = None;
        let snapshot = BlockReadSnapshot {
            database: read_database,
            version,
        };
        Ok(SpeculativeWave {
            canonical: self,
            snapshot,
            expected_epoch: epoch,
            prior_writes: BTreeSet::new(),
            awaiting_serial_fallback: false,
            invalidated: false,
        })
    }
}

impl SpeculativeWave<'_> {
    pub fn snapshot(&self) -> BlockReadSnapshot {
        self.snapshot.clone()
    }

    pub fn try_apply(&mut self, transaction: SpeculativeTransaction) -> SpeculativeCommitOutcome {
        if self.invalidated {
            return SpeculativeCommitOutcome::RetrySerial(
                SpeculativeFallbackReason::WaveInvalidated,
            );
        }
        if self.awaiting_serial_fallback {
            return SpeculativeCommitOutcome::RetrySerial(
                SpeculativeFallbackReason::SerialFallbackRequired,
            );
        }
        if transaction.version != self.snapshot.version {
            return self.reject(SpeculativeFallbackReason::SnapshotMismatch, false);
        }
        if self.current_epoch() != self.expected_epoch {
            return self.reject(SpeculativeFallbackReason::MutationEpochAdvanced, true);
        }
        if let Some(reason) = transaction.invalid {
            return self.reject(reason, false);
        }
        if !transaction.dependencies.is_complete() {
            return self.reject(SpeculativeFallbackReason::UnsupportedMutation, false);
        }
        if transaction
            .dependencies
            .conflicts_with_prior_writes(&self.prior_writes)
        {
            return self.reject(SpeculativeFallbackReason::DependencyConflict, false);
        }

        self.canonical.arena_start_undo_session();
        for operation in &transaction.operations {
            if let Err(error) = self.apply_operation(operation) {
                self.canonical.arena_undo();
                self.expected_epoch = self.current_epoch();
                return self.reject(
                    SpeculativeFallbackReason::ApplyFailed(error.to_string()),
                    true,
                );
            }
        }
        self.canonical.arena_squash();
        self.expected_epoch = self.current_epoch();
        self.prior_writes
            .extend(transaction.dependencies.writes().iter().copied());
        SpeculativeCommitOutcome::Applied
    }

    /// Run the existing serial executor after a rejected speculative result.
    ///
    /// The old block-start snapshot is invalid after this mutation, so this
    /// conservative first slice rejects all remaining worker results. A future
    /// ordered executor can restart a wave from the new prefix.
    pub fn run_serial_fallback<T>(
        &mut self,
        fallback: impl FnOnce(&mut Database) -> Result<T, ChainError>,
    ) -> Result<T, ChainError> {
        if !self.awaiting_serial_fallback {
            return Err(ChainError::DatabaseError(
                "serial fallback requested without a rejected speculative transaction".into(),
            ));
        }
        self.canonical
            .speculation_freeze
            .store(false, Ordering::Release);
        let result = fallback(self.canonical);
        self.expected_epoch = self.current_epoch();
        self.awaiting_serial_fallback = false;
        self.invalidated = true;
        result
    }

    fn current_epoch(&self) -> u64 {
        self.canonical
            .speculation_epoch
            .get()
            .expect("speculative wave always installs an epoch")
            .load(Ordering::Acquire)
    }

    fn reject(
        &mut self,
        reason: SpeculativeFallbackReason,
        invalidate_wave: bool,
    ) -> SpeculativeCommitOutcome {
        self.awaiting_serial_fallback = true;
        self.invalidated |= invalidate_wave;
        SpeculativeCommitOutcome::RetrySerial(reason)
    }

    fn apply_operation(&self, operation: &LogicalOperation) -> Result<(), ChainError> {
        match operation {
            LogicalOperation::Create { key, payer, value } => {
                self.canonical.apply_speculative_primary_create(
                    key.code,
                    key.scope,
                    key.table,
                    *payer,
                    key.primary,
                    value,
                )
            }
            LogicalOperation::Update { key, payer, value } => {
                self.canonical.apply_speculative_primary_update(
                    key.code,
                    key.scope,
                    key.table,
                    key.primary,
                    *payer,
                    value,
                )
            }
            LogicalOperation::Remove { key } => self.canonical.apply_speculative_primary_remove(
                key.code,
                key.scope,
                key.table,
                key.primary,
            ),
        }
    }
}

impl Drop for SpeculativeWave<'_> {
    fn drop(&mut self) {
        self.canonical
            .speculation_freeze
            .store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seeded(rows: &[(ContractPrimaryKey, &[u8])]) -> Database {
        let db = Database::default();
        for (key, value) in rows {
            db.create_key_value_object_standalone(
                key.code,
                key.scope,
                key.table,
                1,
                key.primary,
                value,
            )
            .unwrap();
        }
        db
    }

    #[test]
    fn mutation_epoch_is_not_installed_on_the_default_path() {
        let db = Database::default();
        assert!(db.speculation_epoch.get().is_none());
        db.create_key_value_object_standalone(1, 2, 3, 1, 4, b"serial")
            .unwrap();
        assert!(db.speculation_epoch.get().is_none());

        let mut db = db;
        let wave = db.begin_speculative_wave().unwrap();
        assert_eq!(wave.snapshot().version().mutation_epoch, 0);
    }

    #[test]
    fn overlays_are_isolated_from_the_snapshot_and_each_other() {
        let key = ContractPrimaryKey::new(1, 2, 3, 4);
        let mut db = seeded(&[(key, b"base")]);
        let wave = db.begin_speculative_wave().unwrap();
        let snapshot = wave.snapshot();
        let left_snapshot = snapshot.clone();
        let right_snapshot = snapshot.clone();

        let left = std::thread::spawn(move || {
            let mut overlay = left_snapshot.transaction();
            overlay.update(key, 1, b"left".to_vec()).unwrap();
            assert_eq!(overlay.get(key).unwrap(), Some(b"left".to_vec()));
            overlay.finish()
        });
        let right = std::thread::spawn(move || {
            let mut overlay = right_snapshot.transaction();
            assert_eq!(overlay.get(key).unwrap(), Some(b"base".to_vec()));
            overlay.finish()
        });

        assert!(left.join().unwrap().dependencies().is_complete());
        assert!(right.join().unwrap().dependencies().is_complete());
        let mut untouched = snapshot.transaction();
        assert_eq!(untouched.get(key).unwrap(), Some(b"base".to_vec()));
    }

    #[test]
    fn ordered_apply_matches_serial_logical_operations_and_ids() {
        let first = ContractPrimaryKey::new(1, 2, 10, 1);
        let second = ContractPrimaryKey::new(1, 2, 11, 1);
        let mut speculative = seeded(&[]);
        let serial = seeded(&[]);

        let mut wave = speculative.begin_speculative_wave().unwrap();
        let mut first_overlay = wave.snapshot().transaction();
        first_overlay.create(first, 7, b"first".to_vec()).unwrap();
        let mut second_overlay = wave.snapshot().transaction();
        second_overlay
            .create(second, 8, b"second".to_vec())
            .unwrap();
        assert_eq!(
            wave.try_apply(first_overlay.finish()),
            SpeculativeCommitOutcome::Applied
        );
        assert_eq!(
            wave.try_apply(second_overlay.finish()),
            SpeculativeCommitOutcome::Applied
        );
        drop(wave);

        serial
            .create_key_value_object_standalone(1, 2, 10, 7, 1, b"first")
            .unwrap();
        serial
            .create_key_value_object_standalone(1, 2, 11, 8, 1, b"second")
            .unwrap();
        assert_eq!(speculative.arena_state_root(), serial.arena_state_root());
    }

    #[test]
    fn conflicting_result_is_rejected_before_apply() {
        let key = ContractPrimaryKey::new(1, 2, 3, 4);
        let mut db = seeded(&[(key, b"base")]);
        let mut wave = db.begin_speculative_wave().unwrap();
        let mut first = wave.snapshot().transaction();
        first.update(key, 1, b"first".to_vec()).unwrap();
        let mut second = wave.snapshot().transaction();
        second.update(key, 1, b"second".to_vec()).unwrap();

        assert_eq!(
            wave.try_apply(first.finish()),
            SpeculativeCommitOutcome::Applied
        );
        assert_eq!(
            wave.try_apply(second.finish()),
            SpeculativeCommitOutcome::RetrySerial(SpeculativeFallbackReason::DependencyConflict)
        );
        let snapshot = wave.snapshot();
        drop(wave);
        assert_eq!(db.arena_kv_get(1, 2, 3, 4), Some(b"first".to_vec()));
        assert_eq!(
            snapshot.primary_get(key),
            Err(SpeculativeFallbackReason::MutationEpochAdvanced)
        );
    }

    #[test]
    fn freeze_rejects_alias_writes_and_epoch_rejects_old_results() {
        let key = ContractPrimaryKey::new(1, 2, 3, 4);
        let other = ContractPrimaryKey::new(9, 8, 7, 6);
        let mut db = seeded(&[(key, b"base")]);
        let mut rogue = db.clone();
        let wave = db.begin_speculative_wave().unwrap();
        let snapshot = wave.snapshot();
        let mut overlay = snapshot.transaction();
        overlay.update(key, 1, b"candidate".to_vec()).unwrap();

        assert!(rogue.begin_speculative_wave().is_err());
        assert!(
            rogue
                .create_key_value_object_standalone(
                    other.code,
                    other.scope,
                    other.table,
                    1,
                    other.primary,
                    b"rogue",
                )
                .is_err()
        );
        let transaction = overlay.finish();
        drop(wave);

        rogue
            .create_key_value_object_standalone(
                other.code,
                other.scope,
                other.table,
                1,
                other.primary,
                b"rogue",
            )
            .unwrap();
        assert_eq!(
            snapshot.primary_get(key),
            Err(SpeculativeFallbackReason::MutationEpochAdvanced)
        );
        let mut wave = db.begin_speculative_wave().unwrap();
        assert_eq!(
            wave.try_apply(transaction),
            SpeculativeCommitOutcome::RetrySerial(SpeculativeFallbackReason::SnapshotMismatch)
        );
    }

    #[test]
    fn unsupported_mutation_forces_serial_fallback_and_invalidates_wave() {
        let key = ContractPrimaryKey::new(1, 2, 3, 4);
        let mut db = seeded(&[(key, b"base")]);
        let mut wave = db.begin_speculative_wave().unwrap();
        let mut unsupported = wave.snapshot().transaction();
        unsupported.mark_unsupported_mutation();
        let mut later = wave.snapshot().transaction();
        later.update(key, 1, b"later".to_vec()).unwrap();

        assert_eq!(
            wave.try_apply(unsupported.finish()),
            SpeculativeCommitOutcome::RetrySerial(SpeculativeFallbackReason::UnsupportedMutation)
        );
        wave.run_serial_fallback(|canonical| {
            canonical.update_key_value_object_standalone(1, 2, 3, 4, 1, b"serial")
        })
        .unwrap();
        assert_eq!(
            wave.try_apply(later.finish()),
            SpeculativeCommitOutcome::RetrySerial(SpeculativeFallbackReason::WaveInvalidated)
        );
        drop(wave);
        assert_eq!(db.arena_kv_get(1, 2, 3, 4), Some(b"serial".to_vec()));
    }
}
