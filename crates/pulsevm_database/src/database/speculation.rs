//! Default-off, transaction-private speculation primitives.
//!
//! A [`SpeculativeWave`] borrows the canonical [`Database`] mutably, which
//! establishes the controller-side freeze boundary. Read snapshots expose only
//! immutable operations, while each worker records contract-table mutations as
//! logical keys and values. Nothing assigns Arena object ids until ordered
//! apply invokes the canonical database APIs.

use std::{
    collections::{
        BTreeMap,
        BTreeSet,
    },
    num::NonZeroUsize,
    panic::{
        AssertUnwindSafe,
        catch_unwind,
    },
    sync::{
        Arc,
        Mutex,
        atomic::{
            AtomicBool,
            AtomicU64,
            AtomicUsize,
            Ordering,
        },
    },
};

use pulsevm_error::ChainError;

use super::Database;
use crate::{
    Float128,
    U256,
    dependency::{
        ContractIndex,
        ContractRowKey,
        DependencyKey,
        DependencyTracker,
        TransactionDependencies,
    },
};

/// Bound wasted work when a batch is too conflict-heavy for optimistic
/// execution. The suffix still runs through the authoritative serial path.
const MAX_SPECULATIVE_RESTARTS: usize = 2;

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

/// Value stored by one Antelope contract secondary-index row.
///
/// Float keys are kept in their canonical raw-bit representation. This avoids
/// host floating-point comparisons in the optimistic layer and matches the
/// values crossing the WASM database intrinsic boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContractSecondaryValue {
    Idx64(u64),
    Idx128(u128),
    Idx256([u8; 32]),
    IdxDouble(u64),
    IdxLongDouble((u64, u64)),
}

impl ContractSecondaryValue {
    const fn index(self) -> ContractIndex {
        match self {
            Self::Idx64(_) => ContractIndex::Idx64,
            Self::Idx128(_) => ContractIndex::Idx128,
            Self::Idx256(_) => ContractIndex::Idx256,
            Self::IdxDouble(_) => ContractIndex::IdxDouble,
            Self::IdxLongDouble(_) => ContractIndex::IdxLongDouble,
        }
    }
}

/// Transaction-visible secondary row, including the payer needed for RAM
/// accounting when a later operation changes ownership or removes the row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContractSecondaryRow {
    pub payer: u64,
    pub value: ContractSecondaryValue,
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
    WorkerPanicked,
    ApplyFailed(String),
    SerialEscapeHatch,
    SerialFallbackRequired,
    WaveInvalidated,
}

/// Whether one task committed its worker result or used the serial reference
/// executor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpeculativeTaskOutcome {
    Applied,
    RetriedSerial(SpeculativeFallbackReason),
}

/// Ordered outputs and execution metadata for one optimistic batch.
#[derive(Debug)]
pub struct SpeculativeBatchResult<T> {
    outputs: Vec<T>,
    outcomes: Vec<SpeculativeTaskOutcome>,
    waves: usize,
}

/// Serial-authoritative result of a speculative shadow batch.
#[derive(Debug)]
pub struct SpeculativeShadowResult<T> {
    outputs: Vec<T>,
    speculative_outputs: Vec<T>,
    outcomes: Vec<SpeculativeTaskOutcome>,
    waves: usize,
    speculative_state_root: Option<[u8; 32]>,
    serial_state_root: Option<[u8; 32]>,
    outputs_match: bool,
    state_root_matches: bool,
}

impl<T> SpeculativeShadowResult<T> {
    pub fn outputs(&self) -> &[T] {
        &self.outputs
    }

    pub fn into_outputs(self) -> Vec<T> {
        self.outputs
    }

    pub fn speculative_outputs(&self) -> &[T] {
        &self.speculative_outputs
    }

    pub fn outcomes(&self) -> &[SpeculativeTaskOutcome] {
        &self.outcomes
    }

    pub const fn waves(&self) -> usize {
        self.waves
    }

    pub const fn speculative_state_root(&self) -> Option<[u8; 32]> {
        self.speculative_state_root
    }

    pub const fn serial_state_root(&self) -> Option<[u8; 32]> {
        self.serial_state_root
    }

    pub const fn outputs_match(&self) -> bool {
        self.outputs_match
    }

    pub const fn state_root_matches(&self) -> bool {
        self.state_root_matches
    }

    pub const fn parity_matches(&self) -> bool {
        self.outputs_match && self.state_root_matches
    }
}

impl<T> SpeculativeBatchResult<T> {
    pub fn outputs(&self) -> &[T] {
        &self.outputs
    }

    pub fn into_outputs(self) -> Vec<T> {
        self.outputs
    }

    pub fn outcomes(&self) -> &[SpeculativeTaskOutcome] {
        &self.outcomes
    }

    pub const fn waves(&self) -> usize {
        self.waves
    }
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

    pub fn transaction(&self) -> ContractTableOverlay {
        ContractTableOverlay {
            snapshot: self.clone(),
            visible: BTreeMap::new(),
            secondary_visible: BTreeMap::new(),
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

    fn secondary_get(
        &self,
        key: ContractPrimaryKey,
        index: ContractIndex,
    ) -> Result<Option<ContractSecondaryRow>, SpeculativeFallbackReason> {
        if self.mutation_epoch() != self.version.mutation_epoch {
            return Err(SpeculativeFallbackReason::MutationEpochAdvanced);
        }
        let row = match index {
            ContractIndex::Idx64 => self
                .database
                .arena_idx64_find_primary(key.code, key.scope, key.table, key.primary)
                .zip(
                    self.database
                        .arena_idx64_payer(key.code, key.scope, key.table, key.primary),
                )
                .map(|(value, payer)| ContractSecondaryRow {
                    payer,
                    value: ContractSecondaryValue::Idx64(value),
                }),
            ContractIndex::Idx128 => self
                .database
                .arena_idx128_find_primary(key.code, key.scope, key.table, key.primary)
                .zip(
                    self.database
                        .arena_idx128_payer(key.code, key.scope, key.table, key.primary),
                )
                .map(|(value, payer)| ContractSecondaryRow {
                    payer,
                    value: ContractSecondaryValue::Idx128(value),
                }),
            ContractIndex::Idx256 => self
                .database
                .arena_idx256_find_primary(key.code, key.scope, key.table, key.primary)
                .zip(
                    self.database
                        .arena_idx256_payer(key.code, key.scope, key.table, key.primary),
                )
                .map(|(value, payer)| ContractSecondaryRow {
                    payer,
                    value: ContractSecondaryValue::Idx256(value),
                }),
            ContractIndex::IdxDouble => self
                .database
                .arena_idx_double_find_primary(key.code, key.scope, key.table, key.primary)
                .zip(self.database.arena_idx_double_payer(
                    key.code,
                    key.scope,
                    key.table,
                    key.primary,
                ))
                .map(|(value, payer)| ContractSecondaryRow {
                    payer,
                    value: ContractSecondaryValue::IdxDouble(value),
                }),
            ContractIndex::IdxLongDouble => self
                .database
                .arena_idx_long_double_find_primary(key.code, key.scope, key.table, key.primary)
                .zip(self.database.arena_idx_long_double_payer(
                    key.code,
                    key.scope,
                    key.table,
                    key.primary,
                ))
                .map(|(value, payer)| ContractSecondaryRow {
                    payer,
                    value: ContractSecondaryValue::IdxLongDouble(value),
                }),
            ContractIndex::Table | ContractIndex::Primary => None,
        };
        if self.mutation_epoch() != self.version.mutation_epoch {
            return Err(SpeculativeFallbackReason::MutationEpochAdvanced);
        }
        Ok(row)
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
    SecondaryCreate {
        key: ContractPrimaryKey,
        payer: u64,
        value: ContractSecondaryValue,
    },
    SecondaryUpdate {
        key: ContractPrimaryKey,
        payer: u64,
        value: ContractSecondaryValue,
    },
    SecondaryRemove {
        key: ContractPrimaryKey,
        index: ContractIndex,
    },
}

/// Transaction-private contract-row overlay.
///
/// Exact primary and secondary CRUD plus conservative range dependencies can
/// produce a complete report. Future adapters must call
/// [`Self::mark_unsupported_mutation`] before falling back when execution
/// reaches a system table or another operation not represented here.
pub struct ContractTableOverlay {
    snapshot: BlockReadSnapshot,
    visible: BTreeMap<ContractPrimaryKey, Option<Vec<u8>>>,
    secondary_visible: BTreeMap<(ContractIndex, ContractPrimaryKey), Option<ContractSecondaryRow>>,
    operations: Vec<LogicalOperation>,
    tracker: DependencyTracker,
    invalid: Option<SpeculativeFallbackReason>,
}

/// Backward-compatible name for the original primary-only overlay API.
pub type ContractPrimaryOverlay = ContractTableOverlay;

impl ContractTableOverlay {
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

    /// Read one secondary row by primary key from the transaction's private
    /// view. `Table` and `Primary` are rejected because they are not secondary
    /// index families.
    pub fn secondary_get(
        &mut self,
        key: ContractPrimaryKey,
        index: ContractIndex,
    ) -> Result<Option<ContractSecondaryRow>, SpeculativeFallbackReason> {
        if !Self::is_secondary_index(index) {
            self.invalid
                .get_or_insert(SpeculativeFallbackReason::UnsupportedMutation);
            return Err(SpeculativeFallbackReason::UnsupportedMutation);
        }
        self.tracker
            .recorder()
            .exact_read(Self::secondary_dependency_key(key, index));
        if let Some(value) = self.secondary_visible.get(&(index, key)) {
            return Ok(*value);
        }
        match self.snapshot.secondary_get(key, index) {
            Ok(value) => Ok(value),
            Err(reason) => {
                self.invalid.get_or_insert_with(|| reason.clone());
                Err(reason)
            }
        }
    }

    /// Create a secondary row. The index family is carried by `value`, so a
    /// key cannot be committed into an index with a mismatched representation.
    pub fn secondary_create(
        &mut self,
        key: ContractPrimaryKey,
        payer: u64,
        value: ContractSecondaryValue,
    ) -> Result<(), ChainError> {
        let index = value.index();
        if self
            .secondary_get(key, index)
            .map_err(Self::snapshot_error)?
            .is_some()
        {
            return self.execution_error(format!(
                "speculative create found existing {index:?} row {key:?}"
            ));
        }
        self.record_secondary_write(key, index, true);
        self.secondary_visible
            .insert((index, key), Some(ContractSecondaryRow { payer, value }));
        self.operations
            .push(LogicalOperation::SecondaryCreate { key, payer, value });
        Ok(())
    }

    pub fn secondary_update(
        &mut self,
        key: ContractPrimaryKey,
        payer: u64,
        value: ContractSecondaryValue,
    ) -> Result<(), ChainError> {
        let index = value.index();
        if self
            .secondary_get(key, index)
            .map_err(Self::snapshot_error)?
            .is_none()
        {
            return self.execution_error(format!(
                "speculative update did not find {index:?} row {key:?}"
            ));
        }
        self.record_secondary_write(key, index, false);
        self.secondary_visible
            .insert((index, key), Some(ContractSecondaryRow { payer, value }));
        self.operations
            .push(LogicalOperation::SecondaryUpdate { key, payer, value });
        Ok(())
    }

    pub fn secondary_remove(
        &mut self,
        key: ContractPrimaryKey,
        index: ContractIndex,
    ) -> Result<(), ChainError> {
        if !Self::is_secondary_index(index) {
            return self.execution_error(format!("{index:?} is not a contract secondary index"));
        }
        if self
            .secondary_get(key, index)
            .map_err(Self::snapshot_error)?
            .is_none()
        {
            return self.execution_error(format!(
                "speculative remove did not find {index:?} row {key:?}"
            ));
        }
        self.record_secondary_write(key, index, true);
        self.secondary_visible.insert((index, key), None);
        self.operations
            .push(LogicalOperation::SecondaryRemove { key, index });
        Ok(())
    }

    /// Declare an ordering/absence observation in one contract index.
    ///
    /// Host adapters call this before lower/upper-bound and iterator movement.
    /// The dependency deliberately covers the whole index: any earlier insert,
    /// remove, or re-key then forces serial replay, preventing phantoms.
    pub fn record_index_range_read(
        &mut self,
        code: u64,
        scope: u64,
        table: u64,
        index: ContractIndex,
    ) {
        self.tracker
            .recorder()
            .range_read(crate::dependency::RangeDependency::Contract(
                crate::dependency::ContractRangeKey {
                    code,
                    scope,
                    table,
                    index,
                },
            ));
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

    fn record_secondary_write(
        &self,
        key: ContractPrimaryKey,
        index: ContractIndex,
        changes_table_metadata: bool,
    ) {
        let recorder = self.tracker.recorder();
        if changes_table_metadata {
            recorder.write(key.table_dependency_key());
        }
        recorder.write(Self::secondary_dependency_key(key, index));
    }

    const fn secondary_dependency_key(
        key: ContractPrimaryKey,
        index: ContractIndex,
    ) -> DependencyKey {
        DependencyKey::Contract(ContractRowKey {
            code: key.code,
            scope: key.scope,
            table: key.table,
            index,
            primary: key.primary,
        })
    }

    const fn is_secondary_index(index: ContractIndex) -> bool {
        matches!(
            index,
            ContractIndex::Idx64
                | ContractIndex::Idx128
                | ContractIndex::Idx256
                | ContractIndex::IdxDouble
                | ContractIndex::IdxLongDouble
        )
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

/// A worker's private changeset plus the output computed from the same read
/// view. The output is published only after the changeset commits in canonical
/// order.
pub struct SpeculativeCandidate<T> {
    transaction: SpeculativeTransaction,
    output: T,
}

impl<T> SpeculativeCandidate<T> {
    pub const fn new(transaction: SpeculativeTransaction, output: T) -> Self {
        Self {
            transaction,
            output,
        }
    }
}

/// One repeatable unit of optimistic work.
///
/// `speculate` may only read through the supplied snapshot and mutate its
/// transaction-private overlay. It can be called more than once when an
/// earlier task falls back and the remaining suffix must be restarted from a
/// new canonical prefix. `execute_serial` is the authoritative implementation
/// and may use the complete [`Database`] API. Both methods must keep durable
/// effects inside the supplied database and returned output: shadow execution
/// can invoke the serial method once during speculative fallback and again for
/// the authoritative serial pass.
pub trait SpeculativeTask: Sync {
    type Output: Send;

    fn speculate(
        &self,
        snapshot: BlockReadSnapshot,
    ) -> Result<SpeculativeCandidate<Self::Output>, ChainError>;

    fn execute_serial(&self, database: &mut Database) -> Result<Self::Output, ChainError>;
}

/// Exclusive canonical commit boundary for a speculative block wave.
pub struct SpeculativeWave<'db> {
    canonical: &'db mut Database,
    _coordinator: Option<SpeculationCoordinatorGuard>,
    snapshot: BlockReadSnapshot,
    expected_epoch: u64,
    prior_writes: BTreeSet<DependencyKey>,
    awaiting_serial_fallback: bool,
    invalidated: bool,
}

struct SpeculationCoordinatorGuard {
    coordinator: Arc<AtomicBool>,
}

impl Drop for SpeculationCoordinatorGuard {
    fn drop(&mut self) {
        self.coordinator.store(false, Ordering::Release);
    }
}

impl Database {
    /// Freeze the controller's canonical handle and begin a default-off wave.
    pub fn begin_speculative_wave(&mut self) -> Result<SpeculativeWave<'_>, ChainError> {
        let coordinator = self.acquire_speculation_coordinator()?;
        self.begin_speculative_wave_owned(Some(coordinator))
    }

    fn acquire_speculation_coordinator(&self) -> Result<SpeculationCoordinatorGuard, ChainError> {
        self.speculation_coordinator
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                ChainError::DatabaseError("a speculative coordinator is already active".into())
            })?;
        Ok(SpeculationCoordinatorGuard {
            coordinator: Arc::clone(&self.speculation_coordinator),
        })
    }

    fn begin_speculative_wave_owned(
        &mut self,
        coordinator: Option<SpeculationCoordinatorGuard>,
    ) -> Result<SpeculativeWave<'_>, ChainError> {
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
            _coordinator: coordinator,
            snapshot,
            expected_epoch: epoch,
            prior_writes: BTreeSet::new(),
            awaiting_serial_fallback: false,
            invalidated: false,
        })
    }

    /// Execute a batch concurrently and commit it in slice order.
    ///
    /// A rejected worker result is discarded and re-executed through the
    /// task's serial implementation. Because that changes the canonical
    /// prefix, every uncommitted suffix task is speculated again from a fresh
    /// snapshot. Worker completion order is never observable.
    pub fn execute_speculative_batch<Task>(
        &mut self,
        tasks: &[Task],
        max_workers: NonZeroUsize,
    ) -> Result<SpeculativeBatchResult<Task::Output>, ChainError>
    where
        Task: SpeculativeTask,
    {
        if tasks.is_empty() {
            return Ok(SpeculativeBatchResult {
                outputs: Vec::new(),
                outcomes: Vec::new(),
                waves: 0,
            });
        }

        let _coordinator = self.acquire_speculation_coordinator()?;
        self.execute_speculative_batch_locked(tasks, max_workers)
    }

    fn execute_speculative_batch_locked<Task>(
        &mut self,
        tasks: &[Task],
        max_workers: NonZeroUsize,
    ) -> Result<SpeculativeBatchResult<Task::Output>, ChainError>
    where
        Task: SpeculativeTask,
    {
        // Mirror the controller's block session around the per-transaction
        // sessions opened during ordered apply and serial fallback. Besides
        // making the batch atomic on error, this preserves Arena blob reuse and
        // object-allocation behavior relative to canonical serial execution.
        self.arena_start_undo_session();
        match self.execute_speculative_batch_inner(tasks, max_workers) {
            Ok(result) => {
                self.arena_squash();
                Ok(result)
            }
            Err(error) => {
                self.arena_undo();
                Err(error)
            }
        }
    }

    /// Exercise optimistic execution without making its result authoritative.
    ///
    /// The speculative batch runs in an undo session, its output and state root
    /// are captured, and all of its mutations are rolled back. The same tasks
    /// then execute serially and those serial results remain in the database.
    /// Parity differences are returned as observation data rather than errors,
    /// so shadow mode cannot change transaction validity.
    pub fn execute_speculative_shadow_batch<Task>(
        &mut self,
        tasks: &[Task],
        max_workers: NonZeroUsize,
    ) -> Result<SpeculativeShadowResult<Task::Output>, ChainError>
    where
        Task: SpeculativeTask,
        Task::Output: PartialEq,
    {
        if tasks.is_empty() {
            return Ok(SpeculativeShadowResult {
                outputs: Vec::new(),
                speculative_outputs: Vec::new(),
                outcomes: Vec::new(),
                waves: 0,
                speculative_state_root: self.arena_state_root(),
                serial_state_root: self.arena_state_root(),
                outputs_match: true,
                state_root_matches: true,
            });
        }

        let _coordinator = self.acquire_speculation_coordinator()?;

        self.arena_start_undo_session();
        let speculative = match self.execute_speculative_batch_locked(tasks, max_workers) {
            Ok(result) => result,
            Err(error) => {
                self.arena_undo();
                return Err(error);
            }
        };
        let speculative_root = self.arena_state_root();
        self.arena_undo();

        let serial_outputs = self.execute_serial_batch(tasks)?;
        let serial_root = self.arena_state_root();
        let SpeculativeBatchResult {
            outputs: speculative_outputs,
            outcomes,
            waves,
        } = speculative;
        let outputs_match = speculative_outputs == serial_outputs;

        Ok(SpeculativeShadowResult {
            outputs: serial_outputs,
            speculative_outputs,
            outcomes,
            waves,
            speculative_state_root: speculative_root,
            serial_state_root: serial_root,
            outputs_match,
            state_root_matches: speculative_root == serial_root,
        })
    }

    fn execute_serial_batch<Task>(
        &mut self,
        tasks: &[Task],
    ) -> Result<Vec<Task::Output>, ChainError>
    where
        Task: SpeculativeTask,
    {
        self.arena_start_undo_session();
        let mut outputs = Vec::with_capacity(tasks.len());
        for task in tasks {
            match execute_serial_task(self, task) {
                Ok(output) => outputs.push(output),
                Err(error) => {
                    self.arena_undo();
                    return Err(error);
                }
            }
        }
        self.arena_squash();
        Ok(outputs)
    }

    fn execute_speculative_batch_inner<Task>(
        &mut self,
        tasks: &[Task],
        max_workers: NonZeroUsize,
    ) -> Result<SpeculativeBatchResult<Task::Output>, ChainError>
    where
        Task: SpeculativeTask,
    {
        let mut outputs = Vec::with_capacity(tasks.len());
        let mut outcomes = Vec::with_capacity(tasks.len());
        let mut waves = 0usize;
        let mut restarts = 0usize;
        let mut next = 0usize;

        while next < tasks.len() {
            let mut wave = self.begin_speculative_wave_owned(None)?;
            waves = waves.saturating_add(1);
            let candidates = execute_workers(wave.snapshot(), &tasks[next..], max_workers);
            if wave.current_epoch() != wave.expected_epoch {
                return Err(ChainError::DatabaseError(
                    "canonical state mutated while speculative workers were active".into(),
                ));
            }
            let mut restarted = false;
            let mut escape_to_serial = false;

            for (offset, candidate) in candidates.into_iter().enumerate() {
                let index = next + offset;
                let (transaction, speculative_output) = match candidate {
                    Ok(candidate) => (candidate.transaction, Some(candidate.output)),
                    Err(reason) => {
                        wave.require_serial_fallback();
                        let output = wave.run_serial_fallback(|database| {
                            execute_serial_task(database, &tasks[index])
                        })?;
                        outputs.push(output);
                        outcomes.push(SpeculativeTaskOutcome::RetriedSerial(reason));
                        next = index + 1;
                        restarts = restarts.saturating_add(1);
                        escape_to_serial = restarts >= MAX_SPECULATIVE_RESTARTS;
                        restarted = true;
                        break;
                    }
                };

                match wave.try_apply(transaction) {
                    SpeculativeCommitOutcome::Applied => {
                        let output = speculative_output.ok_or_else(|| {
                            ChainError::DatabaseError(
                                "applied speculative task has no output".into(),
                            )
                        })?;
                        outputs.push(output);
                        outcomes.push(SpeculativeTaskOutcome::Applied);
                    }
                    SpeculativeCommitOutcome::RetrySerial(
                        SpeculativeFallbackReason::MutationEpochAdvanced,
                    ) => {
                        return Err(ChainError::DatabaseError(
                            "canonical state mutated during ordered speculative apply".into(),
                        ));
                    }
                    SpeculativeCommitOutcome::RetrySerial(reason) => {
                        let output = wave.run_serial_fallback(|database| {
                            execute_serial_task(database, &tasks[index])
                        })?;
                        outputs.push(output);
                        outcomes.push(SpeculativeTaskOutcome::RetriedSerial(reason));
                        next = index + 1;
                        restarts = restarts.saturating_add(1);
                        escape_to_serial = restarts >= MAX_SPECULATIVE_RESTARTS;
                        restarted = true;
                        break;
                    }
                }
            }

            drop(wave);

            if escape_to_serial {
                for task in &tasks[next..] {
                    outputs.push(execute_serial_task(self, task)?);
                    outcomes.push(SpeculativeTaskOutcome::RetriedSerial(
                        SpeculativeFallbackReason::SerialEscapeHatch,
                    ));
                }
                next = tasks.len();
                continue;
            }

            if !restarted {
                next = tasks.len();
            }
        }

        Ok(SpeculativeBatchResult {
            outputs,
            outcomes,
            waves,
        })
    }
}

fn execute_serial_task<Task>(
    database: &mut Database,
    task: &Task,
) -> Result<Task::Output, ChainError>
where
    Task: SpeculativeTask,
{
    database.arena_start_undo_session();
    match task.execute_serial(database) {
        Ok(output) => {
            database.arena_squash();
            Ok(output)
        }
        Err(error) => {
            database.arena_undo();
            Err(error)
        }
    }
}

fn execute_workers<Task>(
    snapshot: BlockReadSnapshot,
    tasks: &[Task],
    max_workers: NonZeroUsize,
) -> Vec<Result<SpeculativeCandidate<Task::Output>, SpeculativeFallbackReason>>
where
    Task: SpeculativeTask,
{
    let worker_count = max_workers.get().min(tasks.len());
    let next = AtomicUsize::new(0);
    let results = std::iter::repeat_with(|| Mutex::new(None))
        .take(tasks.len())
        .collect::<Vec<_>>();

    std::thread::scope(|scope| {
        for _ in 0..worker_count {
            let snapshot = snapshot.clone();
            let next = &next;
            let results = &results;
            scope.spawn(move || {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(task) = tasks.get(index) else {
                        break;
                    };
                    let candidate =
                        catch_unwind(AssertUnwindSafe(|| task.speculate(snapshot.clone())))
                            .map_err(|_| SpeculativeFallbackReason::WorkerPanicked)
                            .and_then(|result| {
                                result.map_err(|error| {
                                    SpeculativeFallbackReason::SpeculativeExecutionFailed(
                                        error.to_string(),
                                    )
                                })
                            });
                    if let Some(slot) = results.get(index)
                        && let Ok(mut result) = slot.lock()
                    {
                        result.replace(candidate);
                    }
                }
            });
        }
    });

    results
        .into_iter()
        .map(|result| {
            result
                .into_inner()
                .ok()
                .flatten()
                .unwrap_or(Err(SpeculativeFallbackReason::WorkerPanicked))
        })
        .collect()
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

    fn require_serial_fallback(&mut self) {
        self.awaiting_serial_fallback = true;
    }

    /// Run the existing serial executor after a rejected speculative result.
    ///
    /// The old block-start snapshot is invalid after this mutation, so this
    /// wave rejects all remaining worker results. The batch coordinator starts
    /// a fresh wave for the uncommitted suffix.
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
            LogicalOperation::SecondaryCreate { key, payer, value } => {
                self.apply_secondary_create(*key, *payer, *value)
            }
            LogicalOperation::SecondaryUpdate { key, payer, value } => {
                self.apply_secondary_update(*key, *payer, *value)
            }
            LogicalOperation::SecondaryRemove { key, index } => {
                self.apply_secondary_remove(*key, *index)
            }
        }
    }

    fn apply_secondary_create(
        &self,
        key: ContractPrimaryKey,
        payer: u64,
        value: ContractSecondaryValue,
    ) -> Result<(), ChainError> {
        match value {
            ContractSecondaryValue::Idx64(value) => {
                self.canonical.create_index64_object_standalone(
                    key.code,
                    key.scope,
                    key.table,
                    payer,
                    key.primary,
                    value,
                )
            }
            ContractSecondaryValue::Idx128(value) => {
                self.canonical.create_index128_object_standalone(
                    key.code,
                    key.scope,
                    key.table,
                    payer,
                    key.primary,
                    value,
                )
            }
            ContractSecondaryValue::Idx256(value) => {
                self.canonical.create_index256_object_standalone(
                    key.code,
                    key.scope,
                    key.table,
                    payer,
                    key.primary,
                    U256 { value },
                )
            }
            ContractSecondaryValue::IdxDouble(value) => {
                self.canonical.create_idx_double_object_standalone(
                    key.code,
                    key.scope,
                    key.table,
                    payer,
                    key.primary,
                    value,
                )
            }
            ContractSecondaryValue::IdxLongDouble((lo, hi)) => {
                self.canonical.create_idx_long_double_object_standalone(
                    key.code,
                    key.scope,
                    key.table,
                    payer,
                    key.primary,
                    Float128 { lo, hi },
                )
            }
        }
    }

    fn apply_secondary_update(
        &self,
        key: ContractPrimaryKey,
        payer: u64,
        value: ContractSecondaryValue,
    ) -> Result<(), ChainError> {
        match value {
            ContractSecondaryValue::Idx64(value) => {
                self.canonical.update_index64_object_standalone(
                    key.code,
                    key.scope,
                    key.table,
                    key.primary,
                    payer,
                    value,
                )
            }
            ContractSecondaryValue::Idx128(value) => {
                self.canonical.update_index128_object_standalone(
                    key.code,
                    key.scope,
                    key.table,
                    key.primary,
                    payer,
                    value,
                )
            }
            ContractSecondaryValue::Idx256(value) => {
                self.canonical.update_index256_object_standalone(
                    key.code,
                    key.scope,
                    key.table,
                    key.primary,
                    payer,
                    U256 { value },
                )
            }
            ContractSecondaryValue::IdxDouble(value) => {
                self.canonical.update_idx_double_object_standalone(
                    key.code,
                    key.scope,
                    key.table,
                    key.primary,
                    payer,
                    value,
                )
            }
            ContractSecondaryValue::IdxLongDouble((lo, hi)) => {
                self.canonical.update_idx_long_double_object_standalone(
                    key.code,
                    key.scope,
                    key.table,
                    key.primary,
                    payer,
                    Float128 { lo, hi },
                )
            }
        }
    }

    fn apply_secondary_remove(
        &self,
        key: ContractPrimaryKey,
        index: ContractIndex,
    ) -> Result<(), ChainError> {
        match index {
            ContractIndex::Idx64 => self.canonical.remove_index64_object_standalone(
                key.code,
                key.scope,
                key.table,
                key.primary,
            ),
            ContractIndex::Idx128 => self.canonical.remove_index128_object_standalone(
                key.code,
                key.scope,
                key.table,
                key.primary,
            ),
            ContractIndex::Idx256 => self.canonical.remove_index256_object_standalone(
                key.code,
                key.scope,
                key.table,
                key.primary,
            ),
            ContractIndex::IdxDouble => self.canonical.remove_idx_double_object_standalone(
                key.code,
                key.scope,
                key.table,
                key.primary,
            ),
            ContractIndex::IdxLongDouble => {
                self.canonical.remove_idx_long_double_object_standalone(
                    key.code,
                    key.scope,
                    key.table,
                    key.primary,
                )
            }
            ContractIndex::Table | ContractIndex::Primary => Err(ChainError::DatabaseError(
                format!("{index:?} is not a secondary index"),
            )),
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
    use std::sync::{
        Arc,
        Barrier,
        Mutex,
        atomic::{
            AtomicUsize,
            Ordering as AtomicOrdering,
        },
    };

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
    fn secondary_overlay_applies_every_index_family_with_serial_parity() {
        let keys = [
            ContractPrimaryKey::new(1, 2, 30, 1),
            ContractPrimaryKey::new(1, 2, 30, 2),
            ContractPrimaryKey::new(1, 2, 30, 3),
            ContractPrimaryKey::new(1, 2, 30, 4),
            ContractPrimaryKey::new(1, 2, 30, 5),
        ];
        let values = [
            ContractSecondaryValue::Idx64(10),
            ContractSecondaryValue::Idx128(20),
            ContractSecondaryValue::Idx256([30; 32]),
            ContractSecondaryValue::IdxDouble(40),
            ContractSecondaryValue::IdxLongDouble((50, 51)),
        ];
        let mut speculative = Database::default();
        let serial = Database::default();

        let mut wave = speculative.begin_speculative_wave().unwrap();
        let mut overlay = wave.snapshot().transaction();
        for (offset, (key, value)) in keys.iter().zip(values).enumerate() {
            let payer = 100 + offset as u64;
            overlay.secondary_create(*key, payer, value).unwrap();
            assert_eq!(
                overlay.secondary_get(*key, value.index()).unwrap(),
                Some(ContractSecondaryRow { payer, value })
            );
        }
        assert_eq!(
            wave.try_apply(overlay.finish()),
            SpeculativeCommitOutcome::Applied
        );
        drop(wave);

        serial.arena_start_undo_session();
        serial
            .create_index64_object_standalone(1, 2, 30, 100, 1, 10)
            .unwrap();
        serial
            .create_index128_object_standalone(1, 2, 30, 101, 2, 20)
            .unwrap();
        serial
            .create_index256_object_standalone(1, 2, 30, 102, 3, U256 { value: [30; 32] })
            .unwrap();
        serial
            .create_idx_double_object_standalone(1, 2, 30, 103, 4, 40)
            .unwrap();
        serial
            .create_idx_long_double_object_standalone(1, 2, 30, 104, 5, Float128 { lo: 50, hi: 51 })
            .unwrap();
        serial.arena_squash();

        assert_eq!(speculative.arena_state_root(), serial.arena_state_root());

        let mut wave = speculative.begin_speculative_wave().unwrap();
        let mut overlay = wave.snapshot().transaction();
        overlay
            .secondary_update(keys[0], 200, ContractSecondaryValue::Idx64(11))
            .unwrap();
        overlay
            .secondary_remove(keys[1], ContractIndex::Idx128)
            .unwrap();
        assert_eq!(
            wave.try_apply(overlay.finish()),
            SpeculativeCommitOutcome::Applied
        );
        drop(wave);

        serial.arena_start_undo_session();
        serial
            .update_index64_object_standalone(1, 2, 30, 1, 200, 11)
            .unwrap();
        serial
            .remove_index128_object_standalone(1, 2, 30, 2)
            .unwrap();
        serial.arena_squash();
        assert_eq!(speculative.arena_state_root(), serial.arena_state_root());
    }

    #[test]
    fn secondary_range_read_rejects_a_rekey_phantom() {
        let key = ContractPrimaryKey::new(1, 2, 30, 1);
        let mut db = Database::default();
        db.create_index64_object_standalone(1, 2, 30, 1, 1, 10)
            .unwrap();
        let mut wave = db.begin_speculative_wave().unwrap();

        let mut rekey = wave.snapshot().transaction();
        rekey
            .secondary_update(key, 1, ContractSecondaryValue::Idx64(20))
            .unwrap();
        let mut iterator = wave.snapshot().transaction();
        iterator.record_index_range_read(1, 2, 30, ContractIndex::Idx64);

        assert_eq!(
            wave.try_apply(rekey.finish()),
            SpeculativeCommitOutcome::Applied
        );
        assert_eq!(
            wave.try_apply(iterator.finish()),
            SpeculativeCommitOutcome::RetrySerial(SpeculativeFallbackReason::DependencyConflict)
        );
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
        let competing = [IncrementTask { key }];
        let error = rogue
            .execute_speculative_batch(&competing, NonZeroUsize::new(1).unwrap())
            .expect_err("an active low-level wave must exclude a competing batch");
        assert!(error.to_string().contains("coordinator"));
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

    #[derive(Clone, Copy)]
    struct IncrementTask {
        key: ContractPrimaryKey,
    }

    impl SpeculativeTask for IncrementTask {
        type Output = u64;

        fn speculate(
            &self,
            snapshot: BlockReadSnapshot,
        ) -> Result<SpeculativeCandidate<Self::Output>, ChainError> {
            let mut overlay = snapshot.transaction();
            let current = decode_counter(overlay.get(self.key).map_err(|reason| {
                ChainError::DatabaseError(format!("speculative counter read failed: {reason:?}"))
            })?)?;
            let next = current.saturating_add(1);
            overlay.update(self.key, 1, next.to_le_bytes().to_vec())?;
            Ok(SpeculativeCandidate::new(overlay.finish(), next))
        }

        fn execute_serial(&self, database: &mut Database) -> Result<Self::Output, ChainError> {
            let current = decode_counter(database.arena_kv_get(
                self.key.code,
                self.key.scope,
                self.key.table,
                self.key.primary,
            ))?;
            let next = current.saturating_add(1);
            database.update_key_value_object_standalone(
                self.key.code,
                self.key.scope,
                self.key.table,
                self.key.primary,
                1,
                &next.to_le_bytes(),
            )?;
            Ok(next)
        }
    }

    fn decode_counter(value: Option<Vec<u8>>) -> Result<u64, ChainError> {
        let value =
            value.ok_or_else(|| ChainError::DatabaseError("counter row does not exist".into()))?;
        let bytes: [u8; 8] = value
            .try_into()
            .map_err(|_| ChainError::DatabaseError("counter row is not a u64".into()))?;
        Ok(u64::from_le_bytes(bytes))
    }

    struct BarrierCreateTask {
        key: ContractPrimaryKey,
        barrier: Arc<Barrier>,
        attempts: Arc<AtomicUsize>,
    }

    impl SpeculativeTask for BarrierCreateTask {
        type Output = u64;

        fn speculate(
            &self,
            snapshot: BlockReadSnapshot,
        ) -> Result<SpeculativeCandidate<Self::Output>, ChainError> {
            self.attempts.fetch_add(1, AtomicOrdering::Relaxed);
            self.barrier.wait();
            let mut overlay = snapshot.transaction();
            overlay.create(self.key, 1, self.key.primary.to_le_bytes().to_vec())?;
            Ok(SpeculativeCandidate::new(
                overlay.finish(),
                self.key.primary,
            ))
        }

        fn execute_serial(&self, database: &mut Database) -> Result<Self::Output, ChainError> {
            database.create_key_value_object_standalone(
                self.key.code,
                self.key.scope,
                self.key.table,
                1,
                self.key.primary,
                &self.key.primary.to_le_bytes(),
            )?;
            Ok(self.key.primary)
        }
    }

    #[test]
    fn batch_runs_independent_tasks_concurrently_and_applies_in_order() {
        const TASKS: usize = 4;
        let barrier = Arc::new(Barrier::new(TASKS));
        let attempts = Arc::new(AtomicUsize::new(0));
        let tasks = (0..TASKS)
            .map(|index| BarrierCreateTask {
                // Separate tables avoid the conservative table-metadata
                // dependency emitted by primary-row creation.
                key: ContractPrimaryKey::new(1, 2, 100 + index as u64, index as u64),
                barrier: Arc::clone(&barrier),
                attempts: Arc::clone(&attempts),
            })
            .collect::<Vec<_>>();
        let mut db = Database::default();

        let result = db
            .execute_speculative_batch(&tasks, NonZeroUsize::new(TASKS).unwrap())
            .unwrap();

        assert_eq!(attempts.load(AtomicOrdering::Relaxed), TASKS);
        assert_eq!(result.outputs(), &[0, 1, 2, 3]);
        assert!(
            result
                .outcomes()
                .iter()
                .all(|outcome| outcome == &SpeculativeTaskOutcome::Applied)
        );
        assert_eq!(result.waves(), 1);
        for task in tasks {
            assert_eq!(
                db.arena_kv_get(
                    task.key.code,
                    task.key.scope,
                    task.key.table,
                    task.key.primary,
                ),
                Some(task.key.primary.to_le_bytes().to_vec())
            );
        }
    }

    #[test]
    fn conflict_falls_back_serially_then_restarts_the_remaining_suffix() {
        let contested = ContractPrimaryKey::new(1, 2, 3, 4);
        let independent = ContractPrimaryKey::new(1, 2, 5, 6);
        let mut db = seeded(&[
            (contested, &0u64.to_le_bytes()),
            (independent, &40u64.to_le_bytes()),
        ]);
        let tasks = [
            IncrementTask { key: contested },
            IncrementTask { key: contested },
            IncrementTask { key: independent },
        ];

        let result = db
            .execute_speculative_batch(&tasks, NonZeroUsize::new(3).unwrap())
            .unwrap();

        assert_eq!(result.outputs(), &[1, 2, 41]);
        assert_eq!(
            result.outcomes(),
            &[
                SpeculativeTaskOutcome::Applied,
                SpeculativeTaskOutcome::RetriedSerial(
                    SpeculativeFallbackReason::DependencyConflict,
                ),
                SpeculativeTaskOutcome::Applied,
            ]
        );
        assert_eq!(result.waves(), 2);
        assert_eq!(
            db.arena_kv_get(1, 2, 3, 4),
            Some(2u64.to_le_bytes().to_vec())
        );
        assert_eq!(
            db.arena_kv_get(1, 2, 5, 6),
            Some(41u64.to_le_bytes().to_vec())
        );
    }

    #[test]
    fn conflict_storm_uses_the_bounded_serial_escape_hatch() {
        let key = ContractPrimaryKey::new(1, 2, 3, 4);
        let mut db = seeded(&[(key, &0u64.to_le_bytes())]);
        let tasks = [IncrementTask { key }; 12];

        let result = db
            .execute_speculative_batch(&tasks, NonZeroUsize::new(4).unwrap())
            .unwrap();

        assert_eq!(result.outputs(), &(1u64..=12).collect::<Vec<_>>());
        assert_eq!(result.waves(), MAX_SPECULATIVE_RESTARTS);
        assert_eq!(
            result.outcomes().last(),
            Some(&SpeculativeTaskOutcome::RetriedSerial(
                SpeculativeFallbackReason::SerialEscapeHatch,
            ))
        );
        assert_eq!(
            db.arena_kv_get(key.code, key.scope, key.table, key.primary),
            Some(12u64.to_le_bytes().to_vec())
        );
    }

    #[derive(Clone, Copy)]
    enum FailingWorkerTask {
        Error(ContractPrimaryKey),
        Panic(ContractPrimaryKey),
        Fatal,
    }

    impl SpeculativeTask for FailingWorkerTask {
        type Output = u64;

        fn speculate(
            &self,
            _snapshot: BlockReadSnapshot,
        ) -> Result<SpeculativeCandidate<Self::Output>, ChainError> {
            match self {
                Self::Error(_) => Err(ChainError::DatabaseError("worker failed".into())),
                Self::Panic(_) => panic!("worker panicked"),
                Self::Fatal => Err(ChainError::DatabaseError("fatal worker failure".into())),
            }
        }

        fn execute_serial(&self, database: &mut Database) -> Result<Self::Output, ChainError> {
            let key = match self {
                Self::Error(key) | Self::Panic(key) => *key,
                Self::Fatal => {
                    return Err(ChainError::DatabaseError("fatal serial failure".into()));
                }
            };
            database.create_key_value_object_standalone(
                key.code,
                key.scope,
                key.table,
                1,
                key.primary,
                &key.primary.to_le_bytes(),
            )?;
            Ok(key.primary)
        }
    }

    #[test]
    fn worker_errors_and_panics_are_contained_by_serial_fallback() {
        let tasks = [
            FailingWorkerTask::Error(ContractPrimaryKey::new(1, 2, 3, 10)),
            FailingWorkerTask::Panic(ContractPrimaryKey::new(1, 2, 4, 20)),
        ];
        let mut db = Database::default();

        let result = db
            .execute_speculative_batch(&tasks, NonZeroUsize::new(2).unwrap())
            .unwrap();

        assert_eq!(result.outputs(), &[10, 20]);
        assert!(matches!(
            &result.outcomes()[0],
            SpeculativeTaskOutcome::RetriedSerial(
                SpeculativeFallbackReason::SpeculativeExecutionFailed(message)
            ) if message.contains("worker failed")
        ));
        assert_eq!(
            result.outcomes()[1],
            SpeculativeTaskOutcome::RetriedSerial(SpeculativeFallbackReason::WorkerPanicked)
        );
        assert_eq!(result.waves(), 2);
        assert_eq!(
            db.arena_kv_get(1, 2, 3, 10),
            Some(10u64.to_le_bytes().to_vec())
        );
        assert_eq!(
            db.arena_kv_get(1, 2, 4, 20),
            Some(20u64.to_le_bytes().to_vec())
        );
    }

    #[test]
    fn serial_fallback_error_rolls_back_the_entire_batch() {
        let key = ContractPrimaryKey::new(1, 2, 3, 4);
        let mut db = seeded(&[(key, &0u64.to_le_bytes())]);
        let root_before = db.arena_state_root();
        let tasks = [
            FailingWorkerTask::Error(ContractPrimaryKey::new(1, 2, 10, 20)),
            FailingWorkerTask::Fatal,
        ];

        let error = db
            .execute_speculative_batch(&tasks, NonZeroUsize::new(2).unwrap())
            .expect_err("fatal serial fallback must fail the batch");

        assert!(error.to_string().contains("fatal serial failure"));
        assert_eq!(db.arena_state_root(), root_before);
        assert_eq!(db.arena_kv_get(1, 2, 10, 20), None);
        db.update_key_value_object_standalone(1, 2, 3, 4, 1, &1u64.to_le_bytes())
            .unwrap();
    }

    struct RogueMutationTask {
        alias: Mutex<Database>,
        serial_calls: Arc<AtomicUsize>,
    }

    impl SpeculativeTask for RogueMutationTask {
        type Output = ();

        fn speculate(
            &self,
            snapshot: BlockReadSnapshot,
        ) -> Result<SpeculativeCandidate<Self::Output>, ChainError> {
            self.alias
                .lock()
                .map_err(|_| ChainError::DatabaseError("rogue alias lock poisoned".into()))?
                .create_account(99, 7)?;
            Ok(SpeculativeCandidate::new(
                snapshot.transaction().finish(),
                (),
            ))
        }

        fn execute_serial(&self, _database: &mut Database) -> Result<Self::Output, ChainError> {
            self.serial_calls.fetch_add(1, AtomicOrdering::Relaxed);
            Ok(())
        }
    }

    #[test]
    fn aliased_canonical_mutation_aborts_and_rolls_back_the_batch() {
        let mut db = Database::default();
        let root_before = db.arena_state_root();
        let serial_calls = Arc::new(AtomicUsize::new(0));
        let tasks = [RogueMutationTask {
            alias: Mutex::new(db.clone()),
            serial_calls: Arc::clone(&serial_calls),
        }];

        let error = db
            .execute_speculative_batch(&tasks, NonZeroUsize::new(1).unwrap())
            .expect_err("canonical alias mutation must abort speculation");

        assert!(error.to_string().contains("canonical state mutated"));
        assert_eq!(db.arena_state_root(), root_before);
        assert_eq!(db.arena_account_creation_date(99), None);
        assert_eq!(serial_calls.load(AtomicOrdering::Relaxed), 0);
    }

    #[test]
    fn randomized_batch_matches_the_serial_reference_state_and_outputs() {
        const KEYS: usize = 12;
        const TASKS: usize = 48;
        let keys = (0..KEYS)
            .map(|index| ContractPrimaryKey::new(7, 8, 9, index as u64))
            .collect::<Vec<_>>();
        let rows = keys
            .iter()
            .map(|key| (*key, 0u64.to_le_bytes()))
            .collect::<Vec<_>>();
        let row_refs = rows
            .iter()
            .map(|(key, value)| (*key, value.as_slice()))
            .collect::<Vec<_>>();
        let mut parallel = seeded(&row_refs);
        let mut serial = seeded(&row_refs);
        let mut seed = 0x6a09_e667_f3bc_c909u64;
        let tasks = (0..TASKS)
            .map(|_| {
                // Fixed arithmetic PRNG keeps this regression deterministic and
                // deliberately creates many read/write conflicts.
                seed = seed
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                IncrementTask {
                    key: keys[(seed as usize) % KEYS],
                }
            })
            .collect::<Vec<_>>();

        let parallel_result = parallel
            .execute_speculative_batch(&tasks, NonZeroUsize::new(4).unwrap())
            .unwrap();
        serial.arena_start_undo_session();
        let serial_outputs = tasks
            .iter()
            .map(|task| execute_serial_task(&mut serial, task).unwrap())
            .collect::<Vec<_>>();
        serial.arena_squash();

        assert_eq!(parallel_result.outputs(), serial_outputs);
        assert_eq!(parallel.arena_state_root(), serial.arena_state_root());
        assert_eq!(parallel_result.outcomes().len(), TASKS);
        assert!(parallel_result.waves() > 1);
    }

    #[test]
    fn shadow_batch_commits_serial_state_and_reports_matching_parity() {
        let first = ContractPrimaryKey::new(1, 2, 3, 4);
        let second = ContractPrimaryKey::new(1, 2, 3, 5);
        let mut db = seeded(&[(first, &0u64.to_le_bytes()), (second, &10u64.to_le_bytes())]);
        let tasks = [
            IncrementTask { key: first },
            IncrementTask { key: first },
            IncrementTask { key: second },
        ];

        let result = db
            .execute_speculative_shadow_batch(&tasks, NonZeroUsize::new(3).unwrap())
            .unwrap();

        assert_eq!(result.outputs(), &[1, 2, 11]);
        assert_eq!(result.speculative_outputs(), &[1, 2, 11]);
        assert!(result.outputs_match());
        assert!(result.state_root_matches());
        assert_eq!(result.speculative_state_root(), result.serial_state_root());
        assert!(result.parity_matches());
        assert_eq!(
            db.arena_kv_get(1, 2, 3, 4),
            Some(2u64.to_le_bytes().to_vec())
        );
        assert_eq!(
            db.arena_kv_get(1, 2, 3, 5),
            Some(11u64.to_le_bytes().to_vec())
        );
    }

    struct DivergentShadowTask {
        key: ContractPrimaryKey,
    }

    impl SpeculativeTask for DivergentShadowTask {
        type Output = u64;

        fn speculate(
            &self,
            snapshot: BlockReadSnapshot,
        ) -> Result<SpeculativeCandidate<Self::Output>, ChainError> {
            let mut overlay = snapshot.transaction();
            overlay.create(self.key, 1, b"speculative".to_vec())?;
            Ok(SpeculativeCandidate::new(overlay.finish(), 1))
        }

        fn execute_serial(&self, database: &mut Database) -> Result<Self::Output, ChainError> {
            database.create_key_value_object_standalone(
                self.key.code,
                self.key.scope,
                self.key.table,
                1,
                self.key.primary,
                b"serial-value",
            )?;
            Ok(2)
        }
    }

    #[test]
    fn shadow_parity_mismatch_never_overrides_the_serial_result() {
        let key = ContractPrimaryKey::new(1, 2, 3, 4);
        let mut db = Database::default();
        let tasks = [DivergentShadowTask { key }];

        let result = db
            .execute_speculative_shadow_batch(&tasks, NonZeroUsize::new(1).unwrap())
            .unwrap();

        assert_eq!(result.outputs(), &[2]);
        assert_eq!(result.speculative_outputs(), &[1]);
        assert!(!result.outputs_match());
        assert!(!result.state_root_matches());
        assert_ne!(result.speculative_state_root(), result.serial_state_root());
        assert!(!result.parity_matches());
        assert_eq!(db.arena_kv_get(1, 2, 3, 4), Some(b"serial-value".to_vec()));
    }

    #[test]
    fn empty_batch_does_not_install_a_speculation_epoch() {
        let mut db = Database::default();
        let tasks: [IncrementTask; 0] = [];

        let result = db
            .execute_speculative_batch(&tasks, NonZeroUsize::new(1).unwrap())
            .unwrap();

        assert!(result.outputs().is_empty());
        assert!(result.outcomes().is_empty());
        assert_eq!(result.waves(), 0);
        assert!(db.speculation_epoch.get().is_none());
    }
}
