//! Transaction-local database dependency recording.
//!
//! This is the observation-only first stage of optimistic execution. A
//! recorder is attached to a cloned [`crate::Database`] handle, so all clones
//! made for inline actions and WASM host functions share one transaction-local
//! report while unrelated transactions do not. Recording never participates in
//! a database result and is absent from the default execution path.

use std::{
    collections::BTreeSet,
    sync::{
        Arc,
        Mutex,
    },
};

/// A consensus contract-table index.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ContractIndex {
    /// The table metadata row (`table_id_object`).
    Table,
    Primary,
    Idx64,
    Idx128,
    Idx256,
    IdxDouble,
    IdxLongDouble,
}

/// Stable logical identity of one contract database row.
///
/// Secondary rows are identified by their primary key. Their secondary value
/// can change, but the logical row (and its RAM payer) remains the same.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ContractRowKey {
    pub code: u64,
    pub scope: u64,
    pub table: u64,
    pub index: ContractIndex,
    pub primary: u64,
}

impl ContractRowKey {
    pub(crate) const fn new(
        code: u64,
        scope: u64,
        table: u64,
        index: ContractIndex,
        primary: u64,
    ) -> Self {
        Self {
            code,
            scope,
            table,
            index,
            primary,
        }
    }

    pub(crate) const fn table(code: u64, scope: u64, table: u64) -> Self {
        Self::new(code, scope, table, ContractIndex::Table, 0)
    }
}

/// A conservative dependency on ordering or absence within one whole index.
///
/// Lower/upper-bound and iterator steps can change when any row is inserted,
/// removed, or re-keyed in the index. Whole-index dependencies intentionally
/// over-report conflicts until interval phantom tracking is proven correct.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ContractRangeKey {
    pub code: u64,
    pub scope: u64,
    pub table: u64,
    pub index: ContractIndex,
}

impl ContractRangeKey {
    pub(crate) const fn new(code: u64, scope: u64, table: u64, index: ContractIndex) -> Self {
        Self {
            code,
            scope,
            table,
            index,
        }
    }
}

/// Stable logical identity of consensus-visible non-contract state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SystemKey {
    Account(u64),
    AccountMetadata(u64),
    Permission {
        owner: u64,
        name: u64,
    },
    PermissionUsage {
        owner: u64,
        name: u64,
    },
    PermissionLink {
        account: u64,
        code: u64,
        message_type: u64,
    },
    /// Code rows are conservatively coarsened by hash because unlink resolves
    /// its refcount target by hash before VM metadata.
    Code([u8; 32]),
    PermissionSequence,
    GlobalActionSequence,
    ChainConfig,
    ProposedSchedule,
    ProtocolFeature([u8; 32]),
    PreactivatedProtocolFeatures,
    ResourceUsage(u64),
    /// Effective limits coarsen the pending and committed rows into one key.
    ResourceLimits(u64),
    ResourceState,
    ResourceConfig,
    Transaction([u8; 32]),
    DeferredTransaction([u8; 32]),
    DeferredSender {
        sender: u64,
        sender_id: u128,
    },
}

/// Conservative non-contract scan dependency.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SystemRangeKey {
    PermissionsByOwner(u64),
    DeferredDueQueue,
}

/// One exact consensus-state dependency across contract and system tables.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DependencyKey {
    Contract(ContractRowKey),
    System(SystemKey),
}

/// One conservative range/phantom dependency.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RangeDependency {
    Contract(ContractRangeKey),
    System(SystemRangeKey),
}

/// Dependencies observed while executing one serial transaction.
///
/// Serial telemetry leaves `complete` false. The closed, typed speculative
/// overlay marks it true only when execution used exclusively supported logical
/// operations; any unsupported path keeps the report incomplete. An optimistic
/// commit implementation must reject incomplete reports.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TransactionDependencies {
    exact_reads: BTreeSet<DependencyKey>,
    range_reads: BTreeSet<RangeDependency>,
    writes: BTreeSet<DependencyKey>,
    complete: bool,
}

impl TransactionDependencies {
    pub fn exact_reads(&self) -> &BTreeSet<DependencyKey> {
        &self.exact_reads
    }

    pub fn range_reads(&self) -> &BTreeSet<RangeDependency> {
        &self.range_reads
    }

    pub fn writes(&self) -> &BTreeSet<DependencyKey> {
        &self.writes
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn exact_read_count(&self) -> usize {
        self.exact_reads.len()
    }

    pub fn range_read_count(&self) -> usize {
        self.range_reads.len()
    }

    pub fn write_count(&self) -> usize {
        self.writes.len()
    }

    /// Whether earlier serial-order writes invalidate this observation.
    ///
    /// Writes are implicit reads: an update/remove must conflict if an earlier
    /// transaction changed the same logical row. A range read conflicts with
    /// any earlier write to that index, providing conservative phantom safety.
    /// Incomplete reports must still be rejected by the caller independently.
    pub fn conflicts_with_prior_writes(&self, prior_writes: &BTreeSet<DependencyKey>) -> bool {
        prior_writes.iter().any(|write| {
            self.exact_reads.contains(write)
                || self.writes.contains(write)
                || match write {
                    DependencyKey::Contract(write) => self.range_reads.contains(
                        &RangeDependency::Contract(ContractRangeKey::new(
                            write.code,
                            write.scope,
                            write.table,
                            write.index,
                        )),
                    ),
                    DependencyKey::System(SystemKey::Permission { owner, .. }) => {
                        self.range_reads.contains(&RangeDependency::System(
                            SystemRangeKey::PermissionsByOwner(*owner),
                        ))
                    }
                    DependencyKey::System(SystemKey::DeferredTransaction(_))
                    | DependencyKey::System(SystemKey::DeferredSender { .. }) => self
                        .range_reads
                        .contains(&RangeDependency::System(SystemRangeKey::DeferredDueQueue)),
                    DependencyKey::System(_) => false,
                }
        })
    }

    /// Safe ordered-commit gate for a future optimistic executor.
    ///
    /// Keeping the completeness check next to conflict validation prevents a
    /// partially instrumented report from being accidentally treated as valid.
    pub fn can_optimistically_commit_after(&self, prior_writes: &BTreeSet<DependencyKey>) -> bool {
        self.complete && !self.conflicts_with_prior_writes(prior_writes)
    }

    /// Whether two transactions that execute from the same block-prefix
    /// snapshot have a consensus-state dependency. Receipt/resource counters
    /// are deliberately excluded: an optimistic executor must allocate and
    /// apply those in canonical order after action execution. Contract rows,
    /// deferred queues, authorities, code, schedules, and protocol state remain
    /// conflict-bearing.
    pub fn conflicts_for_parallel_execution(&self, other: &Self) -> bool {
        self.execution_writes()
            .any(|write| dependencies_observe_write(other, write))
            || other
                .execution_writes()
                .any(|write| dependencies_observe_write(self, write))
    }

    fn execution_writes(&self) -> impl Iterator<Item = DependencyKey> + '_ {
        self.writes
            .iter()
            .copied()
            .filter(|key| !is_ordered_commit_bookkeeping(*key))
    }
}

fn is_ordered_commit_bookkeeping(key: DependencyKey) -> bool {
    matches!(
        key,
        DependencyKey::System(
            SystemKey::AccountMetadata(_)
                | SystemKey::GlobalActionSequence
                | SystemKey::PermissionUsage { .. }
                | SystemKey::ResourceUsage(_)
                | SystemKey::ResourceState
                | SystemKey::Transaction(_)
        )
    )
}

fn dependencies_observe_write(
    dependencies: &TransactionDependencies,
    write: DependencyKey,
) -> bool {
    if dependencies.exact_reads.contains(&write) || dependencies.writes.contains(&write) {
        return true;
    }
    match write {
        DependencyKey::Contract(write) => {
            dependencies
                .range_reads
                .contains(&RangeDependency::Contract(ContractRangeKey::new(
                    write.code,
                    write.scope,
                    write.table,
                    write.index,
                )))
        }
        DependencyKey::System(SystemKey::Permission { owner, .. }) => {
            dependencies.range_reads.contains(&RangeDependency::System(
                SystemRangeKey::PermissionsByOwner(owner),
            ))
        }
        DependencyKey::System(SystemKey::DeferredTransaction(_))
        | DependencyKey::System(SystemKey::DeferredSender { .. }) => dependencies
            .range_reads
            .contains(&RangeDependency::System(SystemRangeKey::DeferredDueQueue)),
        DependencyKey::System(_) => false,
    }
}

/// Observation-only estimate of dependency depth within one canonical block.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ParallelWaveEstimate {
    pub transactions: usize,
    pub waves: usize,
    pub max_width: usize,
    pub conflict_pairs: usize,
}

/// Assign every transaction to the earliest dependency-safe wave while
/// preserving canonical order. The resulting depth is an upper-bound input for
/// engineering the executor, not a consensus decision.
pub fn estimate_parallel_waves(reports: &[TransactionDependencies]) -> ParallelWaveEstimate {
    if reports.is_empty() {
        return ParallelWaveEstimate::default();
    }

    let mut levels = Vec::with_capacity(reports.len());
    let mut widths = Vec::<usize>::new();
    let mut conflict_pairs = 0;
    for (index, report) in reports.iter().enumerate() {
        let mut level = 0;
        for (prior_index, prior) in reports[..index].iter().enumerate() {
            if report.conflicts_for_parallel_execution(prior) {
                conflict_pairs += 1;
                level = level.max(levels[prior_index] + 1);
            }
        }
        levels.push(level);
        if widths.len() <= level {
            widths.resize(level + 1, 0);
        }
        widths[level] += 1;
    }

    ParallelWaveEstimate {
        transactions: reports.len(),
        waves: widths.len(),
        max_width: widths.into_iter().max().unwrap_or(0),
        conflict_pairs,
    }
}

#[derive(Clone, Default)]
pub(crate) struct DependencyRecorder {
    inner: Arc<Mutex<TransactionDependencies>>,
}

impl DependencyRecorder {
    pub(crate) fn exact_read(&self, key: DependencyKey) {
        // Telemetry must never affect consensus execution. A poisoned recorder
        // is therefore ignored rather than surfaced through a database API.
        if let Ok(mut report) = self.inner.lock() {
            report.exact_reads.insert(key);
        }
    }

    pub(crate) fn range_read(&self, key: RangeDependency) {
        if let Ok(mut report) = self.inner.lock() {
            report.range_reads.insert(key);
        }
    }

    pub(crate) fn write(&self, key: DependencyKey) {
        if let Ok(mut report) = self.inner.lock() {
            report.writes.insert(key);
        }
    }

    pub(crate) fn mark_complete(&self) {
        if let Ok(mut report) = self.inner.lock() {
            report.complete = true;
        }
    }

    fn snapshot(&self) -> TransactionDependencies {
        self.inner
            .lock()
            .map(|report| report.clone())
            .unwrap_or_default()
    }
}

/// Read handle for a transaction-local dependency report.
///
/// The handle can be sampled after execution even though the `Database` clone
/// carrying the recorder has moved through transaction and action contexts.
#[derive(Clone, Default)]
pub struct DependencyTracker {
    recorder: DependencyRecorder,
}

impl DependencyTracker {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub fn snapshot(&self) -> TransactionDependencies {
        self.recorder.snapshot()
    }

    pub(crate) fn recorder(&self) -> DependencyRecorder {
        self.recorder.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorder_deduplicates_stable_dependencies() {
        let tracker = DependencyTracker::new();
        let row = DependencyKey::Contract(ContractRowKey::new(1, 2, 3, ContractIndex::Primary, 4));
        let range =
            RangeDependency::Contract(ContractRangeKey::new(1, 2, 3, ContractIndex::Primary));

        tracker.recorder.exact_read(row);
        tracker.recorder.exact_read(row);
        tracker.recorder.range_read(range);
        tracker.recorder.range_read(range);
        tracker.recorder.write(row);
        tracker.recorder.write(row);

        let report = tracker.snapshot();
        assert_eq!(report.exact_reads, BTreeSet::from([row]));
        assert_eq!(report.range_reads, BTreeSet::from([range]));
        assert_eq!(report.writes, BTreeSet::from([row]));
        assert!(!report.is_complete());
    }

    #[test]
    fn cloned_trackers_share_only_their_own_report() {
        let first = DependencyTracker::new();
        let first_clone = first.clone();
        let second = DependencyTracker::new();
        let row = DependencyKey::Contract(ContractRowKey::table(7, 8, 9));

        first_clone.recorder.write(row);

        assert_eq!(first.snapshot().writes, BTreeSet::from([row]));
        assert!(second.snapshot().writes.is_empty());
    }

    #[test]
    fn conflict_check_covers_exact_write_and_range_phantoms() {
        let table = (11, 12, 13);
        let row_7 = DependencyKey::Contract(ContractRowKey::new(
            table.0,
            table.1,
            table.2,
            ContractIndex::Idx64,
            7,
        ));
        let row_8 = DependencyKey::Contract(ContractRowKey::new(
            table.0,
            table.1,
            table.2,
            ContractIndex::Idx64,
            8,
        ));
        let unrelated =
            DependencyKey::Contract(ContractRowKey::new(99, 12, 13, ContractIndex::Idx64, 8));

        let exact = TransactionDependencies {
            exact_reads: BTreeSet::from([row_7]),
            ..Default::default()
        };
        assert!(exact.conflicts_with_prior_writes(&BTreeSet::from([row_7])));
        assert!(!exact.conflicts_with_prior_writes(&BTreeSet::from([row_8])));
        assert!(!exact.can_optimistically_commit_after(&BTreeSet::new()));

        let complete_exact = TransactionDependencies {
            complete: true,
            ..exact.clone()
        };
        assert!(complete_exact.can_optimistically_commit_after(&BTreeSet::from([row_8])));
        assert!(!complete_exact.can_optimistically_commit_after(&BTreeSet::from([row_7])));

        let write = TransactionDependencies {
            writes: BTreeSet::from([row_7]),
            ..Default::default()
        };
        assert!(write.conflicts_with_prior_writes(&BTreeSet::from([row_7])));

        let range = TransactionDependencies {
            range_reads: BTreeSet::from([RangeDependency::Contract(ContractRangeKey::new(
                table.0,
                table.1,
                table.2,
                ContractIndex::Idx64,
            ))]),
            ..Default::default()
        };
        assert!(range.conflicts_with_prior_writes(&BTreeSet::from([row_8])));
        assert!(!range.conflicts_with_prior_writes(&BTreeSet::from([unrelated])));

        let permission_range = TransactionDependencies {
            range_reads: BTreeSet::from([RangeDependency::System(
                SystemRangeKey::PermissionsByOwner(42),
            )]),
            ..Default::default()
        };
        let permission_write = DependencyKey::System(SystemKey::Permission { owner: 42, name: 7 });
        assert!(permission_range.conflicts_with_prior_writes(&BTreeSet::from([permission_write,])));

        let due_queue = TransactionDependencies {
            range_reads: BTreeSet::from([RangeDependency::System(
                SystemRangeKey::DeferredDueQueue,
            )]),
            ..Default::default()
        };
        let deferred_write = DependencyKey::System(SystemKey::DeferredSender {
            sender: 17,
            sender_id: 18,
        });
        assert!(due_queue.conflicts_with_prior_writes(&BTreeSet::from([deferred_write])));
        assert!(
            !due_queue.conflicts_with_prior_writes(&BTreeSet::from([DependencyKey::System(
                SystemKey::Account(17)
            ),]))
        );
    }

    #[test]
    fn wave_estimate_serializes_data_conflicts_but_not_commit_counters() {
        let row_a =
            DependencyKey::Contract(ContractRowKey::new(1, 2, 3, ContractIndex::Primary, 10));
        let row_b =
            DependencyKey::Contract(ContractRowKey::new(1, 2, 3, ContractIndex::Primary, 11));
        let bookkeeping = BTreeSet::from([
            DependencyKey::System(SystemKey::GlobalActionSequence),
            DependencyKey::System(SystemKey::AccountMetadata(1)),
            DependencyKey::System(SystemKey::ResourceUsage(7)),
        ]);
        let first = TransactionDependencies {
            writes: BTreeSet::from([row_a])
                .into_iter()
                .chain(bookkeeping.iter().copied())
                .collect(),
            ..Default::default()
        };
        let independent = TransactionDependencies {
            writes: BTreeSet::from([row_b])
                .into_iter()
                .chain(bookkeeping.iter().copied())
                .collect(),
            ..Default::default()
        };
        let dependent = TransactionDependencies {
            exact_reads: BTreeSet::from([row_a]),
            writes: bookkeeping,
            ..Default::default()
        };

        assert!(!first.conflicts_for_parallel_execution(&independent));
        assert!(first.conflicts_for_parallel_execution(&dependent));
        assert_eq!(
            estimate_parallel_waves(&[first, independent, dependent]),
            ParallelWaveEstimate {
                transactions: 3,
                waves: 2,
                max_width: 2,
                conflict_pairs: 1,
            }
        );
    }
}
