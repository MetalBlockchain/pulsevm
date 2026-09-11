mod backend;
mod database;
mod dependency;
mod objects;
mod pod;
mod snapshot;
mod xpr_import;

pub use crate::pod::{
    CpuLimitResult,
    Float128,
    NetLimitResult,
    U256,
};

pub use crate::{
    database::{
        BlockReadSnapshot,
        ContractPrimaryKey,
        ContractPrimaryOverlay,
        Database,
        DbRead,
        PermissionInfo,
        SnapshotVersion,
        SpeculativeCommitOutcome,
        SpeculativeFallbackReason,
        SpeculativeTransaction,
        SpeculativeWave,
        SystemAccountNames,
        restore_snapshot,
    },
    dependency::{
        ContractIndex,
        ContractRangeKey,
        ContractRowKey,
        DependencyKey,
        DependencyTracker,
        ParallelWaveEstimate,
        RangeDependency,
        SystemKey,
        SystemRangeKey,
        TransactionDependencies,
        estimate_parallel_waves,
    },
    objects::{
        Index64Object,
        Index128Object,
        Index256Object,
        IndexDoubleObject,
        IndexLongDoubleObject,
        KeyValueObject,
        PermissionObject,
        SharedAuthority,
        TableObject,
    },
    snapshot::{
        SNAPSHOT_VERSION,
        SnapshotHeader,
        peek_header as peek_snapshot_header,
    },
    xpr_import::{
        DeferredTransactionSidecar,
        DeferredTransactionSidecarRow,
        ImportSummary,
        MigrationManifest,
        StateHistoryEntry,
        StateHistoryWindowSummary,
        TableDelta,
        TableDeltaRow,
        XprImportError,
        apply_state_history_delta,
        apply_state_history_delta_with_sidecar,
        apply_state_history_log_window,
        apply_state_history_log_window_with_sidecars,
        hydrate_full_state,
        hydrate_full_state_with_deferred_transactions,
        inspect_state_history_log,
        parse_initial_state_history_log,
    },
};
pub use pulsevm_chaindb::DeferredTransaction;
// Re-export shared chain value types for the database facade's public API.
pub use pulsevm_chain_types::{
    Authority,
    BlockTimestamp,
    ChainConfigV0,
    ElasticLimitParameters,
    GenesisState,
    KeyWeight,
    Microseconds,
    PermissionLevel,
    PermissionLevelWeight,
    Ratio,
    TimePoint,
    TimePointSec,
    WaitWeight,
    days,
    hours,
    microseconds,
    milliseconds,
    minutes,
    seconds,
};
