//! Feature-gated execution + FFI/state + block-finalization profiler.
//!
//! One thread-local registry attributes time and call counts across three groups:
//!
//! * **Execution** stages of a single transaction (decode, signature recovery,
//!   authority check, WASM setup/instantiate/exec, finalize) — recorded by
//!   `pulsevm_core`.
//! * **FFI / state** operations at the database boundary (each takes the
//!   `RwLock` and crosses into C++ chainbase) — recorded here in `database.rs`.
//! * **Block finalization** (merkle roots, block serialization, state-history
//!   store, chainbase commit) — recorded by `pulsevm_core` around a block.
//!
//! Everything is behind the `profiling` feature. With it off, `Timer::new`,
//! `count`, `reset` and `snapshot` are empty inlines, so the consensus path
//! carries zero overhead.

pub use imp::{Group, Metric, MetricStat, Timer, count, reset, snapshot};

/// Every metric, in report order (Execution, then FFI/state, then Block). Kept
/// in sync with the `Metric` enum's discriminants.
pub const METRICS: [Metric; 23] = [
    Metric::TxDecode,
    Metric::SigRecovery,
    Metric::Authorization,
    Metric::TxInit,
    Metric::WasmSetup,
    Metric::WasmInstantiate,
    Metric::WasmExec,
    Metric::Finalize,
    Metric::DbFind,
    Metric::DbGet,
    Metric::DbIterate,
    Metric::DbInsert,
    Metric::DbModify,
    Metric::DbRemove,
    Metric::DbAccessor,
    Metric::DbSession,
    Metric::DbCommit,
    Metric::DbResource,
    Metric::DbGlobal,
    Metric::BlockMerkle,
    Metric::BlockPack,
    Metric::BlockStore,
    Metric::BlockCommit,
];

pub fn group(metric: Metric) -> Group {
    match metric {
        Metric::TxDecode
        | Metric::SigRecovery
        | Metric::Authorization
        | Metric::TxInit
        | Metric::WasmSetup
        | Metric::WasmInstantiate
        | Metric::WasmExec
        | Metric::Finalize => Group::Execution,
        Metric::BlockMerkle | Metric::BlockPack | Metric::BlockStore | Metric::BlockCommit => {
            Group::Block
        }
        _ => Group::FfiState,
    }
}

pub fn metric_name(metric: Metric) -> &'static str {
    match metric {
        Metric::TxDecode => "tx decode + context setup",
        Metric::SigRecovery => "signature recovery",
        Metric::Authorization => "authority check",
        Metric::TxInit => "tx init (net/cpu)",
        Metric::WasmSetup => "wasm setup (compile/store/imports)",
        Metric::WasmInstantiate => "wasm instantiate (Instance::new)",
        Metric::WasmExec => "wasm exec (+ host calls)",
        Metric::Finalize => "finalize / billing",
        Metric::DbFind => "db find (by key)",
        Metric::DbGet => "db get (row read)",
        Metric::DbIterate => "db iterate (next/bound/end)",
        Metric::DbInsert => "db insert",
        Metric::DbModify => "db modify",
        Metric::DbRemove => "db remove",
        Metric::DbAccessor => "object field accessor",
        Metric::DbSession => "undo session (create/squash/undo)",
        Metric::DbCommit => "db commit",
        Metric::DbResource => "resource limits/usage",
        Metric::DbGlobal => "global properties",
        Metric::BlockMerkle => "merkle roots",
        Metric::BlockPack => "block serialize (pack)",
        Metric::BlockStore => "state-history store",
        Metric::BlockCommit => "chainbase commit",
    }
}

#[cfg(feature = "profiling")]
mod imp {
    use std::cell::RefCell;
    use std::time::{Duration, Instant};

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum Group {
        Execution,
        FfiState,
        Block,
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    #[repr(usize)]
    pub enum Metric {
        TxDecode = 0,
        SigRecovery,
        Authorization,
        TxInit,
        WasmSetup,
        WasmInstantiate,
        WasmExec,
        Finalize,
        DbFind,
        DbGet,
        DbIterate,
        DbInsert,
        DbModify,
        DbRemove,
        DbAccessor,
        DbSession,
        DbCommit,
        DbResource,
        DbGlobal,
        BlockMerkle,
        BlockPack,
        BlockStore,
        BlockCommit,
    }

    const N: usize = 23;

    #[derive(Clone, Copy, Default, Debug)]
    pub struct MetricStat {
        pub total: Duration,
        pub calls: u64,
    }

    thread_local! {
        static REG: RefCell<[MetricStat; N]> = const { RefCell::new([MetricStat { total: Duration::ZERO, calls: 0 }; N]) };
    }

    pub fn reset() {
        REG.with(|r| *r.borrow_mut() = [MetricStat { total: Duration::ZERO, calls: 0 }; N]);
    }

    pub fn snapshot() -> Vec<(Metric, MetricStat)> {
        REG.with(|r| {
            let r = r.borrow();
            super::METRICS.iter().map(|&m| (m, r[m as usize])).collect()
        })
    }

    /// Increment the call count for `metric` without timing it — for the very
    /// cheap, very frequent operations (object field accessors) where an
    /// `Instant::now()` pair would dominate what it measures.
    #[inline]
    pub fn count(metric: Metric) {
        REG.with(|r| r.borrow_mut()[metric as usize].calls += 1);
    }

    /// RAII timer: adds elapsed time and one call to `metric` on drop.
    pub struct Timer {
        metric: Metric,
        start: Instant,
    }

    impl Timer {
        #[inline]
        pub fn new(metric: Metric) -> Self {
            Timer { metric, start: Instant::now() }
        }
    }

    impl Drop for Timer {
        fn drop(&mut self) {
            let elapsed = self.start.elapsed();
            REG.with(|r| {
                let mut r = r.borrow_mut();
                let s = &mut r[self.metric as usize];
                s.total += elapsed;
                s.calls += 1;
            });
        }
    }
}

#[cfg(not(feature = "profiling"))]
mod imp {
    use std::time::Duration;

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum Group {
        Execution,
        FfiState,
        Block,
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum Metric {
        TxDecode,
        SigRecovery,
        Authorization,
        TxInit,
        WasmSetup,
        WasmInstantiate,
        WasmExec,
        Finalize,
        DbFind,
        DbGet,
        DbIterate,
        DbInsert,
        DbModify,
        DbRemove,
        DbAccessor,
        DbSession,
        DbCommit,
        DbResource,
        DbGlobal,
        BlockMerkle,
        BlockPack,
        BlockStore,
        BlockCommit,
    }

    #[derive(Clone, Copy, Default, Debug)]
    pub struct MetricStat {
        pub total: Duration,
        pub calls: u64,
    }

    #[inline(always)]
    pub fn reset() {}

    #[inline(always)]
    pub fn snapshot() -> Vec<(Metric, MetricStat)> {
        Vec::new()
    }

    #[inline(always)]
    pub fn count(_metric: Metric) {}

    pub struct Timer;

    impl Timer {
        #[inline(always)]
        pub fn new(_metric: Metric) -> Self {
            Timer
        }
    }
}
