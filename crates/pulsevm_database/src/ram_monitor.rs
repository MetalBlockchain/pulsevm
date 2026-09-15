use std::{
    collections::{
        BTreeMap,
        BTreeSet,
        VecDeque,
    },
    sync::{
        Mutex,
        atomic::{
            AtomicBool,
            Ordering,
        },
    },
};

/// Hard ceiling for per-table Prometheus series created by one node.
///
/// Every series has four labels, so an operator typo must not be able to turn
/// contract-created table names into unbounded process memory or scrape output.
pub const MAX_RAM_MONITOR_SERIES: usize = 4_096;

/// One bounded RAM-attribution series.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct RamUsageSeriesKey {
    pub code: u64,
    pub scope: u64,
    pub table: u64,
    pub payer: u64,
}

/// Accepted workload totals for one RAM-attribution series.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RamUsageSeriesSnapshot {
    pub key: RamUsageSeriesKey,
    pub current_bytes: i64,
    pub allocated_bytes_total: u64,
    pub freed_bytes_total: u64,
    pub operations_total: u64,
}

/// Accepted live RAM state and cumulative workload counters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RamUsageMonitorSnapshot {
    pub revision: i64,
    pub max_series: usize,
    pub accepted_blocks_total: u64,
    pub series: Vec<RamUsageSeriesSnapshot>,
    /// Exact aggregate for keys outside the bounded labelled series set.
    pub overflow: RamUsageSeriesSnapshot,
    pub overflow_events_total: u64,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RamUsageEvent {
    pub key: RamUsageSeriesKey,
    pub delta_bytes: i64,
}

#[derive(Debug, Clone, Default)]
struct RamUsageDelta {
    net_bytes: i64,
    allocated_bytes: u64,
    freed_bytes: u64,
    operations: u64,
}

impl RamUsageDelta {
    fn record(&mut self, delta: i64) {
        self.net_bytes = self.net_bytes.saturating_add(delta);
        if delta >= 0 {
            self.allocated_bytes = self.allocated_bytes.saturating_add(delta as u64);
        } else {
            self.freed_bytes = self.freed_bytes.saturating_add(delta.unsigned_abs());
        }
        self.operations = self.operations.saturating_add(1);
    }

    fn merge(&mut self, other: &Self) {
        self.net_bytes = self.net_bytes.saturating_add(other.net_bytes);
        self.allocated_bytes = self.allocated_bytes.saturating_add(other.allocated_bytes);
        self.freed_bytes = self.freed_bytes.saturating_add(other.freed_bytes);
        self.operations = self.operations.saturating_add(other.operations);
    }
}

#[derive(Default)]
struct RamUsageLayer {
    revision: i64,
    series: BTreeMap<RamUsageSeriesKey, RamUsageDelta>,
    new_keys: BTreeSet<RamUsageSeriesKey>,
    overflow: RamUsageDelta,
    overflow_events: u64,
}

#[derive(Default)]
struct RamUsageMonitorState {
    max_series: usize,
    revision: i64,
    accepted_blocks_total: u64,
    series: BTreeMap<RamUsageSeriesKey, RamUsageSeriesSnapshot>,
    reserved_keys: BTreeSet<RamUsageSeriesKey>,
    overflow: RamUsageSeriesSnapshot,
    overflow_events_total: u64,
    layers: VecDeque<RamUsageLayer>,
}

/// Local observability sidecar for logical contract RAM.
///
/// It deliberately lives outside Arena state. Its undo layers mirror Arena's
/// revision stack, so rejected transactions and forks never reach a scrape.
pub(crate) struct RamUsageMonitor {
    enabled: AtomicBool,
    state: Mutex<RamUsageMonitorState>,
}

impl Default for RamUsageMonitor {
    fn default() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            state: Mutex::new(RamUsageMonitorState::default()),
        }
    }
}

impl RamUsageMonitor {
    pub(crate) fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub(crate) fn enable(
        &self,
        revision: i64,
        max_series: usize,
        mut baseline: Vec<(RamUsageSeriesKey, i64)>,
    ) -> Result<(), String> {
        if max_series == 0 || max_series > MAX_RAM_MONITOR_SERIES {
            return Err(format!(
                "RAM monitor max_series must be between 1 and {MAX_RAM_MONITOR_SERIES}"
            ));
        }

        baseline.sort_unstable_by(|(left_key, left_bytes), (right_key, right_bytes)| {
            right_bytes
                .cmp(left_bytes)
                .then_with(|| left_key.cmp(right_key))
        });
        let mut state = RamUsageMonitorState {
            max_series,
            revision,
            ..RamUsageMonitorState::default()
        };
        for (position, (key, bytes)) in baseline.into_iter().enumerate() {
            if position < max_series {
                state.series.insert(
                    key,
                    RamUsageSeriesSnapshot {
                        key,
                        current_bytes: bytes,
                        ..RamUsageSeriesSnapshot::default()
                    },
                );
                state.reserved_keys.insert(key);
            } else {
                state.overflow.current_bytes = state.overflow.current_bytes.saturating_add(bytes);
            }
        }
        *self.state.lock().expect("RAM monitor lock poisoned") = state;
        self.enabled.store(true, Ordering::Release);
        Ok(())
    }

    pub(crate) fn disable(&self) {
        self.enabled.store(false, Ordering::Release);
        *self.state.lock().expect("RAM monitor lock poisoned") = RamUsageMonitorState::default();
    }

    pub(crate) fn start_session(&self, revision: i64) {
        if !self.is_enabled() {
            return;
        }
        self.state
            .lock()
            .expect("RAM monitor lock poisoned")
            .layers
            .push_back(RamUsageLayer {
                revision,
                ..RamUsageLayer::default()
            });
    }

    pub(crate) fn record(&self, events: &[RamUsageEvent]) {
        if !self.is_enabled() || events.is_empty() {
            return;
        }
        let mut state = self.state.lock().expect("RAM monitor lock poisoned");
        if state.layers.is_empty() {
            // Runtime contract writes are required to live in an Arena undo
            // session. Ignore bootstrap/maintenance writes outside one; the
            // next explicit enable/reseed establishes an exact baseline.
            return;
        }

        let max_series = state.max_series;
        for event in events {
            if event.delta_bytes == 0 {
                continue;
            }
            let known = state.reserved_keys.contains(&event.key);
            if known || state.reserved_keys.len() < max_series {
                if !known {
                    state.reserved_keys.insert(event.key);
                }
                let layer = state
                    .layers
                    .back_mut()
                    .expect("RAM monitor layer checked above");
                if !known {
                    layer.new_keys.insert(event.key);
                }
                layer
                    .series
                    .entry(event.key)
                    .or_default()
                    .record(event.delta_bytes);
            } else {
                let layer = state
                    .layers
                    .back_mut()
                    .expect("RAM monitor layer checked above");
                layer.overflow.record(event.delta_bytes);
                layer.overflow_events = layer.overflow_events.saturating_add(1);
            }
        }
    }

    pub(crate) fn undo(&self) {
        if self.is_enabled() {
            let mut state = self.state.lock().expect("RAM monitor lock poisoned");
            if let Some(layer) = state.layers.pop_back() {
                for key in layer.new_keys {
                    state.reserved_keys.remove(&key);
                }
            }
        }
    }

    pub(crate) fn squash(&self, revision: i64) {
        if !self.is_enabled() {
            return;
        }
        let mut state = self.state.lock().expect("RAM monitor lock poisoned");
        let Some(top) = state.layers.pop_back() else {
            return;
        };
        if let Some(parent) = state.layers.back_mut() {
            for (key, delta) in top.series {
                parent.series.entry(key).or_default().merge(&delta);
            }
            parent.new_keys.extend(top.new_keys);
            parent.overflow.merge(&top.overflow);
            parent.overflow_events = parent.overflow_events.saturating_add(top.overflow_events);
        } else {
            Self::apply_layer(&mut state, top);
            state.revision = revision;
        }
    }

    pub(crate) fn commit(&self, revision: i64) {
        if !self.is_enabled() {
            return;
        }
        let mut state = self.state.lock().expect("RAM monitor lock poisoned");
        while state
            .layers
            .front()
            .is_some_and(|layer| layer.revision <= revision)
        {
            let layer = state.layers.pop_front().expect("front checked above");
            Self::apply_layer(&mut state, layer);
            state.accepted_blocks_total = state.accepted_blocks_total.saturating_add(1);
        }
        state.revision = state.revision.max(revision);
    }

    fn apply_layer(state: &mut RamUsageMonitorState, layer: RamUsageLayer) {
        for (key, delta) in layer.series {
            let series = state
                .series
                .entry(key)
                .or_insert_with(|| RamUsageSeriesSnapshot {
                    key,
                    ..RamUsageSeriesSnapshot::default()
                });
            series.current_bytes = series.current_bytes.saturating_add(delta.net_bytes);
            series.allocated_bytes_total = series
                .allocated_bytes_total
                .saturating_add(delta.allocated_bytes);
            series.freed_bytes_total = series.freed_bytes_total.saturating_add(delta.freed_bytes);
            series.operations_total = series.operations_total.saturating_add(delta.operations);
        }
        state.overflow.current_bytes = state
            .overflow
            .current_bytes
            .saturating_add(layer.overflow.net_bytes);
        state.overflow.allocated_bytes_total = state
            .overflow
            .allocated_bytes_total
            .saturating_add(layer.overflow.allocated_bytes);
        state.overflow.freed_bytes_total = state
            .overflow
            .freed_bytes_total
            .saturating_add(layer.overflow.freed_bytes);
        state.overflow.operations_total = state
            .overflow
            .operations_total
            .saturating_add(layer.overflow.operations);
        state.overflow_events_total = state
            .overflow_events_total
            .saturating_add(layer.overflow_events);
    }

    pub(crate) fn snapshot(&self) -> Option<RamUsageMonitorSnapshot> {
        if !self.is_enabled() {
            return None;
        }
        let state = self.state.lock().expect("RAM monitor lock poisoned");
        Some(RamUsageMonitorSnapshot {
            revision: state.revision,
            max_series: state.max_series,
            accepted_blocks_total: state.accepted_blocks_total,
            series: state.series.values().cloned().collect(),
            overflow: state.overflow.clone(),
            overflow_events_total: state.overflow_events_total,
        })
    }
}
