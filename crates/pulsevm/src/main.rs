mod api;
mod chain;

use pulsevm_core::{
    ChainError,
    Name,
    config::{
        PLUGIN_VERSION,
        VERSION,
    },
    controller::Controller,
    id::{
        Id,
        NodeId,
    },
    mempool::Mempool,
    state_history::StateHistoryServer,
    transaction::PackedTransaction,
};
use pulsevm_grpc::{
    http::{
        self,
        Element,
        http_server::{
            Http,
            HttpServer,
        },
    },
    prometheus::{
        Counter,
        Gauge,
        LabelPair,
        Metric,
        MetricFamily,
        MetricType,
    },
    vm::{
        self,
        Handler,
        ParseBlockResponse,
        runtime::{
            InitializeRequest,
            runtime_client::RuntimeClient,
        },
        vm_server::{
            Vm,
            VmServer,
        },
    },
};
use pulsevm_serialization::{
    Read,
    Write,
};
use spdlog::{
    debug,
    error,
    info,
    warn,
};
use std::{
    net::{
        SocketAddr,
        TcpListener,
    },
    sync::{
        Arc,
        atomic::AtomicBool,
    },
    time::{
        Duration,
        Instant,
    },
};
use tokio::{
    net::TcpListener as TokioTcpListener,
    signal::unix::{
        SignalKind,
        signal,
    },
    sync::RwLock,
};
use tokio_util::sync::CancellationToken;
use tonic::{
    Request,
    Response,
    Status,
    transport::{
        Server,
        server::TcpIncoming,
    },
};

use crate::chain::{
    BlockTimer,
    GossipType,
    Gossipable,
};

/// Default bind address for the state history WebSocket API. Used when WS_BIND
/// is unset, in which case a busy port is tolerated (see run_ws_server).
const DEFAULT_WS_BIND: &str = "0.0.0.0:9090";

/// Stop without running destructors when persistence reports that consensus
/// state may be only partly published. In particular, leaving chainbase dirty
/// makes a subsequent startup fail closed instead of silently using mismatched
/// arena and metadata files.
#[cold]
pub(crate) fn abort_on_fatal_consistency(operation: &str, error: &ChainError) -> ! {
    error!(
        "fatal consistency failure during {}: {}; aborting VM before it can resume consensus",
        operation, error
    );
    // `abort` skips logger teardown; write the same diagnostic directly so an
    // operator still has a recovery breadcrumb if the configured sink buffers.
    eprintln!(
        "FATAL: consistency failure during {operation}: {error}; aborting VM before it can resume consensus"
    );
    std::process::abort()
}

/// Whether a block is at or below the accepted head, so already decided.
fn block_is_decided_history(block_height: u32, accepted_height: u32) -> bool {
    block_height <= accepted_height
}

/// The log threshold for a `PULSEVM_LOG_LEVEL` value: info by default, and an
/// unrecognised value also means info rather than silencing or flooding the log.
fn log_level_filter(value: Option<&str>) -> spdlog::LevelFilter {
    use spdlog::{
        Level,
        LevelFilter,
    };
    match value
        .map(|text| text.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("trace") => LevelFilter::All,
        Some("debug") => LevelFilter::MoreSevereEqual(Level::Debug),
        Some("warn") | Some("warning") => LevelFilter::MoreSevereEqual(Level::Warn),
        Some("error") => LevelFilter::MoreSevereEqual(Level::Error),
        _ => LevelFilter::MoreSevereEqual(Level::Info),
    }
}

#[cfg(test)]
mod decided_history_tests {
    use super::block_is_decided_history;

    #[test]
    fn only_blocks_above_the_head_are_news() {
        assert!(block_is_decided_history(10, 10), "the head itself");
        assert!(block_is_decided_history(3, 10), "history");
        assert!(!block_is_decided_history(11, 10), "the next block");
        assert!(!block_is_decided_history(500, 10), "far ahead");
    }
}

/// Whether a state summary at `target_height` should be installed by a node at
/// `last_accepted`. A summary at or below the node's own height gains nothing, and
/// one within `min_blocks_behind` blocks is closer to a catch-up than a rebase.
fn state_sync_is_worth_it(target_height: u64, last_accepted: u64, min_blocks_behind: u64) -> bool {
    target_height > last_accepted.saturating_add(min_blocks_behind)
}

fn dead_chain_timeout_reached(now_ms: u64, last_accept_ms: u64, timeout_ms: u64) -> bool {
    timeout_ms > 0 && now_ms.saturating_sub(last_accept_ms) >= timeout_ms
}

#[cfg(test)]
mod dead_chain_watchdog_tests {
    use super::dead_chain_timeout_reached;

    #[test]
    fn timeout_is_disabled_and_resets_on_each_accepted_block() {
        assert!(!dead_chain_timeout_reached(10_000, 0, 0));
        assert!(!dead_chain_timeout_reached(9_999, 0, 10_000));
        assert!(dead_chain_timeout_reached(10_000, 0, 10_000));
        assert!(!dead_chain_timeout_reached(10_000, 1, 10_000));
        assert!(!dead_chain_timeout_reached(0, 1, 10_000));
    }
}

#[cfg(test)]
mod state_sync_threshold_tests {
    use super::state_sync_is_worth_it;

    #[test]
    fn a_node_a_few_blocks_behind_catches_up_instead_of_syncing() {
        assert!(!state_sync_is_worth_it(100, 100, 1024), "already there");
        assert!(
            !state_sync_is_worth_it(95, 100, 1024),
            "ahead of the summary"
        );
        assert!(
            !state_sync_is_worth_it(105, 100, 1024),
            "five blocks behind"
        );
        assert!(
            !state_sync_is_worth_it(1124, 100, 1024),
            "exactly at the limit"
        );
        assert!(state_sync_is_worth_it(1125, 100, 1024), "one block past it");
        assert!(state_sync_is_worth_it(1_000_000, 0, 1024), "a fresh node");
    }

    #[test]
    fn a_zero_threshold_syncs_whenever_a_summary_is_ahead() {
        assert!(state_sync_is_worth_it(101, 100, 0));
        assert!(!state_sync_is_worth_it(100, 100, 0));
    }

    #[test]
    fn a_huge_threshold_cannot_overflow() {
        assert!(!state_sync_is_worth_it(u64::MAX, u64::MAX - 1, u64::MAX));
        assert!(!state_sync_is_worth_it(5, u64::MAX, 1024));
    }
}

#[cfg(test)]
mod engine_event_tests {
    use super::{
        next_engine_event,
        vm,
    };
    use std::{
        sync::{
            Arc,
            atomic::{
                AtomicBool,
                Ordering,
            },
        },
        time::Duration,
    };
    use tokio::sync::Notify;

    async fn ready_now() {}

    async fn never() {
        std::future::pending::<()>().await
    }

    // Paul's hang: transactions pending while the node state-syncs. The pool is
    // always ready, yet the engine must only ever be told the sync finished.
    #[tokio::test]
    async fn a_pending_transaction_does_not_end_a_state_sync_wait() {
        let syncing = AtomicBool::new(true);
        let done = Arc::new(Notify::new());
        let wait = next_engine_event(&syncing, ready_now, &done);
        tokio::pin!(wait);
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut wait)
                .await
                .is_err(),
            "reported an event while syncing without the sync having finished"
        );
        done.notify_one();
        assert_eq!(wait.await, vm::Message::StateSyncFinished);
    }

    #[tokio::test]
    async fn a_ready_pool_builds_when_the_engine_is_not_syncing() {
        let syncing = AtomicBool::new(false);
        let done = Notify::new();
        assert_eq!(
            next_engine_event(&syncing, ready_now, &done).await,
            vm::Message::BuildBlock
        );
    }

    #[tokio::test]
    async fn the_end_of_a_sync_is_reported_when_not_syncing_too() {
        // A sync can finish after the host has already left the syncing state.
        let syncing = AtomicBool::new(false);
        let done = Notify::new();
        done.notify_one();
        assert_eq!(
            next_engine_event(&syncing, never, &done).await,
            vm::Message::StateSyncFinished
        );
    }

    // The engine switches state while a wait is outstanding: a build signal that
    // arrives after that must be held back, not reported.
    #[tokio::test]
    async fn a_build_signal_that_races_the_switch_to_syncing_is_held_back() {
        let syncing = Arc::new(AtomicBool::new(false));
        let flag = syncing.clone();
        let done = Arc::new(Notify::new());
        let build = move || {
            let flag = flag.clone();
            async move {
                flag.store(true, Ordering::Release);
            }
        };
        let wait = next_engine_event(&syncing, build, &done);
        tokio::pin!(wait);
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut wait)
                .await
                .is_err()
        );
        done.notify_one();
        assert_eq!(wait.await, vm::Message::StateSyncFinished);
    }
}

#[cfg(test)]
mod log_level_tests {
    use super::log_level_filter;
    use spdlog::{
        Level,
        LevelFilter,
    };

    #[test]
    fn info_unless_asked_and_never_a_surprise() {
        assert_eq!(
            log_level_filter(None),
            LevelFilter::MoreSevereEqual(Level::Info)
        );
        assert_eq!(
            log_level_filter(Some("nonsense")),
            LevelFilter::MoreSevereEqual(Level::Info)
        );
        assert_eq!(
            log_level_filter(Some(" DEBUG ")),
            LevelFilter::MoreSevereEqual(Level::Debug)
        );
        assert_eq!(log_level_filter(Some("trace")), LevelFilter::All);
        assert_eq!(
            log_level_filter(Some("warn")),
            LevelFilter::MoreSevereEqual(Level::Warn)
        );
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 10)]
async fn main() {
    // Initialize logging. Debug is opt-in (`PULSEVM_LOG_LEVEL=debug` when the
    // binary is launched directly, `log_level` in the chain config under a host
    // such as MetalGo, which does not pass its environment to the plugin): at debug
    // the controller hashes the whole state after every block just to print it,
    // which a production node should not pay for on every block.
    spdlog::default_logger().set_level_filter(log_level_filter(
        std::env::var("PULSEVM_LOG_LEVEL").ok().as_deref(),
    ));

    {
        let build = crate::api::BuildInfo::current();
        spdlog::info!(
            "pulsevm build {} (write-ahead log {}, state hash {})",
            build.build_id,
            build.wal_format,
            build.state_hash_format
        );
    }

    let cancel = CancellationToken::new();
    let cancel_ws = cancel.clone();
    let cancel_runtime = cancel.clone();
    let avalanche_addr = std::env::var("AVALANCHE_VM_RUNTIME_ENGINE_ADDR").unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind to address");
    listener
        .set_nonblocking(true)
        .expect("failed to set listener to non-blocking");
    let addr: std::net::SocketAddr = listener.local_addr().expect("failed to get local address");
    let tokio_listener =
        TokioTcpListener::from_std(listener).expect("failed to convert to tokio listener");
    let incoming = TcpIncoming::from(tokio_listener).with_nodelay(Some(true));
    // Main VM instance
    let vm = VirtualMachine::new(addr).unwrap();

    let runtime_vm = vm.clone();
    let runtime_handle = tokio::spawn(async move {
        let res = start_runtime_service(runtime_vm, incoming).await;
        // if this ends, trigger shutdown for the rest
        cancel_runtime.cancel();
        res
    });
    let mut client: RuntimeClient<tonic::transport::Channel> =
        RuntimeClient::connect(format!("http://{}", avalanche_addr))
            .await
            .expect("failed to connect to runtime engine");
    let request = Request::new(InitializeRequest {
        protocol_version: PLUGIN_VERSION,
        addr: addr.to_string(),
    });
    client
        .initialize(request)
        .await
        .expect("failed to initialize runtime engine");

    let state_history_service = StateHistoryServer::new(vm.controller.clone());
    // An explicit WS_BIND is honoured exactly; the default is allowed to move to
    // an ephemeral port so that co-located nodes do not contend for one port.
    let ws_bind_override = std::env::var("WS_BIND").ok();
    let allow_port_fallback = ws_bind_override.is_none();
    let ws_bind = ws_bind_override.unwrap_or_else(|| DEFAULT_WS_BIND.into());
    let ws_handle = tokio::spawn(async move {
        if let Err(e) = state_history_service
            .run_ws_server(&ws_bind, allow_port_fallback, cancel_ws)
            .await
        {
            spdlog::error!("WS server error: {:?}", e);
        }
    });

    // A window of refused blocks that ends with nothing more refused is still
    // reported, so a count is never left unwritten.
    {
        let refused = vm.refused_blocks.clone();
        let started = vm.started;
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                tick.tick().await;
                let summary = refused
                    .lock()
                    .ok()
                    .and_then(|mut log| log.flush_if_due(started.elapsed()));
                if let Some(summary) = summary {
                    spdlog::warn!("{summary}");
                }
            }
        });
    }

    // Keep listening
    let _ = runtime_handle.await;
    let _ = ws_handle.await;

    // The opt-in dead-chain watchdog shuts down the runtime server itself. Fold
    // the accepted log into the database just as the host's Shutdown RPC does.
    if let Err(error) = vm.shutdown_controller().await {
        error!("could not shut down controller: {error}");
    }

    // Gracefully shutdown
    info!("shutting down...");
}

async fn shutdown_signal(vm: VirtualMachine) {
    let mut sigterm_stream =
        signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");

    let terminate = async {
        loop {
            sigterm_stream.recv().await;

            let ready_to_terminate = vm.ready_to_terminate.clone();
            if ready_to_terminate.load(std::sync::atomic::Ordering::Relaxed) {
                info!("received SIGTERM, shutting down...");
                break;
            }

            info!("received SIGTERM, but not ready to terminate yet");
        }
    };

    let mut sigint_stream =
        signal(SignalKind::interrupt()).expect("failed to install SIGINT handler");

    let sigint = async {
        loop {
            sigint_stream.recv().await; // We ignore SIGINT, this is in line with MetalGo's behavior
        }
    };

    tokio::select! {
        _ = terminate => {},
        _ = sigint => {},
        _ = vm.shutdown_requested.notified() => {
            info!("dead-chain watchdog requested a graceful shutdown");
        },
    }
}

async fn start_runtime_service(
    vm: VirtualMachine,
    incoming: TcpIncoming,
) -> Result<(), tonic::transport::Error> {
    let shutdown_signal = shutdown_signal(vm.clone());
    Server::builder()
        .add_service(VmServer::new(vm.clone()))
        .add_service(HttpServer::new(vm.clone()))
        .serve_with_incoming_shutdown(incoming, shutdown_signal)
        .await
}

#[derive(Clone)]
pub struct VirtualMachine {
    server_addr: SocketAddr,
    controller: Arc<RwLock<Controller>>,
    mempool: Arc<RwLock<Mempool>>,
    network_manager: Arc<RwLock<chain::NetworkManager>>,
    rpc_service: chain::RpcService,
    block_timer: Arc<RwLock<BlockTimer>>,
    ready_to_terminate: Arc<AtomicBool>,
    shutdown_requested: Arc<tokio::sync::Notify>,
    controller_shutdown: Arc<AtomicBool>,
    last_block_accept_ms: Arc<std::sync::atomic::AtomicU64>,
    // Fired when a background state sync finishes applying, so `wait_for_event`
    // can report MESSAGE_STATE_SYNC_FINISHED to the engine.
    sync_finished: Arc<tokio::sync::Notify>,
    // True while the engine has put this VM in the state-syncing state. Read by
    // `wait_for_event`, which must report nothing but the end of the sync then.
    engine_state_syncing: Arc<AtomicBool>,
    // Refused blocks above the head, gathered into a summary per window.
    refused_blocks: Arc<std::sync::Mutex<chain::RefusedBlocks>>,
    started: std::time::Instant,
    // The state summaries this node offers, kept on disk (see chain::SummaryService).
    summaries: Arc<chain::SummaryService>,
}

/// What `wait_for_event` reports next.
///
/// The host takes one notification per subscription and then waits for its own
/// signal before subscribing again. A state syncer only accepts the end of the
/// sync, so a "build a block" sent while it runs is ignored by it and the end of
/// the sync is never subscribed to: the node stays in state sync until it is
/// restarted by hand. While the engine has this VM state-syncing, the only event
/// that may be reported is the sync finishing, whatever the mempool holds.
async fn next_engine_event<Build, BuildFuture>(
    syncing: &AtomicBool,
    build_ready: Build,
    sync_finished: &tokio::sync::Notify,
) -> vm::Message
where
    Build: Fn() -> BuildFuture,
    BuildFuture: std::future::Future<Output = ()>,
{
    loop {
        if syncing.load(std::sync::atomic::Ordering::Acquire) {
            sync_finished.notified().await;
            return vm::Message::StateSyncFinished;
        }
        tokio::select! {
            _ = build_ready() => {
                // The state may have changed while waiting. The build signal is
                // dropped if so; the block timer raises it again on its next tick
                // once the sync is over and transactions are still pending.
                if syncing.load(std::sync::atomic::Ordering::Acquire) {
                    continue;
                }
                return vm::Message::BuildBlock;
            }
            _ = sync_finished.notified() => return vm::Message::StateSyncFinished,
        }
    }
}

impl VirtualMachine {
    pub fn new(server_addr: SocketAddr) -> Result<Self, Box<dyn std::error::Error>> {
        let controller = Arc::new(RwLock::new(Controller::new()));
        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let network_manager = Arc::new(RwLock::new(chain::NetworkManager::new()));
        let rpc_service =
            chain::RpcService::new(mempool.clone(), controller.clone(), network_manager.clone());
        let block_timer = Arc::new(RwLock::new(BlockTimer::new(mempool.clone())));

        Ok(Self {
            server_addr,
            controller: controller,
            mempool: mempool,
            network_manager: network_manager,
            rpc_service: rpc_service,
            block_timer,
            ready_to_terminate: Arc::new(AtomicBool::new(false)),
            shutdown_requested: Arc::new(tokio::sync::Notify::new()),
            controller_shutdown: Arc::new(AtomicBool::new(false)),
            last_block_accept_ms: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            sync_finished: Arc::new(tokio::sync::Notify::new()),
            engine_state_syncing: Arc::new(AtomicBool::new(false)),
            refused_blocks: Arc::new(std::sync::Mutex::new(chain::RefusedBlocks::default())),
            started: std::time::Instant::now(),
            summaries: Arc::new(chain::SummaryService::new()),
        })
    }

    async fn shutdown_controller(&self) -> Result<(), ChainError> {
        if self
            .controller_shutdown
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            return Ok(());
        }
        let result = self.controller.write().await.shutdown();
        if result.is_err() {
            self.controller_shutdown
                .store(false, std::sync::atomic::Ordering::Release);
        }
        result
    }

    fn start_dead_chain_watchdog(&self, timeout_secs: u64) {
        if timeout_secs == 0 {
            return;
        }
        let timeout_ms = timeout_secs.saturating_mul(1000);
        let last_accept = self.last_block_accept_ms.clone();
        let requested = self.shutdown_requested.clone();
        let started = self.started;
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            loop {
                tick.tick().await;
                let now_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
                let last_ms = last_accept.load(std::sync::atomic::Ordering::Acquire);
                if dead_chain_timeout_reached(now_ms, last_ms, timeout_ms) {
                    warn!(
                        "no block has been accepted for {timeout_secs} seconds; the opt-in dead-chain watchdog is shutting down"
                    );
                    requested.notify_one();
                    break;
                }
            }
        });
    }
}

fn ram_usage_labels(key: pulsevm_core::RamUsageSeriesKey, overflow: bool) -> Vec<LabelPair> {
    let value = |name: &'static str, value: String| LabelPair {
        name: name.into(),
        value,
    };
    vec![
        value("code", Name::new(key.code).to_string()),
        value("scope", Name::new(key.scope).to_string()),
        value("table", Name::new(key.table).to_string()),
        value("payer", Name::new(key.payer).to_string()),
        value("overflow", overflow.to_string()),
    ]
}

fn gauge_metric(label: Vec<LabelPair>, value: f64) -> Metric {
    Metric {
        label,
        gauge: Some(Gauge { value }),
        ..Metric::default()
    }
}

fn counter_metric(label: Vec<LabelPair>, value: f64) -> Metric {
    Metric {
        label,
        counter: Some(Counter {
            value,
            ..Counter::default()
        }),
        ..Metric::default()
    }
}

fn metric_family(
    name: &'static str,
    help: &'static str,
    metric_type: MetricType,
    metric: Vec<Metric>,
) -> MetricFamily {
    MetricFamily {
        name: name.into(),
        help: help.into(),
        r#type: metric_type as i32,
        metric,
        ..MetricFamily::default()
    }
}

fn ram_usage_metric_families(snapshot: pulsevm_core::RamUsageMonitorSnapshot) -> Vec<MetricFamily> {
    let capacity = snapshot.series.len().saturating_add(1);
    let mut current = Vec::with_capacity(capacity);
    let mut allocated = Vec::with_capacity(capacity);
    let mut freed = Vec::with_capacity(capacity);
    let mut operations = Vec::with_capacity(capacity);
    for series in snapshot
        .series
        .iter()
        .map(|series| (series, false))
        .chain(std::iter::once((&snapshot.overflow, true)))
    {
        let (series, overflow) = series;
        current.push(gauge_metric(
            ram_usage_labels(series.key, overflow),
            series.current_bytes as f64,
        ));
        allocated.push(counter_metric(
            ram_usage_labels(series.key, overflow),
            series.allocated_bytes_total as f64,
        ));
        freed.push(counter_metric(
            ram_usage_labels(series.key, overflow),
            series.freed_bytes_total as f64,
        ));
        operations.push(counter_metric(
            ram_usage_labels(series.key, overflow),
            series.operations_total as f64,
        ));
    }

    vec![
        metric_family(
            "pulsevm_contract_ram_bytes",
            "Current accepted logical contract RAM usage.",
            MetricType::Gauge,
            current,
        ),
        metric_family(
            "pulsevm_contract_ram_allocated_bytes_total",
            "Logical contract RAM bytes allocated by accepted workload since startup.",
            MetricType::Counter,
            allocated,
        ),
        metric_family(
            "pulsevm_contract_ram_freed_bytes_total",
            "Logical contract RAM bytes freed by accepted workload since startup.",
            MetricType::Counter,
            freed,
        ),
        metric_family(
            "pulsevm_contract_ram_operations_total",
            "Accepted logical contract RAM allocation and refund operations since startup.",
            MetricType::Counter,
            operations,
        ),
        metric_family(
            "pulsevm_contract_ram_monitor_revision",
            "Latest Arena revision published by the RAM monitor.",
            MetricType::Gauge,
            vec![gauge_metric(Vec::new(), snapshot.revision as f64)],
        ),
        metric_family(
            "pulsevm_contract_ram_monitor_accepted_blocks_total",
            "Arena revisions published by the RAM monitor since startup.",
            MetricType::Counter,
            vec![counter_metric(
                Vec::new(),
                snapshot.accepted_blocks_total as f64,
            )],
        ),
        metric_family(
            "pulsevm_contract_ram_monitor_tracked_series",
            "Currently tracked labelled RAM series.",
            MetricType::Gauge,
            vec![gauge_metric(Vec::new(), snapshot.series.len() as f64)],
        ),
        metric_family(
            "pulsevm_contract_ram_monitor_max_series",
            "Configured maximum number of labelled RAM series.",
            MetricType::Gauge,
            vec![gauge_metric(Vec::new(), snapshot.max_series as f64)],
        ),
        metric_family(
            "pulsevm_contract_ram_monitor_overflow_events_total",
            "Accepted RAM events aggregated after the labelled-series limit was reached.",
            MetricType::Counter,
            vec![counter_metric(
                Vec::new(),
                snapshot.overflow_events_total as f64,
            )],
        ),
    ]
}

#[tonic::async_trait]
impl Vm for VirtualMachine {
    async fn initialize(
        &self,
        request: Request<vm::InitializeRequest>,
    ) -> Result<tonic::Response<vm::InitializeResponse>, Status> {
        let config_bytes = request.get_ref().config_bytes.clone();
        let genesis_bytes = request.get_ref().genesis_bytes.clone();
        let upgrade_bytes = request.get_ref().upgrade_bytes.clone();
        let db_path = request.get_ref().chain_data_dir.clone();
        let node_identity = request.get_ref().node_id.clone();
        let server_addr = request.get_ref().server_addr.clone();
        let chain_id: Id = request
            .get_ref()
            .chain_id
            .clone()
            .try_into()
            .map_err(|_| Status::invalid_argument("invalid chain id"))?;
        // MetalGo starts the plugin with a minimal environment, so the log level
        // an operator wants arrives in the chain config, not as a variable.
        if let Some(level) = serde_json::from_slice::<serde_json::Value>(&config_bytes)
            .ok()
            .and_then(|config| config.get("log_level")?.as_str().map(str::to_owned))
        {
            spdlog::default_logger().set_level_filter(log_level_filter(Some(&level)));
        }
        let summaries_dir = std::path::Path::new(&db_path).join("summaries");
        let dead_chain_shutdown_after_secs =
            serde_json::from_slice::<serde_json::Value>(&config_bytes)
                .ok()
                .and_then(|config| config.get("dead_chain_shutdown_after_secs")?.as_u64())
                .unwrap_or(0);
        let controller = self.controller.clone();
        // Restoring a full Arena checkpoint is CPU- and I/O-bound. Keep it off
        // the Tokio worker while MetalGo's RPC transport remains responsive.
        tokio::task::spawn_blocking(move || {
            let mut controller = controller.blocking_write();
            controller.set_node_identity(&node_identity);
            if let Err(error) = controller.initialize_with_protocol_upgrades(
                &chain_id,
                &config_bytes,
                &genesis_bytes,
                &upgrade_bytes,
                db_path.as_str(),
            ) {
                if error.is_fatal_consistency() {
                    abort_on_fatal_consistency("controller initialization", &error);
                }
                // MetalGo gets this as a gRPC status and the plugin used to say
                // nothing of its own, so a node that could not start (a damaged
                // log, say) looked like a hang with an empty log. Say why here.
                spdlog::error!("controller initialization failed: {error}");
                return Err(Status::internal(format!(
                    "could not initialize controller: {error}"
                )));
            }
            Ok::<_, Status>(())
        })
        .await
        .map_err(|e| Status::internal(format!("controller initialization task failed: {e}")))??;
        let admission_state = {
            let controller = self.controller.clone();
            let mut controller = controller.write().await;
            let mempool = self.mempool.clone();
            let mut mempool = mempool.write().await;
            if let Err(error) = controller
                .recover_pending_accepted_block(&mut mempool)
                .await
            {
                if error.is_fatal_consistency() {
                    abort_on_fatal_consistency("accepted-block recovery", &error);
                }
                spdlog::error!("accepted-block recovery failed: {error}");
                return Err(Status::internal(format!(
                    "could not recover accepted block: {error}"
                )));
            }
            controller.mempool_admission_state()
        };
        self.last_block_accept_ms.store(
            self.started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
            std::sync::atomic::Ordering::Release,
        );
        self.start_dead_chain_watchdog(dead_chain_shutdown_after_secs);
        self.rpc_service.set_admission_state(admission_state);
        // A node that cannot keep summaries still runs; it just offers none.
        if let Err(error) = self.summaries.open(summaries_dir) {
            spdlog::warn!("this node will offer no state summaries: {error}");
        }
        let controller = self.controller.read().await;

        let network_manager = Arc::clone(&self.network_manager);
        let mut network_manager = network_manager.write().await;
        network_manager.set_server_address(server_addr.clone());

        let block_timer = self.block_timer.clone();
        let mut block_timer = block_timer.write().await;
        block_timer.start(server_addr.clone()).await;

        let last_accepted_block_id = controller.last_accepted_block().id().map_err(|e| {
            Status::internal(format!("could not get last accepted block id: {}", e))
        })?;

        return Ok(Response::new(vm::InitializeResponse {
            last_accepted_id: last_accepted_block_id.into(),
            last_accepted_parent_id: controller
                .last_accepted_block()
                .previous_id()
                .as_bytes()
                .to_vec(),
            height: controller.last_accepted_block().block_num() as u64,
            bytes: controller
                .last_accepted_block()
                .pack()
                .map_err(|e| Status::internal(format!("could not pack block: {}", e)))?,
            timestamp: Some(controller.last_accepted_block().timestamp().into()),
        }));
    }

    async fn set_state(
        &self,
        request: Request<vm::SetStateRequest>,
    ) -> Result<tonic::Response<vm::SetStateResponse>, Status> {
        let controller = self.controller.clone();
        let mut controller = controller.write().await;
        let last_accepted_block_id = controller.last_accepted_block().id().map_err(|e| {
            Status::internal(format!("could not get last accepted block id: {}", e))
        })?;

        // Update state in controller
        let new_state = vm::State::try_from(request.get_ref().state)
            .map_err(|_| Status::invalid_argument("invalid state"))?;
        self.engine_state_syncing.store(
            new_state == vm::State::StateSyncing,
            std::sync::atomic::Ordering::Release,
        );
        controller.set_state(new_state);

        return Ok(Response::new(vm::SetStateResponse {
            last_accepted_id: last_accepted_block_id.into(),
            last_accepted_parent_id: controller
                .last_accepted_block()
                .previous_id()
                .as_bytes()
                .to_vec(),
            height: controller.last_accepted_block().block_num() as u64,
            bytes: controller
                .last_accepted_block()
                .pack()
                .map_err(|e| Status::internal(format!("could not pack block: {}", e)))?,
            timestamp: Some(controller.last_accepted_block().timestamp().into()),
        }));
    }

    async fn new_http_handler(
        &self,
        _request: Request<()>,
    ) -> Result<tonic::Response<vm::NewHttpHandlerResponse>, Status> {
        Ok(Response::new(vm::NewHttpHandlerResponse::default()))
    }

    async fn wait_for_event(
        &self,
        _request: Request<()>,
    ) -> Result<tonic::Response<vm::WaitForEventResponse>, Status> {
        debug!("wait_for_event called, waiting for the next event...");
        let block_timer = self.block_timer.clone();
        let block_timer = block_timer.read().await;

        // Wake on whichever comes first: a block is ready to build, or a
        // background state sync just finished. While the engine has this VM
        // state-syncing only the second may be reported (see next_engine_event).
        let message = next_engine_event(
            &self.engine_state_syncing,
            || block_timer.wait_for_block_build(),
            &self.sync_finished,
        )
        .await;
        if message == vm::Message::StateSyncFinished {
            info!("state sync finished, notifying engine");
        }

        Ok(Response::new(vm::WaitForEventResponse {
            message: message.into(),
        }))
    }

    async fn shutdown(&self, _request: Request<()>) -> Result<tonic::Response<()>, Status> {
        let ready_to_terminate = self.ready_to_terminate.clone();
        ready_to_terminate.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Err(error) = self.shutdown_controller().await {
            if error.is_fatal_consistency() {
                abort_on_fatal_consistency("controller shutdown", &error);
            }
            return Err(Status::internal(format!(
                "could not shutdown controller: {error}"
            )));
        }
        Ok(Response::new(()))
    }

    async fn create_handlers(
        &self,
        _request: Request<()>,
    ) -> Result<tonic::Response<vm::CreateHandlersResponse>, Status> {
        let mut handlers = vec![Handler {
            prefix: "/rpc".to_string(),
            server_addr: self.server_addr.to_string(),
        }];
        handlers.extend(
            crate::api::nodeos_compat::CHAIN_HANDLER_METHODS
                .iter()
                .map(|method| Handler {
                    prefix: format!("/v1/chain/{method}"),
                    server_addr: self.server_addr.to_string(),
                }),
        );
        Ok(Response::new(vm::CreateHandlersResponse { handlers }))
    }

    async fn connected(
        &self,
        request: Request<vm::ConnectedRequest>,
    ) -> Result<tonic::Response<()>, Status> {
        let network_manager = Arc::clone(&self.network_manager);
        let mut network_manager = network_manager.write().await;
        let node_id: NodeId = request
            .get_ref()
            .node_id
            .clone()
            .try_into()
            .map_err(|_| Status::invalid_argument("invalid node id"))?;
        network_manager.connected(node_id);
        Ok(Response::new(()))
    }

    async fn disconnected(
        &self,
        request: Request<vm::DisconnectedRequest>,
    ) -> Result<tonic::Response<()>, Status> {
        let network_manager = Arc::clone(&self.network_manager);
        let mut network_manager = network_manager.write().await;
        let node_id: NodeId = request
            .get_ref()
            .node_id
            .clone()
            .try_into()
            .map_err(|_| Status::invalid_argument("invalid node id"))?;
        network_manager.disconnected(node_id);
        Ok(Response::new(()))
    }

    async fn build_block(
        &self,
        _request: Request<vm::BuildBlockRequest>,
    ) -> Result<tonic::Response<vm::BuildBlockResponse>, Status> {
        debug!("build_block called, building block...");
        let block = match self.rpc_service.build_block().await {
            Ok(block) => block,
            Err(error) if error.is_fatal_consistency() => {
                abort_on_fatal_consistency("block building", &error)
            }
            Err(error) => {
                // A failed build is otherwise silent: MetalGo only retries on
                // new mempool activity, so log the cause where operators look.
                error!("could not build block: {error}");
                return Err(Status::internal(format!("could not build block: {error}")));
            }
        };
        let block_id = block
            .id()
            .map_err(|e| Status::internal(format!("could not get block id: {}", e)))?;
        debug!(
            "block built with id {}, returning from build_block",
            block_id
        );
        Ok(Response::new(vm::BuildBlockResponse {
            id: block_id.into(),
            parent_id: block.previous_id().as_bytes().to_vec(),
            height: block.block_num() as u64,
            bytes: block
                .pack()
                .map_err(|e| Status::internal(format!("could not pack block: {}", e)))?,
            timestamp: Some(block.timestamp().into()),
            verify_with_context: false,
        }))
    }

    async fn parse_block(
        &self,
        request: Request<vm::ParseBlockRequest>,
    ) -> Result<tonic::Response<vm::ParseBlockResponse>, Status> {
        debug!("parse_block called, parsing block...");
        let controller = self.controller.read().await;
        let block = controller
            .parse_block(&request.get_ref().bytes)
            .map_err(|_| Status::internal("could not parse block"))?;
        let block_id = block
            .id()
            .map_err(|e| Status::internal(format!("could not get block id: {}", e)))?;
        debug!(
            "block parsed with id {}, returning from parse_block",
            block_id
        );
        Ok(Response::new(vm::ParseBlockResponse {
            id: block_id.into(),
            parent_id: block.previous_id().as_bytes().to_vec(),
            height: block.block_num() as u64,
            timestamp: Some(block.timestamp().into()),
            verify_with_context: false,
        }))
    }

    async fn get_block(
        &self,
        request: Request<vm::GetBlockRequest>,
    ) -> Result<tonic::Response<vm::GetBlockResponse>, Status> {
        let controller = self.controller.read().await;
        let block_id: Id = request
            .get_ref()
            .id
            .clone()
            .try_into()
            .map_err(|_| Status::invalid_argument("invalid block id"))?;
        let block = controller
            .get_block(block_id)
            .map_err(|_| Status::internal("could not get block"))?;

        if let Some(block) = block {
            debug!("block found with id {}, returning from get_block", block_id);
            return Ok(Response::new(vm::GetBlockResponse {
                parent_id: block.previous_id().as_bytes().to_vec(),
                bytes: block
                    .pack()
                    .map_err(|e| Status::internal(format!("could not pack block: {}", e)))?,
                height: block.block_num() as u64,
                timestamp: Some(block.timestamp().into()),
                verify_with_context: false,
                err: 0,
            }));
        } else {
            warn!("block not found: {}", block_id);
        }

        return Ok(Response::new(vm::GetBlockResponse {
            parent_id: vec![],
            bytes: vec![],
            height: 0,
            timestamp: None,
            verify_with_context: false,
            err: vm::Error::NotFound as i32,
        }));
    }

    async fn block_verify(
        &self,
        request: Request<vm::BlockVerifyRequest>,
    ) -> Result<tonic::Response<vm::BlockVerifyResponse>, Status> {
        debug!("block_verify called, verifying block...");
        let block = match self
            .controller
            .read()
            .await
            .parse_block(&request.get_ref().bytes)
        {
            Ok(block) => block,
            Err(e) => {
                warn!("failed parsing block for verification: {}", e);

                return Err(Status::internal("could not parse block"));
            }
        };

        let verify_result = self.rpc_service.verify_block(&block).await;

        match verify_result {
            Ok(_) => {
                debug!(
                    "block verified with id {}, returning from block_verify",
                    block.id().unwrap_or_default()
                );
            }
            Err(e) => {
                if e.is_fatal_consistency() {
                    abort_on_fatal_consistency("block verification", &e);
                }
                // A block at or below the accepted head is decided history: a
                // peer's copy of a block this node already has, or a fork that
                // lost. Refusing it is right and is not news, and at about seven
                // a block it buried the warnings that are. A block above the head
                // whose parent is unknown is still a warning.
                let accepted = self
                    .controller
                    .read()
                    .await
                    .last_accepted_block()
                    .block_num();
                if block_is_decided_history(block.block_num(), accepted) {
                    debug!(
                        "refused block {} at height {} (accepted head {accepted}): {:?}",
                        block.id().unwrap_or_default(),
                        block.block_num(),
                        e
                    );
                } else {
                    // Above the head: a block this node cannot place yet, usually
                    // because it is behind. Logged in full once per window, counted
                    // after that, never hidden (see chain::RefusedBlocks).
                    let reason = format!("{e:?}");
                    let (decision, summary) = self
                        .refused_blocks
                        .lock()
                        .map(|mut log| log.note(self.started.elapsed(), block.block_num(), &reason))
                        .unwrap_or((chain::Refusal::LogInFull, None));
                    if let Some(summary) = summary {
                        warn!("{summary}");
                    }
                    if decision == chain::Refusal::LogInFull {
                        warn!(
                            "could not verify block with id {} and height {}: {:?}",
                            block.id().unwrap_or_default(),
                            block.block_num(),
                            e
                        );
                    }
                }

                return Err(Status::internal(format!(
                    "could not verify block with id {}: {}",
                    block.id().unwrap_or_default(),
                    e
                )));
            }
        }

        Ok(Response::new(vm::BlockVerifyResponse {
            timestamp: Some(block.timestamp().into()),
        }))
    }

    async fn block_accept(
        &self,
        request: Request<vm::BlockAcceptRequest>,
    ) -> Result<tonic::Response<()>, Status> {
        debug!("block_accept called, accepting block...");
        let mut controller = self.controller.write().await;
        let mut mempool = self.mempool.write().await;
        let block_id: Id = request
            .get_ref()
            .id
            .clone()
            .try_into()
            .map_err(|_| Status::invalid_argument("invalid block id"))?;
        if let Err(e) = controller.accept_block(&block_id, &mut mempool) {
            if e.is_fatal_consistency() {
                abort_on_fatal_consistency("block acceptance", &e);
            }
            return Err(Status::internal(format!("could not accept block: {}", e)));
        }
        self.last_block_accept_ms.store(
            self.started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
            std::sync::atomic::Ordering::Release,
        );
        debug!(
            "block accepted with id {}, returning from block_accept",
            block_id
        );
        // At a summary height, copy the state out now, under the lock already held
        // (about a second at mainnet size, on every validator at the same block), and
        // build the summary after both locks are released.
        let staged = match controller.stage_summary_if_due() {
            Ok(staged) => staged,
            Err(error) => {
                if error.is_fatal_consistency() {
                    abort_on_fatal_consistency("state-summary staging", &error);
                }
                warn!("could not stage a state summary: {error}");
                None
            }
        };
        drop(mempool);
        drop(controller);
        if let Some(staged) = staged {
            let summaries = self.summaries.clone();
            tokio::spawn(async move {
                let height = staged.height();
                match summaries.build_and_keep(staged).await {
                    Ok(height) => info!("kept the state summary for height {height}"),
                    Err(error) => {
                        warn!("could not build the state summary for height {height}: {error}")
                    }
                }
            });
        }

        Ok(Response::new(()))
    }

    async fn block_reject(
        &self,
        request: Request<vm::BlockRejectRequest>,
    ) -> Result<tonic::Response<()>, Status> {
        debug!("block_reject called, rejecting block...");
        let mut controller = self.controller.write().await;
        let mut mempool = self.mempool.write().await;
        let block_id: Id = request
            .get_ref()
            .id
            .clone()
            .try_into()
            .map_err(|_| Status::invalid_argument("invalid block id"))?;
        if let Err(error) = controller.reject_block(&block_id, &mut mempool) {
            if error.is_fatal_consistency() {
                abort_on_fatal_consistency("block rejection", &error);
            }
            return Err(Status::internal(format!("could not reject block: {error}")));
        }
        warn!("block rejected: {}", block_id);
        Ok(Response::new(()))
    }

    async fn set_preference(
        &self,
        request: Request<vm::SetPreferenceRequest>,
    ) -> Result<tonic::Response<()>, Status> {
        let controller = self.controller.clone();
        let mut controller = controller.write().await;
        let preferred_id: Id = request
            .get_ref()
            .id
            .clone()
            .try_into()
            .map_err(|_| Status::invalid_argument("invalid block id"))?;
        debug!(
            "set_preference called, setting preferred block to {}",
            preferred_id
        );
        controller.set_preferred_id(preferred_id);
        Ok(Response::new(()))
    }

    async fn health(
        &self,
        _request: Request<()>,
    ) -> Result<tonic::Response<vm::HealthResponse>, Status> {
        Ok(Response::new(vm::HealthResponse::default()))
    }

    async fn version(
        &self,
        _request: Request<()>,
    ) -> Result<tonic::Response<vm::VersionResponse>, Status> {
        let response = vm::VersionResponse {
            version: VERSION.to_string(),
        };
        Ok(Response::new(response))
    }

    async fn app_request(
        &self,
        request: Request<vm::AppRequestMsg>,
    ) -> Result<tonic::Response<()>, Status> {
        // A peer is syncing from us and asked for a snapshot chunk. Serve it from
        // the cached snapshot, or return an AppError so the peer retries.
        let msg = request.get_ref();
        let node_id: NodeId = match msg.node_id.clone().try_into() {
            Ok(id) => id,
            Err(_) => return Ok(Response::new(())),
        };
        let request_id = msg.request_id;
        let req = match pulsevm_core::state_sync::ChunkRequest::decode(&msg.request) {
            Ok(req) => req,
            Err(e) => {
                let network = self.network_manager.clone();
                let _ = chain::NetworkManager::send_app_error(
                    &network,
                    node_id,
                    request_id,
                    1,
                    format!("bad chunk request: {}", e),
                )
                .await;
                return Ok(Response::new(()));
            }
        };

        // Read from the kept snapshot's file; the controller is not involved.
        let served = self
            .summaries
            .read_chunk(req.height, req.hash, req.offset, req.len)
            .await;
        let network = self.network_manager.clone();
        match served {
            Ok(chunk) => {
                if let Err(e) =
                    chain::NetworkManager::send_app_response(&network, node_id, request_id, chunk)
                        .await
                {
                    warn!("failed to send snapshot chunk: {}", e);
                }
            }
            Err(e) => {
                let _ = chain::NetworkManager::send_app_error(
                    &network,
                    node_id,
                    request_id,
                    2,
                    format!("cannot serve chunk: {}", e),
                )
                .await;
            }
        }
        Ok(Response::new(()))
    }

    async fn app_request_failed(
        &self,
        request: Request<vm::AppRequestFailedMsg>,
    ) -> Result<tonic::Response<()>, Status> {
        let msg = request.get_ref();
        let network = self.network_manager.read().await;
        network.fail_request(
            msg.request_id,
            format!("peer error {}: {}", msg.error_code, msg.error_message),
        );
        Ok(Response::new(()))
    }

    async fn app_response(
        &self,
        request: Request<vm::AppResponseMsg>,
    ) -> Result<tonic::Response<()>, Status> {
        let msg = request.get_ref();
        let network = self.network_manager.read().await;
        network.resolve_response(msg.request_id, msg.response.clone());
        Ok(Response::new(()))
    }

    async fn app_gossip(
        &self,
        request: Request<vm::AppGossipMsg>,
    ) -> Result<tonic::Response<()>, Status> {
        let data = request.get_ref().msg.as_slice();
        let gossipable = match Gossipable::read(data, &mut 0) {
            Err(e) => {
                warn!("failed to read gossip: {}", e);
                return Ok(Response::new(()));
            }
            Ok(gossipable) => gossipable,
        };

        if gossipable.gossip_type == GossipType::Transaction {
            match gossipable.to_type::<PackedTransaction>() {
                Err(e) => {
                    warn!("failed to parse gossip as packed transaction: {}", e);
                    return Ok(Response::new(()));
                }
                Ok(tx) => {
                    // Validate before admitting: unlike the RPC path, a peer's
                    // gossip is untrusted, so run it through the same admission
                    // check rather than trusting the bytes into the mempool.
                    match self.rpc_service.admit_transaction(tx.clone()).await {
                        Err(e) => {
                            warn!("rejecting gossiped transaction: {}", e);
                        }
                        // Already known: don't relay again, or gossip would loop.
                        Ok(false) => {}
                        // New and valid: relay onward so it reaches beyond one hop.
                        Ok(true) => {
                            let nm = self.network_manager.read().await;
                            match Gossipable::new(GossipType::Transaction, tx) {
                                Ok(msg) => {
                                    if let Err(e) = nm.gossip(msg).await {
                                        warn!("failed to relay gossiped transaction: {}", e);
                                    }
                                }
                                Err(e) => {
                                    warn!("failed to build relay gossip: {}", e);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(Response::new(()))
    }

    async fn gather(
        &self,
        _request: Request<()>,
    ) -> Result<tonic::Response<vm::GatherResponse>, Status> {
        let database = self.controller.read().await.database();
        let metric_families = database
            .ram_usage_monitor_snapshot()
            .map(ram_usage_metric_families)
            .unwrap_or_default();
        Ok(Response::new(vm::GatherResponse { metric_families }))
    }

    async fn get_ancestors(
        &self,
        request: Request<vm::GetAncestorsRequest>,
    ) -> Result<tonic::Response<vm::GetAncestorsResponse>, Status> {
        debug!("get_ancestors called, retrieving ancestors...");
        let controller = self.controller.clone();
        let controller = controller.read().await;
        let deadline = Instant::now()
            + Duration::from_nanos(request.get_ref().max_blocks_retrival_time as u64);
        let mut ancestors: Vec<Vec<u8>> = Vec::new();
        let mut total_size = 0usize;
        let mut current_id: Id = request
            .get_ref()
            .blk_id
            .clone()
            .try_into()
            .map_err(|_| Status::invalid_argument("invalid block id"))?;
        let max_blocks_size = request.get_ref().max_blocks_size as usize;

        while ancestors.len() < request.get_ref().max_blocks_num as usize {
            // If we are past the deadline, break out of the loop and return what we have so far
            if Instant::now() > deadline {
                break;
            }

            let blk = match controller.get_block(current_id) {
                Ok(Some(blk)) => blk,
                Ok(None) if !ancestors.is_empty() => break,
                Ok(None) => return Err(Status::not_found("block not found")),
                Err(e) => return Err(Status::internal(format!("could not get block: {}", e))),
            };

            let blk_bytes = blk
                .pack()
                .map_err(|e| Status::internal(format!("could not pack block: {}", e)))?;
            if total_size + blk_bytes.len() > max_blocks_size && !ancestors.is_empty() {
                break;
            }

            total_size += blk_bytes.len();
            let parent_id = blk.previous_id().clone();
            ancestors.push(blk_bytes);

            // Did we hit the genesis block? If so, break out of the loop
            if parent_id.is_empty() {
                break;
            }

            current_id = parent_id;
        }

        debug!(
            "retrieved {} ancestors with total size {}, returning from get_ancestors",
            ancestors.len(),
            total_size
        );

        Ok(Response::new(vm::GetAncestorsResponse {
            blks_bytes: ancestors,
        }))
    }

    async fn batched_parse_block(
        &self,
        request: Request<vm::BatchedParseBlockRequest>,
    ) -> Result<tonic::Response<vm::BatchedParseBlockResponse>, Status> {
        debug!("batched_parse_block called, parsing blocks...");
        let controller = self.controller.clone();
        let controller = controller.read().await;
        let mut parsed_blocks: Vec<ParseBlockResponse> = Vec::new();

        for block in request.get_ref().request.iter() {
            let block = controller
                .parse_block(&block)
                .map_err(|_| Status::internal("could not parse block"))?;
            let block_id = block
                .id()
                .map_err(|e| Status::internal(format!("could not get block id: {}", e)))?;
            parsed_blocks.push(ParseBlockResponse {
                id: block_id.into(),
                parent_id: block.previous_id().as_bytes().to_vec(),
                height: block.block_num() as u64,
                timestamp: Some(block.timestamp().into()),
                verify_with_context: false,
            });
        }

        debug!(
            "parsed {} blocks, returning from batched_parse_block",
            parsed_blocks.len()
        );

        Ok(Response::new(vm::BatchedParseBlockResponse {
            response: parsed_blocks,
        }))
    }

    async fn get_block_id_at_height(
        &self,
        request: Request<vm::GetBlockIdAtHeightRequest>,
    ) -> Result<tonic::Response<vm::GetBlockIdAtHeightResponse>, Status> {
        debug!(
            "get_block_id_at_height called, retrieving block id at height {}...",
            request.get_ref().height
        );
        let controller = self.controller.clone();
        let controller = controller.read().await;

        match controller.get_block_by_height(request.get_ref().height as u32) {
            Ok(Some(block)) => {
                let block_id = block
                    .id()
                    .map_err(|e| Status::internal(format!("could not get block id: {}", e)))?;

                return Ok(Response::new(vm::GetBlockIdAtHeightResponse {
                    blk_id: block_id.into(),
                    err: 0,
                }));
            }
            Ok(None) => {
                warn!("block not found at height: {}", request.get_ref().height);

                return Ok(Response::new(vm::GetBlockIdAtHeightResponse {
                    blk_id: vec![].into(),
                    err: vm::Error::NotFound as i32,
                }));
            }
            Err(_) => {
                warn!("block not found at height: {}", request.get_ref().height);

                return Ok(Response::new(vm::GetBlockIdAtHeightResponse {
                    blk_id: vec![].into(),
                    err: vm::Error::NotFound as i32,
                }));
            }
        }
    }

    async fn state_sync_enabled(
        &self,
        _request: Request<()>,
    ) -> Result<tonic::Response<vm::StateSyncEnabledResponse>, Status> {
        Ok(Response::new(vm::StateSyncEnabledResponse {
            enabled: true,
            err: 0,
        }))
    }

    async fn get_ongoing_sync_state_summary(
        &self,
        request: Request<()>,
    ) -> Result<tonic::Response<vm::GetOngoingSyncStateSummaryResponse>, Status> {
        info!("received request: {:?}", request);
        // No sync is resumed across restarts: a summary is produced fresh from
        // the last accepted block on demand.
        Ok(Response::new(vm::GetOngoingSyncStateSummaryResponse {
            id: vec![],
            height: 0,
            bytes: vec![],
            err: vm::Error::NotFound as i32,
        }))
    }

    async fn get_last_state_summary(
        &self,
        request: Request<()>,
    ) -> Result<tonic::Response<vm::GetLastStateSummaryResponse>, Status> {
        info!("received request: {:?}", request);
        let (tip, min_age) = {
            let controller = self.controller.read().await;
            (
                u64::from(controller.last_accepted_block().block_num()),
                controller.state_summary_min_age(),
            )
        };
        // Whatever is kept and old enough. Nothing is built here: a summary is built
        // once, in the background, when a block at a summary height is accepted.
        Ok(Response::new(
            match self.summaries.offer_latest(tip, min_age) {
                Some(summary) => vm::GetLastStateSummaryResponse {
                    id: summary.id.into(),
                    height: summary.height,
                    bytes: summary.bytes,
                    err: 0,
                },
                None => vm::GetLastStateSummaryResponse {
                    id: vec![],
                    height: 0,
                    bytes: vec![],
                    err: vm::Error::NotFound as i32,
                },
            },
        ))
    }

    async fn parse_state_summary(
        &self,
        request: Request<vm::ParseStateSummaryRequest>,
    ) -> Result<tonic::Response<vm::ParseStateSummaryResponse>, Status> {
        let (id, height) = Controller::parse_state_summary(&request.get_ref().bytes)
            .map_err(|e| Status::invalid_argument(format!("invalid state summary: {}", e)))?;
        Ok(Response::new(vm::ParseStateSummaryResponse {
            id: id.into(),
            height,
            err: 0,
        }))
    }

    async fn get_state_summary(
        &self,
        request: Request<vm::GetStateSummaryRequest>,
    ) -> Result<tonic::Response<vm::GetStateSummaryResponse>, Status> {
        info!("received request: {:?}", request);
        // The host asks for the heights it chose when it voted; this node answers
        // for the fixed heights it keeps a summary for, and for no other.
        Ok(Response::new(
            match self.summaries.offer_at(request.get_ref().height) {
                Some(summary) => vm::GetStateSummaryResponse {
                    id: summary.id.into(),
                    bytes: summary.bytes,
                    err: 0,
                },
                None => vm::GetStateSummaryResponse {
                    id: vec![],
                    bytes: vec![],
                    err: vm::Error::NotFound as i32,
                },
            },
        ))
    }

    async fn state_summary_accept(
        &self,
        request: Request<vm::StateSummaryAcceptRequest>,
    ) -> Result<tonic::Response<vm::StateSummaryAcceptResponse>, Status> {
        info!("received state summary accept request");

        // Parse the commitment up front so a malformed summary is rejected here,
        // before we commit to the asynchronous DYNAMIC mode.
        let target = Controller::sync_target_from_summary(&request.get_ref().bytes)
            .map_err(|e| Status::invalid_argument(format!("invalid state summary: {}", e)))?;

        // Only sync forward. A validator that already has the summary's height
        // gains nothing from applying it, and a single-node network is offered
        // its own tip as a summary during bootstrap: accepting it would fire a
        // stray StateSyncFinished after consensus has already started, wedging
        // the wait_for_event stream so no block ever builds. Skip instead.
        let (last_accepted, min_blocks_behind) = {
            let controller = self.controller.read().await;
            (
                controller.last_accepted_block().block_num() as u64,
                controller.state_sync_min_blocks_behind(),
            )
        };
        if !state_sync_is_worth_it(target.height, last_accepted, min_blocks_behind) {
            info!(
                "skipping state summary at height {} (this node is at {}, which is within {} blocks of it: fetching them is cheaper than a snapshot install)",
                target.height, last_accepted, min_blocks_behind
            );
            return Ok(Response::new(vm::StateSummaryAcceptResponse {
                mode: vm::state_summary_accept_response::Mode::Skipped as i32,
                err: 0,
            }));
        }

        // Refuse a schedule/version mismatch before downloading tens of MB or
        // entering asynchronous state-sync mode. Apply revalidates this again
        // immediately before the database swap.
        self.controller
            .read()
            .await
            .validate_state_sync_target(&target)
            .map_err(|e| Status::failed_precondition(format!("invalid state summary: {e}")))?;

        // The snapshot payload is downloaded out of band over AppRequest, so the
        // sync runs in the background and completes later. Report STATIC, not
        // DYNAMIC: DYNAMIC tells the engine to bootstrap the block chain forward
        // from its current last-accepted (genesis) while the VM syncs, which
        // assumes every block genesis..tip stays verifiable. A snapshot transfer
        // rebases the block log onto the synced tip and drops the earlier blocks,
        // so that walk can never resolve. STATIC instead makes the engine wait
        // for our done-signal, then bootstrap from the synced height with nothing
        // left to fetch. Signal `wait_for_event` when the background apply lands.
        // Fetch each chunk from peers, verify the payload against the summary
        // hash, then apply it.
        let controller = self.controller.clone();
        let quarantine_path = self.controller.read().await.state_sync_quarantine_path();
        let network = self.network_manager.clone();
        let sync_finished = self.sync_finished.clone();
        tokio::spawn(async move {
            let net = network.clone();
            let height = target.height;
            let hash = target.hash;
            let download =
                pulsevm_core::state_sync::download_snapshot(&target, move |offset, len| {
                    let net = net.clone();
                    async move {
                        let req = pulsevm_core::state_sync::ChunkRequest {
                            height,
                            hash,
                            offset,
                            len,
                        };
                        chain::NetworkManager::request_chunk(&net, &req).await
                    }
                })
                .await;

            match download {
                Ok(envelope) => {
                    let mut controller = controller.write().await;
                    match controller.apply_state_snapshot(
                        target.block.clone(),
                        target.schedule.clone(),
                        target.protocol_commitment,
                        target.state_root,
                        &envelope,
                    ) {
                        Ok(()) => {
                            info!("state sync applied at height {}", height);
                            drop(controller);
                            if let Some(path) = quarantine_path {
                                tokio::task::spawn_blocking(move || match std::fs::remove_dir_all(
                                    &path,
                                ) {
                                    Ok(()) => info!(
                                        "removed abandoned pre-sync data after authenticated state sync"
                                    ),
                                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                                    Err(error) => warn!(
                                        "state sync succeeded, but could not remove abandoned pre-sync data: {error}"
                                    ),
                                });
                            }
                        }
                        Err(e) if e.is_fatal_consistency() => {
                            // The arena or its companion metadata crossed a
                            // publication boundary. Never wake MetalGo to fall
                            // back on a view that may now be internally split.
                            abort_on_fatal_consistency("state-sync apply", &e)
                        }
                        Err(e) => error!("state sync apply failed: {}", e),
                    }
                }
                Err(e) => error!("state sync download failed: {}", e),
            }
            // Safe rejection/download failures fall back to normal
            // bootstrapping. Fatal consistency failures abort in the match above
            // and can never reach this notification.
            sync_finished.notify_one();
        });

        Ok(Response::new(vm::StateSummaryAcceptResponse {
            mode: vm::state_summary_accept_response::Mode::Static as i32,
            err: 0,
        }))
    }
}

#[tonic::async_trait]
impl Http for VirtualMachine {
    async fn handle(
        &self,
        _request: Request<http::HttpRequest>,
    ) -> Result<tonic::Response<http::HttpResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
    }

    async fn handle_simple(
        &self,
        request: Request<http::HandleSimpleHttpRequest>,
    ) -> Result<tonic::Response<http::HandleSimpleHttpResponse>, Status> {
        let http_req = request.get_ref();
        let url = &http_req.url;
        if http_req.method.eq_ignore_ascii_case("OPTIONS") {
            return Ok(Response::new(http::HandleSimpleHttpResponse {
                code: 204,
                headers: vec![
                    Element {
                        key: "Access-Control-Allow-Origin".to_string(),
                        values: vec!["*".to_string()],
                    },
                    Element {
                        key: "Access-Control-Allow-Methods".to_string(),
                        values: vec!["POST, OPTIONS".to_string()],
                    },
                    Element {
                        key: "Access-Control-Allow-Headers".to_string(),
                        values: vec!["Content-Type".to_string()],
                    },
                ],
                body: Vec::new(),
            }));
        }
        // Bound the body before parsing anything: the route decides the ceiling.
        let limit = api::nodeos_compat::max_body_bytes(url);
        if http_req.body.len() > limit {
            return Ok(api::nodeos_compat::body_too_large(limit));
        }
        let body = std::str::from_utf8(http_req.body.as_slice())
            .map_err(|_| Status::invalid_argument("invalid utf-8"))?;

        // Dispatch based on URL path
        if url.contains("/v1/chain/") {
            // Handle nodeos compatibility API
            return api::nodeos_compat::handle_nodeos_request(&self.rpc_service, url, body).await;
        }

        // Default to JSON-RPC handler
        let resp = self
            .rpc_service
            .handle_api_request(&body)
            .await
            .map_err(|_| Status::internal("failed to handle API request"))?;
        Ok(Response::new(http::HandleSimpleHttpResponse {
            code: 200,
            headers: vec![
                Element {
                    key: "Content-Type".to_string(),
                    values: vec!["application/json".to_string()],
                },
                Element {
                    key: "Access-Control-Allow-Origin".to_string(),
                    values: vec!["*".to_string()],
                },
                Element {
                    key: "Access-Control-Allow-Methods".to_string(),
                    values: vec!["POST, OPTIONS".to_string()],
                },
                Element {
                    key: "Access-Control-Allow-Headers".to_string(),
                    values: vec!["Content-Type".to_string()],
                },
            ],
            body: resp.into_bytes(),
        }))
    }
}

#[cfg(test)]
mod ram_usage_metric_tests {
    use super::*;
    use pulsevm_core::{
        RamUsageMonitorSnapshot,
        RamUsageSeriesKey,
        RamUsageSeriesSnapshot,
    };
    use std::str::FromStr;

    #[test]
    fn exports_bounded_ram_series_and_monitor_health() {
        let families = ram_usage_metric_families(RamUsageMonitorSnapshot {
            revision: 42,
            max_series: 8,
            accepted_blocks_total: 3,
            series: vec![RamUsageSeriesSnapshot {
                key: RamUsageSeriesKey {
                    code: Name::from_str("token").unwrap().as_u64(),
                    scope: Name::from_str("alice").unwrap().as_u64(),
                    table: Name::from_str("accounts").unwrap().as_u64(),
                    payer: Name::from_str("alice").unwrap().as_u64(),
                },
                current_bytes: 128,
                allocated_bytes_total: 160,
                freed_bytes_total: 32,
                operations_total: 4,
            }],
            overflow: RamUsageSeriesSnapshot {
                current_bytes: 64,
                allocated_bytes_total: 64,
                operations_total: 1,
                ..RamUsageSeriesSnapshot::default()
            },
            overflow_events_total: 1,
        });

        assert_eq!(families.len(), 9);
        let current = families
            .iter()
            .find(|family| family.name == "pulsevm_contract_ram_bytes")
            .unwrap();
        assert_eq!(current.r#type, MetricType::Gauge as i32);
        assert_eq!(current.metric.len(), 2);
        assert_eq!(current.metric[0].gauge.as_ref().unwrap().value, 128.0);
        assert!(
            current.metric[0]
                .label
                .iter()
                .any(|label| label.name == "table" && label.value == "accounts")
        );
        assert!(
            current.metric[1]
                .label
                .iter()
                .any(|label| label.name == "overflow" && label.value == "true")
        );
    }

    #[tokio::test]
    async fn create_handlers_advertises_rpc_and_nodeos_endpoints() {
        let vm = VirtualMachine::new("127.0.0.1:1234".parse().unwrap()).unwrap();
        let response = vm.create_handlers(Request::new(())).await.unwrap();
        let handlers = response.into_inner().handlers;

        assert_eq!(
            handlers.len(),
            1 + crate::api::nodeos_compat::CHAIN_HANDLER_METHODS.len()
        );
        assert_eq!(handlers[0].prefix, "/rpc");
        assert_eq!(handlers[1].prefix, "/v1/chain/get_info");
        assert!(
            handlers
                .iter()
                .any(|handler| handler.prefix == "/v1/chain/push_transaction")
        );
        assert!(
            handlers
                .iter()
                .all(|handler| handler.server_addr == "127.0.0.1:1234")
        );
    }

    #[tokio::test]
    async fn an_oversized_request_body_is_refused_before_it_is_parsed() {
        let vm = VirtualMachine::new("127.0.0.1:1234".parse().unwrap()).unwrap();
        let request = |url: &str, body: Vec<u8>| {
            Request::new(http::HandleSimpleHttpRequest {
                method: "POST".to_string(),
                url: url.to_string(),
                request_headers: vec![],
                body,
                response_headers: vec![],
            })
        };

        // A query route takes at most a small body. This one is not valid
        // UTF-8, so reaching the parser would have failed differently: the
        // 413 proves the size check ran first.
        let query_limit = api::nodeos_compat::MAX_QUERY_BODY_BYTES;
        let refused = vm
            .handle_simple(request(
                "/v1/chain/get_account",
                vec![0xff; query_limit + 1],
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(refused.code, 413);
        assert!(
            String::from_utf8(refused.body)
                .unwrap()
                .contains("payload_too_large")
        );

        // A body at the limit is still handed to the route (and rejected as
        // bad JSON, not as too large).
        let at_limit = vm
            .handle_simple(request("/v1/chain/get_account", vec![b' '; query_limit]))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(at_limit.code, 400);

        // The JSON-RPC and submit routes keep the large ceiling.
        let submit_limit = api::nodeos_compat::MAX_SUBMIT_BODY_BYTES;
        let refused = vm
            .handle_simple(request("/rpc", vec![b' '; submit_limit + 1]))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(refused.code, 413);
    }

    #[tokio::test]
    async fn simple_http_dispatches_nodeos_and_json_rpc_requests() {
        let vm = VirtualMachine::new("127.0.0.1:1234".parse().unwrap()).unwrap();

        let nodeos = vm
            .handle_simple(Request::new(http::HandleSimpleHttpRequest {
                method: "POST".to_string(),
                url: "/v1/chain/unknown".to_string(),
                request_headers: vec![],
                body: b"{}".to_vec(),
                response_headers: vec![],
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(nodeos.code, 404);
        assert!(nodeos.headers.iter().any(|header| {
            header.key == "Access-Control-Allow-Origin"
                && header.values.iter().any(|value| value == "*")
        }));
        assert!(
            String::from_utf8(nodeos.body)
                .unwrap()
                .contains("unknown_method")
        );

        let utf8_status = vm
            .handle_simple(Request::new(http::HandleSimpleHttpRequest {
                method: "POST".to_string(),
                url: "/rpc".to_string(),
                request_headers: vec![],
                body: vec![0xff],
                response_headers: vec![],
            }))
            .await
            .expect_err("invalid UTF-8 should be rejected");
        assert_eq!(utf8_status.code(), tonic::Code::InvalidArgument);

        let rpc_status = vm
            .handle_simple(Request::new(http::HandleSimpleHttpRequest {
                method: "POST".to_string(),
                url: "/rpc".to_string(),
                request_headers: vec![],
                body: b"not-json".to_vec(),
                response_headers: vec![],
            }))
            .await
            .expect_err("malformed JSON-RPC should be rejected");
        assert_eq!(rpc_status.code(), tonic::Code::Internal);
    }
}
