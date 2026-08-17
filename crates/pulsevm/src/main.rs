mod api;
mod chain;
mod state_history;

use pulsevm_core::{
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

use crate::{
    chain::{
        BlockTimer,
        GossipType,
        Gossipable,
    },
    state_history::StateHistoryServer,
};

/// Default bind address for the state history WebSocket API. Used when WS_BIND
/// is unset, in which case a busy port is tolerated (see run_ws_server).
const DEFAULT_WS_BIND: &str = "0.0.0.0:9090";

#[tokio::main(flavor = "multi_thread", worker_threads = 10)]
async fn main() {
    // Initialize logging
    spdlog::default_logger().set_level_filter(spdlog::LevelFilter::All);

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
    let incoming = TcpIncoming::from_listener(tokio_listener, true, None)
        .expect("failed to create incoming listener");
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

    let state_history_service = StateHistoryServer::new(vm.clone());
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

    // Keep listening
    let _ = runtime_handle.await;
    let _ = ws_handle.await;

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
    // Fired when a background state sync finishes applying, so `wait_for_event`
    // can report MESSAGE_STATE_SYNC_FINISHED to the engine.
    sync_finished: Arc<tokio::sync::Notify>,
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
            sync_finished: Arc::new(tokio::sync::Notify::new()),
        })
    }
}

#[tonic::async_trait]
impl Vm for VirtualMachine {
    async fn initialize(
        &self,
        request: Request<vm::InitializeRequest>,
    ) -> Result<tonic::Response<vm::InitializeResponse>, Status> {
        let config_bytes = request.get_ref().config_bytes.clone();
        let genesis_bytes = request.get_ref().genesis_bytes.clone();
        let db_path = request.get_ref().chain_data_dir.clone();
        let server_addr = request.get_ref().server_addr.clone();
        let chain_id: Id = request
            .get_ref()
            .chain_id
            .clone()
            .try_into()
            .map_err(|_| Status::invalid_argument("invalid chain id"))?;
        let controller = self.controller.clone();
        let mut controller = controller.write().await;

        // Initialize the controller with the genesis bytes
        controller
            .initialize(&chain_id, &config_bytes, &genesis_bytes, db_path.as_str())
            .map_err(|e| Status::internal(format!("could not initialize controller: {}", e)))?;

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
        controller.set_state(
            vm::State::try_from(request.get_ref().state)
                .map_err(|_| Status::invalid_argument("invalid state"))?,
        );

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
        // background state sync just finished.
        let message = tokio::select! {
            _ = block_timer.wait_for_block_build() => vm::Message::BuildBlock,
            _ = self.sync_finished.notified() => {
                info!("state sync finished, notifying engine");
                vm::Message::StateSyncFinished
            }
        };

        Ok(Response::new(vm::WaitForEventResponse {
            message: message.into(),
        }))
    }

    async fn shutdown(&self, _request: Request<()>) -> Result<tonic::Response<()>, Status> {
        let ready_to_terminate = self.ready_to_terminate.clone();
        ready_to_terminate.store(true, std::sync::atomic::Ordering::Relaxed);
        let controller = self.controller.clone();
        let mut controller = controller.write().await;
        controller
            .shutdown()
            .map_err(|e| Status::internal(format!("could not shutdown controller: {}", e)))?;
        Ok(Response::new(()))
    }

    async fn create_handlers(
        &self,
        _request: Request<()>,
    ) -> Result<tonic::Response<vm::CreateHandlersResponse>, Status> {
        Ok(Response::new(vm::CreateHandlersResponse {
            handlers: vec![Handler {
                prefix: "/rpc".to_string(),
                server_addr: self.server_addr.to_string(),
            }],
        }))
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
        let controller = self.controller.clone();
        let mut controller = controller.write().await;
        let mempool = self.mempool.clone();
        let mut mempool = mempool.write().await;
        let block = controller
            .build_block(&mut mempool)
            .await
            .map_err(|e| Status::internal(format!("could not build block: {}", e)))?;
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
        let mut controller = self.controller.write().await;
        let mut mempool = self.mempool.write().await;
        let block = match controller.parse_block(&request.get_ref().bytes) {
            Ok(block) => block,
            Err(e) => {
                warn!("failed parsing block for verification: {}", e);

                return Err(Status::internal("could not parse block"));
            }
        };

        // Verify the block
        match controller.verify_block(&block, &mut mempool).await {
            Ok(_) => {
                debug!(
                    "block verified with id {}, returning from block_verify",
                    block.id().unwrap_or_default()
                );
            }
            Err(e) => {
                warn!(
                    "could not verify block with id {} and height {}: {:?}",
                    block.id().unwrap_or_default(),
                    block.block_num(),
                    e
                );

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
        controller
            .accept_block(&block_id, &mut mempool)
            .map_err(|e| Status::internal(format!("could not accept block: {}", e)))?;
        debug!(
            "block accepted with id {}, returning from block_accept",
            block_id
        );

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
        controller
            .reject_block(&block_id, &mut mempool)
            .map_err(|e| Status::internal(format!("could not reject block: {}", e)))?;
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

        let served = {
            let controller = self.controller.read().await;
            controller.serve_snapshot_chunk(req.height, &req.hash, req.offset, req.len)
        };
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
        Ok(Response::new(vm::GatherResponse::default()))
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
        // Exclusive: producing a summary snapshots the arena, which briefly drops
        // and remaps the database.
        let mut controller = self.controller.write().await;
        let summary = controller
            .produce_state_summary()
            .map_err(|e| Status::internal(format!("could not produce state summary: {}", e)))?;
        Ok(Response::new(vm::GetLastStateSummaryResponse {
            id: summary.id.into(),
            height: summary.height,
            bytes: summary.bytes,
            err: 0,
        }))
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
        let requested = request.get_ref().height;
        let mut controller = self.controller.write().await;
        // Only the last accepted height can be served: chainbase keeps a single
        // live image, not per-height snapshots.
        if requested != controller.last_accepted_block().block_num() as u64 {
            return Ok(Response::new(vm::GetStateSummaryResponse {
                id: vec![],
                bytes: vec![],
                err: vm::Error::NotFound as i32,
            }));
        }
        let summary = controller
            .produce_state_summary()
            .map_err(|e| Status::internal(format!("could not produce state summary: {}", e)))?;
        Ok(Response::new(vm::GetStateSummaryResponse {
            id: summary.id.into(),
            bytes: summary.bytes,
            err: 0,
        }))
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
        let last_accepted = self
            .controller
            .read()
            .await
            .last_accepted_block()
            .block_num() as u64;
        if target.height <= last_accepted {
            info!(
                "skipping state summary at height {} (already at {})",
                target.height, last_accepted
            );
            return Ok(Response::new(vm::StateSummaryAcceptResponse {
                mode: vm::state_summary_accept_response::Mode::Skipped as i32,
                err: 0,
            }));
        }

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
                        &envelope,
                    ) {
                        Ok(()) => info!("state sync applied at height {}", height),
                        Err(e) => error!("state sync apply failed: {}", e),
                    }
                }
                Err(e) => error!("state sync download failed: {}", e),
            }
            // Wake the engine regardless: on failure it falls back to normal
            // bootstrapping rather than hanging on wait_for_event.
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
        let body = std::str::from_utf8(request.get_ref().body.as_slice())
            .map_err(|_| Status::invalid_argument("invalid utf-8"))?;
        let resp = self
            .rpc_service
            .handle_api_request(&body)
            .await
            .map_err(|_| Status::internal("failed to handle API request"))?;
        Ok(Response::new(http::HandleSimpleHttpResponse {
            code: 200,
            headers: vec![Element {
                key: "Content-Type".to_string(),
                values: vec!["application/json".to_string()],
            }],
            body: resp.into_bytes(),
        }))
    }
}
