mod api;
mod chain;
mod state_history;

use pulsevm_core::{
    config::{PLUGIN_VERSION, VERSION},
    controller::Controller,
    id::{Id, NodeId},
    mempool::Mempool,
    transaction::PackedTransaction,
};
use pulsevm_grpc::{
    http::{
        self, Element,
        http_server::{Http, HttpServer},
    },
    vm::{
        self, Handler, ParseBlockResponse,
        runtime::{InitializeRequest, runtime_client::RuntimeClient},
        vm_server::{Vm, VmServer},
    },
};
use pulsevm_serialization::{Read, Write};
use spdlog::{debug, info, warn};
use std::{
    net::{SocketAddr, TcpListener},
    sync::{Arc, atomic::AtomicBool},
};
use tokio::{
    net::TcpListener as TokioTcpListener,
    signal::unix::{SignalKind, signal},
    sync::RwLock,
};
use tokio_util::sync::CancellationToken;
use tonic::transport::server::TcpIncoming;
use tonic::{Request, Response, Status, transport::Server};

use crate::{
    chain::{BlockTimer, GossipType, Gossipable},
    state_history::StateHistoryServer,
};

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
    let ws_bind = std::env::var("WS_BIND").unwrap_or_else(|_| "127.0.0.1:9090".into());
    let ws_handle = tokio::spawn(async move {
        if let Err(e) = state_history_service
            .run_ws_server(&ws_bind, cancel_ws)
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
        _request: Request<vm::SetStateRequest>,
    ) -> Result<tonic::Response<vm::SetStateResponse>, Status> {
        let controller = self.controller.clone();
        let controller = controller.read().await;
        let last_accepted_block_id = controller.last_accepted_block().id().map_err(|e| {
            Status::internal(format!("could not get last accepted block id: {}", e))
        })?;

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

    async fn shutdown(&self, _request: Request<()>) -> Result<tonic::Response<()>, Status> {
        let ready_to_terminate = self.ready_to_terminate.clone();
        ready_to_terminate.store(true, std::sync::atomic::Ordering::Relaxed);
        let controller = self.controller.clone();
        let mut controller = controller.write().await;
        controller
            .shutdown()
            .map_err(|e| Status::internal(format!("could not shutdown controller: {}", e)));
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
        debug!("built block: {}", block_id);
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
        let controller = self.controller.read().await;
        let block = controller
            .parse_block(&request.get_ref().bytes)
            .map_err(|_| Status::internal("could not parse block"))?;
        let block_id = block
            .id()
            .map_err(|e| Status::internal(format!("could not get block id: {}", e)))?;
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
        }

        warn!("get_block: block not found: {}", block_id);

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
        let controller = self.controller.clone();
        let mut controller = controller.write().await;
        let block = match controller.parse_block(&request.get_ref().bytes) {
            Ok(block) => block,
            Err(e) => {
                warn!("failed parsing block for verification: {}", e);

                return Err(Status::internal("could not parse block"));
            }
        };

        // Verify the block
        match controller.verify_block(&block, self.mempool.clone()).await {
            Ok(_) => {
                debug!(
                    "block verified successfully: {}",
                    block.id().map_err(|_| Status::internal(
                        "failed getting block id during verification"
                    ))?
                );
            }
            Err(e) => {
                warn!("could not verify block: {:?}", e);

                return Err(Status::internal(format!("could not verify block: {}", e)));
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
        let controller = self.controller.clone();
        let mut controller = controller.write().await;
        let block_id: Id = request
            .get_ref()
            .id
            .clone()
            .try_into()
            .map_err(|_| Status::invalid_argument("invalid block id"))?;
        controller
            .accept_block(&block_id, self.mempool.clone())
            .await
            .map_err(|e| Status::internal(format!("could not accept block: {}", e)))?;

        info!("block accepted: {}", block_id);

        Ok(Response::new(()))
    }

    async fn block_reject(
        &self,
        request: Request<vm::BlockRejectRequest>,
    ) -> Result<tonic::Response<()>, Status> {
        let block_id: Id = request
            .get_ref()
            .id
            .clone()
            .try_into()
            .map_err(|_| Status::invalid_argument("invalid block id"))?;
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
        _request: Request<vm::AppRequestMsg>,
    ) -> Result<tonic::Response<()>, Status> {
        Ok(Response::new(()))
    }

    async fn app_request_failed(
        &self,
        _request: Request<vm::AppRequestFailedMsg>,
    ) -> Result<tonic::Response<()>, Status> {
        Ok(Response::new(()))
    }

    async fn app_response(
        &self,
        _request: Request<vm::AppResponseMsg>,
    ) -> Result<tonic::Response<()>, Status> {
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
                    let mempool = self.mempool.clone();
                    let mut mempool = mempool.write().await;
                    mempool.add_transaction(&tx);
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
        debug!("received request: {:?}", request);
        Ok(Response::new(vm::GetAncestorsResponse::default()))
    }

    async fn batched_parse_block(
        &self,
        request: Request<vm::BatchedParseBlockRequest>,
    ) -> Result<tonic::Response<vm::BatchedParseBlockResponse>, Status> {
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

        Ok(Response::new(vm::BatchedParseBlockResponse {
            response: parsed_blocks,
        }))
    }

    async fn get_block_id_at_height(
        &self,
        request: Request<vm::GetBlockIdAtHeightRequest>,
    ) -> Result<tonic::Response<vm::GetBlockIdAtHeightResponse>, Status> {
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
                return Ok(Response::new(vm::GetBlockIdAtHeightResponse {
                    blk_id: vec![].into(),
                    err: vm::Error::NotFound as i32,
                }));
            }
            Err(e) => {
                warn!(
                    "could not get block at height {}: {}",
                    request.get_ref().height,
                    e
                );
                return Err(Status::internal("could not get block at height"));
            }
        }
    }

    async fn state_sync_enabled(
        &self,
        _request: Request<()>,
    ) -> Result<tonic::Response<vm::StateSyncEnabledResponse>, Status> {
        Ok(Response::new(vm::StateSyncEnabledResponse {
            enabled: false,
            err: 0,
        }))
    }

    async fn get_ongoing_sync_state_summary(
        &self,
        request: Request<()>,
    ) -> Result<tonic::Response<vm::GetOngoingSyncStateSummaryResponse>, Status> {
        info!("received request: {:?}", request);
        Ok(Response::new(
            vm::GetOngoingSyncStateSummaryResponse::default(),
        ))
    }

    async fn get_last_state_summary(
        &self,
        request: Request<()>,
    ) -> Result<tonic::Response<vm::GetLastStateSummaryResponse>, Status> {
        info!("received request: {:?}", request);
        Ok(Response::new(vm::GetLastStateSummaryResponse::default()))
    }

    async fn parse_state_summary(
        &self,
        request: Request<vm::ParseStateSummaryRequest>,
    ) -> Result<tonic::Response<vm::ParseStateSummaryResponse>, Status> {
        info!("received request: {:?}", request);
        Ok(Response::new(vm::ParseStateSummaryResponse::default()))
    }

    async fn get_state_summary(
        &self,
        request: Request<vm::GetStateSummaryRequest>,
    ) -> Result<tonic::Response<vm::GetStateSummaryResponse>, Status> {
        info!("received request: {:?}", request);
        Ok(Response::new(vm::GetStateSummaryResponse::default()))
    }

    async fn state_summary_accept(
        &self,
        request: Request<vm::StateSummaryAcceptRequest>,
    ) -> Result<tonic::Response<vm::StateSummaryAcceptResponse>, Status> {
        info!("received request: {:?}", request);
        Ok(Response::new(vm::StateSummaryAcceptResponse::default()))
    }
}

#[tonic::async_trait]
impl Http for VirtualMachine {
    async fn handle(
        &self,
        _request: Request<http::HttpRequest>,
    ) -> Result<tonic::Response<()>, Status> {
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
