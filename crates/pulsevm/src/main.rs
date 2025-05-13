mod chain;
mod mempool;

use chain::{Controller, Id, NodeId};
use jsonrpsee::server::middleware::rpc::{self, rpc_service};
use mempool::build_block_timer;
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
use spdlog::info;
use std::{
    net::{SocketAddr, TcpListener},
    sync::Arc,
};
use tokio::{
    net::TcpListener as TokioTcpListener,
    signal, spawn,
    sync::{Mutex, RwLock},
    task::JoinHandle,
};
use tonic::transport::server::TcpIncoming;
use tonic::{Request, Response, Status, transport::Server};

const PLUGIN_VERSION: u32 = 38;
const VERSION: &str = "0.0.1";

#[tokio::main]
async fn main() {
    // Initialize logging
    spdlog::default_logger().set_level_filter(spdlog::LevelFilter::All);

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

    let handle = tokio::spawn(async move { start_runtime_service(incoming, addr).await });
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
    // Keep listening
    let _ = handle.await;

    // Gracefully shutdown
    info!("shutting down...");
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install SIGINT handler");
    };
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("received shutdown signal, shutting down...");
}

async fn start_runtime_service(
    incoming: TcpIncoming,
    server_addr: SocketAddr,
) -> Result<(), tonic::transport::Error> {
    let shutdown_signal = shutdown_signal();
    let vm = VirtualMachine::new(server_addr).unwrap();
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
    mempool: Arc<RwLock<mempool::Mempool>>,
    network_manager: Arc<RwLock<chain::NetworkManager>>,
    rpc_service: chain::RpcService,
    block_timer: Arc<RwLock<Option<JoinHandle<()>>>>,
}

impl VirtualMachine {
    pub fn new(server_addr: SocketAddr) -> Result<Self, Box<dyn std::error::Error>> {
        let controller = Arc::new(RwLock::new(Controller::new()));
        let mempool = Arc::new(RwLock::new(mempool::Mempool::new()));
        let network_manager = Arc::new(RwLock::new(chain::NetworkManager::new()));
        let rpc_service =
            chain::RpcService::new(mempool.clone(), controller.clone(), network_manager.clone());

        Ok(Self {
            server_addr,
            controller: controller,
            mempool: mempool,
            network_manager: network_manager,
            rpc_service: rpc_service,
            block_timer: Arc::new(RwLock::new(None)),
        })
    }
}

#[tonic::async_trait]
impl Vm for VirtualMachine {
    async fn initialize(
        &self,
        request: Request<vm::InitializeRequest>,
    ) -> Result<tonic::Response<vm::InitializeResponse>, Status> {
        let genesis_bytes = request.get_ref().genesis_bytes.clone();
        let db_path = request.get_ref().chain_data_dir.clone();
        let server_addr = request.get_ref().server_addr.clone();
        let controller = self.controller.clone();
        let mut controller = controller.write().await;

        // Initialize the controller with the genesis bytes
        controller
            .initialize(&genesis_bytes, db_path)
            .map_err(|e| Status::internal(format!("could not initialize controller: {}", e)))?;

        let network_manager = Arc::clone(&self.network_manager);
        let mut network_manager = network_manager.write().await;
        network_manager.set_server_address(server_addr.clone());

        let mempool = Arc::clone(&self.mempool);
        let mut mempool = mempool.write().await;
        mempool.set_server_address(server_addr.clone());

        build_block_timer(self.mempool.clone());

        return Ok(Response::new(vm::InitializeResponse {
            last_accepted_id: controller.last_accepted_block().id().as_bytes().to_vec(),
            last_accepted_parent_id: controller
                .last_accepted_block()
                .parent_id
                .as_bytes()
                .to_vec(),
            height: controller.last_accepted_block().height,
            bytes: controller.last_accepted_block().bytes(),
            timestamp: Some(controller.last_accepted_block().timestamp.into()),
        }));
    }

    async fn set_state(
        &self,
        _request: Request<vm::SetStateRequest>,
    ) -> Result<tonic::Response<vm::SetStateResponse>, Status> {
        let controller = self.controller.clone();
        let controller = controller.read().await;

        return Ok(Response::new(vm::SetStateResponse {
            last_accepted_id: controller.last_accepted_block().id().as_bytes().to_vec(),
            last_accepted_parent_id: controller
                .last_accepted_block()
                .parent_id
                .as_bytes()
                .to_vec(),
            height: controller.last_accepted_block().height,
            bytes: controller.last_accepted_block().bytes(),
            timestamp: Some(controller.last_accepted_block().timestamp.into()),
        }));
    }

    async fn shutdown(&self, _request: Request<()>) -> Result<tonic::Response<()>, Status> {
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
        request: Request<vm::BuildBlockRequest>,
    ) -> Result<tonic::Response<vm::BuildBlockResponse>, Status> {
        info!("received request: {:?}", request);
        let controller = self.controller.clone();
        let controller = controller.write().await;
        let block = controller
            .build_block(self.mempool.clone())
            .await
            .map_err(|_| Status::internal("could not build block"))?;
        Ok(Response::new(vm::BuildBlockResponse {
            id: block.id().into(),
            parent_id: block.parent_id.into(),
            height: block.height,
            bytes: block.bytes(),
            timestamp: Some(block.timestamp.into()),
            verify_with_context: false,
        }))
    }

    async fn parse_block(
        &self,
        request: Request<vm::ParseBlockRequest>,
    ) -> Result<tonic::Response<vm::ParseBlockResponse>, Status> {
        let controller = self.controller.clone();
        let controller = controller.read().await;
        let block = controller
            .parse_block(&request.get_ref().bytes)
            .map_err(|_| Status::internal("could not parse block"))?;
        Ok(Response::new(vm::ParseBlockResponse {
            id: block.id().into(),
            parent_id: block.parent_id.into(),
            height: block.height,
            timestamp: Some(block.timestamp.into()),
            verify_with_context: false,
        }))
    }

    async fn get_block(
        &self,
        request: Request<vm::GetBlockRequest>,
    ) -> Result<tonic::Response<vm::GetBlockResponse>, Status> {
        let controller = self.controller.clone();
        let controller = controller.read().await;
        let block_id: Id = request
            .get_ref()
            .id
            .clone()
            .try_into()
            .map_err(|_| Status::invalid_argument("invalid block id"))?;
        let block = controller
            .get_block(block_id)
            .map_err(|_| Status::internal("could not get block"))?;

        if block.is_none() {
            return Ok(Response::new(vm::GetBlockResponse {
                parent_id: vec![],
                bytes: vec![],
                height: 0,
                timestamp: None,
                verify_with_context: false,
                err: vm::Error::NotFound as i32,
            }));
        }

        let block = block.unwrap();

        Ok(Response::new(vm::GetBlockResponse {
            parent_id: block.parent_id.into(),
            bytes: block.bytes(),
            height: block.height,
            timestamp: Some(block.timestamp.into()),
            verify_with_context: false,
            err: 0,
        }))
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
        request: Request<vm::AppRequestMsg>,
    ) -> Result<tonic::Response<()>, Status> {
        info!("received request: {:?}", request);
        Ok(Response::new(()))
    }

    async fn app_request_failed(
        &self,
        request: Request<vm::AppRequestFailedMsg>,
    ) -> Result<tonic::Response<()>, Status> {
        info!("received request: {:?}", request);
        Ok(Response::new(()))
    }

    async fn app_response(
        &self,
        request: Request<vm::AppResponseMsg>,
    ) -> Result<tonic::Response<()>, Status> {
        info!("received request: {:?}", request);
        Ok(Response::new(()))
    }

    async fn app_gossip(
        &self,
        request: Request<vm::AppGossipMsg>,
    ) -> Result<tonic::Response<()>, Status> {
        info!("received request: {:?}", request);
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
        info!("received request: {:?}", request);
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
            parsed_blocks.push(ParseBlockResponse {
                id: block.id().into(),
                parent_id: block.parent_id.into(),
                height: block.height,
                timestamp: Some(block.timestamp.into()),
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
        let block = controller
            .get_block_by_height(request.get_ref().height)
            .map_err(|_| Status::internal("could not get block by height"))?;

        if block.is_none() {
            return Ok(Response::new(vm::GetBlockIdAtHeightResponse {
                blk_id: vec![].into(),
                err: vm::Error::NotFound as i32,
            }));
        }

        Ok(Response::new(vm::GetBlockIdAtHeightResponse {
            blk_id: block.unwrap().id().as_bytes().to_vec(),
            err: 0,
        }))
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

    async fn block_verify(
        &self,
        request: Request<vm::BlockVerifyRequest>,
    ) -> Result<tonic::Response<vm::BlockVerifyResponse>, Status> {
        info!("received request: {:?}", request);
        let controller = self.controller.clone();
        let mut controller = controller.write().await;
        let block = controller
            .parse_block(&request.get_ref().bytes)
            .map_err(|_| Status::internal("could not parse block"))?;

        // Verify the block
        controller
            .verify_block(&block)
            .await
            .map_err(|_| Status::internal("could not verify block"))?;

        Ok(Response::new(vm::BlockVerifyResponse {
            timestamp: Some(block.timestamp.into()),
        }))
    }

    async fn block_accept(
        &self,
        request: Request<vm::BlockAcceptRequest>,
    ) -> Result<tonic::Response<()>, Status> {
        info!("received request: {:?}", request);
        let controller = self.controller.clone();
        let mut controller = controller.write().await;
        let block_id: Id = request
            .get_ref()
            .id
            .clone()
            .try_into()
            .map_err(|_| Status::invalid_argument("invalid block id"))?;
        controller
            .accept_block(&block_id)
            .await
            .map_err(|_| Status::internal("could not accept block"))?;

        Ok(Response::new(()))
    }

    async fn block_reject(
        &self,
        request: Request<vm::BlockRejectRequest>,
    ) -> Result<tonic::Response<()>, Status> {
        info!("received request: {:?}", request);
        Ok(Response::new(()))
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
