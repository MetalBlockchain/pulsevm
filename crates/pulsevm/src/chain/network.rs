use std::{
    collections::HashMap,
    sync::{
        Arc,
        Mutex,
        atomic::{
            AtomicU32,
            Ordering,
        },
    },
    time::Duration,
};

use pulsevm_core::{
    ChainError,
    id::NodeId,
    state_sync::ChunkRequest,
};
use pulsevm_crypto::Bytes;
use pulsevm_grpc::appsender::{
    SendAppErrorMsg,
    SendAppGossipMsg,
    SendAppRequestMsg,
    SendAppResponseMsg,
    app_sender_client::AppSenderClient,
};
use pulsevm_proc_macros::{
    NumBytes,
    Read,
    Write,
};
use pulsevm_serialization::{
    NumBytes,
    Read,
    Write,
};
use tokio::sync::{
    RwLock,
    oneshot,
};
use tonic::Request;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum GossipType {
    Transaction = 0,
}

impl NumBytes for GossipType {
    fn num_bytes(&self) -> usize {
        2
    }
}

impl Read for GossipType {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let value = u16::read(bytes, pos)?;
        match value {
            0 => Ok(GossipType::Transaction),
            _ => Err(pulsevm_serialization::ReadError::CustomError(format!(
                "invalid GossipType value: {}",
                value
            ))),
        }
    }
}

impl Write for GossipType {
    fn write(
        &self,
        bytes: &mut [u8],
        pos: &mut usize,
    ) -> Result<(), pulsevm_serialization::WriteError> {
        (*self as u16).write(bytes, pos)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Write, Read, NumBytes)]
pub struct Gossipable {
    pub gossip_type: GossipType,
    pub data: Bytes,
}

impl Gossipable {
    pub fn new<T>(gossip_type: GossipType, data: T) -> Result<Self, ChainError>
    where
        T: Write,
    {
        let data = data.pack().map_err(|e| {
            ChainError::NetworkError(format!("failed to serialize gossipable data: {}", e))
        })?;

        Ok(Gossipable {
            gossip_type,
            data: data.into(),
        })
    }

    pub fn to_type<T>(&self) -> Result<T, ChainError>
    where
        T: Read,
    {
        T::read(&self.data.as_ref(), &mut 0).map_err(|e| {
            ChainError::NetworkError(format!("failed to deserialize gossipable data: {}", e))
        })
    }
}

pub struct ConnectedNode {
    #[allow(dead_code)]
    pub id: NodeId,
}

/// Outstanding chunk requests, keyed by the request id sent to peers. The
/// AppResponse / AppRequestFailed handlers complete the matching sender, waking
/// the download loop. Held in an `Arc<Mutex<_>>` so those handlers only need a
/// read lock on the `NetworkManager`.
type PendingChunks = Arc<Mutex<HashMap<u32, oneshot::Sender<Result<Vec<u8>, String>>>>>;

pub struct NetworkManager {
    connected_nodes: HashMap<NodeId, ConnectedNode>,
    server_address: String,
    pending: PendingChunks,
    next_request_id: Arc<AtomicU32>,
}

impl NetworkManager {
    pub fn new() -> Self {
        Self {
            connected_nodes: HashMap::new(),
            server_address: String::new(),
            pending: Arc::new(Mutex::new(HashMap::new())),
            next_request_id: Arc::new(AtomicU32::new(1)),
        }
    }

    pub fn connected(&mut self, node_id: NodeId) {
        self.connected_nodes
            .insert(node_id, ConnectedNode { id: node_id });
    }

    pub fn disconnected(&mut self, node_id: NodeId) {
        self.connected_nodes.remove(&node_id);
    }

    pub fn set_server_address(&mut self, address: String) {
        self.server_address = address;
    }

    pub fn connected_node_ids(&self) -> Vec<NodeId> {
        self.connected_nodes.keys().copied().collect()
    }

    /// Complete the download-loop future waiting on `request_id` with a chunk.
    pub fn resolve_response(&self, request_id: u32, response: Vec<u8>) {
        if let Some(tx) = self.pending.lock().unwrap().remove(&request_id) {
            let _ = tx.send(Ok(response));
        }
    }

    /// Fail the download-loop future waiting on `request_id` so it retries.
    pub fn fail_request(&self, request_id: u32, error: String) {
        if let Some(tx) = self.pending.lock().unwrap().remove(&request_id) {
            let _ = tx.send(Err(error));
        }
    }

    pub async fn gossip(&self, gossipable: Gossipable) -> Result<(), ChainError> {
        let channel =
            tonic::transport::Endpoint::from_shared(format!("http://{}", self.server_address))
                .map_err(|e| ChainError::NetworkError(format!("bad appsender address: {}", e)))?
                .connect_timeout(Duration::from_secs(5))
                .timeout(Duration::from_secs(5)) // applies to all requests on this channel
                .connect()
                .await
                .map_err(|e| {
                    ChainError::NetworkError(format!("failed to connect to appsender: {}", e))
                })?;
        let mut client = AppSenderClient::new(channel);
        let msg = gossipable.pack().map_err(|e| {
            ChainError::NetworkError(format!("failed to serialize gossipable: {}", e))
        })?;

        let result = client
            .send_app_gossip(Request::new(SendAppGossipMsg {
                node_ids: vec![], // don't hand-pick; let the engine sample
                validators: 3,
                non_validators: 0,
                peers: 2,
                msg: msg,
            }))
            .await;

        if result.is_err() {
            return Err(ChainError::NetworkError(format!(
                "failed to send gossip: {}",
                result.unwrap_err()
            )));
        }

        Ok(())
    }

    async fn connect_appsender(
        server: &str,
    ) -> Result<AppSenderClient<tonic::transport::Channel>, ChainError> {
        let channel = tonic::transport::Endpoint::from_shared(format!("http://{}", server))
            .map_err(|e| ChainError::NetworkError(format!("bad appsender address: {}", e)))?
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .connect()
            .await
            .map_err(|e| {
                ChainError::NetworkError(format!("failed to connect to appsender: {}", e))
            })?;
        Ok(AppSenderClient::new(channel))
    }

    /// Request one snapshot chunk from a connected peer, over AppRequest.
    ///
    /// Registers a pending entry keyed by request id, sends the request, and
    /// waits (with a timeout) for the AppResponse handler to complete it. Peers
    /// are tried in turn until one answers; the network lock is never held across
    /// the wait, so responses and peer churn proceed meanwhile. Each chunk is a
    /// fresh call, so a long download always sees the current peer set.
    pub async fn request_chunk(
        net: &Arc<RwLock<Self>>,
        req: &ChunkRequest,
    ) -> Result<Vec<u8>, ChainError> {
        let (peers, server, pending, next_id) = {
            let g = net.read().await;
            (
                g.connected_node_ids(),
                g.server_address.clone(),
                g.pending.clone(),
                g.next_request_id.clone(),
            )
        };
        if peers.is_empty() {
            return Err(ChainError::NetworkError(
                "state sync: no connected peers to fetch from".into(),
            ));
        }
        let body = req.encode();
        let mut last_err = String::from("no peer answered");
        for peer in peers {
            let request_id = next_id.fetch_add(1, Ordering::Relaxed);
            let (tx, rx) = oneshot::channel();
            pending.lock().unwrap().insert(request_id, tx);

            let mut client = match Self::connect_appsender(&server).await {
                Ok(c) => c,
                Err(e) => {
                    pending.lock().unwrap().remove(&request_id);
                    last_err = e.to_string();
                    continue;
                }
            };
            let sent = client
                .send_app_request(Request::new(SendAppRequestMsg {
                    node_ids: vec![peer.0.to_vec()],
                    request_id,
                    request: body.clone(),
                }))
                .await;
            if let Err(e) = sent {
                pending.lock().unwrap().remove(&request_id);
                last_err = e.to_string();
                continue;
            }

            match tokio::time::timeout(Duration::from_secs(30), rx).await {
                Ok(Ok(Ok(data))) => return Ok(data),
                Ok(Ok(Err(e))) => last_err = e,
                Ok(Err(_canceled)) => {
                    pending.lock().unwrap().remove(&request_id);
                    last_err = "response channel canceled".into();
                }
                Err(_timeout) => {
                    pending.lock().unwrap().remove(&request_id);
                    last_err = "chunk request timed out".into();
                }
            }
        }
        Err(ChainError::NetworkError(format!(
            "state sync: chunk request failed on all peers: {}",
            last_err
        )))
    }

    /// Answer a peer's AppRequest with the chunk bytes it asked for.
    pub async fn send_app_response(
        net: &Arc<RwLock<Self>>,
        node_id: NodeId,
        request_id: u32,
        response: Vec<u8>,
    ) -> Result<(), ChainError> {
        let server = net.read().await.server_address.clone();
        let mut client = Self::connect_appsender(&server).await?;
        client
            .send_app_response(Request::new(SendAppResponseMsg {
                node_id: node_id.0.to_vec(),
                request_id,
                response,
            }))
            .await
            .map_err(|e| ChainError::NetworkError(format!("send_app_response: {}", e)))?;
        Ok(())
    }

    /// Tell a peer we can't serve its AppRequest, so it retries elsewhere.
    pub async fn send_app_error(
        net: &Arc<RwLock<Self>>,
        node_id: NodeId,
        request_id: u32,
        code: i32,
        message: String,
    ) -> Result<(), ChainError> {
        let server = net.read().await.server_address.clone();
        let mut client = Self::connect_appsender(&server).await?;
        client
            .send_app_error(Request::new(SendAppErrorMsg {
                node_id: node_id.0.to_vec(),
                request_id,
                error_code: code,
                error_message: message,
            }))
            .await
            .map_err(|e| ChainError::NetworkError(format!("send_app_error: {}", e)))?;
        Ok(())
    }
}
