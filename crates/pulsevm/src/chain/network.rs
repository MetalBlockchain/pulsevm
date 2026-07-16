use std::{collections::HashMap, time::Duration};

use pulsevm_core::{ChainError, id::NodeId};
use pulsevm_crypto::Bytes;
use pulsevm_grpc::appsender::{SendAppGossipMsg, app_sender_client::AppSenderClient};
use pulsevm_proc_macros::{NumBytes, Read, Write};
use pulsevm_serialization::{NumBytes, Read, Write};
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
    pub id: NodeId,
}

pub struct NetworkManager {
    connected_nodes: HashMap<NodeId, ConnectedNode>,
    server_address: String,
}

impl NetworkManager {
    pub fn new() -> Self {
        Self {
            connected_nodes: HashMap::new(),
            server_address: String::new(),
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
}
