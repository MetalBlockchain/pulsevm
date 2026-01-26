use std::collections::HashMap;

use pulsevm_core::{ChainError, id::NodeId};
use pulsevm_crypto::Bytes;
use pulsevm_grpc::appsender::{SendAppGossipMsg, app_sender_client::AppSenderClient};
use pulsevm_proc_macros::{NumBytes, Read, Write};
use pulsevm_serialization::{Read, Write};
use tonic::Request;

#[derive(Debug, Clone, PartialEq, Eq, Write, Read, NumBytes)]
pub struct Gossipable {
    pub gossip_type: u16,
    pub data: Bytes,
}

impl Gossipable {
    pub fn new<T>(gossip_type: u16, data: T) -> Result<Self, ChainError>
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
        let mut client: AppSenderClient<tonic::transport::Channel> =
            AppSenderClient::connect(format!("http://{}", self.server_address))
                .await
                .expect("failed to connect to appsender engine");
        let msg = gossipable.pack().map_err(|e| {
            ChainError::NetworkError(format!("failed to serialize gossipable: {}", e))
        })?;

        let result = client
            .send_app_gossip(Request::new(SendAppGossipMsg {
                node_ids: self
                    .connected_nodes
                    .keys()
                    .map(|id| id.0.to_vec())
                    .collect(),
                validators: 3,
                non_validators: 2,
                peers: 5,
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
