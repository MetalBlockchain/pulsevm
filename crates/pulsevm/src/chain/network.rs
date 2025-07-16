use std::collections::HashMap;

use pulsevm_grpc::appsender::{SendAppGossipMsg, app_sender_client::AppSenderClient};
use tonic::Request;

use super::{error::ChainError, id::NodeId};

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

    pub async fn gossip(&self, gossipable: Vec<u8>) -> Result<(), ChainError> {
        let mut client: AppSenderClient<tonic::transport::Channel> =
            AppSenderClient::connect(format!("http://{}", self.server_address))
                .await
                .expect("failed to connect to appsender engine");
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
                msg: gossipable,
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
