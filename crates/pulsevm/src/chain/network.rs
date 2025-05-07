use std::collections::HashMap;

use super::id::NodeId;

pub struct ConnectedNode {
    pub id: NodeId,
}

pub struct NetworkManager {
    pub connected_nodes: HashMap<NodeId, ConnectedNode>,
}

impl NetworkManager {
    pub fn new() -> Self {
        Self {
            connected_nodes: HashMap::new(),
        }
    }

    pub fn connected(&mut self, node_id: NodeId) {
        self.connected_nodes
            .insert(node_id, ConnectedNode { id: node_id });
    }

    pub fn disconnected(&mut self, node_id: NodeId) {
        self.connected_nodes.remove(&node_id);
    }
}
