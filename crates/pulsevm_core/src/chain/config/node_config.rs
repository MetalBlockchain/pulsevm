use pulsevm_name::Name;
use serde::Deserialize;

use crate::crypto::PrivateKey;

#[derive(Clone, Deserialize)]
pub struct NodeConfig {
    pub producer_name: Name,
    pub producer_key: PrivateKey,
}
