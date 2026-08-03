use pulsevm_proc_macros::{NumBytes, Read, Write};
use serde::{Deserialize, Serialize};

use crate::chain::{crypto::PublicKey, name::Name};

/// A producer and the key its blocks must be signed with. This is the packed
/// element `set_proposed_producers` receives (a `vector<producer_key>`), and the
/// unit the active schedule is stored as.
#[derive(Debug, Clone, PartialEq, Eq, Read, Write, NumBytes, Serialize, Deserialize)]
pub struct ProducerKey {
    pub producer_name: Name,
    pub block_signing_key: PublicKey,
}

/// The active set of block producers. A block is valid only if signed by the
/// `block_signing_key` its `producer` holds here. Seeded from genesis and, once
/// `set_proposed_producers` is wired, updated by it — `version` bumps on every
/// change. This is the EOSIO producer schedule without the multi-round
/// activation delay, which is not needed while the chain is single-producer.
#[derive(Debug, Clone, PartialEq, Eq, Read, Write, NumBytes, Serialize, Deserialize, Default)]
pub struct ProducerSchedule {
    pub version: u32,
    pub producers: Vec<ProducerKey>,
}

impl ProducerSchedule {
    pub fn block_signing_key(&self, producer: &Name) -> Option<&PublicKey> {
        self.producers
            .iter()
            .find(|p| &p.producer_name == producer)
            .map(|p| &p.block_signing_key)
    }
}
