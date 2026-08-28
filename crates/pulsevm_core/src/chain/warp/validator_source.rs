//! Where a destination chain gets the *source* subnet's validator set.
//!
//! To verify an inbound ICM message, PulseVM needs the canonical validator set of
//! the chain that produced it, as of the relevant P-chain height. In production
//! that comes from MetalGo's validator-state service (the same gRPC channel
//! exposed at `Initialize`'s `server_addr`): resolve the blockchain id to its
//! subnet, then fetch `(nodeID -> {weight, BLS public key})` at a height. This
//! trait is that boundary — the verification logic depends only on it, so the
//! P-chain lookup can be swapped for a static set in tests and local clusters.

use super::validator::CanonicalValidatorSet;

/// Supplies the canonical validator set for a source chain.
pub trait ValidatorSetSource: Send + Sync {
    /// The canonical validator set for `source_chain_id`, or `None` if the chain
    /// (or its subnet) is unknown to this node.
    fn validator_set(&self, source_chain_id: &[u8; 32]) -> Option<CanonicalValidatorSet>;
}

/// A fixed, in-memory validator source: a map from source chain id to its
/// canonical set. Used by tests and single-subnet local clusters where the set
/// is known ahead of time rather than fetched from the P-chain.
#[derive(Default)]
pub struct StaticValidatorSource {
    sets: std::collections::HashMap<[u8; 32], CanonicalValidatorSet>,
}

impl StaticValidatorSource {
    pub fn new() -> Self {
        StaticValidatorSource {
            sets: std::collections::HashMap::new(),
        }
    }

    /// Register (or replace) the validator set for a source chain.
    pub fn insert(&mut self, source_chain_id: [u8; 32], set: CanonicalValidatorSet) {
        self.sets.insert(source_chain_id, set);
    }
}

impl ValidatorSetSource for StaticValidatorSource {
    fn validator_set(&self, source_chain_id: &[u8; 32]) -> Option<CanonicalValidatorSet> {
        self.sets.get(source_chain_id).cloned()
    }
}
