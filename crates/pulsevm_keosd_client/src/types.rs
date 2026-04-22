use std::collections::HashSet;

use pulsevm_core::crypto::Signature;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct SignedKeosdTransaction {
    pub signatures: HashSet<Signature>,
}
