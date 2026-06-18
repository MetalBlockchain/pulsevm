use std::collections::{BTreeSet, HashSet};

use pulsevm_core::crypto::Signature;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct SignedKeosdTransaction {
    pub signatures: BTreeSet<Signature>,
}
