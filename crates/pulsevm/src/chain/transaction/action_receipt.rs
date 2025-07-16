use std::collections::{HashMap, HashSet};

use crate::chain::{Id, Name};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionReceipt {
    receiver: Name,
    act_digest: Id,
    global_sequence: u64,
    recv_sequence: u64,
    auth_sequence: HashMap<Name, u64>,
    code_sequence: u32,
    abi_sequence: u32,
}
