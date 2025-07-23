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

impl ActionReceipt {
    pub fn new(
        receiver: Name,
        act_digest: Id,
        global_sequence: u64,
        recv_sequence: u64,
        auth_sequence: HashMap<Name, u64>,
        code_sequence: u32,
        abi_sequence: u32,
    ) -> Self {
        ActionReceipt {
            receiver,
            act_digest,
            global_sequence,
            recv_sequence,
            auth_sequence,
            code_sequence,
            abi_sequence,
        }
    }

    pub fn add_auth_sequence(&mut self, name: Name, sequence: u64) {
        self.auth_sequence.insert(name, sequence);
    }
}
