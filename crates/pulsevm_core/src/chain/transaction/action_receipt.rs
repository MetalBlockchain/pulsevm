use std::collections::HashMap;

use pulsevm_crypto::Digest;
use pulsevm_proc_macros::{NumBytes, Read, Write};

use crate::chain::name::Name;

#[derive(Debug, Clone, PartialEq, Eq, Read, Write, NumBytes)]
pub struct ActionReceipt {
    pub receiver: Name,
    pub act_digest: Digest,
    pub global_sequence: u64,
    pub recv_sequence: u64,
    pub auth_sequence: HashMap<Name, u64>,
    pub code_sequence: u32,
    pub abi_sequence: u32,
}

impl ActionReceipt {
    pub fn new(
        receiver: Name,
        act_digest: Digest,
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
