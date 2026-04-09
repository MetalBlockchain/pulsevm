use std::collections::HashMap;

use pulsevm_crypto::Digest;
use pulsevm_error::ChainError;
use pulsevm_proc_macros::{NumBytes, Read, Write};
use pulsevm_serialization::Write;

use crate::chain::name::Name;

#[derive(Debug, Clone, PartialEq, Eq, Read, Write, NumBytes)]
pub struct ActionReceipt {
    pub receiver: Name,
    pub act_digest: Digest,
    pub global_sequence: u64,
    pub recv_sequence: u64,
    pub auth_sequence: HashMap<u64, u64>,
    pub code_sequence: u32,
    pub abi_sequence: u32,
}

impl ActionReceipt {
    pub fn new(
        receiver: Name,
        act_digest: Digest,
        global_sequence: u64,
        recv_sequence: u64,
        auth_sequence: HashMap<u64, u64>,
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

    pub fn add_auth_sequence(&mut self, name: u64, sequence: u64) {
        self.auth_sequence.insert(name, sequence);
    }

    pub fn digest(&self) -> Result<Digest, ChainError> {
        let packed = self
            .pack()
            .map_err(|e| ChainError::SerializationError(e.to_string()))?;

        Ok(Digest::hash(&packed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ACTIVE_NAME;

    #[test]
    fn test_action_receipt_digest() {
        let mut auth_sequence = HashMap::new();
        auth_sequence.insert(1, 100);
        auth_sequence.insert(2, 200);

        let receipt = ActionReceipt::new(
            ACTIVE_NAME,
            Digest::default(),
            12345,
            67890,
            auth_sequence,
            1,
            1,
        );

        let digest = receipt.digest().unwrap();
        assert_eq!(
            digest.to_string(),
            "aef915d3b57bc88c3a09423e051ca1084738e41c0d4c8d1d3f179aa0bec895b0"
        );
    }
}
