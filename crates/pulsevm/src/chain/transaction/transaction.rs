use std::collections::HashSet;

use pulsevm_proc_macros::{NumBytes, Read, Write};
use pulsevm_serialization::Write;
use secp256k1::hashes::{Hash, sha256};
use serde::{ser::SerializeStruct, Serialize};

use crate::chain::{
    Id, PrivateKey, PublicKey, Signature, SignedTransaction, TransactionCompression,
    TransactionHeader, error::ChainError, transaction::signed_transaction,
};

use super::action::Action;

#[derive(Debug, Clone, PartialEq, Eq, Read, Write, NumBytes, Hash)]
pub struct Transaction {
    pub header: TransactionHeader,
    pub actions: Vec<Action>, // Actions to be executed in this transaction
}

impl Transaction {
    pub fn new(header: TransactionHeader, actions: Vec<Action>) -> Self {
        Self { header, actions }
    }

    pub fn id(&self) -> Result<Id, ChainError> {
        Ok(Id::from_sha256(&self.digest()?))
    }

    pub fn digest(&self) -> Result<sha256::Hash, ChainError> {
        let bytes: Vec<u8> = self.pack().map_err(|e| {
            ChainError::SerializationError(format!("failed to pack transaction: {}", e))
        })?;
        Ok(sha256::Hash::hash(&bytes))
    }

    // Helper function for testing
    pub fn sign(&self, private_key: &PrivateKey) -> Result<SignedTransaction, ChainError> {
        let signed_transaction = SignedTransaction::new(self.clone(), HashSet::new());

        signed_transaction.sign(private_key)
    }
}

impl Serialize for Transaction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("Transaction", 4)?;
        state.serialize_field("expiration", &self.header.expiration)?;
        state.serialize_field("max_net_usage_words", &self.header.max_net_usage_words)?;
        state.serialize_field("max_cpu_usage_ms", &self.header.max_cpu_usage)?;
        state.serialize_field("actions", &self.actions)?;
        state.end()
    }
}

/* impl UnsignedTransaction {
    #[allow(dead_code)]
    pub fn new(blockchain_id: Id, actions: Vec<Action>) -> Self {
        Self {
            blockchain_id,
            actions,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, str::FromStr, vec};

    use pulsevm_proc_macros::name;
    use pulsevm_serialization::{Read, Write};

    use crate::chain::{
        Id, Name, PULSE_NAME, PrivateKey,
        authority::{Authority, KeyWeight, PermissionLevel},
        transaction::transaction::UnsignedTransaction,
    };

    use super::{Action, Transaction};

    #[test]
    fn test_transaction_serialization() {
        let data = "0000e19b30bc0bfabfab01c9260469fab7529ae88987b2eb337dac5650305226b38e00000001aea38500000000009ab864229a9e40000000006eaea385000000000064553988000000000000000100000001027f4dbe05a88d4c3974cec8d03f192c96a9813ea4d60811c4e68a2d459842497c0001000000000000000100000001027f4dbe05a88d4c3974cec8d03f192c96a9813ea4d60811c4e68a2d459842497c00010000000000000001aea38500000000003232eda80000000000000001ada3bd9c65952513b98753bcc582cf368fb8bf8432e3e0389498a248756b209a0eb4e0846a1f85cad63fd2203cb1577514a902a54ae718a33552bb782fe11c960178ed5cd2";
        let bytes = hex::decode(data).unwrap();
        let _ = Transaction::read(&bytes, &mut 0).unwrap();
    }

    #[test]
    fn test_p() {
        let private_key =
            PrivateKey::from_str("frqNAoTevNse58hUoJMDzPXDbfNicjCGjNz5VDgqqHJbhBBG9").unwrap();
        let action_data = (
            PULSE_NAME,
            name!("glenn2"),
            Authority::new(1, vec![KeyWeight::new(private_key.public_key(), 1)], vec![]),
            Authority::new(1, vec![KeyWeight::new(private_key.public_key(), 1)], vec![]),
        )
            .pack()
            .unwrap();
        let tx = Transaction {
            tx_type: 0,
            unsigned_tx: UnsignedTransaction {
                blockchain_id: Id::from_str("2iMormvesjkHEuF4toW2WGvvKsrrFkytLjTjRWCvis43pTC3AJ")
                    .unwrap(),
                actions: vec![Action::new(
                    Name::from_str("pulse").unwrap(),
                    Name::from_str("newaccount").unwrap(),
                    action_data,
                    vec![PermissionLevel::new(
                        Name::from_str("pulse").unwrap(),
                        Name::from_str("active").unwrap(),
                    )],
                )],
            },
            signatures: HashSet::new(),
        };
        let mut bytes: Vec<u8> = tx.pack().unwrap();
        let hex = hex::encode(bytes);
        assert_eq!(
            hex,
            "0000e19b30bc0bfabfab01c9260469fab7529ae88987b2eb337dac5650305226b38e00000001aea38500000000009ab864229a9e40000000006eaea385000000000064553988000000000000000100000001027f4dbe05a88d4c3974cec8d03f192c96a9813ea4d60811c4e68a2d459842497c0001000000000000000100000001027f4dbe05a88d4c3974cec8d03f192c96a9813ea4d60811c4e68a2d459842497c00010000000000000001aea38500000000003232eda80000000000000001ada3bd9c65952513b98753bcc582cf368fb8bf8432e3e0389498a248756b209a0eb4e0846a1f85cad63fd2203cb1577514a902a54ae718a33552bb782fe11c960178ed5cd2"
        );
    }
}
 */
