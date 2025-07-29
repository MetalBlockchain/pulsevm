use std::collections::HashSet;

use pulsevm_proc_macros::{NumBytes, Read, Write};
use pulsevm_serialization::Write;
use secp256k1::hashes::{Hash, sha256};

use crate::chain::{Id, PrivateKey, PublicKey, Signature, error::ChainError};

use super::action::Action;

#[derive(Debug, Clone, PartialEq, Eq, Read, Write, NumBytes)]
pub struct Transaction {
    pub tx_type: u16, // Type of transaction (e.g., transfer, contract call)
    pub unsigned_tx: UnsignedTransaction, // Unsigned transaction data
    pub signatures: HashSet<Signature>, // Signatures of the transaction
}

impl Transaction {
    #[allow(dead_code)]
    pub fn new(tx_type: u16, unsigned_tx: UnsignedTransaction) -> Self {
        Self {
            tx_type,
            unsigned_tx,
            signatures: HashSet::new(),
        }
    }

    pub fn id(&self) -> Id {
        let bytes: Vec<u8> = self.pack().unwrap();
        let digest = sha256::Hash::hash(&bytes);
        Id::from_sha256(&digest)
    }

    pub fn digest(&self) -> sha256::Hash {
        let bytes: Vec<u8> = self.unsigned_tx.pack().unwrap();
        sha256::Hash::hash(&bytes)
    }

    #[must_use]
    pub fn recovered_keys(&self) -> Result<HashSet<PublicKey>, ChainError> {
        let mut recovered_keys: HashSet<PublicKey> = HashSet::new();
        let digest = self.digest();

        for signature in self.signatures.iter() {
            let public_key = signature
                .recover_public_key(&digest)
                .map_err(|e| ChainError::SignatureRecoverError(format!("{}", e)))?;
            recovered_keys.insert(public_key);
        }

        Ok(recovered_keys)
    }

    #[allow(dead_code)]
    pub fn sign(mut self, private_key: &PrivateKey) -> Self {
        let digest = self.digest();
        let signature = private_key.sign(&digest);
        self.signatures.insert(signature);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Read, Write, NumBytes)]
pub struct UnsignedTransaction {
    pub blockchain_id: Id, // ID of the chain on which this transaction exists (prevents replay attacks)
    pub actions: Vec<Action>, // Actions to be executed in this transaction
}

impl UnsignedTransaction {
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
