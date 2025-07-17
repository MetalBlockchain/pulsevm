use std::collections::HashSet;

use pulsevm_serialization::{Deserialize, Serialize};
use secp256k1::hashes::{Hash, sha256};

use crate::chain::{Id, PrivateKey, PublicKey, Signature, error::ChainError};

use super::action::Action;

#[derive(Debug, Clone, PartialEq, Eq)]
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
        let mut bytes: Vec<u8> = Vec::new();
        self.serialize(&mut bytes);
        let digest = sha256::Hash::hash(&bytes);
        Id::from_sha256(&digest)
    }

    pub fn digest(&self) -> sha256::Hash {
        let mut bytes: Vec<u8> = Vec::new();
        self.unsigned_tx.serialize(&mut bytes);
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

impl Serialize for Transaction {
    fn serialize(&self, bytes: &mut Vec<u8>) {
        self.tx_type.serialize(bytes);
        self.unsigned_tx.serialize(bytes);
        self.signatures.serialize(bytes);
    }
}

impl Deserialize for Transaction {
    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let tx_type = u16::deserialize(data, pos)?;
        let unsigned_tx = UnsignedTransaction::deserialize(data, pos)?;
        let signatures = HashSet::<Signature>::deserialize(data, pos)?;
        Ok(Transaction {
            tx_type,
            unsigned_tx,
            signatures,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

impl Serialize for UnsignedTransaction {
    fn serialize(&self, bytes: &mut Vec<u8>) {
        self.blockchain_id.serialize(bytes);
        self.actions.serialize(bytes);
    }
}

impl Deserialize for UnsignedTransaction {
    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let blockchain_id = Id::deserialize(data, pos)?;
        let actions = Vec::<Action>::deserialize(data, pos)?;
        Ok(UnsignedTransaction {
            blockchain_id,
            actions,
        })
    }
}

#[allow(dead_code)]
#[must_use]
pub fn encode_action_data(data: Vec<Box<dyn Serialize>>) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    for action in data {
        action.serialize(&mut bytes);
    }
    bytes
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, str::FromStr, vec};

    use pulsevm_serialization::{Deserialize, Serialize};

    use crate::chain::{
        Id, Name, PrivateKey,
        authority::Authority,
        authority::KeyWeight,
        authority::PermissionLevel,
        transaction::transaction::{UnsignedTransaction, encode_action_data},
    };

    use super::{Action, Transaction};

    #[test]
    fn test_transaction_serialization() {
        let data = "0000e19b30bc0bfabfab01c9260469fab7529ae88987b2eb337dac5650305226b38e00000001aea38500000000009ab864229a9e40000000006eaea385000000000064553988000000000000000100000001027f4dbe05a88d4c3974cec8d03f192c96a9813ea4d60811c4e68a2d459842497c0001000000000000000100000001027f4dbe05a88d4c3974cec8d03f192c96a9813ea4d60811c4e68a2d459842497c00010000000000000001aea38500000000003232eda80000000000000001ada3bd9c65952513b98753bcc582cf368fb8bf8432e3e0389498a248756b209a0eb4e0846a1f85cad63fd2203cb1577514a902a54ae718a33552bb782fe11c960178ed5cd2";
        let bytes = hex::decode(data).unwrap();
        let _ = Transaction::deserialize(&bytes, &mut 0).unwrap();
    }

    #[test]
    fn test_p() {
        let private_key =
            PrivateKey::from_str("frqNAoTevNse58hUoJMDzPXDbfNicjCGjNz5VDgqqHJbhBBG9").unwrap();
        let tx = Transaction {
            tx_type: 0,
            unsigned_tx: UnsignedTransaction {
                blockchain_id: Id::from_str("2iMormvesjkHEuF4toW2WGvvKsrrFkytLjTjRWCvis43pTC3AJ")
                    .unwrap(),
                actions: vec![Action::new(
                    Name::from_str("pulse").unwrap(),
                    Name::from_str("newaccount").unwrap(),
                    encode_action_data(vec![
                        Box::new(Name::from_str("pulse").unwrap()),
                        Box::new(Name::from_str("glenn2").unwrap()),
                        Box::new(Authority::new(
                            1,
                            vec![KeyWeight::new(private_key.public_key(), 1)],
                            vec![],
                        )),
                        Box::new(Authority::new(
                            1,
                            vec![KeyWeight::new(private_key.public_key(), 1)],
                            vec![],
                        )),
                    ]),
                    vec![PermissionLevel::new(
                        Name::from_str("pulse").unwrap(),
                        Name::from_str("active").unwrap(),
                    )],
                )],
            },
            signatures: HashSet::new(),
        };
        let mut bytes: Vec<u8> = Vec::new();
        tx.serialize(&mut bytes);
        let hex = hex::encode(bytes);
        assert_eq!(
            hex,
            "0000e19b30bc0bfabfab01c9260469fab7529ae88987b2eb337dac5650305226b38e00000001aea38500000000009ab864229a9e40000000006eaea385000000000064553988000000000000000100000001027f4dbe05a88d4c3974cec8d03f192c96a9813ea4d60811c4e68a2d459842497c0001000000000000000100000001027f4dbe05a88d4c3974cec8d03f192c96a9813ea4d60811c4e68a2d459842497c00010000000000000001aea38500000000003232eda80000000000000001ada3bd9c65952513b98753bcc582cf368fb8bf8432e3e0389498a248756b209a0eb4e0846a1f85cad63fd2203cb1577514a902a54ae718a33552bb782fe11c960178ed5cd2"
        );
    }
}
