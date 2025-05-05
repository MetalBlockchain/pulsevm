mod action;
pub use action::Action;

use pulsevm_serialization::{Deserialize, Serialize};

use super::{Id, Signature};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub tx_type: u16, // Type of transaction (e.g., transfer, contract call)
    pub unsigned_tx: UnsignedTransaction, // Unsigned transaction data
    pub signatures: Vec<Signature>, // Signatures of the transaction
}

impl Serialize for Transaction {
    fn serialize(
        &self,
        bytes: &mut Vec<u8>,
    ) {
        self.tx_type.serialize(bytes);
        self.unsigned_tx.serialize(bytes);
        self.signatures.serialize(bytes);
    }
}

impl Deserialize for Transaction {
    fn deserialize(
        data: &[u8],
        pos: &mut usize
    ) -> Result<Self, pulsevm_serialization::ReadError> {
        let tx_type = u16::deserialize(data, pos)?;
        let unsigned_tx = UnsignedTransaction::deserialize(data, pos)?;
        let signatures = Vec::<Signature>::deserialize(data, pos)?;
        Ok(Transaction { tx_type, unsigned_tx, signatures })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedTransaction {
    pub blockchain_id: Id, // ID of the chain on which this transaction exists (prevents replay attacks)
    pub actions: Vec<Action>, // Actions to be executed in this transaction
}

impl Serialize for UnsignedTransaction {
    fn serialize(
        &self,
        bytes: &mut Vec<u8>,
    ) {
        self.blockchain_id.serialize(bytes);
        self.actions.serialize(bytes);
    }
}

impl Deserialize for UnsignedTransaction {
    fn deserialize(
        data: &[u8],
        pos: &mut usize
    ) -> Result<Self, pulsevm_serialization::ReadError> {
        let blockchain_id = Id::deserialize(data, pos)?;
        let actions = Vec::<Action>::deserialize(data, pos)?;
        Ok(UnsignedTransaction { blockchain_id, actions })
    }
}

pub fn encode_action_data(data: Vec<Box<dyn Serialize>>) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    for action in data {
        action.serialize(&mut bytes);
    }
    bytes
}



mod tests {
    use std::{str::FromStr, vec};

    use pulsevm_serialization::{Deserialize, Serialize};

    use crate::chain::{transaction::{encode_action_data, UnsignedTransaction}, Authority, Id, KeyWeight, Name, PermissionLevel, PrivateKey, Signature};

    use super::{Action, Transaction};

    #[test]
    fn test_transaction_serialization() {
        let data = "0000e19b30bc0bfabfab01c9260469fab7529ae88987b2eb337dac5650305226b38e00000001aea38500000000009ab864229a9e40000000006eaea385000000000064553988000000000000000100000001027f4dbe05a88d4c3974cec8d03f192c96a9813ea4d60811c4e68a2d459842497c0001000000000000000100000001027f4dbe05a88d4c3974cec8d03f192c96a9813ea4d60811c4e68a2d459842497c00010000000000000001aea38500000000003232eda80000000000000001ada3bd9c65952513b98753bcc582cf368fb8bf8432e3e0389498a248756b209a0eb4e0846a1f85cad63fd2203cb1577514a902a54ae718a33552bb782fe11c960178ed5cd2";
        let bytes = hex::decode(data).unwrap();
        let tx = Transaction::deserialize(&bytes, &mut 0).unwrap();
    }

    #[test]
    fn test_p() {
        let private_key = PrivateKey::from_str("frqNAoTevNse58hUoJMDzPXDbfNicjCGjNz5VDgqqHJbhBBG9").unwrap();
        let tx = Transaction {
            tx_type: 0,
            unsigned_tx: UnsignedTransaction{
                blockchain_id: Id::from_str("2iMormvesjkHEuF4toW2WGvvKsrrFkytLjTjRWCvis43pTC3AJ").unwrap(),
                actions: vec![
                    Action::new(
                        Name::from_str("pulse").unwrap(),
                        Name::from_str("newaccount").unwrap(),
                        encode_action_data(
                            vec![
                                Box::new(Name::from_str("pulse").unwrap()),
                                Box::new(Name::from_str("glenn2").unwrap()),
                                Box::new(Authority::new(
                                    1,
                                    vec![
                                        KeyWeight::new(
                                            private_key.public_key(),
                                            1,
                                        ),
                                    ],
                                    vec![],
                                )),
                                Box::new(Authority::new(
                                    1,
                                    vec![
                                        KeyWeight::new(
                                            private_key.public_key(),
                                            1,
                                        ),
                                    ],
                                    vec![],
                                )),
                            ],
                        ),
                        vec![PermissionLevel::new(
                            Name::from_str("pulse").unwrap(),
                            Name::from_str("active").unwrap(),
                        )],
                    ),
                ]
            },
            signatures: vec![
                Signature::new([0u8; 65]),
            ],
        };
        let mut bytes: Vec<u8> = Vec::new();
        tx.serialize(&mut bytes);
        let hex = hex::encode(bytes);
        assert_eq!(hex, "0000e19b30bc0bfabfab01c9260469fab7529ae88987b2eb337dac5650305226b38e00000001aea38500000000009ab864229a9e40000000006eaea385000000000064553988000000000000000100000001027f4dbe05a88d4c3974cec8d03f192c96a9813ea4d60811c4e68a2d459842497c0001000000000000000100000001027f4dbe05a88d4c3974cec8d03f192c96a9813ea4d60811c4e68a2d459842497c00010000000000000001aea38500000000003232eda80000000000000001ada3bd9c65952513b98753bcc582cf368fb8bf8432e3e0389498a248756b209a0eb4e0846a1f85cad63fd2203cb1577514a902a54ae718a33552bb782fe11c960178ed5cd2");
    }
}