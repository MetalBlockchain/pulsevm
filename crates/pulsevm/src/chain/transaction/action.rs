use core::fmt;

use pulsevm_serialization::{Deserialize, Serialize};
use secp256k1::hashes::{Hash, sha256};

use crate::chain::{Name, authority::PermissionLevel};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action {
    account: Name,
    name: Name,
    data: Vec<u8>,
    authorization: Vec<PermissionLevel>,
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "action {{ account: {}, name: {}, data: {:?}, authorization: {:?} }}",
            self.account, self.name, self.data, self.authorization
        )
    }
}

impl Action {
    pub fn new(
        account: Name,
        name: Name,
        data: Vec<u8>,
        authorization: Vec<PermissionLevel>,
    ) -> Self {
        Action {
            account,
            name,
            data,
            authorization,
        }
    }

    pub fn account(&self) -> Name {
        self.account
    }

    pub fn name(&self) -> Name {
        self.name
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn authorization(&self) -> &[PermissionLevel] {
        &self.authorization
    }

    pub fn data_as<T: Deserialize>(&self) -> Result<T, pulsevm_serialization::ReadError> {
        let mut pos = 0;
        T::deserialize(&self.data, &mut pos)
    }

    pub fn digest(&self) -> sha256::Hash {
        let mut bytes: Vec<u8> = Vec::new();
        self.serialize(&mut bytes);
        sha256::Hash::hash(&bytes)
    }
}

impl Serialize for Action {
    fn serialize(&self, bytes: &mut Vec<u8>) {
        self.account.serialize(bytes);
        self.name.serialize(bytes);
        self.data.serialize(bytes);
        self.authorization.serialize(bytes);
    }
}

impl Deserialize for Action {
    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let account = Name::deserialize(&data, pos)?;
        let name = Name::deserialize(&data, pos)?;
        let action_data = Vec::<u8>::deserialize(&data, pos)?;
        let authorization = Vec::<PermissionLevel>::deserialize(&data, pos)?;
        Ok(Action {
            account,
            name,
            data: action_data,
            authorization,
        })
    }
}

pub fn generate_action_digest(act: &Action, action_return_value: Option<Vec<u8>>) -> sha256::Hash {
    let mut bytes: Vec<u8> = Vec::new();
    act.serialize(&mut bytes);
    if let Some(return_value) = action_return_value {
        return_value.serialize(&mut bytes);
    }
    sha256::Hash::hash(&bytes)
}
