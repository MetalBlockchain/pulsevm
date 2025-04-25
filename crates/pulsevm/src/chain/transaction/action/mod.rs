use pulsevm_serialization::{Deserialize, Serialize};

use crate::chain::{Name, PermissionLevel};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action {
    account: Name,
    name: Name,
    data: Vec<u8>,
    authorization: Vec<PermissionLevel>,
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

    pub fn account(&self) -> &Name {
        &self.account
    }

    pub fn name(&self) -> &Name {
        &self.name
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn authorization(&self) -> &[PermissionLevel] {
        &self.authorization
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