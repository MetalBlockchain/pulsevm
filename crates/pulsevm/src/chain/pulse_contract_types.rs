use pulsevm_serialization::{Deserialize, Serialize};

use super::{Name, authority::Authority};

pub struct NewAccount {
    pub creator: Name,
    pub name: Name,
    pub owner: Authority,
    pub active: Authority,
}

impl NewAccount {
    pub fn new(creator: Name, name: Name, owner: Authority, active: Authority) -> Self {
        NewAccount {
            creator,
            name,
            owner,
            active,
        }
    }
}

impl Serialize for NewAccount {
    fn serialize(&self, bytes: &mut Vec<u8>) {
        self.creator.serialize(bytes);
        self.name.serialize(bytes);
        self.owner.serialize(bytes);
        self.active.serialize(bytes);
    }
}

impl Deserialize for NewAccount {
    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let creator = Name::deserialize(data, pos)?;
        let name = Name::deserialize(data, pos)?;
        let owner = Authority::deserialize(data, pos)?;
        let active = Authority::deserialize(data, pos)?;
        Ok(NewAccount {
            creator,
            name,
            owner,
            active,
        })
    }
}

pub struct UpdateAuth {
    pub account: Name,
    pub permission: Name,
    pub parent: Name,
    pub auth: Authority,
}

impl Deserialize for UpdateAuth {
    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let account = Name::deserialize(data, pos)?;
        let permission = Name::deserialize(data, pos)?;
        let parent = Name::deserialize(data, pos)?;
        let auth = Authority::deserialize(data, pos)?;
        Ok(UpdateAuth {
            account,
            permission,
            parent,
            auth,
        })
    }
}

pub struct DeleteAuth {
    pub account: Name,
    pub permission: Name,
}

impl Deserialize for DeleteAuth {
    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let account = Name::deserialize(data, pos)?;
        let permission = Name::deserialize(data, pos)?;
        Ok(DeleteAuth {
            account,
            permission,
        })
    }
}

pub struct LinkAuth {
    pub account: Name,
    pub code: Name,
    pub message_type: Name,
    pub requirement: Name,
}

impl Deserialize for LinkAuth {
    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let account = Name::deserialize(data, pos)?;
        let code = Name::deserialize(data, pos)?;
        let message_type = Name::deserialize(data, pos)?;
        let requirement = Name::deserialize(data, pos)?;
        Ok(LinkAuth {
            account,
            code,
            message_type,
            requirement,
        })
    }
}

pub struct UnlinkAuth {
    pub account: Name,
    pub code: Name,
    pub message_type: Name,
}

impl Deserialize for UnlinkAuth {
    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let account = Name::deserialize(data, pos)?;
        let code = Name::deserialize(data, pos)?;
        let message_type = Name::deserialize(data, pos)?;
        Ok(UnlinkAuth {
            account,
            code,
            message_type,
        })
    }
}

pub struct SetCode {
    pub account: Name,
    pub vm_type: u8,
    pub vm_version: u8,
    pub code: Vec<u8>,
}

impl Deserialize for SetCode {
    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let account = Name::deserialize(data, pos)?;
        let vm_type = u8::deserialize(data, pos)?;
        let vm_version = u8::deserialize(data, pos)?;
        let code = Vec::<u8>::deserialize(data, pos)?;
        Ok(SetCode {
            account,
            vm_type,
            vm_version,
            code,
        })
    }
}

pub struct SetAbi {
    pub account: Name,
    pub abi: Vec<u8>,
}

impl Deserialize for SetAbi {
    fn deserialize(data: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let account = Name::deserialize(data, pos)?;
        let abi = Vec::<u8>::deserialize(data, pos)?;
        Ok(SetAbi { account, abi })
    }
}
