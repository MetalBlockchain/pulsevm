use pulsevm_serialization::Deserialize;

use super::{Name, authority::Authority};

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
