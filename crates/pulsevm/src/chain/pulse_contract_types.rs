use pulsevm_proc_macros::{NumBytes, Read, Write};

use crate::chain::AbiDefinition;

use super::{Name, authority::Authority};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes)]
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

#[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes)]
pub struct UpdateAuth {
    pub account: Name,
    pub permission: Name,
    pub parent: Name,
    pub auth: Authority,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes)]
pub struct DeleteAuth {
    pub account: Name,
    pub permission: Name,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes)]
pub struct LinkAuth {
    pub account: Name,
    pub code: Name,
    pub message_type: Name,
    pub requirement: Name,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes)]
pub struct UnlinkAuth {
    pub account: Name,
    pub code: Name,
    pub message_type: Name,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes)]
pub struct SetCode {
    pub account: Name,
    pub vm_type: u8,
    pub vm_version: u8,
    pub code: Vec<u8>,
}

impl SetCode {
    pub fn new(account: Name, vm_type: u8, vm_version: u8, code: Vec<u8>) -> Self {
        SetCode {
            account,
            vm_type,
            vm_version,
            code,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Read, Write, NumBytes)]
pub struct SetAbi {
    pub account: Name,
    pub abi: Vec<u8>,
}
