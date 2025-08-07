use core::fmt;

use pulsevm_proc_macros::{NumBytes, Read, Write};
use pulsevm_serialization::{Read, Write};
use secp256k1::hashes::{Hash, sha256};
use serde::Serialize;

use crate::chain::{Name, authority::PermissionLevel};

#[derive(Debug, Clone, PartialEq, Eq, Read, Write, NumBytes, Hash, Serialize)]
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

    pub fn data_as<T: Read>(&self) -> Result<T, pulsevm_serialization::ReadError> {
        let mut pos = 0;
        T::read(&self.data, &mut pos)
    }

    pub fn digest(&self) -> sha256::Hash {
        let bytes: Vec<u8> = self.pack().unwrap();
        sha256::Hash::hash(&bytes)
    }
}

pub fn generate_action_digest(act: &Action, action_return_value: Option<Vec<u8>>) -> sha256::Hash {
    let mut bytes = act.pack().unwrap();
    if let Some(return_value) = action_return_value {
        bytes.extend(return_value);
    }
    sha256::Hash::hash(&bytes)
}
