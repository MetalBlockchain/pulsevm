use core::fmt;
use std::sync::Arc;

use pulsevm_crypto::Digest;
use pulsevm_serialization::{NumBytes, Read, Write};
use secp256k1::hashes::{Hash, sha256};
use serde::Serialize;

use crate::chain::{Name, authority::PermissionLevel};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct Action {
    account: Name,
    name: Name,
    authorization: Vec<PermissionLevel>,
    #[serde(with = "arc_bytes_serde")]
    data: Arc<[u8]>,
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
            data: Arc::from(data),
            authorization,
        }
    }

    pub fn account(&self) -> Name {
        self.account
    }

    pub fn name(&self) -> Name {
        self.name
    }

    pub fn data(&self) -> Arc<[u8]> {
        Arc::clone(&self.data)
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

pub fn generate_action_digest(act: &Action, action_return_value: Option<Vec<u8>>) -> Digest {
    let mut bytes = act.pack().unwrap();
    if let Some(return_value) = action_return_value {
        bytes.extend(return_value);
    }
    Digest::hash(&bytes)
}

impl NumBytes for Action {
    fn num_bytes(&self) -> usize {
        self.account.num_bytes()
            + self.name.num_bytes()
            + self.authorization.num_bytes()
            + self.data.num_bytes()
    }
}

impl Read for Action {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        let account = Name::read(bytes, pos)?;
        let name = Name::read(bytes, pos)?;
        let authorization = Vec::<PermissionLevel>::read(bytes, pos)?;
        let data = Vec::<u8>::read(bytes, pos)?;
        Ok(Action::new(account, name, data, authorization))
    }
}

impl Write for Action {
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), pulsevm_serialization::WriteError> {
        self.account.write(bytes, pos)?;
        self.name.write(bytes, pos)?;
        self.authorization.write(bytes, pos)?;
        self.data.as_ref().to_vec().write(bytes, pos)?;
        Ok(())
    }
}

mod arc_bytes_serde {
    use serde::Serializer;

    use super::*;
    pub fn serialize<S>(data: &Arc<[u8]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // serialize as normal bytes (base64 for JSON)
        serializer.serialize_bytes(data)
    }
}