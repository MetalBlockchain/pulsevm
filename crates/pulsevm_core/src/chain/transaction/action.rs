use core::fmt;
use std::sync::Arc;

use pulsevm_crypto::Digest as OurDigest;
use pulsevm_serialization::{
    NumBytes,
    Read,
    Write,
};
use serde::{
    Deserialize,
    Serialize,
};
use sha2::Digest;

use crate::chain::{
    Name,
    authority::PermissionLevel,
};

pub const ACTION_RETURN_VALUE_FEATURE_DIGEST: [u8; 32] = [
    0xc3, 0xa6, 0x13, 0x8c, 0x50, 0x61, 0xcf, 0x29, 0x13, 0x10, 0x88, 0x7c, 0x0b, 0x5c, 0x71, 0xfc,
    0xaf, 0xfe, 0xab, 0x90, 0xd5, 0xde, 0xb5, 0x0d, 0x3b, 0x9e, 0x68, 0x7c, 0xea, 0xd4, 0x50, 0x71,
];

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize, Default)]
pub struct Action {
    pub account: Name,
    pub name: Name,
    pub authorization: Vec<PermissionLevel>,
    #[serde(with = "arc_bytes_serde")]
    pub data: Arc<[u8]>,
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

    pub fn account(&self) -> &Name {
        &self.account
    }

    pub fn name(&self) -> &Name {
        &self.name
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

    pub fn digest(&self) -> [u8; 32] {
        let bytes: Vec<u8> = self.pack().unwrap();
        sha2::Sha256::digest(&bytes).into()
    }
}

/// Generate the action digest used by `action_receipt`.
///
/// Before `ACTION_RETURN_VALUE`, this is the hash of the packed action. Once
/// activated, Leap hashes the action base separately from the length-prefixed
/// input and output byte arrays, then hashes those two digests together. An
/// action that does not call `set_action_return_value` therefore passes an
/// empty (but still length-prefixed) output rather than using the legacy path.
pub fn generate_action_digest(act: &Action, action_return_value: Option<&[u8]>) -> OurDigest {
    let Some(action_return_value) = action_return_value else {
        return OurDigest::hash(&act.pack().expect("action serialization cannot fail"));
    };

    // Mirror Leap's single reusable buffer so the post-activation consensus
    // rule does not introduce several temporary allocations per action.
    let action_base_size =
        act.account.num_bytes() + act.name.num_bytes() + act.authorization.num_bytes();
    let input_and_output_size = act.data.as_ref().num_bytes() + action_return_value.num_bytes();
    let mut buffer = vec![0u8; action_base_size.max(input_and_output_size)];

    let mut position = 0;
    act.account
        .write(&mut buffer, &mut position)
        .expect("account serialization cannot fail");
    act.name
        .write(&mut buffer, &mut position)
        .expect("action-name serialization cannot fail");
    act.authorization
        .write(&mut buffer, &mut position)
        .expect("authorization serialization cannot fail");
    let left = OurDigest::hash(&buffer[..action_base_size]);

    position = 0;
    act.data
        .len()
        .write(&mut buffer, &mut position)
        .expect("action-data length serialization cannot fail");
    let input_end = position + act.data.len();
    buffer[position..input_end].copy_from_slice(&act.data);
    position = input_end;
    action_return_value
        .len()
        .write(&mut buffer, &mut position)
        .expect("action-return length serialization cannot fail");
    let output_end = position + action_return_value.len();
    buffer[position..output_end].copy_from_slice(action_return_value);
    let right = OurDigest::hash(&buffer[..input_and_output_size]);

    let mut digests = [0u8; 64];
    digests[..32].copy_from_slice(&left.0);
    digests[32..].copy_from_slice(&right.0);
    OurDigest::hash(&digests)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn action_return_value_digest_matches_xpr_activation_block() {
        let action = Action::new(
            Name::from_str("dex").unwrap(),
            Name::from_str("process").unwrap(),
            vec![100, 0, 1, 0],
            vec![PermissionLevel::new(
                Name::from_str("metallicusmm").unwrap().as_u64(),
                Name::from_str("active").unwrap().as_u64(),
            )],
        );

        assert_eq!(
            generate_action_digest(&action, None).to_string(),
            "07a540ba4a8826e09f7fefd001fcf850f3b0ae4abd548405c163acab1c1d2408"
        );
        assert_eq!(
            generate_action_digest(&action, Some(&[])).to_string(),
            "1fd62ea13c8feb99e8dd4dcb0b6def53b242a9cf2ea5e81da04f4a6e958bd979"
        );
    }
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
    fn write(
        &self,
        bytes: &mut [u8],
        pos: &mut usize,
    ) -> Result<(), pulsevm_serialization::WriteError> {
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
        let hex_string = hex::encode(data.as_ref());
        serializer.serialize_str(&hex_string)
    }

    use serde::Deserializer;
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Arc<[u8]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let str = String::deserialize(deserializer)?;
        let bytes = hex::decode(str).map_err(serde::de::Error::custom)?;
        Ok(Arc::from(bytes))
    }
}
