use base64::{Engine, prelude::BASE64_STANDARD};
use pulsevm_proc_macros::{NumBytes, Read, Write};
use serde::Serialize;

#[derive(Clone, Default, NumBytes, Read, Write)]
pub struct Base64Bytes(pub Vec<u8>);

impl Base64Bytes {
    pub const fn new(bytes: Vec<u8>) -> Self {
        Base64Bytes(bytes)
    }

    pub fn to_base64(&self) -> String {
        BASE64_STANDARD.encode(&self.0)
    }
}

impl Serialize for Base64Bytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_base64())
    }
}
