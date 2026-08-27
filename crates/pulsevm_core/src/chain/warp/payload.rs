//! ICM message payloads, matching AvalancheGo `warp/payload`.
//!
//! A warp [`UnsignedMessage`](super::message::UnsignedMessage) carries an opaque
//! `payload` blob. By convention that blob is itself a codec-encoded payload with
//! a leading version and a type id. Two payload kinds exist upstream:
//!
//! * `Hash` (type id 0) — attests to a 32-byte hash (e.g. a block id);
//! * `AddressedCall` (type id 1) — a message *from* a specific on-chain address,
//!   carrying an application payload. This is what smart-contract messaging uses.
//!
//! The type-id order is significant: it is the registration order in
//! AvalancheGo's payload codec and is part of the wire format.

use super::codec::{
    CodecError,
    Reader,
    Writer,
};

const TYPE_ID_HASH: u32 = 0;
const TYPE_ID_ADDRESSED_CALL: u32 = 1;

/// A payload attesting to a single 32-byte hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hash {
    pub hash: [u8; 32],
}

impl Hash {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_version();
        w.write_u32(TYPE_ID_HASH);
        w.write_raw(&self.hash);
        w.into_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        r.read_version()?;
        let type_id = r.read_u32()?;
        if type_id != TYPE_ID_HASH {
            return Err(CodecError::UnknownTypeId(type_id));
        }
        let hash = r.read_fixed::<32>()?;
        r.finish()?;
        Ok(Hash { hash })
    }
}

/// A message originating from a specific address on the source chain.
///
/// `source_address` identifies the sender (for PulseVM this is derived from the
/// sending account/contract); `payload` is the application-defined message body
/// the destination contract will consume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressedCall {
    pub source_address: Vec<u8>,
    pub payload: Vec<u8>,
}

impl AddressedCall {
    pub fn new(source_address: Vec<u8>, payload: Vec<u8>) -> Self {
        AddressedCall {
            source_address,
            payload,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_version();
        w.write_u32(TYPE_ID_ADDRESSED_CALL);
        w.write_bytes(&self.source_address);
        w.write_bytes(&self.payload);
        w.into_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        r.read_version()?;
        let type_id = r.read_u32()?;
        if type_id != TYPE_ID_ADDRESSED_CALL {
            return Err(CodecError::UnknownTypeId(type_id));
        }
        let source_address = r.read_bytes()?;
        let payload = r.read_bytes()?;
        r.finish()?;
        Ok(AddressedCall {
            source_address,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addressed_call_roundtrip() {
        let ac = AddressedCall::new(b"pulse.token".to_vec(), b"transfer(alice,bob,10)".to_vec());
        let encoded = ac.to_bytes();
        // version(2) + typeid(4) + len(4)+addr + len(4)+payload
        assert_eq!(
            encoded.len(),
            2 + 4 + 4 + ac.source_address.len() + 4 + ac.payload.len()
        );
        assert_eq!(AddressedCall::from_bytes(&encoded).unwrap(), ac);
    }

    #[test]
    fn addressed_call_type_id_on_the_wire() {
        let ac = AddressedCall::new(vec![], vec![]);
        let encoded = ac.to_bytes();
        // bytes 2..6 are the big-endian type id = 1
        assert_eq!(&encoded[2..6], &[0, 0, 0, 1]);
    }

    #[test]
    fn hash_roundtrip() {
        let h = Hash { hash: [7u8; 32] };
        let encoded = h.to_bytes();
        assert_eq!(&encoded[2..6], &[0, 0, 0, 0]);
        assert_eq!(Hash::from_bytes(&encoded).unwrap(), h);
    }

    #[test]
    fn wrong_type_id_rejected() {
        let h = Hash { hash: [0u8; 32] };
        // Decoding hash bytes as an AddressedCall must fail on the type id.
        assert!(matches!(
            AddressedCall::from_bytes(&h.to_bytes()),
            Err(CodecError::UnknownTypeId(0))
        ));
    }
}
