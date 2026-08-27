//! ICM / warp message envelopes, matching AvalancheGo `warp`.
//!
//! * [`UnsignedMessage`] is what a source chain produces and validators sign. Its
//!   id — a sha256 over the codec bytes — is what a relayer asks validators to
//!   sign and what a destination chain checks for replay.
//! * [`BitSetSignature`] is the aggregated BLS signature plus a bitset naming
//!   which validators (by index into the canonical set) contributed.
//! * [`Message`] pairs an unsigned message with its signature — the fully
//!   relayed artifact a destination chain verifies.

use pulsevm_crypto::bls::SIGNATURE_LEN;
use sha2::{
    Digest,
    Sha256,
};

use super::codec::{
    CodecError,
    Reader,
    Writer,
};

/// AvalancheGo registers `BitSetSignature` as the only signature implementation,
/// at type id 0, in the warp message codec.
const SIGNATURE_TYPE_ID_BITSET: u32 = 0;

/// A message a source chain wants delivered to another chain. Validators of the
/// source subnet sign the [`id`](UnsignedMessage::id) of this structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedMessage {
    /// Avalanche network id (mainnet/fuji/local) — binds a signature to a network.
    pub network_id: u32,
    /// The 32-byte blockchain id of the source chain.
    pub source_chain_id: [u8; 32],
    /// Opaque payload — typically a codec-encoded [`super::payload::AddressedCall`].
    pub payload: Vec<u8>,
}

impl UnsignedMessage {
    pub fn new(network_id: u32, source_chain_id: [u8; 32], payload: Vec<u8>) -> Self {
        UnsignedMessage {
            network_id,
            source_chain_id,
            payload,
        }
    }

    /// Serialize to the AvalancheGo codec bytes. These exact bytes are what gets
    /// hashed for the id and what a BLS signature is computed over.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_version();
        w.write_u32(self.network_id);
        w.write_raw(&self.source_chain_id);
        w.write_bytes(&self.payload);
        w.into_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        r.read_version()?;
        let network_id = r.read_u32()?;
        let source_chain_id = r.read_fixed::<32>()?;
        let payload = r.read_bytes()?;
        r.finish()?;
        Ok(UnsignedMessage {
            network_id,
            source_chain_id,
            payload,
        })
    }

    /// The message id: sha256 over the codec bytes (AvalancheGo
    /// `hashing.ComputeHash256Array`). This is the digest validators sign and the
    /// key a destination chain uses for replay protection.
    pub fn id(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.to_bytes());
        let out = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&out);
        id
    }
}

/// An aggregated BLS signature over an [`UnsignedMessage`], plus the bitset of
/// contributing validators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitSetSignature {
    /// Big-endian bitset: bit `i` set means the validator at canonical index `i`
    /// contributed to the aggregate signature.
    pub signers: Vec<u8>,
    /// The 96-byte aggregated BLS signature.
    pub signature: [u8; SIGNATURE_LEN],
}

impl BitSetSignature {
    /// Encode just the signature portion (type id + fields), as it appears inside
    /// a [`Message`].
    fn write_into(&self, w: &mut Writer) {
        w.write_u32(SIGNATURE_TYPE_ID_BITSET);
        w.write_bytes(&self.signers);
        w.write_raw(&self.signature);
    }

    fn read_from(r: &mut Reader) -> Result<Self, CodecError> {
        let type_id = r.read_u32()?;
        if type_id != SIGNATURE_TYPE_ID_BITSET {
            return Err(CodecError::UnknownTypeId(type_id));
        }
        let signers = r.read_bytes()?;
        let signature = r.read_fixed::<SIGNATURE_LEN>()?;
        Ok(BitSetSignature { signers, signature })
    }
}

/// A signed, fully relayable warp message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub unsigned: UnsignedMessage,
    pub signature: BitSetSignature,
}

impl Message {
    pub fn new(unsigned: UnsignedMessage, signature: BitSetSignature) -> Self {
        Message {
            unsigned,
            signature,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_version();
        // Inline the unsigned message fields (AvalancheGo embeds UnsignedMessage).
        w.write_u32(self.unsigned.network_id);
        w.write_raw(&self.unsigned.source_chain_id);
        w.write_bytes(&self.unsigned.payload);
        self.signature.write_into(&mut w);
        w.into_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader::new(bytes);
        r.read_version()?;
        let network_id = r.read_u32()?;
        let source_chain_id = r.read_fixed::<32>()?;
        let payload = r.read_bytes()?;
        let signature = BitSetSignature::read_from(&mut r)?;
        r.finish()?;
        Ok(Message {
            unsigned: UnsignedMessage {
                network_id,
                source_chain_id,
                payload,
            },
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_unsigned() -> UnsignedMessage {
        UnsignedMessage::new(12345, [9u8; 32], b"payload-bytes".to_vec())
    }

    #[test]
    fn unsigned_roundtrip() {
        let m = sample_unsigned();
        let encoded = m.to_bytes();
        // version(2)+netid(4)+chainid(32)+len(4)+payload(13)
        assert_eq!(encoded.len(), 2 + 4 + 32 + 4 + 13);
        assert_eq!(UnsignedMessage::from_bytes(&encoded).unwrap(), m);
    }

    #[test]
    fn id_is_stable_and_payload_sensitive() {
        let m = sample_unsigned();
        let id1 = m.id();
        assert_eq!(id1, m.id());

        let mut m2 = m.clone();
        m2.payload.push(0xFF);
        assert_ne!(id1, m2.id());
    }

    #[test]
    fn signed_message_roundtrip() {
        let msg = Message::new(
            sample_unsigned(),
            BitSetSignature {
                signers: vec![0b0000_0101],
                signature: [3u8; SIGNATURE_LEN],
            },
        );
        let encoded = msg.to_bytes();
        assert_eq!(Message::from_bytes(&encoded).unwrap(), msg);
    }

    #[test]
    fn signed_message_embeds_unsigned_id() {
        // The unsigned id computed from a Message must equal the id of the
        // standalone unsigned message — i.e. the signature bytes are excluded.
        let unsigned = sample_unsigned();
        let msg = Message::new(
            unsigned.clone(),
            BitSetSignature {
                signers: vec![0xFF],
                signature: [1u8; SIGNATURE_LEN],
            },
        );
        assert_eq!(msg.unsigned.id(), unsigned.id());
    }
}
