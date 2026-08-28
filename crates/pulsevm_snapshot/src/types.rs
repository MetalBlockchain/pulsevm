//! Raw wire types that appear inside snapshot rows. Snapshot decoding keeps
//! curve points unchecked so it can report malformed source rows; consumers
//! can convert public keys into `pulsevm_crypto::AuthorityPublicKey` to perform
//! canonical curve and WebAuthn validation.

use pulsevm_crypto::{
    AuthorityKeyError,
    AuthorityPublicKey,
};

use pulsevm_serialization::{
    NumBytes,
    Read,
    ReadError,
    VarUint32,
};

fn read_exact<const N: usize>(bytes: &[u8], pos: &mut usize) -> Result<[u8; N], ReadError> {
    if bytes.len() < *pos + N {
        return Err(ReadError::NotEnoughBytes);
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[*pos..*pos + N]);
    *pos += N;
    Ok(out)
}

/// A WebAuthn public key (`fc::crypto::webauthn::public_key`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebAuthnPublicKey {
    /// Compressed R1 point.
    pub key: [u8; 33],
    /// `fc::crypto::webauthn::public_key::user_presence_t`.
    pub user_presence: u8,
    /// Relying-party id (domain) the credential is bound to.
    pub rpid: String,
}

/// An `fc::crypto::public_key` as packed inside snapshot rows: a variant tag
/// (unsigned varint) followed by the storage of the selected key type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotPublicKey {
    K1([u8; 33]),
    R1([u8; 33]),
    WebAuthn(WebAuthnPublicKey),
}

impl SnapshotPublicKey {
    /// The 33-byte curve point, whichever variant carries it.
    pub fn point(&self) -> &[u8; 33] {
        match self {
            SnapshotPublicKey::K1(k) | SnapshotPublicKey::R1(k) => k,
            SnapshotPublicKey::WebAuthn(w) => &w.key,
        }
    }

    /// The key rendered in the Antelope packed form (1-byte type tag + point),
    /// i.e. the same 34 bytes `pulsevm_crypto::K1PublicKey::to_packed` yields
    /// for K1 keys. WebAuthn keys have no fixed-width packed form and return
    /// the tag + point prefix only.
    pub fn to_tagged_point(&self) -> [u8; 34] {
        let (tag, point) = match self {
            SnapshotPublicKey::K1(k) => (0u8, k),
            SnapshotPublicKey::R1(k) => (1u8, k),
            SnapshotPublicKey::WebAuthn(w) => (2u8, &w.key),
        };
        let mut out = [0u8; 34];
        out[0] = tag;
        out[1..].copy_from_slice(point);
        out
    }
}

impl TryFrom<&SnapshotPublicKey> for AuthorityPublicKey {
    type Error = AuthorityKeyError;

    fn try_from(value: &SnapshotPublicKey) -> Result<Self, Self::Error> {
        let mut packed = Vec::with_capacity(value.num_bytes());
        match value {
            SnapshotPublicKey::K1(point) => {
                packed.push(0);
                packed.extend_from_slice(point);
            }
            SnapshotPublicKey::R1(point) => {
                packed.push(1);
                packed.extend_from_slice(point);
            }
            SnapshotPublicKey::WebAuthn(key) => {
                packed.push(2);
                packed.extend_from_slice(&key.key);
                packed.push(key.user_presence);
                let mut len = u32::try_from(key.rpid.len())
                    .map_err(|_| AuthorityKeyError("WebAuthn RP ID is too long".into()))?;
                loop {
                    let mut byte = (len & 0x7f) as u8;
                    len >>= 7;
                    if len != 0 {
                        byte |= 0x80;
                    }
                    packed.push(byte);
                    if len == 0 {
                        break;
                    }
                }
                packed.extend_from_slice(key.rpid.as_bytes());
            }
        }
        AuthorityPublicKey::from_packed(&packed)
    }
}

impl TryFrom<SnapshotPublicKey> for AuthorityPublicKey {
    type Error = AuthorityKeyError;

    fn try_from(value: SnapshotPublicKey) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl NumBytes for SnapshotPublicKey {
    fn num_bytes(&self) -> usize {
        match self {
            SnapshotPublicKey::K1(_) | SnapshotPublicKey::R1(_) => 1 + 33,
            SnapshotPublicKey::WebAuthn(w) => {
                1 + 33 + 1 + VarUint32(w.rpid.len() as u32).num_bytes() + w.rpid.len()
            }
        }
    }
}

impl Read for SnapshotPublicKey {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let tag = VarUint32::read(bytes, pos)?.0;
        match tag {
            0 => Ok(SnapshotPublicKey::K1(read_exact::<33>(bytes, pos)?)),
            1 => Ok(SnapshotPublicKey::R1(read_exact::<33>(bytes, pos)?)),
            2 => Ok(SnapshotPublicKey::WebAuthn(WebAuthnPublicKey {
                key: read_exact::<33>(bytes, pos)?,
                user_presence: u8::read(bytes, pos)?,
                rpid: String::read(bytes, pos)?,
            })),
            _ => Err(ReadError::CustomError(format!(
                "unknown public key variant tag {tag}"
            ))),
        }
    }
}

/// A WebAuthn signature (`fc::crypto::webauthn::signature`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebAuthnSignature {
    /// Compact R1 signature over the WebAuthn challenge.
    pub compact_signature: [u8; 65],
    /// Raw authenticator data.
    pub auth_data: Vec<u8>,
    /// The client data JSON the browser signed.
    pub client_json: String,
}

/// An `fc::crypto::signature` as packed inside snapshot rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotSignature {
    K1([u8; 65]),
    R1([u8; 65]),
    WebAuthn(WebAuthnSignature),
}

impl NumBytes for SnapshotSignature {
    fn num_bytes(&self) -> usize {
        match self {
            SnapshotSignature::K1(_) | SnapshotSignature::R1(_) => 1 + 65,
            SnapshotSignature::WebAuthn(w) => {
                1 + 65
                    + VarUint32(w.auth_data.len() as u32).num_bytes()
                    + w.auth_data.len()
                    + VarUint32(w.client_json.len() as u32).num_bytes()
                    + w.client_json.len()
            }
        }
    }
}

impl Read for SnapshotSignature {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let tag = VarUint32::read(bytes, pos)?.0;
        match tag {
            0 => Ok(SnapshotSignature::K1(read_exact::<65>(bytes, pos)?)),
            1 => Ok(SnapshotSignature::R1(read_exact::<65>(bytes, pos)?)),
            2 => Ok(SnapshotSignature::WebAuthn(WebAuthnSignature {
                compact_signature: read_exact::<65>(bytes, pos)?,
                auth_data: Vec::<u8>::read(bytes, pos)?,
                client_json: String::read(bytes, pos)?,
            })),
            _ => Err(ReadError::CustomError(format!(
                "unknown signature variant tag {tag}"
            ))),
        }
    }
}

/// A `block_signing_authority` variant. Only `v0` exists on any Antelope chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockSigningAuthority {
    V0(crate::rows::BlockSigningAuthorityV0),
}

impl NumBytes for BlockSigningAuthority {
    fn num_bytes(&self) -> usize {
        match self {
            BlockSigningAuthority::V0(v) => 1 + v.num_bytes(),
        }
    }
}

impl Read for BlockSigningAuthority {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let tag = VarUint32::read(bytes, pos)?.0;
        match tag {
            0 => Ok(BlockSigningAuthority::V0(
                crate::rows::BlockSigningAuthorityV0::read(bytes, pos)?,
            )),
            _ => Err(ReadError::CustomError(format!(
                "unknown block signing authority variant tag {tag}"
            ))),
        }
    }
}

/// A 256-bit secondary index key (`eosio::chain::key256_t`), kept as raw
/// little-endian bytes exactly as packed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct U256Key(pub [u8; 32]);

impl NumBytes for U256Key {
    fn num_bytes(&self) -> usize {
        32
    }
}

impl Read for U256Key {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        Ok(U256Key(read_exact::<32>(bytes, pos)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_a_k1_public_key() {
        let mut bytes = vec![0u8]; // variant tag 0 = K1
        bytes.extend([2u8; 33]);
        let mut pos = 0;
        let key = SnapshotPublicKey::read(&bytes, &mut pos).unwrap();
        assert_eq!(pos, 34);
        assert_eq!(key, SnapshotPublicKey::K1([2u8; 33]));
        assert_eq!(key.num_bytes(), 34);
        assert_eq!(key.to_tagged_point()[0], 0);
    }

    #[test]
    fn decodes_a_webauthn_public_key() {
        let mut bytes = vec![2u8]; // variant tag 2 = WebAuthn
        bytes.extend([3u8; 33]);
        bytes.push(1); // user_presence
        bytes.push(11); // rpid length (varuint)
        bytes.extend(b"example.com");
        let mut pos = 0;
        let key = SnapshotPublicKey::read(&bytes, &mut pos).unwrap();
        assert_eq!(pos, bytes.len());
        let SnapshotPublicKey::WebAuthn(wa) = &key else {
            panic!("expected WebAuthn key");
        };
        assert_eq!(wa.rpid, "example.com");
        assert_eq!(wa.user_presence, 1);
        assert_eq!(key.num_bytes(), bytes.len());
    }

    #[test]
    fn converts_a_snapshot_webauthn_key_to_the_canonical_authority_type() {
        let key = SnapshotPublicKey::WebAuthn(WebAuthnPublicKey {
            key: [
                3, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63,
                0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39,
                0x45, 0xd8, 0x98, 0xc2, 0x96,
            ],
            user_presence: 1,
            rpid: "example.com".into(),
        });
        let canonical = AuthorityPublicKey::try_from(&key).unwrap();
        assert!(matches!(
            canonical,
            AuthorityPublicKey::WebAuthn { rpid, .. } if rpid == "example.com"
        ));
    }

    #[test]
    fn rejects_an_unknown_key_tag() {
        let bytes = [9u8; 40];
        let mut pos = 0;
        assert!(SnapshotPublicKey::read(&bytes, &mut pos).is_err());
    }

    #[test]
    fn decodes_a_truncated_signature_as_an_error() {
        let bytes = [0u8; 30]; // K1 tag but only 29 payload bytes
        let mut pos = 0;
        assert!(SnapshotSignature::read(&bytes, &mut pos).is_err());
    }
}
