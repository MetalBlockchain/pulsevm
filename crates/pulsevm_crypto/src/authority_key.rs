use core::fmt;

use p256::PublicKey as P256PublicKey;
use pulsevm_serialization::{
    NumBytes,
    Read,
    ReadError,
    Write,
    WriteError,
};
use serde::{
    Deserialize,
    Serialize,
};

use crate::k1::{
    K1PublicKey,
    decode_b58_checked,
    encode_b58_checked,
};

/// A public-key variant accepted by Antelope authorities.
///
/// The packed form is exactly `fc::raw::pack(public_key_type)`: the variant
/// index as a varuint, followed by the variant payload.  Keeping the tagged
/// payload intact matters for imported chainbase state: a WebAuthn key is not
/// interchangeable with the same P-256 point used as an R1 key.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AuthorityPublicKey {
    K1(K1PublicKey),
    R1([u8; 33]),
    WebAuthn {
        point: [u8; 33],
        /// `0`: none, `1`: user presence, `2`: user verification.
        user_presence: u8,
        rpid: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityKeyError(pub String);

impl fmt::Display for AuthorityKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for AuthorityKeyError {}

impl From<K1PublicKey> for AuthorityPublicKey {
    fn from(value: K1PublicKey) -> Self {
        Self::K1(value)
    }
}

impl AuthorityPublicKey {
    pub fn as_k1(&self) -> Option<K1PublicKey> {
        match self {
            Self::K1(key) => Some(*key),
            Self::R1(_) | Self::WebAuthn { .. } => None,
        }
    }

    /// Canonical Antelope binary representation, including the variant tag.
    pub fn to_packed(&self) -> Vec<u8> {
        match self {
            Self::K1(key) => key.to_packed().to_vec(),
            Self::R1(point) => {
                let mut out = Vec::with_capacity(34);
                out.push(1);
                out.extend_from_slice(point);
                out
            }
            Self::WebAuthn {
                point,
                user_presence,
                rpid,
            } => {
                let mut out = Vec::with_capacity(36 + rpid.len());
                out.push(2);
                out.extend_from_slice(point);
                out.push(*user_presence);
                write_varuint(rpid.len() as u64, &mut out);
                out.extend_from_slice(rpid.as_bytes());
                out
            }
        }
    }

    pub fn from_packed(bytes: &[u8]) -> Result<Self, AuthorityKeyError> {
        let mut pos = 0;
        let tag = read_varuint(bytes, &mut pos)?;
        let result = match tag {
            0 => {
                let point: [u8; 33] = take(bytes, &mut pos, 33)?.try_into().unwrap();
                Self::K1(
                    K1PublicKey::from_compressed(&point)
                        .map_err(|e| AuthorityKeyError(format!("invalid K1 authority key: {e}")))?,
                )
            }
            1 => Self::R1(read_p256_point(bytes, &mut pos, "R1")?),
            2 => {
                let point = read_p256_point(bytes, &mut pos, "WebAuthn")?;
                let user_presence = take_byte(bytes, &mut pos)?;
                if user_presence > 2 {
                    return Err(AuthorityKeyError(format!(
                        "invalid WebAuthn user-presence policy {user_presence}"
                    )));
                }
                let rpid_len = usize::try_from(read_varuint(bytes, &mut pos)?)
                    .map_err(|_| AuthorityKeyError("WebAuthn RP ID length is too large".into()))?;
                let rpid = take(bytes, &mut pos, rpid_len)?;
                let rpid = String::from_utf8(rpid.to_vec())
                    .map_err(|_| AuthorityKeyError("WebAuthn RP ID is not UTF-8".into()))?;
                if rpid.is_empty() {
                    return Err(AuthorityKeyError("WebAuthn RP ID cannot be empty".into()));
                }
                Self::WebAuthn {
                    point,
                    user_presence,
                    rpid,
                }
            }
            _ => {
                return Err(AuthorityKeyError(format!(
                    "unsupported authority public-key type {tag}"
                )));
            }
        };
        if pos != bytes.len() {
            return Err(AuthorityKeyError(
                "trailing bytes in authority public key".into(),
            ));
        }
        Ok(result)
    }

    /// Antelope JSON spelling (`PUB_K1_`, `PUB_R1_`, or `PUB_WA_`).
    #[allow(clippy::inherent_to_string_shadow_display)]
    pub fn to_string(&self) -> String {
        match self {
            Self::K1(key) => key.to_string(),
            Self::R1(point) => format!("PUB_R1_{}", encode_b58_checked(point, b"R1")),
            Self::WebAuthn {
                point,
                user_presence,
                rpid,
            } => {
                let mut data = Vec::with_capacity(35 + rpid.len());
                data.extend_from_slice(point);
                data.push(*user_presence);
                write_varuint(rpid.len() as u64, &mut data);
                data.extend_from_slice(rpid.as_bytes());
                format!("PUB_WA_{}", encode_b58_checked(&data, b"WA"))
            }
        }
    }

    pub fn from_string(s: &str) -> Result<Self, AuthorityKeyError> {
        if s.starts_with("PUB_K1_") {
            return K1PublicKey::from_string(s)
                .map(Self::K1)
                .map_err(|e| AuthorityKeyError(format!("invalid K1 authority key: {e}")));
        }
        if let Some(data) = s.strip_prefix("PUB_R1_") {
            let point = decode_b58_checked(data, 33, b"R1")
                .map_err(|e| AuthorityKeyError(format!("invalid R1 authority key: {e}")))?;
            let mut packed = vec![1];
            packed.extend_from_slice(&point);
            return Self::from_packed(&packed);
        }
        if let Some(data) = s.strip_prefix("PUB_WA_") {
            let raw = bs58::decode(data)
                .into_vec()
                .map_err(|_| AuthorityKeyError("invalid WebAuthn base58 data".into()))?;
            if raw.len() < 38 {
                return Err(AuthorityKeyError(
                    "WebAuthn base58 data is too short".into(),
                ));
            }
            let payload_len = raw.len() - 4;
            let payload = decode_b58_checked(data, payload_len, b"WA")
                .map_err(|e| AuthorityKeyError(format!("invalid WebAuthn authority key: {e}")))?;
            let mut packed = vec![2];
            packed.extend_from_slice(&payload);
            return Self::from_packed(&packed);
        }
        Err(AuthorityKeyError(
            "unsupported authority public-key prefix".into(),
        ))
    }
}

impl fmt::Display for AuthorityPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_string())
    }
}

impl fmt::Debug for AuthorityPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AuthorityPublicKey")
            .field(&self.to_string())
            .finish()
    }
}

impl Serialize for AuthorityPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for AuthorityPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_string(&value).map_err(serde::de::Error::custom)
    }
}

impl NumBytes for AuthorityPublicKey {
    fn num_bytes(&self) -> usize {
        self.to_packed().len()
    }
}

impl Read for AuthorityPublicKey {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let start = *pos;
        let end = packed_end(bytes, start).map_err(|e| ReadError::CustomError(e.to_string()))?;
        let key = Self::from_packed(&bytes[start..end])
            .map_err(|e| ReadError::CustomError(e.to_string()))?;
        *pos = end;
        Ok(key)
    }
}

impl Write for AuthorityPublicKey {
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        let packed = self.to_packed();
        let end = pos
            .checked_add(packed.len())
            .filter(|end| *end <= bytes.len())
            .ok_or(WriteError::NotEnoughSpace)?;
        bytes[*pos..end].copy_from_slice(&packed);
        *pos = end;
        Ok(())
    }
}

fn read_p256_point(
    bytes: &[u8],
    pos: &mut usize,
    name: &str,
) -> Result<[u8; 33], AuthorityKeyError> {
    let point: [u8; 33] = take(bytes, pos, 33)?.try_into().unwrap();
    P256PublicKey::from_sec1_bytes(&point)
        .map_err(|_| AuthorityKeyError(format!("invalid {name} P-256 public key")))?;
    Ok(point)
}

fn take<'a>(bytes: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8], AuthorityKeyError> {
    let end = pos
        .checked_add(len)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| AuthorityKeyError("truncated authority public key".into()))?;
    let result = &bytes[*pos..end];
    *pos = end;
    Ok(result)
}

fn take_byte(bytes: &[u8], pos: &mut usize) -> Result<u8, AuthorityKeyError> {
    Ok(take(bytes, pos, 1)?[0])
}

fn packed_end(bytes: &[u8], start: usize) -> Result<usize, AuthorityKeyError> {
    let mut pos = start;
    match read_varuint(bytes, &mut pos)? {
        0 | 1 => {
            take(bytes, &mut pos, 33)?;
        }
        2 => {
            take(bytes, &mut pos, 34)?;
            let len = usize::try_from(read_varuint(bytes, &mut pos)?)
                .map_err(|_| AuthorityKeyError("WebAuthn RP ID length is too large".into()))?;
            take(bytes, &mut pos, len)?;
        }
        tag => {
            return Err(AuthorityKeyError(format!(
                "unsupported authority public-key type {tag}"
            )));
        }
    }
    Ok(pos)
}

fn read_varuint(bytes: &[u8], pos: &mut usize) -> Result<u64, AuthorityKeyError> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let byte = take_byte(bytes, pos)?;
        let part = (byte & 0x7f) as u64;
        if shift == 63 && part > 1 {
            return Err(AuthorityKeyError(
                "authority public-key varuint overflows u64".into(),
            ));
        }
        value |= part << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(AuthorityKeyError(
        "authority public-key varuint is too long".into(),
    ))
}

fn write_varuint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AuthorityPublicKey;
    use pulsevm_serialization::{
        Read,
        Write,
    };

    #[test]
    fn webauthn_packed_and_json_forms_round_trip() {
        let packed = [
            2, 3, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63,
            0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39,
            0x45, 0xd8, 0x98, 0xc2, 0x96, 0, 17, b'f', b'c', b't', b'e', b's', b't', b'i', b'n',
            b'g', b'.', b'i', b'n', b'v', b'a', b'l', b'i', b'd',
        ];
        let key = AuthorityPublicKey::from_packed(&packed).unwrap();
        assert_eq!(key.to_packed(), packed);
        assert_eq!(
            AuthorityPublicKey::from_string(&key.to_string()).unwrap(),
            key
        );
        let bytes = key.pack().unwrap();
        assert_eq!(AuthorityPublicKey::read(&bytes, &mut 0).unwrap(), key);
        let json = serde_json::to_string(&key).unwrap();
        assert_eq!(
            serde_json::from_str::<AuthorityPublicKey>(&json).unwrap(),
            key
        );
    }
}
