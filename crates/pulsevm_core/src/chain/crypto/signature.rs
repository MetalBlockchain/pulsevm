use std::{
    fmt::{
        self,
        Debug,
        Display,
    },
    hash::{
        Hash,
        Hasher,
    },
    str::FromStr,
};

use pulsevm_crypto::{
    AuthorityPublicKey,
    Digest,
    FixedBytes,
    K1Signature,
    R1Signature,
};
use pulsevm_error::ChainError;
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

use crate::crypto::PublicKey;

/// A recoverable Antelope transaction signature. K1 and R1 have the same fixed
/// packed size; their first byte is the `fc::static_variant` index.
#[derive(Clone, Copy)]
pub struct Signature {
    inner: SignatureInner,
}

#[derive(Clone, Copy)]
enum SignatureInner {
    K1(K1Signature),
    R1(R1Signature),
}

impl Signature {
    pub fn new(inner: K1Signature) -> Self {
        Signature {
            inner: SignatureInner::K1(inner),
        }
    }

    pub fn new_r1(inner: R1Signature) -> Self {
        Signature {
            inner: SignatureInner::R1(inner),
        }
    }

    pub fn recover_authority_key(
        &self,
        digest: &Digest,
    ) -> Result<AuthorityPublicKey, ChainError> {
        match self.inner {
            SignatureInner::K1(signature) => signature
                .recover(digest.as_bytes())
                .map(AuthorityPublicKey::K1)
                .map_err(|e| ChainError::TransactionError(e.to_string())),
            SignatureInner::R1(signature) => signature
                .recover(digest.as_bytes())
                .map(AuthorityPublicKey::R1)
                .map_err(|e| ChainError::TransactionError(e.to_string())),
        }
    }

    pub fn recover_public_key(&self, digest: &Digest) -> Result<PublicKey, ChainError> {
        match self.recover_authority_key(digest)? {
            AuthorityPublicKey::K1(key) => Ok(PublicKey::new(key)),
            AuthorityPublicKey::R1(_) | AuthorityPublicKey::WebAuthn { .. } => {
                Err(ChainError::TransactionError(
                    "R1/WebAuthn signatures are not valid for this K1-only intrinsic".into(),
                ))
            }
        }
    }

    fn to_packed(&self) -> [u8; 66] {
        match self.inner {
            SignatureInner::K1(signature) => signature.to_packed(),
            SignatureInner::R1(signature) => signature.to_packed(),
        }
    }

    fn to_string(&self) -> String {
        match self.inner {
            SignatureInner::K1(signature) => signature.to_string(),
            SignatureInner::R1(signature) => signature.to_string(),
        }
    }
}

impl Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_string())
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_string())
    }
}

impl PartialOrd for Signature {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Signature {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.to_packed().cmp(&other.to_packed())
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.to_packed() == other.to_packed()
    }
}

impl Eq for Signature {}

impl Hash for Signature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.to_packed().hash(state);
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SigVisitor;

        impl<'de> serde::de::Visitor<'de> for SigVisitor {
            type Value = Signature;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string representing a signature")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Signature::from_str(v).map_err(|e| E::custom(e.to_string()))
            }
        }

        deserializer.deserialize_str(SigVisitor)
    }
}

impl NumBytes for Signature {
    fn num_bytes(&self) -> usize {
        66 // Fixed size for packed signature representation
    }
}

impl Read for Signature {
    fn read(bytes: &[u8], pos: &mut usize) -> Result<Self, ReadError> {
        let packed = FixedBytes::<66>::read(bytes, pos)?;
        let inner = match packed.as_ref()[0] {
            0 => SignatureInner::K1(
                K1Signature::from_packed(packed.as_ref())
                    .map_err(|e| ReadError::CustomError(e.to_string()))?,
            ),
            1 => SignatureInner::R1(
                R1Signature::from_packed(packed.as_ref())
                    .map_err(|e| ReadError::CustomError(e.to_string()))?,
            ),
            tag => {
                return Err(ReadError::CustomError(format!(
                    "unsupported packed signature type {tag}"
                )));
            }
        };
        Ok(Signature { inner })
    }
}

impl Write for Signature {
    fn write(&self, bytes: &mut [u8], pos: &mut usize) -> Result<(), WriteError> {
        let packed = FixedBytes::<66>(self.to_packed());
        packed.write(bytes, pos)
    }
}

impl Default for Signature {
    fn default() -> Self {
        Self::from_str(
            "SIG_K1_111111111111111111111111111111111111111111111111111111111111111116uk5ne",
        )
        .unwrap()
    }
}

impl FromStr for Signature {
    type Err = ChainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let inner = if s.starts_with("SIG_K1_") {
            SignatureInner::K1(K1Signature::from_string(s).map_err(|e| {
                ChainError::TransactionError(format!("failed to parse K1 signature: {e}"))
            })?)
        } else if s.starts_with("SIG_R1_") {
            SignatureInner::R1(R1Signature::from_string(s).map_err(|e| {
                ChainError::TransactionError(format!("failed to parse R1 signature: {e}"))
            })?)
        } else {
            return Err(ChainError::TransactionError(
                "unsupported signature type".into(),
            ));
        };
        Ok(Signature { inner })
    }
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::SigningKey;

    use super::Signature;
    use pulsevm_crypto::{AuthorityPublicKey, Digest, R1Signature};

    #[test]
    fn r1_signature_recovers_an_r1_authority_key() {
        let signing_key = SigningKey::from_bytes((&[11u8; 32]).into()).unwrap();
        let digest = Digest([99u8; 32]);
        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(digest.as_bytes())
            .unwrap();
        let mut compact = [0u8; 65];
        compact[0] = 31 + recovery_id.to_byte();
        compact[1..].copy_from_slice(&signature.to_bytes());

        let signature = Signature::new_r1(R1Signature::from_compact65(&compact));
        let AuthorityPublicKey::R1(key) = signature.recover_authority_key(&digest).unwrap()
        else {
            panic!("R1 signature recovered to a non-R1 authority key");
        };
        assert_eq!(key.as_slice(), signing_key.verifying_key().to_encoded_point(true).as_bytes());
    }
}
