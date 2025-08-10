use std::any::Any;
use std::fmt;
use std::str::FromStr;

use pulsevm_serialization::{NumBytes, Read, Write};
use ripemd::{Digest, Ripemd160};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::hashes::{Hash, sha256};
use serde::{Deserialize, Serialize, ser};

use super::public_key::PublicKey;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SignatureError {
    InvalidSignature,
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignatureError::InvalidSignature => write!(f, "Invalid signature"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Signature(RecoverableSignature);

impl Signature {
    pub fn recover_public_key(&self, digest: &sha256::Hash) -> Result<PublicKey, SignatureError> {
        let msg = secp256k1::Message::from_digest(digest.to_byte_array());
        let pub_key = self
            .0
            .recover(&msg)
            .map_err(|_| SignatureError::InvalidSignature)?;
        Ok(PublicKey(pub_key))
    }
}

impl From<RecoverableSignature> for Signature {
    fn from(sig: RecoverableSignature) -> Self {
        Signature(sig)
    }
}

impl NumBytes for Signature {
    fn num_bytes(&self) -> usize {
        65 // 64 bytes for the signature + 1 byte for the recovery id
    }
}

impl Read for Signature {
    fn read(data: &[u8], pos: &mut usize) -> Result<Self, pulsevm_serialization::ReadError> {
        if *pos + 65 > data.len() {
            return Err(pulsevm_serialization::ReadError::NotEnoughBytes);
        }
        let mut serialized = [0u8; 64];
        serialized.copy_from_slice(&data[*pos..*pos + 64]);
        *pos += 64;
        let recovery_id = data[*pos];
        *pos += 1;
        let recovery_id = RecoveryId::try_from(recovery_id as i32)
            .map_err(|_| pulsevm_serialization::ReadError::ParseError)?;
        let recoverable_signature = RecoverableSignature::from_compact(&serialized, recovery_id)
            .map_err(|_| pulsevm_serialization::ReadError::ParseError)?;
        Ok(Signature(recoverable_signature))
    }
}

impl Write for Signature {
    fn write(
        &self,
        bytes: &mut [u8],
        pos: &mut usize,
    ) -> Result<(), pulsevm_serialization::WriteError> {
        if *pos + 65 > bytes.len() {
            return Err(pulsevm_serialization::WriteError::NotEnoughSpace);
        }
        let (recovery_id, serialized) = self.0.serialize_compact();
        bytes[*pos..*pos + 64].copy_from_slice(&serialized);
        *pos += 64;
        bytes[*pos] = recovery_id as u8;
        *pos += 1;
        Ok(())
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
        let s = String::deserialize(deserializer)?;
        Signature::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Step 1: Get compact form (64 bytes + recovery ID)
        let (rec_id, sig_bytes) = self.0.serialize_compact();
        let mut full_bytes = Vec::with_capacity(65);
        full_bytes.extend_from_slice(&sig_bytes[..]);
        full_bytes.push(rec_id as u8);

        // Step 2: Create EOS-style checksum: RIPEMD160(sig_bytes + "K1")
        let mut hasher = Ripemd160::new();
        hasher.update(&full_bytes);
        hasher.update(b"K1"); // EOS uses "K1" as suffix for secp256k1 signatures
        let digest = hasher.finalize();
        let checksum = &digest[..4]; // first 4 bytes

        // Step 3: Append checksum
        full_bytes.extend_from_slice(checksum);

        // Step 4: Base58 encode and format with EOS prefix
        let encoded = bs58::encode(&full_bytes).into_string();
        write!(f, "SIG_K1_{}", encoded)
    }
}

#[derive(Debug)]
pub enum SignatureParseError {
    InvalidPrefix,
    InvalidBase58(bs58::decode::Error),
    InvalidLength,
    InvalidChecksum,
    InvalidRecoveryId,
    InvalidSignature(secp256k1::Error),
}

impl fmt::Display for SignatureParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignatureParseError::InvalidPrefix => write!(f, "invalid signature prefix"),
            SignatureParseError::InvalidBase58(e) => write!(f, "base58 decoding error: {}", e),
            SignatureParseError::InvalidLength => write!(f, "invalid signature length"),
            SignatureParseError::InvalidChecksum => write!(f, "checksum verification failed"),
            SignatureParseError::InvalidRecoveryId => write!(f, "invalid recovery ID"),
            SignatureParseError::InvalidSignature(e) => write!(f, "invalid signature: {}", e),
        }
    }
}

impl FromStr for Signature {
    type Err = SignatureParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Step 1: Validate prefix
        let prefix = "SIG_K1_";
        if !s.starts_with(prefix) {
            return Err(SignatureParseError::InvalidPrefix);
        }

        // Step 2: Decode base58
        let data = bs58::decode(&s[prefix.len()..])
            .into_vec()
            .map_err(SignatureParseError::InvalidBase58)?;

        if data.len() != 65 + 4 {
            return Err(SignatureParseError::InvalidLength);
        }

        // Step 3: Split data and checksum
        let (sig_and_recid, checksum_provided) = data.split_at(65);
        let (sig_bytes, recid_byte) = sig_and_recid.split_at(64);

        // Step 4: Recompute checksum
        let mut hasher = Ripemd160::new();
        hasher.update(sig_and_recid); // signature + recid
        hasher.update(b"K1"); // EOS curve suffix
        let digest = hasher.finalize();
        let checksum_expected = &digest[..4];

        if checksum_expected != checksum_provided {
            return Err(SignatureParseError::InvalidChecksum);
        }

        // Step 5: Recover RecoveryId
        let recid = RecoveryId::try_from(recid_byte[0] as i32)
            .map_err(|_| SignatureParseError::InvalidRecoveryId)?;

        // Step 6: Rebuild signature
        let sig = RecoverableSignature::from_compact(sig_bytes, recid)
            .map_err(SignatureParseError::InvalidSignature)?;

        Ok(Signature(sig))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use pulsevm_serialization::{Read, Write};
    use secp256k1::hashes::{Hash, sha256};

    use crate::chain::{PrivateKey, Signature};

    #[test]
    fn test_signature_recovery() {
        let private_key = PrivateKey::random();
        let digest = sha256::Hash::hash(b"test");
        let signature = private_key.sign(&digest);
        let digest = sha256::Hash::hash(b"test");
        let public_key = signature
            .recover_public_key(&digest)
            .expect("Failed to recover public key");
        assert_eq!(public_key, private_key.public_key());
        let serialized = signature.pack().expect("Failed to serialize signature");
        let deserialized =
            Signature::read(&serialized, &mut 0).expect("Failed to deserialize signature");
        assert_eq!(signature, deserialized);
    }

    #[test]
    fn test_signature_display_and_parse() {
        let private_key = PrivateKey::random();
        let digest = sha256::Hash::hash(b"test");
        let signature = private_key.sign(&digest);
        let display_str = signature.to_string();
        assert!(display_str.starts_with("SIG_K1_"));
        assert!(display_str.len() > 10); // Ensure it's not just the prefix
        let parsed_signature = Signature::from_str(&display_str)
            .expect("Failed to parse signature from display string");
        assert_eq!(signature, parsed_signature);
    }
}
