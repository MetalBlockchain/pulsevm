use ecdsa::RecoveryId;
use p256::ecdsa::{
    Signature,
    VerifyingKey,
};

use crate::k1::{
    decode_b58_checked,
    encode_b58_checked,
};

/// A recoverable secp256r1/P-256 ECDSA signature in the Antelope `R1`
/// encoding.  Its compact bytes have the same `header || r || s` shape as K1,
/// but the curve and checksum suffix are different.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct R1Signature {
    compact: [u8; 65],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct R1Error(pub String);

impl core::fmt::Display for R1Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for R1Error {}

impl R1Signature {
    pub fn from_compact65(bytes: &[u8; 65]) -> Self {
        Self { compact: *bytes }
    }

    pub fn compact65(&self) -> [u8; 65] {
        self.compact
    }

    fn recovery_id(&self) -> Result<RecoveryId, R1Error> {
        // `fc::crypto::r1::private_key::sign_compact` stores 27 + 4 + recid.
        let byte = self.compact[0];
        let recid = byte
            .checked_sub(31)
            .filter(|recid| *recid <= 3)
            .ok_or_else(|| R1Error("invalid R1 compact-signature header".into()))?;
        RecoveryId::try_from(recid)
            .map_err(|_| R1Error("invalid R1 compact-signature recovery id".into()))
    }

    /// Recover the compressed P-256 public point that signed `digest`.
    pub fn recover(&self, digest: &[u8; 32]) -> Result<[u8; 33], R1Error> {
        let signature = Signature::from_slice(&self.compact[1..])
            .map_err(|_| R1Error("invalid R1 compact signature".into()))?;
        let key = VerifyingKey::recover_from_prehash(digest, &signature, self.recovery_id()?)
            .map_err(|_| R1Error("failed to recover R1 public key".into()))?;
        key.to_encoded_point(true)
            .as_bytes()
            .try_into()
            .map_err(|_| R1Error("recovered R1 public key has invalid length".into()))
    }

    /// The fixed 66-byte `fc::raw::pack` representation: R1 variant tag then
    /// the compact signature.
    pub fn to_packed(&self) -> [u8; 66] {
        let mut out = [0u8; 66];
        out[0] = 1;
        out[1..].copy_from_slice(&self.compact);
        out
    }

    pub fn from_packed(bytes: &[u8]) -> Result<Self, R1Error> {
        if bytes.len() != 66 {
            return Err(R1Error("invalid R1 packed signature length".into()));
        }
        if bytes[0] != 1 {
            return Err(R1Error("unexpected packed signature type".into()));
        }
        let mut compact = [0u8; 65];
        compact.copy_from_slice(&bytes[1..]);
        Ok(Self { compact })
    }

    #[allow(clippy::inherent_to_string_shadow_display)]
    pub fn to_string(&self) -> String {
        format!("SIG_R1_{}", encode_b58_checked(&self.compact, b"R1"))
    }

    pub fn from_string(s: &str) -> Result<Self, R1Error> {
        let data = s
            .strip_prefix("SIG_R1_")
            .ok_or_else(|| R1Error("invalid R1 signature prefix".into()))?;
        let bytes = decode_b58_checked(data, 65, b"R1")
            .map_err(|e| R1Error(format!("invalid R1 signature: {e}")))?;
        let mut compact = [0u8; 65];
        compact.copy_from_slice(&bytes);
        Ok(Self { compact })
    }
}

impl core::fmt::Display for R1Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_string())
    }
}

impl core::fmt::Debug for R1Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "R1Signature({})", self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::SigningKey;

    use super::R1Signature;

    #[test]
    fn r1_signature_recovers_and_round_trips() {
        let signing_key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let digest = [42u8; 32];
        let (signature, recovery_id) = signing_key.sign_prehash_recoverable(&digest).unwrap();
        let mut compact = [0u8; 65];
        compact[0] = 31 + recovery_id.to_byte();
        compact[1..].copy_from_slice(&signature.to_bytes());

        let r1 = R1Signature::from_compact65(&compact);
        assert_eq!(
            r1.recover(&digest).unwrap().as_slice(),
            signing_key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes(),
        );
        assert_eq!(R1Signature::from_string(&r1.to_string()).unwrap(), r1);
        assert_eq!(R1Signature::from_packed(&r1.to_packed()).unwrap(), r1);
    }
}
