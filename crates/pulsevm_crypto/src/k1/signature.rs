use secp256k1::{
    Message,
    SECP256K1,
    ecdsa::{
        RecoverableSignature,
        RecoveryId,
    },
};

use super::{
    K1_SUFFIX,
    K1_TAG,
    K1Error,
    K1PublicKey,
    decode_b58_checked,
    encode_b58_checked,
};

/// A recoverable secp256k1 ECDSA signature in the EOSIO/Antelope `K1` encoding.
///
/// The canonical in-memory form is fc's 65-byte `compact_signature`:
/// `header || r[32] || s[32]`, where `header = 27 + 4 + recovery_id`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct K1Signature {
    /// header || r || s
    compact: [u8; 65],
}

impl K1Signature {
    /// Build from fc's raw 65-byte compact form (header + r + s).
    pub fn from_compact65(bytes: &[u8; 65]) -> Self {
        K1Signature { compact: *bytes }
    }

    /// fc's raw 65-byte compact form.
    pub fn compact65(&self) -> [u8; 65] {
        self.compact
    }

    /// The fc canonical-signature predicate (`public_key::is_canonical`):
    /// reject a high top bit or an unnecessary leading zero byte on either of
    /// the `r` or `s` big-endian integers.
    pub fn is_canonical(&self) -> bool {
        let c = &self.compact;
        // c[0] = header, c[1..33] = r, c[33..65] = s
        (c[1] & 0x80) == 0
            && !(c[1] == 0 && (c[2] & 0x80) == 0)
            && (c[33] & 0x80) == 0
            && !(c[33] == 0 && (c[34] & 0x80) == 0)
    }

    fn recovery_id(&self) -> Result<RecoveryId, K1Error> {
        // fc: header = 27 + 4 + recid, recovered as `(header - 27) & 3`.
        let recid = ((self.compact[0] as i32) - 27) & 3;
        RecoveryId::try_from(recid).map_err(K1Error::Secp)
    }

    #[allow(clippy::wrong_self_convention)]
    fn to_recoverable(&self) -> Result<RecoverableSignature, K1Error> {
        let recid = self.recovery_id()?;
        RecoverableSignature::from_compact(&self.compact[1..], recid).map_err(K1Error::Secp)
    }

    /// Recover the compressed public key that signed `digest` (32 raw bytes).
    pub fn recover(&self, digest: &[u8; 32]) -> Result<K1PublicKey, K1Error> {
        let msg = Message::from_digest(*digest);
        let sig = self.to_recoverable()?;
        let key = SECP256K1.recover_ecdsa(&msg, &sig)?;
        Ok(K1PublicKey::from_secp(&key))
    }

    /// The 66-byte `fc::raw::pack` form: a `0x00` K1 tag followed by the 65
    /// compact bytes.
    pub fn to_packed(&self) -> [u8; 66] {
        let mut out = [0u8; 66];
        out[0] = K1_TAG;
        out[1..].copy_from_slice(&self.compact);
        out
    }

    /// Parse the 66-byte packed form.
    pub fn from_packed(bytes: &[u8]) -> Result<Self, K1Error> {
        if bytes.len() != 66 {
            return Err(K1Error::BadLength);
        }
        if bytes[0] != K1_TAG {
            return Err(K1Error::BadKeyType);
        }
        let mut compact = [0u8; 65];
        compact.copy_from_slice(&bytes[1..]);
        Ok(K1Signature { compact })
    }

    /// The `SIG_K1_...` string form.
    #[allow(clippy::inherent_to_string_shadow_display)]
    pub fn to_string(&self) -> String {
        format!("SIG_K1_{}", encode_b58_checked(&self.compact, K1_SUFFIX))
    }

    /// Parse a `SIG_K1_...` string.
    pub fn from_string(s: &str) -> Result<Self, K1Error> {
        let data = s.strip_prefix("SIG_K1_").ok_or(K1Error::BadPrefix)?;
        let bytes = decode_b58_checked(data, 65, K1_SUFFIX)?;
        let mut compact = [0u8; 65];
        compact.copy_from_slice(&bytes);
        Ok(K1Signature { compact })
    }
}

impl core::fmt::Display for K1Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl core::fmt::Debug for K1Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "K1Signature({})", self.to_string())
    }
}
