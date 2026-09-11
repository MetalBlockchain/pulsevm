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
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
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
        // fc: header = 27 + 4 + recid, and `public_key(compact, digest, ..)`
        // rejects anything outside [27, 35) *before* touching the curve. The
        // range check is not optional there and is not gated on
        // `check_canonical`, so it applies on every path here too.
        //
        // Masking alone -- `(header - 27) & 3` -- accepts all 256 header values
        // and folds them onto four recovery ids, giving one signature 64
        // byte-distinct encodings that all recover the same key.
        let header = self.compact[0];
        if !(27..35).contains(&header) {
            return Err(K1Error::BadRecoveryHeader(header));
        }
        let recid = ((header as i32) - 27) & 3;
        RecoveryId::try_from(recid).map_err(K1Error::Secp)
    }

    #[allow(clippy::wrong_self_convention)]
    fn to_recoverable(&self) -> Result<RecoverableSignature, K1Error> {
        let recid = self.recovery_id()?;
        RecoverableSignature::from_compact(&self.compact[1..], recid).map_err(K1Error::Secp)
    }

    /// Recover the compressed public key that signed `digest` (32 raw bytes),
    /// enforcing fc's canonical-signature predicate.
    ///
    /// This is fc's `public_key(compact_signature, digest, check_canonical = true)`,
    /// the default there and the one every consensus path wants: a transaction
    /// or block signature that is not canonical must be rejected, or the
    /// malleated `(r, n-s)` form is accepted as an equally valid encoding of the
    /// same authorization.
    pub fn recover(&self, digest: &[u8; 32]) -> Result<K1PublicKey, K1Error> {
        self.recover_with_canonical_check(digest, true)
    }

    /// Recover *without* the canonical check.
    ///
    /// This is fc's `check_canonical = false`, which is exactly what the
    /// `recover_key` / `assert_recover_key` contract intrinsics pass. Contracts
    /// recover keys from signatures they were handed by arbitrary parties and
    /// must see the same accept/reject behaviour as nodeos, so tightening this
    /// path would diverge from the oracle rather than converge on it.
    ///
    /// Do not use this for transaction or block signatures.
    pub fn recover_non_canonical(&self, digest: &[u8; 32]) -> Result<K1PublicKey, K1Error> {
        self.recover_with_canonical_check(digest, false)
    }

    fn recover_with_canonical_check(
        &self,
        digest: &[u8; 32],
        check_canonical: bool,
    ) -> Result<K1PublicKey, K1Error> {
        if check_canonical && !self.is_canonical() {
            return Err(K1Error::NotCanonical);
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::k1::K1PrivateKey;

    /// The secp256k1 group order, big-endian.
    const ORDER: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ];

    /// `n - s`, big-endian, with borrow.
    fn negate_scalar(s: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let diff = ORDER[i] as i16 - s[i] as i16 - borrow;
            if diff < 0 {
                out[i] = (diff + 256) as u8;
                borrow = 1;
            } else {
                out[i] = diff as u8;
                borrow = 0;
            }
        }
        out
    }

    /// The ECDSA malleation: `(r, s, v) -> (r, n-s, v^1)`. Different bytes, same
    /// recovered key.
    fn malleate(sig: &K1Signature) -> K1Signature {
        let c = sig.compact65();
        let mut s = [0u8; 32];
        s.copy_from_slice(&c[33..65]);

        let mut out = c;
        out[33..65].copy_from_slice(&negate_scalar(&s));
        // Negating s flips the parity of the recovered point, so the recovery id
        // must flip its low bit to match. The header is `27 + 4 + recid`, and
        // that base is odd — so this has to go through the recid, not through
        // the header byte (31 ^ 1 == 30, which decodes to recid 3, not 1).
        let recid = (c[0] as i32 - 27) & 3;
        out[0] = (31 + (recid ^ 1)) as u8;
        K1Signature::from_compact65(&out)
    }

    fn signed() -> (K1PrivateKey, [u8; 32], K1Signature) {
        // A fixed digest keeps the test deterministic; the key is random, so the
        // signature differs each run and the properties must hold regardless.
        let key = K1PrivateKey::random();
        let digest = [0x42u8; 32];
        let sig = key.sign(&digest);
        (key, digest, sig)
    }

    #[test]
    fn signing_produces_a_canonical_signature() {
        // The signing loop grinds until canonical, so our own signatures must
        // always pass the check we now enforce on recovery.
        for _ in 0..32 {
            let (_key, digest, sig) = signed();
            assert!(
                sig.is_canonical(),
                "signing must yield a canonical signature"
            );
            assert!(sig.recover(&digest).is_ok());
        }
    }

    /// The core of the finding: the malleated signature is *different bytes* that
    /// recover the *same key*. Without the canonical check it is accepted, which
    /// is what let an attacker mint alternative encodings of someone else's
    /// signature.
    #[test]
    fn malleated_signature_recovers_the_same_key_but_is_rejected() {
        let (key, digest, sig) = signed();
        let expected = sig.recover(&digest).expect("original must recover");
        assert_eq!(expected.compressed(), key.public_key().compressed());

        let malleated = malleate(&sig);
        assert_ne!(
            malleated.compact65(),
            sig.compact65(),
            "malleation must change the bytes"
        );

        // Unchecked, it recovers the same key -- the malleability is real.
        let recovered = malleated
            .recover_non_canonical(&digest)
            .expect("malleated form must still recover without the canonical check");
        assert_eq!(
            recovered.compressed(),
            expected.compressed(),
            "the malleated signature must recover the same key"
        );

        // Checked, it is refused. This is the fix.
        assert!(
            matches!(malleated.recover(&digest), Err(K1Error::NotCanonical)),
            "the canonical check must reject the malleated form"
        );
    }

    #[test]
    fn header_outside_fc_range_is_rejected_on_both_paths() {
        let (_key, digest, sig) = signed();
        let c = sig.compact65();

        // fc accepts [27, 35) and rejects everything else before touching the
        // curve. Masking with `& 3` instead would fold these onto valid ids.
        for header in [0u8, 26, 35, 36, 200, 255] {
            let mut bytes = c;
            bytes[0] = header;
            let bad = K1Signature::from_compact65(&bytes);

            assert!(
                matches!(bad.recover(&digest), Err(K1Error::BadRecoveryHeader(h)) if h == header),
                "header {header} must be rejected by the checked path"
            );
            // The range check is not gated on `check_canonical` in fc, so the
            // intrinsic path rejects it too.
            assert!(
                matches!(
                    bad.recover_non_canonical(&digest),
                    Err(K1Error::BadRecoveryHeader(h)) if h == header
                ),
                "header {header} must be rejected by the unchecked path too"
            );
        }
    }

    #[test]
    fn shifted_header_no_longer_aliases_onto_a_valid_recovery_id() {
        // `(header - 27) & 3` mapped 64 distinct header bytes onto each recovery
        // id. Adding 4 lands outside fc's range and must now fail rather than
        // silently recovering the same key.
        let (_key, digest, sig) = signed();
        let c = sig.compact65();

        let mut shifted = c;
        shifted[0] = c[0].wrapping_add(4);
        let aliased = K1Signature::from_compact65(&shifted);

        assert!(
            aliased.recover(&digest).is_err(),
            "a header shifted by one recid period must not recover"
        );
    }

    /// The intrinsic path must stay lenient: fc passes `check_canonical = false`
    /// for `recover_key`/`assert_recover_key`, so tightening it would diverge
    /// from the oracle rather than converge on it.
    #[test]
    fn non_canonical_is_accepted_on_the_intrinsic_path() {
        let (_key, digest, sig) = signed();
        let malleated = malleate(&sig);

        assert!(
            !malleated.is_canonical(),
            "the malleated form is non-canonical"
        );
        assert!(
            malleated.recover_non_canonical(&digest).is_ok(),
            "the contract intrinsic path must still accept it"
        );
    }
}
