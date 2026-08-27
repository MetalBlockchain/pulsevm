//! BLS12-381 signatures, wire-compatible with AvalancheGo / MetalGo.
//!
//! Avalanche Interchain Messaging (ICM, formerly Avalanche Warp Messaging) signs
//! cross-chain messages with the validator's BLS key. To interoperate with
//! MetalGo validators and relayers, PulseVM must use the *exact* same scheme:
//!
//! * the `min-pk` variant of BLS12-381 — public keys live in G1 (48 bytes
//!   compressed), signatures live in G2 (96 bytes compressed);
//! * the hash-to-curve domain separation tags (DSTs) below, taken verbatim from
//!   AvalancheGo's `utils/crypto/bls` package;
//! * proof-of-possession over the compressed public key to guard against
//!   rogue-key attacks when public keys are aggregated.
//!
//! This module wraps `blst` — the same library (supranational/blst) AvalancheGo
//! uses — so the curve arithmetic is identical, not merely equivalent.
//!
//! Consensus-critical: the DSTs, key/signature lengths and the compressed
//! encodings must match MetalGo byte-for-byte. Changing any of them here silently
//! breaks verification of every message signed by a real validator.

use core::fmt;

use blst::{
    BLST_ERROR,
    min_pk::{
        AggregatePublicKey,
        AggregateSignature,
        PublicKey as BlstPublicKey,
        SecretKey as BlstSecretKey,
        Signature as BlstSignature,
    },
};

/// Length of a compressed BLS public key (a G1 point).
pub const PUBLIC_KEY_LEN: usize = 48;
/// Length of a compressed BLS signature (a G2 point).
pub const SIGNATURE_LEN: usize = 96;
/// Length of a BLS secret key scalar.
pub const SECRET_KEY_LEN: usize = 32;

/// Domain separation tag used when signing an arbitrary message. Matches
/// AvalancheGo `bls.CiphersuiteSignature`.
const CIPHERSUITE_SIGNATURE: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
/// Domain separation tag used for proofs of possession. Matches AvalancheGo
/// `bls.CiphersuiteProofOfPossession`.
const CIPHERSUITE_PROOF_OF_POSSESSION: &[u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Errors produced while parsing or using BLS objects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlsError {
    /// The byte blob had the wrong length for the object being parsed.
    BadLength,
    /// `blst` rejected the bytes (not on the curve, wrong subgroup, malformed).
    Deserialization,
    /// Key generation was given insufficient input keying material.
    KeyGen,
    /// Aggregation was asked to combine an empty set of keys/signatures.
    NoElements,
}

impl fmt::Display for BlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlsError::BadLength => write!(f, "invalid BLS object length"),
            BlsError::Deserialization => write!(f, "invalid BLS point encoding"),
            BlsError::KeyGen => write!(f, "BLS key generation failed"),
            BlsError::NoElements => write!(f, "cannot aggregate an empty set"),
        }
    }
}

impl std::error::Error for BlsError {}

/// A BLS secret key. Validators hold one of these; PulseVM only ever sees one in
/// local/dev signing (see [`crate::bls`] users) — in production the key stays
/// inside MetalGo and signing happens over gRPC.
#[derive(Clone)]
pub struct SecretKey(BlstSecretKey);

impl SecretKey {
    /// Derive a secret key from >= 32 bytes of input keying material (RFC 9380
    /// `KeyGen`). Deterministic in `ikm`, which makes it usable for tests and
    /// reproducible dev keys.
    pub fn from_ikm(ikm: &[u8]) -> Result<Self, BlsError> {
        BlstSecretKey::key_gen(ikm, &[])
            .map(SecretKey)
            .map_err(|_| BlsError::KeyGen)
    }

    /// Parse a raw 32-byte big-endian scalar, matching AvalancheGo's
    /// `SecretKeyToBytes` / `BytesToSecretKey`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlsError> {
        if bytes.len() != SECRET_KEY_LEN {
            return Err(BlsError::BadLength);
        }
        BlstSecretKey::from_bytes(bytes)
            .map(SecretKey)
            .map_err(|_| BlsError::Deserialization)
    }

    /// Serialize to 32 bytes.
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_LEN] {
        self.0.to_bytes()
    }

    /// The public key corresponding to this secret key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.sk_to_pk())
    }

    /// Sign an arbitrary message with the message ciphersuite.
    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature(self.0.sign(message, CIPHERSUITE_SIGNATURE, &[]))
    }

    /// Produce a proof of possession: a signature over this key's own compressed
    /// public key, under the PoP ciphersuite.
    pub fn sign_proof_of_possession(&self) -> Signature {
        let pk = self.public_key().to_bytes();
        Signature(self.0.sign(&pk, CIPHERSUITE_PROOF_OF_POSSESSION, &[]))
    }
}

/// A BLS public key (G1 point, 48-byte compressed encoding).
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey(BlstPublicKey);

impl PublicKey {
    /// Parse a 48-byte compressed public key, validating group membership.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlsError> {
        if bytes.len() != PUBLIC_KEY_LEN {
            return Err(BlsError::BadLength);
        }
        let pk = BlstPublicKey::from_bytes(bytes).map_err(|_| BlsError::Deserialization)?;
        // Reject the identity and off-subgroup points, as AvalancheGo does.
        pk.validate().map_err(|_| BlsError::Deserialization)?;
        Ok(PublicKey(pk))
    }

    /// Serialize to the 48-byte compressed encoding.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.0.compress()
    }

    /// Verify a proof of possession for this public key.
    pub fn verify_proof_of_possession(&self, pop: &Signature) -> bool {
        let msg = self.to_bytes();
        pop.0.verify(
            true,
            &msg,
            CIPHERSUITE_PROOF_OF_POSSESSION,
            &[],
            &self.0,
            true,
        ) == BLST_ERROR::BLST_SUCCESS
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", hex::encode(self.to_bytes()))
    }
}

/// A BLS signature (G2 point, 96-byte compressed encoding).
#[derive(Clone, PartialEq, Eq)]
pub struct Signature(BlstSignature);

impl Signature {
    /// Parse a 96-byte compressed signature, validating group membership.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlsError> {
        if bytes.len() != SIGNATURE_LEN {
            return Err(BlsError::BadLength);
        }
        let sig = BlstSignature::from_bytes(bytes).map_err(|_| BlsError::Deserialization)?;
        sig.validate(true).map_err(|_| BlsError::Deserialization)?;
        Ok(Signature(sig))
    }

    /// Serialize to the 96-byte compressed encoding.
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LEN] {
        self.0.compress()
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({})", hex::encode(self.to_bytes()))
    }
}

/// Verify a single signature over `message` under `public_key`, using the
/// message ciphersuite. This is the same predicate MetalGo uses, so a signature
/// produced by a validator verifies here and vice versa.
pub fn verify(public_key: &PublicKey, signature: &Signature, message: &[u8]) -> bool {
    signature.0.verify(
        true,
        message,
        CIPHERSUITE_SIGNATURE,
        &[],
        &public_key.0,
        true,
    ) == BLST_ERROR::BLST_SUCCESS
}

/// Aggregate several public keys into one. Used to combine the keys of the
/// validators that signed an ICM message so their aggregate signature can be
/// checked in a single pairing.
pub fn aggregate_public_keys(keys: &[PublicKey]) -> Result<PublicKey, BlsError> {
    if keys.is_empty() {
        return Err(BlsError::NoElements);
    }
    let refs: Vec<&BlstPublicKey> = keys.iter().map(|k| &k.0).collect();
    let agg = AggregatePublicKey::aggregate(&refs, false).map_err(|_| BlsError::Deserialization)?;
    Ok(PublicKey(agg.to_public_key()))
}

/// Aggregate several signatures over the *same* message into one.
pub fn aggregate_signatures(signatures: &[Signature]) -> Result<Signature, BlsError> {
    if signatures.is_empty() {
        return Err(BlsError::NoElements);
    }
    let refs: Vec<&BlstSignature> = signatures.iter().map(|s| &s.0).collect();
    let agg = AggregateSignature::aggregate(&refs, false).map_err(|_| BlsError::Deserialization)?;
    Ok(Signature(agg.to_signature()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SecretKey {
        SecretKey::from_ikm(&[seed; 32]).unwrap()
    }

    #[test]
    fn sizes_match_avalanchego() {
        let sk = key(1);
        assert_eq!(sk.to_bytes().len(), SECRET_KEY_LEN);
        assert_eq!(sk.public_key().to_bytes().len(), PUBLIC_KEY_LEN);
        assert_eq!(sk.sign(b"hi").to_bytes().len(), SIGNATURE_LEN);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let sk = key(7);
        let pk = sk.public_key();
        let msg = b"cross-chain payload";
        let sig = sk.sign(msg);
        assert!(verify(&pk, &sig, msg));
        assert!(!verify(&pk, &sig, b"tampered"));
    }

    #[test]
    fn wrong_key_rejected() {
        let sk = key(2);
        let other = key(3).public_key();
        let sig = sk.sign(b"m");
        assert!(!verify(&other, &sig, b"m"));
    }

    #[test]
    fn public_key_bytes_roundtrip() {
        let pk = key(9).public_key();
        let bytes = pk.to_bytes();
        let parsed = PublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(pk, parsed);
    }

    #[test]
    fn signature_bytes_roundtrip() {
        let sig = key(4).sign(b"abc");
        let bytes = sig.to_bytes();
        let parsed = Signature::from_bytes(&bytes).unwrap();
        assert_eq!(sig, parsed);
    }

    #[test]
    fn secret_key_bytes_roundtrip() {
        let sk = key(11);
        let parsed = SecretKey::from_bytes(&sk.to_bytes()).unwrap();
        assert_eq!(sk.public_key(), parsed.public_key());
    }

    #[test]
    fn proof_of_possession() {
        let sk = key(5);
        let pk = sk.public_key();
        let pop = sk.sign_proof_of_possession();
        assert!(pk.verify_proof_of_possession(&pop));
        // A PoP from a different key must not verify.
        let other_pop = key(6).sign_proof_of_possession();
        assert!(!pk.verify_proof_of_possession(&other_pop));
        // A plain message signature is not a valid PoP (different ciphersuite).
        let plain = sk.sign(&pk.to_bytes());
        assert!(!pk.verify_proof_of_possession(&plain));
    }

    #[test]
    fn aggregate_same_message() {
        // Three validators sign the same message; aggregate keys + sigs and
        // verify once — this is exactly the ICM verification path.
        let sks = [key(20), key(21), key(22)];
        let msg = b"icm unsigned message bytes";
        let pks: Vec<PublicKey> = sks.iter().map(|s| s.public_key()).collect();
        let sigs: Vec<Signature> = sks.iter().map(|s| s.sign(msg)).collect();

        let agg_pk = aggregate_public_keys(&pks).unwrap();
        let agg_sig = aggregate_signatures(&sigs).unwrap();
        assert!(verify(&agg_pk, &agg_sig, msg));

        // Dropping one signer's key from the aggregate must fail verification.
        let partial_pk = aggregate_public_keys(&pks[..2]).unwrap();
        assert!(!verify(&partial_pk, &agg_sig, msg));
    }

    #[test]
    fn bad_lengths_rejected() {
        assert_eq!(PublicKey::from_bytes(&[0u8; 10]), Err(BlsError::BadLength));
        assert_eq!(Signature::from_bytes(&[0u8; 10]), Err(BlsError::BadLength));
        assert_eq!(SecretKey::from_bytes(&[0u8; 10]).err(), Some(BlsError::BadLength));
        assert_eq!(aggregate_public_keys(&[]), Err(BlsError::NoElements));
    }
}
