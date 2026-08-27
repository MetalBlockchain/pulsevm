//! ICM signature verification: does an aggregated BLS signature carry enough
//! validator stake to be trusted?
//!
//! This is the destination-chain half of Avalanche Interchain Messaging. Given a
//! signed [`Message`] and the source subnet's [`CanonicalValidatorSet`], it:
//!
//! 1. resolves which validators signed (from the bitset);
//! 2. checks their combined stake meets the quorum threshold;
//! 3. aggregates their public keys and verifies the single aggregate signature
//!    over the unsigned message bytes.
//!
//! Steps 2 and 3 are both required: a valid signature from too little stake is
//! rejected, and sufficient stake with an invalid signature is rejected.

use pulsevm_crypto::bls::{
    self,
    Signature,
};

use super::{
    message::Message,
    validator::{
        CanonicalValidatorSet,
        SignerBitset,
    },
};

/// Default warp quorum: signers must hold at least 67% of total stake. Matches
/// AvalancheGo's default `WarpQuorumNumerator` / denominator.
pub const DEFAULT_QUORUM_NUMERATOR: u64 = 67;
pub const QUORUM_DENOMINATOR: u64 = 100;

/// Why a warp signature failed to verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The bitset named a validator index outside the canonical set.
    UnknownSigner,
    /// No validators signed.
    NoSigners,
    /// The source subnet has no validators / zero total weight.
    EmptyValidatorSet,
    /// Signers' combined stake was below the quorum threshold.
    InsufficientWeight { signed: u128, total: u128 },
    /// A signer public key could not be aggregated.
    Aggregation,
    /// The 96-byte aggregate signature was malformed.
    MalformedSignature,
    /// The aggregate signature did not verify against the aggregate public key.
    InvalidSignature,
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VerifyError::UnknownSigner => write!(f, "signer index out of range"),
            VerifyError::NoSigners => write!(f, "no signers"),
            VerifyError::EmptyValidatorSet => write!(f, "empty validator set"),
            VerifyError::InsufficientWeight { signed, total } => {
                write!(f, "insufficient signing weight {signed}/{total}")
            }
            VerifyError::Aggregation => write!(f, "public key aggregation failed"),
            VerifyError::MalformedSignature => write!(f, "malformed aggregate signature"),
            VerifyError::InvalidSignature => write!(f, "aggregate signature did not verify"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Verify `message` against `validators` using the default 67% quorum.
pub fn verify_message(
    message: &Message,
    validators: &CanonicalValidatorSet,
) -> Result<(), VerifyError> {
    verify_message_with_quorum(
        message,
        validators,
        DEFAULT_QUORUM_NUMERATOR,
        QUORUM_DENOMINATOR,
    )
}

/// Verify `message` against `validators` with an explicit quorum fraction
/// (`quorum_num / quorum_den`). The stake check is
/// `signed_weight * quorum_den >= total_weight * quorum_num`, done in `u128` to
/// avoid overflow.
pub fn verify_message_with_quorum(
    message: &Message,
    validators: &CanonicalValidatorSet,
    quorum_num: u64,
    quorum_den: u64,
) -> Result<(), VerifyError> {
    if validators.is_empty() || validators.total_weight() == 0 {
        return Err(VerifyError::EmptyValidatorSet);
    }

    let signers = SignerBitset::from_bytes(message.signature.signers.clone());
    let (selected, signed_weight) = validators
        .select(&signers)
        .ok_or(VerifyError::UnknownSigner)?;

    if selected.is_empty() {
        return Err(VerifyError::NoSigners);
    }

    let total_weight = validators.total_weight();
    // Require signed_weight / total_weight >= quorum_num / quorum_den, evaluated
    // by cross-multiplication to stay exact and overflow-free in u128.
    if signed_weight * (quorum_den as u128) < total_weight * (quorum_num as u128) {
        return Err(VerifyError::InsufficientWeight {
            signed: signed_weight,
            total: total_weight,
        });
    }

    let keys: Vec<bls::PublicKey> = selected.iter().map(|v| v.public_key.clone()).collect();
    let agg_pk = bls::aggregate_public_keys(&keys).map_err(|_| VerifyError::Aggregation)?;

    let signature = Signature::from_bytes(&message.signature.signature)
        .map_err(|_| VerifyError::MalformedSignature)?;

    if bls::verify(&agg_pk, &signature, &message.unsigned.to_bytes()) {
        Ok(())
    } else {
        Err(VerifyError::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use pulsevm_crypto::bls::SecretKey;

    use super::*;
    use crate::chain::warp::{
        message::{
            BitSetSignature,
            UnsignedMessage,
        },
        validator::Validator,
    };

    struct Keyed {
        sk: SecretKey,
        weight: u64,
    }

    /// Build a signed message from a set of validators, having `signer_idxs`
    /// (canonical indices) sign. Returns the message and the canonical set.
    fn build(
        keyed: &[Keyed],
        signer_canonical_idxs: &[usize],
        payload: Vec<u8>,
    ) -> (Message, CanonicalValidatorSet) {
        let set = CanonicalValidatorSet::new(
            keyed
                .iter()
                .map(|k| Validator {
                    public_key: k.sk.public_key(),
                    weight: k.weight,
                })
                .collect(),
        );

        let unsigned = UnsignedMessage::new(9, [1u8; 32], payload);
        let msg_bytes = unsigned.to_bytes();

        // Map canonical index -> the secret key sitting there.
        let mut sigs = Vec::new();
        for &idx in signer_canonical_idxs {
            let pk_at_idx = set.validators()[idx].public_key.to_bytes();
            let sk = keyed
                .iter()
                .find(|k| k.sk.public_key().to_bytes() == pk_at_idx)
                .expect("validator present");
            sigs.push(sk.sk.sign(&msg_bytes));
        }
        let agg = bls::aggregate_signatures(&sigs).unwrap();

        let signature = BitSetSignature {
            signers: SignerBitset::from_indices(signer_canonical_idxs)
                .as_bytes()
                .to_vec(),
            signature: agg.to_bytes(),
        };
        (Message::new(unsigned, signature), set)
    }

    fn keyed(seed: u8, weight: u64) -> Keyed {
        Keyed {
            sk: SecretKey::from_ikm(&[seed; 32]).unwrap(),
            weight,
        }
    }

    #[test]
    fn full_quorum_verifies() {
        let vals = vec![keyed(1, 10), keyed(2, 10), keyed(3, 10)];
        let (msg, set) = build(&vals, &[0, 1, 2], b"hi".to_vec());
        assert_eq!(verify_message(&msg, &set), Ok(()));
    }

    #[test]
    fn exactly_at_threshold_verifies() {
        // Two of three equal-weight validators = 66.6% < 67%, so pick weights
        // where signers hold exactly 67/100.
        let vals = vec![keyed(1, 67), keyed(2, 33)];
        // Canonical index of the 67-weight validator:
        let set_preview = CanonicalValidatorSet::new(vec![
            Validator { public_key: vals[0].sk.public_key(), weight: 67 },
            Validator { public_key: vals[1].sk.public_key(), weight: 33 },
        ]);
        let heavy_idx = set_preview
            .validators()
            .iter()
            .position(|v| v.public_key == vals[0].sk.public_key())
            .unwrap();
        let (msg, set) = build(&vals, &[heavy_idx], b"hi".to_vec());
        assert_eq!(verify_message(&msg, &set), Ok(()));
    }

    #[test]
    fn below_threshold_rejected() {
        let vals = vec![keyed(1, 10), keyed(2, 10), keyed(3, 10)];
        // One of three = 33% < 67%.
        let (msg, set) = build(&vals, &[0], b"hi".to_vec());
        assert!(matches!(
            verify_message(&msg, &set),
            Err(VerifyError::InsufficientWeight { .. })
        ));
    }

    #[test]
    fn tampered_payload_rejected() {
        let vals = vec![keyed(1, 10), keyed(2, 10)];
        let (mut msg, set) = build(&vals, &[0, 1], b"hi".to_vec());
        msg.unsigned.payload = b"tampered".to_vec();
        assert_eq!(verify_message(&msg, &set), Err(VerifyError::InvalidSignature));
    }

    #[test]
    fn wrong_signer_in_bitset_rejected() {
        // Sign with validators 0,1 but claim 0,1,2 in the bitset. The aggregate
        // public key then includes a non-signer, so verification fails.
        let vals = vec![keyed(1, 10), keyed(2, 10), keyed(3, 10)];
        let (mut msg, set) = build(&vals, &[0, 1], b"hi".to_vec());
        msg.signature.signers = SignerBitset::from_indices(&[0, 1, 2]).as_bytes().to_vec();
        assert_eq!(verify_message(&msg, &set), Err(VerifyError::InvalidSignature));
    }

    #[test]
    fn out_of_range_signer_rejected() {
        let vals = vec![keyed(1, 10), keyed(2, 10)];
        let (mut msg, set) = build(&vals, &[0, 1], b"hi".to_vec());
        msg.signature.signers = SignerBitset::from_indices(&[7]).as_bytes().to_vec();
        assert_eq!(verify_message(&msg, &set), Err(VerifyError::UnknownSigner));
    }
}
