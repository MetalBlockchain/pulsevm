//! XPR halt commitment: the old network's signed promise to stop at H.
//!
//! Customer continuity rests on the swap, not on either chain alone: the XPR
//! producers commit to never authoring past H, the new network verifies that
//! commitment against the old schedule's keys before authoring H+1, and the
//! replay terminates. This module defines the commitment wire format and its
//! verification. The quorum policy lives with the ceremony: version 1
//! requires at least one valid producer signature over the halt; a mainnet
//! ceremony upgrades the threshold to 2/3 of schedule weight without
//! changing the format.

use pulsevm_crypto::{
    Digest,
    k1::{
        K1PublicKey,
        K1Signature,
    },
};
use pulsevm_error::ChainError;
use serde::{
    Deserialize,
    Serialize,
};

/// Domain separator for the signed halt message (versioned with the format).
pub const HALT_DOMAIN: &[u8] = b"PULSEVM-XPR-HALT-v1";

/// One producer's signature over the halt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HaltSignature {
    /// Producer name (informational; authorization rides on the key).
    pub producer: String,
    /// Signing key in `PUB_K1_` or legacy `EOS` form.
    pub key: String,
    /// `SIG_K1_` signature over [`halt_digest`] for this halt.
    pub signature: String,
}

/// The old network's commitment to freeze at a terminal block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HaltCommitment {
    pub version: u16,
    /// Terminal height: no valid source block may number above this.
    pub halt_height: u32,
    /// 64-hex id of the terminal block.
    pub halt_block_id: String,
    /// Old-schedule producer keys a commitment signature may come from.
    pub producer_keys: Vec<String>,
    pub signatures: Vec<HaltSignature>,
}

impl HaltCommitment {
    pub const VERSION: u16 = 1;

    /// Canonical message: domain || height-be64 || block-id.
    pub fn message_bytes(halt_height: u32, halt_block_id: &[u8; 32]) -> Vec<u8> {
        let mut message = Vec::with_capacity(HALT_DOMAIN.len() + 4 + 32);
        message.extend_from_slice(HALT_DOMAIN);
        message.extend_from_slice(&halt_height.to_be_bytes());
        message.extend_from_slice(halt_block_id);
        message
    }

    /// Signing digest for a halt.
    pub fn digest(halt_height: u32, halt_block_id: &[u8; 32]) -> [u8; 32] {
        *Digest::hash(Self::message_bytes(halt_height, halt_block_id)).as_bytes()
    }

    /// Shared terminal-block check: version, height, and id must match.
    /// Returns the decoded committed block id.
    fn check_terminal(
        &self,
        expected_height: u32,
        expected_block_id: &[u8; 32],
    ) -> Result<[u8; 32], ChainError> {
        if self.version != Self::VERSION {
            return Err(ChainError::InternalError(format!(
                "unsupported halt commitment version {}",
                self.version
            )));
        }
        if self.halt_height != expected_height {
            return Err(ChainError::InternalError(format!(
                "halt commitment height {} does not match terminal height {}",
                self.halt_height, expected_height
            )));
        }
        let committed_id = decode_hex_32(&self.halt_block_id).map_err(|e| {
            ChainError::InternalError(format!("halt commitment block id invalid: {e}"))
        })?;
        if committed_id != *expected_block_id {
            return Err(ChainError::InternalError(
                "halt commitment block id does not match the terminal block".into(),
            ));
        }
        Ok(committed_id)
    }

    /// Verify this commitment against the expected terminal block: version,
    /// height, and id must match, every signature must come from a listed
    /// producer key, and at least one signature must recover to its claimed
    /// key over the halt digest.
    pub fn verify(
        &self,
        expected_height: u32,
        expected_block_id: &[u8; 32],
    ) -> Result<(), ChainError> {
        let committed_id = self.check_terminal(expected_height, expected_block_id)?;
        let schedule: Vec<K1PublicKey> = self
            .producer_keys
            .iter()
            .map(|key| {
                K1PublicKey::from_string(key).map_err(|e| {
                    ChainError::InternalError(format!("halt producer key invalid: {e:?}"))
                })
            })
            .collect::<Result<_, _>>()?;
        let digest = Self::digest(self.halt_height, &committed_id);
        let mut valid = 0u32;
        for entry in &self.signatures {
            let claimed = K1PublicKey::from_string(&entry.key).map_err(|e| {
                ChainError::InternalError(format!("halt signature key invalid: {e:?}"))
            })?;
            if !schedule.contains(&claimed) {
                return Err(ChainError::InternalError(format!(
                    "halt signature from producer {} is not in the committed schedule",
                    entry.producer
                )));
            }
            let signature = K1Signature::from_string(&entry.signature).map_err(|e| {
                ChainError::InternalError(format!("halt signature malformed: {e:?}"))
            })?;
            let recovered = signature.recover(&digest).map_err(|e| {
                ChainError::InternalError(format!("halt signature unrecoverable: {e:?}"))
            })?;
            if recovered != claimed {
                return Err(ChainError::InternalError(format!(
                    "halt signature from producer {} does not verify",
                    entry.producer
                )));
            }
            valid += 1;
        }
        if valid == 0 {
            return Err(ChainError::InternalError(
                "halt commitment carries no valid producer signature".into(),
            ));
        }
        Ok(())
    }

    /// Verify this commitment against a weighted producer roster (the
    /// on-chain ceremony): version, height, and id must match, every
    /// signature must recover to a rostered key over the halt digest, and the
    /// signers' combined weight must reach two thirds of the roster weight.
    /// Each producer's weight counts once no matter how often it signed.
    /// Integer cross-multiplication (`signed * 3 >= total * 2`, in u128) sets
    /// the threshold with no float rounding; an empty or all-zero roster
    /// fails closed.
    pub fn verify_weighted_quorum(
        &self,
        expected_height: u32,
        expected_block_id: &[u8; 32],
        roster: &[HaltRosterEntry],
    ) -> Result<(), ChainError> {
        let committed_id = self.check_terminal(expected_height, expected_block_id)?;
        let total: u128 = roster.iter().map(|entry| entry.weight as u128).sum();
        if roster.is_empty() || total == 0 {
            return Err(ChainError::InternalError(
                "halt commitment roster carries no weight".into(),
            ));
        }
        let digest = Self::digest(self.halt_height, &committed_id);
        let mut signed: std::collections::HashSet<K1PublicKey> = std::collections::HashSet::new();
        for entry in &self.signatures {
            let claimed = K1PublicKey::from_string(&entry.key).map_err(|e| {
                ChainError::InternalError(format!("halt signature key invalid: {e:?}"))
            })?;
            if !roster.iter().any(|rostered| rostered.key == claimed) {
                return Err(ChainError::InternalError(format!(
                    "halt signature from producer {} is not in the committed schedule",
                    entry.producer
                )));
            }
            let signature = K1Signature::from_string(&entry.signature).map_err(|e| {
                ChainError::InternalError(format!("halt signature malformed: {e:?}"))
            })?;
            let recovered = signature.recover(&digest).map_err(|e| {
                ChainError::InternalError(format!("halt signature unrecoverable: {e:?}"))
            })?;
            if recovered != claimed {
                return Err(ChainError::InternalError(format!(
                    "halt signature from producer {} does not verify",
                    entry.producer
                )));
            }
            signed.insert(claimed);
        }
        let signed_weight: u128 = roster
            .iter()
            .filter(|entry| signed.contains(&entry.key))
            .map(|entry| entry.weight as u128)
            .sum();
        if signed_weight * 3 < total * 2 {
            return Err(ChainError::InternalError(format!(
                "halt commitment weight {signed_weight} below two-thirds quorum of {total}"
            )));
        }
        Ok(())
    }
}

/// One roster entry for weighted quorum verification: a scheduled
/// producer's signing key and its vote weight (e.g. `total_votes`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HaltRosterEntry {
    pub producer: String,
    pub key: K1PublicKey,
    pub weight: u64,
}
fn decode_hex_32(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("must be 64 hexadecimal characters".into());
    }
    let mut bytes = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks(2).enumerate() {
        bytes[index] = (hex_nibble(chunk[0]) << 4) | hex_nibble(chunk[1]);
    }
    Ok(bytes)
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pulsevm_crypto::k1::K1PrivateKey;

    const HEIGHT: u32 = 310;
    const WEIGHTS: [u64; 3] = [50, 30, 20];

    fn block_id() -> [u8; 32] {
        [0xab; 32]
    }

    fn block_id_hex() -> String {
        "ab".repeat(32)
    }

    fn key(seed: &str) -> K1PrivateKey {
        K1PrivateKey::from_seed_string(seed).expect("deterministic test key")
    }

    fn roster() -> (Vec<K1PrivateKey>, Vec<HaltRosterEntry>) {
        let keys = vec![key("halt-test-1"), key("halt-test-2"), key("halt-test-3")];
        let entries = keys
            .iter()
            .zip(["prod.a", "prod.b", "prod.c"])
            .zip(WEIGHTS)
            .map(|((signing, producer), weight)| HaltRosterEntry {
                producer: producer.to_string(),
                key: signing.public_key(),
                weight,
            })
            .collect();
        (keys, entries)
    }

    fn sign(signing: &K1PrivateKey, producer: &str, height: u32, id: &[u8; 32]) -> HaltSignature {
        let digest = HaltCommitment::digest(height, id);
        HaltSignature {
            producer: producer.to_string(),
            key: signing.public_key().to_string(),
            signature: signing.sign(&digest).to_string(),
        }
    }

    fn commitment(signatures: Vec<HaltSignature>) -> HaltCommitment {
        HaltCommitment {
            version: HaltCommitment::VERSION,
            halt_height: HEIGHT,
            halt_block_id: block_id_hex(),
            producer_keys: Vec::new(),
            signatures,
        }
    }

    #[test]
    fn quorum_accepts_two_thirds_weight() {
        let (keys, roster) = roster();
        let id = block_id();
        for pair in [&[0, 1][..], &[0, 2][..], &[0, 1, 2][..]] {
            let signatures = pair
                .iter()
                .map(|&i| sign(&keys[i], &roster[i].producer, HEIGHT, &id))
                .collect();
            commitment(signatures)
                .verify_weighted_quorum(HEIGHT, &id, &roster)
                .expect("quorum weight must verify");
        }
    }

    #[test]
    fn quorum_accepts_exact_two_thirds() {
        let a = key("halt-test-1");
        let b = key("halt-test-2");
        let roster = vec![
            HaltRosterEntry {
                producer: "prod.a".to_string(),
                key: a.public_key(),
                weight: 2,
            },
            HaltRosterEntry {
                producer: "prod.b".to_string(),
                key: b.public_key(),
                weight: 1,
            },
        ];
        let id = block_id();
        commitment(vec![sign(&a, "prod.a", HEIGHT, &id)])
            .verify_weighted_quorum(HEIGHT, &id, &roster)
            .expect("exact two-thirds must verify");
    }

    #[test]
    fn quorum_rejects_shortfall_on_both_sides_of_the_line() {
        let (keys, roster) = roster();
        let id = block_id();
        // 30 + 20 = 50 < 67: below quorum.
        let below = vec![
            sign(&keys[1], &roster[1].producer, HEIGHT, &id),
            sign(&keys[2], &roster[2].producer, HEIGHT, &id),
        ];
        assert!(
            commitment(below)
                .verify_weighted_quorum(HEIGHT, &id, &roster)
                .is_err()
        );
        // 50 alone is below quorum even though it is the largest single weight.
        let single = vec![sign(&keys[0], &roster[0].producer, HEIGHT, &id)];
        assert!(
            commitment(single)
                .verify_weighted_quorum(HEIGHT, &id, &roster)
                .is_err()
        );
    }

    #[test]
    fn quorum_counts_each_producer_once() {
        let (keys, roster) = roster();
        let id = block_id();
        // prod.a signs twice: still only 50 of weight, below quorum.
        let double = vec![
            sign(&keys[0], &roster[0].producer, HEIGHT, &id),
            sign(&keys[0], &roster[0].producer, HEIGHT, &id),
        ];
        assert!(
            commitment(double)
                .verify_weighted_quorum(HEIGHT, &id, &roster)
                .is_err()
        );
    }

    #[test]
    fn quorum_rejects_non_roster_signer() {
        let (keys, roster) = roster();
        let id = block_id();
        let outsider = key("halt-test-outsider");
        let signatures = vec![
            sign(&keys[0], &roster[0].producer, HEIGHT, &id),
            sign(&keys[1], &roster[1].producer, HEIGHT, &id),
            sign(&outsider, "prod.zz", HEIGHT, &id),
        ];
        assert!(
            commitment(signatures)
                .verify_weighted_quorum(HEIGHT, &id, &roster)
                .is_err()
        );
    }

    #[test]
    fn quorum_rejects_signature_over_other_height() {
        let (keys, roster) = roster();
        let id = block_id();
        let signatures = vec![
            sign(&keys[0], &roster[0].producer, HEIGHT, &id),
            sign(&keys[1], &roster[1].producer, HEIGHT + 1, &id),
        ];
        assert!(
            commitment(signatures)
                .verify_weighted_quorum(HEIGHT, &id, &roster)
                .is_err()
        );
    }

    #[test]
    fn quorum_rejects_wrong_terminal_and_empty_roster() {
        let (keys, roster) = roster();
        let id = block_id();
        let signatures = vec![
            sign(&keys[0], &roster[0].producer, HEIGHT, &id),
            sign(&keys[1], &roster[1].producer, HEIGHT, &id),
        ];
        let committed = commitment(signatures);
        assert!(
            committed
                .verify_weighted_quorum(HEIGHT + 1, &id, &roster)
                .is_err()
        );
        assert!(
            committed
                .verify_weighted_quorum(HEIGHT, &[0xcd; 32], &roster)
                .is_err()
        );
        assert!(committed.verify_weighted_quorum(HEIGHT, &id, &[]).is_err());
        let zeroed: Vec<HaltRosterEntry> = roster
            .iter()
            .map(|entry| HaltRosterEntry {
                weight: 0,
                ..entry.clone()
            })
            .collect();
        assert!(
            committed
                .verify_weighted_quorum(HEIGHT, &id, &zeroed)
                .is_err()
        );
    }

    #[test]
    fn v1_single_signature_path_still_valid() {
        let (keys, roster) = roster();
        let id = block_id();
        let committed = HaltCommitment {
            producer_keys: roster.iter().map(|entry| entry.key.to_string()).collect(),
            ..commitment(vec![sign(&keys[0], &roster[0].producer, HEIGHT, &id)])
        };
        committed
            .verify(HEIGHT, &id)
            .expect("v1 path must keep working");
    }
}
