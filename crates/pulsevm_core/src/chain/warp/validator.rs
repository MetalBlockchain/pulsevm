//! The canonical validator set an ICM signature is checked against.
//!
//! To verify a warp signature a destination chain needs the *source* subnet's
//! validator set as it was at some P-chain height: each validator's BLS public
//! key and stake weight. AvalancheGo puts this set in a canonical order — sorted
//! ascending by the 48-byte compressed public key, with validators sharing a key
//! merged — so that a compact bitset can name signers by index. Both signer and
//! verifier must derive the identical ordering or the bitset means different
//! things on each side.

use pulsevm_crypto::bls::PublicKey;

/// One entry in the canonical validator set: a BLS key and the total weight of
/// all validators using it.
#[derive(Debug, Clone)]
pub struct Validator {
    pub public_key: PublicKey,
    pub weight: u64,
}

/// A source subnet's validators in canonical (AvalancheGo) order.
#[derive(Debug, Clone)]
pub struct CanonicalValidatorSet {
    validators: Vec<Validator>,
    total_weight: u128,
}

impl CanonicalValidatorSet {
    /// Build a canonical set from an unordered list of `(public_key, weight)`.
    /// Entries sharing a public key are merged (weights summed) and the result is
    /// sorted ascending by compressed public-key bytes.
    pub fn new(mut validators: Vec<Validator>) -> Self {
        validators.sort_by(|a, b| a.public_key.to_bytes().cmp(&b.public_key.to_bytes()));

        // Merge adjacent duplicates by public key.
        let mut merged: Vec<Validator> = Vec::with_capacity(validators.len());
        for v in validators {
            match merged.last_mut() {
                Some(last) if last.public_key == v.public_key => {
                    last.weight = last.weight.saturating_add(v.weight);
                }
                _ => merged.push(v),
            }
        }

        let total_weight = merged.iter().map(|v| v.weight as u128).sum();
        CanonicalValidatorSet {
            validators: merged,
            total_weight,
        }
    }

    pub fn len(&self) -> usize {
        self.validators.len()
    }

    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    pub fn total_weight(&self) -> u128 {
        self.total_weight
    }

    pub fn validators(&self) -> &[Validator] {
        &self.validators
    }

    /// The validators selected by a signer bitset, in canonical order, together
    /// with their summed weight. Returns `None` if the bitset references an index
    /// outside the set (a malformed or forward-incompatible signature).
    pub fn select(&self, signers: &SignerBitset) -> Option<(Vec<&Validator>, u128)> {
        if let Some(highest) = signers.highest_set_bit() {
            if highest >= self.validators.len() {
                return None;
            }
        }
        let mut selected = Vec::new();
        let mut weight: u128 = 0;
        for (i, v) in self.validators.iter().enumerate() {
            if signers.contains(i) {
                selected.push(v);
                weight += v.weight as u128;
            }
        }
        Some((selected, weight))
    }
}

/// A bitset naming signer indices, encoded exactly as AvalancheGo's `set.Bits`:
/// a big-endian big-integer whose bit `i` (0 = least-significant) is set when the
/// canonical validator at index `i` contributed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerBitset {
    /// Big-endian bytes (most-significant byte first), as they appear on the wire.
    bytes: Vec<u8>,
}

impl SignerBitset {
    /// Wrap on-wire bitset bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        SignerBitset { bytes }
    }

    /// Build a bitset from a list of signer indices (used when producing a
    /// signature locally / in tests).
    pub fn from_indices(indices: &[usize]) -> Self {
        let max_bit = indices.iter().copied().max();
        let byte_len = match max_bit {
            Some(m) => m / 8 + 1,
            None => 0,
        };
        // Little-endian scratch (index 0 = least-significant byte), reversed to
        // big-endian at the end to match `set.Bits`.
        let mut le = vec![0u8; byte_len];
        for &i in indices {
            le[i / 8] |= 1 << (i % 8);
        }
        le.reverse();
        SignerBitset { bytes: le }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Is bit `i` set? Big-endian: the least-significant byte is the last one.
    pub fn contains(&self, i: usize) -> bool {
        let byte_from_end = i / 8;
        if byte_from_end >= self.bytes.len() {
            return false;
        }
        let byte = self.bytes[self.bytes.len() - 1 - byte_from_end];
        byte & (1 << (i % 8)) != 0
    }

    /// Number of set bits (the population count).
    pub fn count(&self) -> usize {
        self.bytes.iter().map(|b| b.count_ones() as usize).sum()
    }

    /// Index of the highest set bit, or `None` if empty.
    pub fn highest_set_bit(&self) -> Option<usize> {
        for (offset, &byte) in self.bytes.iter().enumerate() {
            if byte != 0 {
                // Most-significant set bit within this byte.
                let bit_in_byte = 7 - byte.leading_zeros() as usize;
                let byte_from_end = self.bytes.len() - 1 - offset;
                return Some(byte_from_end * 8 + bit_in_byte);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pulsevm_crypto::bls::SecretKey;

    fn pk(seed: u8) -> PublicKey {
        SecretKey::from_ikm(&[seed; 32]).unwrap().public_key()
    }

    #[test]
    fn bitset_indices_roundtrip() {
        let bs = SignerBitset::from_indices(&[0, 3, 9]);
        assert!(bs.contains(0));
        assert!(bs.contains(3));
        assert!(bs.contains(9));
        assert!(!bs.contains(1));
        assert!(!bs.contains(8));
        assert_eq!(bs.count(), 3);
        assert_eq!(bs.highest_set_bit(), Some(9));
    }

    #[test]
    fn bitset_is_big_endian() {
        // Bit 0 set => integer value 1 => single byte 0x01.
        assert_eq!(SignerBitset::from_indices(&[0]).as_bytes(), &[0x01]);
        // Bit 8 set => integer value 256 => big-endian [0x01, 0x00].
        assert_eq!(SignerBitset::from_indices(&[8]).as_bytes(), &[0x01, 0x00]);
        // Bits 0 and 8 => 257 => [0x01, 0x01].
        assert_eq!(SignerBitset::from_indices(&[0, 8]).as_bytes(), &[0x01, 0x01]);
    }

    #[test]
    fn empty_bitset() {
        let bs = SignerBitset::from_indices(&[]);
        assert_eq!(bs.count(), 0);
        assert_eq!(bs.highest_set_bit(), None);
        assert!(!bs.contains(0));
    }

    #[test]
    fn canonical_order_sorts_by_pubkey() {
        let set = CanonicalValidatorSet::new(vec![
            Validator { public_key: pk(3), weight: 10 },
            Validator { public_key: pk(1), weight: 20 },
            Validator { public_key: pk(2), weight: 30 },
        ]);
        let keys: Vec<[u8; 48]> = set.validators().iter().map(|v| v.public_key.to_bytes()).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
        assert_eq!(set.total_weight(), 60);
    }

    #[test]
    fn duplicate_keys_merged() {
        let set = CanonicalValidatorSet::new(vec![
            Validator { public_key: pk(5), weight: 10 },
            Validator { public_key: pk(5), weight: 15 },
        ]);
        assert_eq!(set.len(), 1);
        assert_eq!(set.total_weight(), 25);
    }

    #[test]
    fn select_rejects_out_of_range_bits() {
        let set = CanonicalValidatorSet::new(vec![
            Validator { public_key: pk(1), weight: 10 },
            Validator { public_key: pk(2), weight: 10 },
        ]);
        // Bit 5 set but only 2 validators exist.
        assert!(set.select(&SignerBitset::from_indices(&[5])).is_none());
    }

    #[test]
    fn select_sums_weight() {
        let set = CanonicalValidatorSet::new(vec![
            Validator { public_key: pk(1), weight: 10 },
            Validator { public_key: pk(2), weight: 20 },
            Validator { public_key: pk(3), weight: 40 },
        ]);
        // Select canonical indices 0 and 2 by iterating; weight depends on order.
        let (selected, weight) = set.select(&SignerBitset::from_indices(&[0, 2])).unwrap();
        assert_eq!(selected.len(), 2);
        // whichever two validators sit at index 0 and 2 in canonical order
        let expected: u128 =
            set.validators()[0].weight as u128 + set.validators()[2].weight as u128;
        assert_eq!(weight, expected);
    }
}
