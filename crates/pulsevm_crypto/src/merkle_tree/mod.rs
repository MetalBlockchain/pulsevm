use std::collections::VecDeque;

use crate::Digest;

/// Canonicalize left by clearing bit 0x80 on first byte
pub fn make_canonical_left(val: &Digest) -> Digest {
    let mut result = *val;
    result.0[0] &= 0x7F;
    result
}

/// Canonicalize right by setting bit 0x80 on first byte
pub fn make_canonical_right(val: &Digest) -> Digest {
    let mut result = *val;
    result.0[0] |= 0x80;
    result
}

pub fn is_canonical_left(val: &Digest) -> bool {
    (val.0[0] & 0x80) == 0
}

pub fn is_canonical_right(val: &Digest) -> bool {
    (val.0[0] & 0x80) != 0
}

/// Pair two digests with canonicalization and hash the result
pub fn make_canonical_pair(a: Digest, b: Digest) -> Digest {
    let left = make_canonical_left(&a);
    let right = make_canonical_right(&b);

    let mut combined = Vec::with_capacity(64);
    combined.extend_from_slice(&left.0);
    combined.extend_from_slice(&right.0);

    Digest::hash(&combined)
}

/// Compute Merkle root from a list of digests
pub fn merkle(mut ids: VecDeque<Digest>) -> Digest {
    if ids.is_empty() {
        return Digest([0u8; 32]);
    }

    while ids.len() > 1 {
        if ids.len() % 2 != 0 {
            ids.push_back(*ids.back().unwrap());
        }

        for i in 0..(ids.len() / 2) {
            let left = ids[2 * i];
            let right = ids[2 * i + 1];
            ids[i] = make_canonical_pair(left, right);
        }

        ids.truncate(ids.len() / 2);
    }

    ids[0]
}
