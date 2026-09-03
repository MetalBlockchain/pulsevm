use pulsevm_crypto::AuthorityPublicKey;
use pulsevm_proc_macros::{
    NumBytes,
    Read,
    Write,
};
use pulsevm_serialization::{
    Read as _,
    ReadError,
    VarUint32,
};
use serde::{
    Deserialize,
    Serialize,
};

use crate::chain::{
    crypto::PublicKey,
    name::Name,
};

/// Matches EOSIO's producer ceiling. Bounds the schedule so a caller can't blow
/// up memory or the per-block work.
pub const MAX_PRODUCERS: usize = 125;
/// Upper bound on a packed schedule payload. A `producer_key` packs to a Name (8)
/// plus a public key (34); the extra headroom covers the length prefixes and the
/// schedule `version` word. Used to cap a decode before it happens.
pub const MAX_SCHEDULE_BYTES: u32 = (MAX_PRODUCERS as u32 + 2) * 64;

/// A producer and the key its blocks must be signed with. This is the packed
/// element `set_proposed_producers` receives (a `vector<producer_key>`), and the
/// unit the active schedule is stored as.
#[derive(Debug, Clone, PartialEq, Eq, Read, Write, NumBytes, Serialize, Deserialize)]
pub struct ProducerKey {
    pub producer_name: Name,
    pub block_signing_key: PublicKey,
}

/// The active set of block producers. A block is valid only if signed by the
/// `block_signing_key` its `producer` holds here. Seeded from genesis and, once
/// `set_proposed_producers` is wired, updated by it — `version` bumps on every
/// change. This is the EOSIO producer schedule without the multi-round
/// activation delay, which is not needed while the chain is single-producer.
#[derive(Debug, Clone, PartialEq, Eq, Read, Write, NumBytes, Serialize, Deserialize, Default)]
pub struct ProducerSchedule {
    pub version: u32,
    pub producers: Vec<ProducerKey>,
}

impl ProducerSchedule {
    pub fn block_signing_key(&self, producer: &Name) -> Option<&PublicKey> {
        self.producers
            .iter()
            .find(|p| &p.producer_name == producer)
            .map(|p| &p.block_signing_key)
    }

    /// Decode a packed schedule (as carried in a block header's `new_producers`),
    /// bounding the declared producer count *before* the full read. `Vec::read`
    /// reserves the declared count up front, and the length prefix is a
    /// `VarUint32` (up to ~4.3 billion), so an unchecked count would drive a huge
    /// pre-allocation from a few bytes. The count is validated against the same
    /// buffer the full read consumes, so there is no decode/check divergence.
    pub fn read_bounded(bytes: &[u8]) -> Result<Self, ReadError> {
        if bytes.len() > MAX_SCHEDULE_BYTES as usize {
            return Err(ReadError::CustomError(format!(
                "packed schedule is too large ({} bytes, max {})",
                bytes.len(),
                MAX_SCHEDULE_BYTES
            )));
        }
        // The packed layout is `version: u32` followed by the producers vector,
        // so the element count's length prefix sits right after the version word.
        let mut pos = 0usize;
        let _version = u32::read(bytes, &mut pos)?;
        let declared = VarUint32::read(bytes, &mut pos)?.0 as usize;
        if declared < 1 || declared > MAX_PRODUCERS {
            return Err(ReadError::CustomError(format!(
                "proposed producer count {} out of range [1, {}]",
                declared, MAX_PRODUCERS
            )));
        }
        let mut pos = 0usize;
        let schedule = Self::read(bytes, &mut pos)?;
        if pos != bytes.len() {
            return Err(ReadError::CustomError(format!(
                "packed schedule has {} trailing byte(s)",
                bytes.len() - pos
            )));
        }
        Ok(schedule)
    }

    /// Decode Leap's format-1 `vector<producer_authority>` payload. PulseVM's
    /// current block-signature representation has one K1 signature, so each v0
    /// authority must reduce exactly to one K1 key whose weight satisfies its
    /// threshold.
    pub fn read_authorities_bounded(bytes: &[u8]) -> Result<Vec<ProducerKey>, ReadError> {
        if bytes.len() > MAX_SCHEDULE_BYTES as usize {
            return Err(ReadError::CustomError(format!(
                "packed producer authorities are too large ({} bytes, max {})",
                bytes.len(),
                MAX_SCHEDULE_BYTES
            )));
        }
        let mut pos = 0usize;
        let producers = read_single_key_authorities(bytes, &mut pos)?;
        if pos != bytes.len() {
            return Err(ReadError::CustomError(format!(
                "producer authority schedule has {} trailing byte(s)",
                bytes.len() - pos
            )));
        }
        Ok(producers)
    }

    /// Decode a format-1 `producer_authority_schedule`, as carried by block
    /// header extension 1. This adds the schedule version before the same
    /// authority vector accepted by `set_proposed_producers_ex`.
    pub fn read_authority_schedule_bounded(bytes: &[u8]) -> Result<Self, ReadError> {
        if bytes.len() > MAX_SCHEDULE_BYTES as usize {
            return Err(ReadError::CustomError(format!(
                "packed producer authority schedule is too large ({} bytes, max {})",
                bytes.len(),
                MAX_SCHEDULE_BYTES
            )));
        }
        let mut pos = 0usize;
        let version = u32::read(bytes, &mut pos)?;
        let producers = read_single_key_authorities(bytes, &mut pos)?;
        if pos != bytes.len() {
            return Err(ReadError::CustomError(format!(
                "producer authority schedule has {} trailing byte(s)",
                bytes.len() - pos
            )));
        }
        Ok(Self { version, producers })
    }
}

fn read_single_key_authorities(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Vec<ProducerKey>, ReadError> {
    let declared = VarUint32::read(bytes, pos)?.0 as usize;
    if declared < 1 || declared > MAX_PRODUCERS {
        return Err(ReadError::CustomError(format!(
            "proposed producer count {} out of range [1, {}]",
            declared, MAX_PRODUCERS
        )));
    }

    let mut producers = Vec::with_capacity(declared);
    for _ in 0..declared {
        let producer_name = Name::read(bytes, pos)?;
        let authority_variant = VarUint32::read(bytes, pos)?.0;
        if authority_variant != 0 {
            return Err(ReadError::CustomError(format!(
                "producer {producer_name} uses unsupported block-signing authority variant {authority_variant}"
            )));
        }
        let threshold = u32::read(bytes, pos)?;
        let key_count = VarUint32::read(bytes, pos)?.0 as usize;
        if key_count != 1 {
            return Err(ReadError::CustomError(format!(
                "producer {producer_name} has {key_count} block-signing keys; PulseVM currently requires exactly one"
            )));
        }
        let authority_key = AuthorityPublicKey::read(bytes, pos)?;
        let weight = u16::read(bytes, pos)?;
        if threshold == 0 || u32::from(weight) < threshold {
            return Err(ReadError::CustomError(format!(
                "producer {producer_name} single-key authority cannot satisfy threshold {threshold} with weight {weight}"
            )));
        }
        let k1 = authority_key.as_k1().ok_or_else(|| {
            ReadError::CustomError(format!(
                "producer {producer_name} uses a non-K1 block-signing key"
            ))
        })?;
        producers.push(ProducerKey {
            producer_name,
            block_signing_key: PublicKey::new(k1),
        });
    }
    Ok(producers)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use pulsevm_serialization::{
        VarUint32,
        Write,
    };

    use super::*;
    use crate::chain::crypto::PrivateKey;

    fn key(name: &str) -> ProducerKey {
        ProducerKey {
            producer_name: Name::from_str(name).unwrap(),
            block_signing_key: PrivateKey::random().get_public_key(),
        }
    }

    #[test]
    fn read_bounded_round_trips() {
        let schedule = ProducerSchedule {
            version: 3,
            producers: vec![key("alice"), key("bob")],
        };
        let packed = schedule.pack().unwrap();
        assert_eq!(ProducerSchedule::read_bounded(&packed).unwrap(), schedule);
    }

    #[test]
    fn read_bounded_rejects_empty_schedule() {
        let packed = ProducerSchedule {
            version: 1,
            producers: vec![],
        }
        .pack()
        .unwrap();
        assert!(ProducerSchedule::read_bounded(&packed).is_err());
    }

    #[test]
    fn read_bounded_rejects_huge_declared_count() {
        // version 0 followed by a length prefix claiming a billion producers and
        // no element bytes: the count check must reject this before `Vec::read`
        // reserves anything (the capacity-DoS guard).
        let mut bytes = 0u32.pack().unwrap();
        bytes.extend(VarUint32(1_000_000_000).pack().unwrap());
        assert!(ProducerSchedule::read_bounded(&bytes).is_err());
    }

    #[test]
    fn read_bounded_rejects_oversized_buffer() {
        let bytes = vec![0u8; MAX_SCHEDULE_BYTES as usize + 1];
        assert!(ProducerSchedule::read_bounded(&bytes).is_err());
    }

    #[test]
    fn read_bounded_rejects_trailing_bytes() {
        let mut packed = ProducerSchedule {
            version: 3,
            producers: vec![key("alice")],
        }
        .pack()
        .unwrap();
        packed.push(0);
        assert!(ProducerSchedule::read_bounded(&packed).is_err());
    }
}
