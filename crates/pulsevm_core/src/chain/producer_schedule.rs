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
        Self::read(bytes, &mut 0)
    }
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
}
