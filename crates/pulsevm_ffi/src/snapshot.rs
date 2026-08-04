//! Physical state snapshots of the chainbase arena.
//!
//! chainbase keeps all state in a single memory-mapped file
//! (`shared_memory.bin`). There is no object serializer, so the only faithful
//! way to capture a point-in-time copy is to take the file itself: drop the
//! mapping (which flushes dirty pages and clears the dirty flag), read the
//! clean bytes, and remap. This module owns the wire envelope that wraps those
//! bytes — a small self-describing header plus a checksum so a transferred
//! snapshot can be validated before it is installed.
//!
//! The envelope is deliberately not the Avalanche state-summary commitment: the
//! summary id a peer agrees on is the accepted block id (canonical across
//! nodes), while these bytes are the physical payload that moves out of band.
//! Two honest nodes that built the same chain hold logically-equal state but
//! byte-different arenas (allocator layout differs), so hashing the file is only
//! meaningful for integrity of a single transferred copy, which is exactly what
//! the checksum here is for.

use pulsevm_crypto::Digest;
use pulsevm_error::ChainError;

const MAGIC: [u8; 4] = *b"PVDB";

/// Bumped on any incompatible change to the envelope or the underlying arena
/// format. A node refuses a snapshot it cannot interpret.
pub const SNAPSHOT_VERSION: u16 = 1;

/// magic(4) + version(2) + reserved(2) + revision(8) + payload_len(8) + sha256(32)
pub const HEADER_LEN: usize = 4 + 2 + 2 + 8 + 8 + 32;

/// The decoded, validated envelope header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotHeader {
    pub version: u16,
    /// The chainbase revision the snapshot was taken at — the accepted block
    /// number. The restore side re-reads it from the arena, but carrying it in
    /// the clear lets a receiver decide relevance without opening the payload.
    pub revision: i64,
    pub payload_len: u64,
    pub payload_sha256: [u8; 32],
}

/// Wrap raw `shared_memory.bin` bytes in the transport envelope.
pub fn encode(revision: i64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&SNAPSHOT_VERSION.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // reserved
    out.extend_from_slice(&revision.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    out.extend_from_slice(Digest::hash(payload).as_bytes());
    out.extend_from_slice(payload);
    out
}

/// Validate the header of an encoded snapshot without touching the payload.
pub fn peek_header(bytes: &[u8]) -> Result<SnapshotHeader, ChainError> {
    if bytes.len() < HEADER_LEN {
        return Err(bad(format!(
            "snapshot too short: {} < {HEADER_LEN} header bytes",
            bytes.len()
        )));
    }
    if bytes[0..4] != MAGIC {
        return Err(bad("snapshot magic mismatch".into()));
    }
    let version = u16::from_le_bytes([bytes[4], bytes[5]]);
    if version != SNAPSHOT_VERSION {
        return Err(bad(format!(
            "snapshot version {version} unsupported (expected {SNAPSHOT_VERSION})"
        )));
    }
    let revision = i64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let payload_len = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
    let mut payload_sha256 = [0u8; 32];
    payload_sha256.copy_from_slice(&bytes[24..56]);
    Ok(SnapshotHeader {
        version,
        revision,
        payload_len,
        payload_sha256,
    })
}

/// Validate the full envelope and return the header alongside the payload
/// slice. The checksum is recomputed, so a truncated or tampered payload is
/// rejected here rather than surfacing as chainbase corruption at open time.
pub fn decode(bytes: &[u8]) -> Result<(SnapshotHeader, &[u8]), ChainError> {
    let header = peek_header(bytes)?;
    let payload = &bytes[HEADER_LEN..];
    if payload.len() as u64 != header.payload_len {
        return Err(bad(format!(
            "snapshot payload length {} != declared {}",
            payload.len(),
            header.payload_len
        )));
    }
    if Digest::hash(payload).as_bytes() != &header.payload_sha256 {
        return Err(bad("snapshot payload checksum mismatch".into()));
    }
    Ok((header, payload))
}

fn bad(msg: String) -> ChainError {
    ChainError::InternalError(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_header_and_payload() {
        let payload = b"the quick brown fox".repeat(100);
        let bytes = encode(42, &payload);
        let (header, decoded) = decode(&bytes).unwrap();
        assert_eq!(header.version, SNAPSHOT_VERSION);
        assert_eq!(header.revision, 42);
        assert_eq!(header.payload_len, payload.len() as u64);
        assert_eq!(decoded, &payload[..]);
    }

    #[test]
    fn empty_payload_round_trips() {
        let bytes = encode(0, &[]);
        let (header, decoded) = decode(&bytes).unwrap();
        assert_eq!(header.payload_len, 0);
        assert!(decoded.is_empty());
    }

    #[test]
    fn rejects_short_buffer() {
        assert!(peek_header(&[0u8; 10]).is_err());
        assert!(decode(&[0u8; 10]).is_err());
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = encode(1, b"payload");
        bytes[0] = b'X';
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn rejects_wrong_version() {
        let mut bytes = encode(1, b"payload");
        // version lives at offset 4..6
        bytes[4] = 0xFF;
        bytes[5] = 0xFF;
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn rejects_tampered_payload() {
        let mut bytes = encode(1, b"payload-bytes-here");
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn rejects_truncated_payload() {
        let bytes = encode(1, b"payload-bytes-here");
        // Drop a payload byte but keep the header intact: length check fires.
        let truncated = &bytes[..bytes.len() - 1];
        assert!(decode(truncated).is_err());
    }

    #[test]
    fn peek_matches_decode_header() {
        let payload = b"abc".repeat(64);
        let bytes = encode(7, &payload);
        let peeked = peek_header(&bytes).unwrap();
        let (decoded, _) = decode(&bytes).unwrap();
        assert_eq!(peeked, decoded);
    }
}
