//! Physical state snapshots of the Rust arena.
//!
//! The arena checkpoint stores all registered tables in one file. This module
//! owns the wire envelope around those bytes: a small self-describing header and
//! checksum so a transferred snapshot can be validated before installation.
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
    /// The database revision the snapshot was taken at — the accepted block
    /// number. The restore side re-reads it from the arena, but carrying it in
    /// the clear lets a receiver decide relevance without opening the payload.
    pub revision: i64,
    pub payload_len: u64,
    pub payload_sha256: [u8; 32],
}

/// Wrap raw arena checkpoint bytes in the transport envelope.
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
/// rejected here rather than surfacing as arena corruption at open time.
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

// ----- sparse payload ----------------------------------------------------
//
// Sparse framing remains part of snapshot version 1 for compatibility with
// existing snapshots. It stores non-zero regions keyed by absolute offset, so
// payload and peak memory stay proportional to live state.
//
// Layout: `[u64 logical_len]` then a sequence of runs `[u64 offset][u64 len][len
// bytes]`, ascending. A run is emitted at block granularity, so a run may carry
// a few zero bytes inside a partially-used block — harmless, and it keeps the
// scan cheap.

/// Granularity at which the sparse scan decides zero vs. non-zero. Matches a
/// typical page so a partially-used page is copied whole.
pub const SPARSE_BLOCK: usize = 4096;

/// Begin a sparse payload for a file of `logical_len` bytes.
pub fn sparse_begin(logical_len: u64) -> Vec<u8> {
    logical_len.to_le_bytes().to_vec()
}

/// Append the non-zero runs of `chunk` — which begins at absolute offset `base`
/// in the file — to `payload`. `base` must be block-aligned (callers feed
/// block-aligned chunks except the final short one), so runs from consecutive
/// chunks abut cleanly.
pub fn sparse_append(payload: &mut Vec<u8>, base: u64, chunk: &[u8]) {
    let mut i = 0;
    while i < chunk.len() {
        let block_end = (i + SPARSE_BLOCK).min(chunk.len());
        if chunk[i..block_end].iter().any(|&b| b != 0) {
            // Extend over consecutive non-zero blocks into one run.
            let start = i;
            let mut j = block_end;
            while j < chunk.len() {
                let next = (j + SPARSE_BLOCK).min(chunk.len());
                if chunk[j..next].iter().any(|&b| b != 0) {
                    j = next;
                } else {
                    break;
                }
            }
            payload.extend_from_slice(&(base + start as u64).to_le_bytes());
            payload.extend_from_slice(&((j - start) as u64).to_le_bytes());
            payload.extend_from_slice(&chunk[start..j]);
            i = j;
        } else {
            i = block_end;
        }
    }
}

/// Walk a sparse payload, calling `write_run(offset, data)` for each stored run,
/// and return the logical length. Every run is bounds-checked against that
/// length, so a malformed payload is rejected rather than writing out of range.
pub fn sparse_expand(
    payload: &[u8],
    mut write_run: impl FnMut(u64, &[u8]) -> std::io::Result<()>,
) -> Result<u64, ChainError> {
    if payload.len() < 8 {
        return Err(bad("sparse: missing length header".into()));
    }
    let logical_len = u64::from_le_bytes(payload[0..8].try_into().unwrap());
    let mut pos = 8usize;
    let mut previous_end = 0u64;
    while pos < payload.len() {
        let header_end = pos
            .checked_add(16)
            .filter(|end| *end <= payload.len())
            .ok_or_else(|| bad("sparse: truncated run header".into()))?;
        let offset = u64::from_le_bytes(payload[pos..pos + 8].try_into().unwrap());
        let len = u64::from_le_bytes(payload[pos + 8..pos + 16].try_into().unwrap());
        pos = header_end;
        if len == 0 {
            return Err(bad("sparse: zero-length run".into()));
        }
        let end = offset
            .checked_add(len)
            .filter(|end| *end <= logical_len)
            .ok_or_else(|| bad("sparse: run out of bounds".into()))?;
        if offset < previous_end {
            return Err(bad("sparse: runs overlap or are out of order".into()));
        }
        let len_usize = usize::try_from(len)
            .map_err(|_| bad("sparse: run length does not fit this platform".into()))?;
        let data_end = pos
            .checked_add(len_usize)
            .filter(|end| *end <= payload.len())
            .ok_or_else(|| bad("sparse: truncated run data".into()))?;
        if end > logical_len {
            return Err(bad("sparse: run out of bounds".into()));
        }
        write_run(offset, &payload[pos..data_end])
            .map_err(|e| bad(format!("sparse: write run: {e}")))?;
        pos = data_end;
        previous_end = end;
    }
    Ok(logical_len)
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

    #[test]
    fn sparse_rejects_noncanonical_and_overflowing_runs() {
        let mut zero_len = 8u64.to_le_bytes().to_vec();
        zero_len.extend_from_slice(&0u64.to_le_bytes());
        zero_len.extend_from_slice(&0u64.to_le_bytes());
        assert!(sparse_expand(&zero_len, |_, _| Ok(())).is_err());

        let mut overlapping = 16u64.to_le_bytes().to_vec();
        for (offset, data) in [(4u64, &[1u8, 2][..]), (5, &[3u8][..])] {
            overlapping.extend_from_slice(&offset.to_le_bytes());
            overlapping.extend_from_slice(&(data.len() as u64).to_le_bytes());
            overlapping.extend_from_slice(data);
        }
        assert!(sparse_expand(&overlapping, |_, _| Ok(())).is_err());

        let mut overflowing = u64::MAX.to_le_bytes().to_vec();
        overflowing.extend_from_slice(&u64::MAX.to_le_bytes());
        overflowing.extend_from_slice(&2u64.to_le_bytes());
        overflowing.extend_from_slice(&[1, 2]);
        assert!(sparse_expand(&overflowing, |_, _| Ok(())).is_err());
    }

    /// Encode `data` as a sparse payload and expand it back into a fresh buffer.
    fn sparse_round_trip(data: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut payload = sparse_begin(data.len() as u64);
        // Feed it in block-aligned chunks, as the file reader does.
        let chunk = SPARSE_BLOCK * 3;
        let mut off = 0;
        while off < data.len() {
            let end = (off + chunk).min(data.len());
            sparse_append(&mut payload, off as u64, &data[off..end]);
            off = end;
        }
        let mut out = vec![0u8; data.len()];
        let logical = sparse_expand(&payload, |o, d| {
            out[o as usize..o as usize + d.len()].copy_from_slice(d);
            Ok(())
        })
        .unwrap();
        assert_eq!(logical, data.len() as u64);
        (payload, out)
    }

    #[test]
    fn sparse_round_trips_mixed_content() {
        let mut data = vec![0u8; SPARSE_BLOCK * 10];
        // Scatter non-zero content across a few blocks, leaving zero gaps.
        data[10] = 1;
        for b in &mut data[SPARSE_BLOCK * 4..SPARSE_BLOCK * 5] {
            *b = 0xAB;
        }
        data[SPARSE_BLOCK * 9 + 7] = 0xFF;
        let (_payload, out) = sparse_round_trip(&data);
        assert_eq!(out, data);
    }

    #[test]
    fn sparse_all_zeros_stores_no_runs() {
        let data = vec![0u8; SPARSE_BLOCK * 8];
        let (payload, out) = sparse_round_trip(&data);
        // Only the 8-byte length header — a zeroed reservation costs nothing.
        assert_eq!(payload.len(), 8);
        assert_eq!(out, data);
    }

    #[test]
    fn sparse_all_nonzero_round_trips() {
        let data = vec![0x7u8; SPARSE_BLOCK * 3 + 123];
        let (_payload, out) = sparse_round_trip(&data);
        assert_eq!(out, data);
    }

    #[test]
    fn sparse_empty_round_trips() {
        let (payload, out) = sparse_round_trip(&[]);
        assert_eq!(payload.len(), 8);
        assert!(out.is_empty());
    }

    #[test]
    fn sparse_expand_rejects_out_of_bounds_run() {
        // logical_len = 16, but a run claims offset 8 len 100.
        let mut payload = sparse_begin(16);
        payload.extend_from_slice(&8u64.to_le_bytes());
        payload.extend_from_slice(&100u64.to_le_bytes());
        payload.extend_from_slice(&[1u8; 100]);
        let r = sparse_expand(&payload, |_, _| Ok(()));
        assert!(r.is_err());
    }

    #[test]
    fn sparse_expand_rejects_truncated_run() {
        let mut payload = sparse_begin(4096);
        payload.extend_from_slice(&0u64.to_le_bytes());
        payload.extend_from_slice(&64u64.to_le_bytes());
        payload.extend_from_slice(&[1u8; 8]); // claims 64, only 8 present
        assert!(sparse_expand(&payload, |_, _| Ok(())).is_err());
    }
}
