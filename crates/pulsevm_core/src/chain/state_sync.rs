//! Peer-to-peer state sync: moving a physical arena snapshot out of band.
//!
//! The Avalanche state summary is a small commitment (the accepted block id,
//! which every node agrees on). The snapshot itself — tens of MB of live arena —
//! travels separately, requested chunk by chunk over the P2P AppRequest channel.
//! This module owns the parts that don't care how bytes reach the wire: the
//! commitment format, the download driver, and the chunk request encoding. The
//! transport (the AppSender gRPC client and the request/response correlation)
//! lives in the node binary; a test drives the same code with a direct fetch.
//!
//! A file-copy snapshot is not verifiable against a cross-node root — two honest
//! nodes hold byte-different arenas for the same state — so a syncing node pulls
//! the whole snapshot from a single peer and checks it against the hash that peer
//! advertised in its summary. That is a trusted transfer, appropriate for a
//! controlled validator set; a verifiable-state-root scheme would replace only
//! the hash check here, not the transport.

use pulsevm_crypto::Digest;
use pulsevm_error::ChainError;
use pulsevm_serialization::Read;

use crate::chain::{
    block::SignedBlock,
    producer_schedule::ProducerSchedule,
};

/// Bytes requested per AppRequest. 256 KiB keeps a chunk comfortably inside a
/// single P2P message while making the round-trip count reasonable for a
/// multi-MB snapshot.
pub const SNAPSHOT_CHUNK_LEN: u32 = 256 * 1024;

/// Hard ceiling on an advertised snapshot length. A summary names the payload
/// size a syncing node will download; this refuses an absurd value up front so a
/// misbehaving or corrupt peer can't point us at a multi-terabyte "snapshot".
/// Well above any real arena (the default mmap DB is 20 GiB).
pub const MAX_SNAPSHOT_LEN: u64 = 64 * 1024 * 1024 * 1024;

/// What a syncing node learned from a state summary and now has to fetch: the
/// tip block and schedule to adopt, and the length and hash of the snapshot
/// payload to download and verify.
#[derive(Debug, Clone)]
pub struct SyncTarget {
    pub height: u64,
    pub hash: [u8; 32],
    pub total_len: u64,
    pub block: SignedBlock,
    pub schedule: ProducerSchedule,
}

/// A request for one slice of the snapshot payload. `height` and `hash` name the
/// exact snapshot (a serving peer only answers if its cached snapshot matches
/// both), and `offset`/`len` the slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkRequest {
    pub height: u64,
    pub hash: [u8; 32],
    pub offset: u64,
    pub len: u32,
}

impl ChunkRequest {
    /// Fixed on-wire size: height(8) + hash(32) + offset(8) + len(4).
    pub const ENCODED_LEN: usize = 8 + 32 + 8 + 4;

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::ENCODED_LEN);
        out.extend_from_slice(&self.height.to_le_bytes());
        out.extend_from_slice(&self.hash);
        out.extend_from_slice(&self.offset.to_le_bytes());
        out.extend_from_slice(&self.len.to_le_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ChainError> {
        if bytes.len() != Self::ENCODED_LEN {
            return Err(ChainError::InternalError(format!(
                "chunk request: expected {} bytes, got {}",
                Self::ENCODED_LEN,
                bytes.len()
            )));
        }
        let height = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes[8..40]);
        let offset = u64::from_le_bytes(bytes[40..48].try_into().unwrap());
        let len = u32::from_le_bytes(bytes[48..52].try_into().unwrap());
        Ok(ChunkRequest {
            height,
            hash,
            offset,
            len,
        })
    }
}

/// Download the whole snapshot payload for `target` by pulling successive chunks
/// through `fetch`, then verify it against the advertised hash.
///
/// `fetch(offset, len)` returns exactly `len` bytes or errors; how it gets them
/// — a direct call in a test, an AppRequest round-trip in the node — is the
/// caller's concern. The final hash check is what makes a truncated or wrong
/// transfer fail here rather than as database corruption at apply time.
pub async fn download_snapshot<F, Fut>(
    target: &SyncTarget,
    mut fetch: F,
) -> Result<Vec<u8>, ChainError>
where
    F: FnMut(u64, u32) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>, ChainError>>,
{
    if target.total_len > MAX_SNAPSHOT_LEN {
        return Err(ChainError::InternalError(format!(
            "snapshot length {} exceeds the maximum of {} bytes",
            target.total_len, MAX_SNAPSHOT_LEN
        )));
    }
    // Grow as bytes arrive rather than reserving the advertised size up front: a
    // peer only costs us the memory it actually delivers, and the length is
    // already bounded above.
    let mut buf: Vec<u8> = Vec::new();
    while (buf.len() as u64) < target.total_len {
        let offset = buf.len() as u64;
        // Compute the remaining length in u64 and clamp before narrowing: a plain
        // `(total_len - offset) as u32` truncates, and lands on exactly 0 when the
        // remainder is a multiple of 2^32, which would stall the loop forever.
        let len = (SNAPSHOT_CHUNK_LEN as u64).min(target.total_len - offset) as u32;
        let data = fetch(offset, len).await?;
        if data.len() != len as usize {
            return Err(ChainError::InternalError(format!(
                "snapshot chunk at {offset}: expected {len} bytes, got {}",
                data.len()
            )));
        }
        buf.extend_from_slice(&data);
    }
    if Digest::hash(&buf).as_bytes() != &target.hash {
        return Err(ChainError::InternalError(
            "downloaded snapshot hash does not match the summary".into(),
        ));
    }
    Ok(buf)
}

/// Split a length-prefixed section off the front of `bytes`, advancing `pos`.
pub fn take_section<'a>(bytes: &'a [u8], pos: &mut usize) -> Result<&'a [u8], ChainError> {
    if *pos + 4 > bytes.len() {
        return Err(ChainError::InternalError(
            "summary: truncated length".into(),
        ));
    }
    let len = u32::from_le_bytes(bytes[*pos..*pos + 4].try_into().unwrap()) as usize;
    *pos += 4;
    if *pos + len > bytes.len() {
        return Err(ChainError::InternalError(
            "summary: truncated section".into(),
        ));
    }
    let section = &bytes[*pos..*pos + len];
    *pos += len;
    Ok(section)
}

/// A state summary's bytes: `[schedule][block][total_len][hash]`, the first two
/// length-prefixed. Small — the id (the block id) is the commitment nodes agree
/// on; the payload is fetched separately.
pub fn encode_summary_bytes(
    schedule_bytes: &[u8],
    block_bytes: &[u8],
    total_len: u64,
    hash: &[u8; 32],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8 + schedule_bytes.len() + block_bytes.len() + 8 + 32);
    bytes.extend_from_slice(&(schedule_bytes.len() as u32).to_le_bytes());
    bytes.extend_from_slice(schedule_bytes);
    bytes.extend_from_slice(&(block_bytes.len() as u32).to_le_bytes());
    bytes.extend_from_slice(block_bytes);
    bytes.extend_from_slice(&total_len.to_le_bytes());
    bytes.extend_from_slice(hash);
    bytes
}

/// Parse a state summary into a [`SyncTarget`].
pub fn decode_summary_bytes(bytes: &[u8]) -> Result<SyncTarget, ChainError> {
    let mut pos = 0usize;
    let schedule = ProducerSchedule::read_bounded(take_section(bytes, &mut pos)?)
        .map_err(|e| ChainError::InternalError(format!("summary: read schedule: {}", e)))?;
    let block = SignedBlock::read(take_section(bytes, &mut pos)?, &mut 0)
        .map_err(|e| ChainError::InternalError(format!("summary: read block: {}", e)))?;
    if pos + 40 > bytes.len() {
        return Err(ChainError::InternalError(
            "summary: truncated trailer".into(),
        ));
    }
    let total_len = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap());
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes[pos + 8..pos + 40]);
    Ok(SyncTarget {
        height: block.block_num() as u64,
        hash,
        total_len,
        block,
        schedule,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_request_round_trips() {
        let req = ChunkRequest {
            height: 42,
            hash: [7u8; 32],
            offset: 1024,
            len: SNAPSHOT_CHUNK_LEN,
        };
        assert_eq!(ChunkRequest::decode(&req.encode()).unwrap(), req);
    }

    #[test]
    fn chunk_request_rejects_wrong_size() {
        assert!(ChunkRequest::decode(&[0u8; 10]).is_err());
    }

    #[tokio::test]
    async fn download_reassembles_and_verifies() {
        // A payload larger than one chunk, so the driver iterates.
        let payload: Vec<u8> = (0..(SNAPSHOT_CHUNK_LEN as usize * 2 + 777))
            .map(|i| i as u8)
            .collect();
        let target = SyncTarget {
            height: 1,
            hash: *Digest::hash(&payload).as_bytes(),
            total_len: payload.len() as u64,
            block: SignedBlock::default(),
            schedule: ProducerSchedule::default(),
        };
        let src = payload.clone();
        let got = download_snapshot(&target, |off, len| {
            let src = src.clone();
            async move { Ok(src[off as usize..off as usize + len as usize].to_vec()) }
        })
        .await
        .unwrap();
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn download_rejects_hash_mismatch() {
        let payload = vec![1u8; 100];
        let target = SyncTarget {
            height: 1,
            hash: [0u8; 32], // wrong
            total_len: payload.len() as u64,
            block: SignedBlock::default(),
            schedule: ProducerSchedule::default(),
        };
        let src = payload.clone();
        let r = download_snapshot(&target, |off, len| {
            let src = src.clone();
            async move { Ok(src[off as usize..off as usize + len as usize].to_vec()) }
        })
        .await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn download_rejects_oversized_total_len() {
        // An absurd advertised length is refused up front, before any fetch, so
        // it can never drive a huge allocation.
        let target = SyncTarget {
            height: 1,
            hash: [0u8; 32],
            total_len: MAX_SNAPSHOT_LEN + 1,
            block: SignedBlock::default(),
            schedule: ProducerSchedule::default(),
        };
        let r = download_snapshot(&target, |_off, _len| async {
            panic!("fetch must not be called for an oversized snapshot");
            #[allow(unreachable_code)]
            Ok(Vec::new())
        })
        .await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn download_rejects_short_chunk() {
        let target = SyncTarget {
            height: 1,
            hash: [0u8; 32],
            total_len: 100,
            block: SignedBlock::default(),
            schedule: ProducerSchedule::default(),
        };
        let r = download_snapshot(&target, |_off, _len| async { Ok(vec![0u8; 1]) }).await;
        assert!(r.is_err());
    }
}
