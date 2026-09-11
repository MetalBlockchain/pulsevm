//! Peer-to-peer state sync: moving a physical arena snapshot out of band.
//!
//! The MetalGo state summary is a small consensus commitment to the accepted
//! block, the deterministic arena state root, the active producer schedule, and
//! the protocol schedule. The snapshot itself — tens of MB of live arena —
//! travels separately, requested chunk by chunk over the P2P AppRequest channel.
//! This module owns the parts that don't care how bytes reach the wire: the
//! commitment format, the download driver, and the chunk request encoding. The
//! transport (the AppSender gRPC client and the request/response correlation)
//! lives in the node binary; a test drives the same code with a direct fetch.
//!
//! Two honest nodes may hold byte-different physical arenas for the same logical
//! state, so the transport hash is intentionally not part of the summary id.
//! Instead, the downloaded arena is loaded in isolation and its canonical state
//! root must match the root covered by the summary id before it can be installed.

use pulsevm_crypto::Digest;
use pulsevm_error::ChainError;
use pulsevm_serialization::{
    Read,
    Write,
};

use crate::chain::{
    block::SignedBlock,
    producer_schedule::ProducerSchedule,
    protocol_features::ProtocolScheduleCommitment,
};

// Prefix every authenticated summary. An old binary interprets these first four
// bytes as an impossible schedule length and rejects it; a new binary rejects
// any summary without this prefix, closing the legacy trusted-transfer path.
const AUTHENTICATED_SUMMARY_MAGIC: &[u8; 8] = b"PVMSUM02";
const PROTOCOL_COMMITMENT_MAGIC: &[u8; 8] = b"PVMPC001";
const PROTOCOL_COMMITMENT_LEN: usize = 8 + 4 + 32;
const STATE_ROOT_LEN: usize = 32;
const SUMMARY_ID_DOMAIN: &[u8] = b"pulsevm-state-summary-v2\0";

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
/// tip block and schedule to adopt, the authenticated logical state root, and
/// the length and hash of the physical snapshot payload.
#[derive(Debug, Clone)]
pub struct SyncTarget {
    pub height: u64,
    /// Canonical logical database root covered by the Avalanche summary id.
    pub state_root: [u8; 32],
    /// Hash of this provider's physical snapshot bytes. This is a transport
    /// integrity check only; different nodes may encode the same state
    /// differently, so it is deliberately excluded from the summary id.
    pub hash: [u8; 32],
    pub total_len: u64,
    pub block: SignedBlock,
    pub schedule: ProducerSchedule,
    /// Always present in authenticated v2 summaries. Kept optional at the
    /// controller boundary so protocol validation remains explicit.
    pub protocol_commitment: Option<ProtocolScheduleCommitment>,
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

/// Encode an authenticated state summary.
///
/// Layout: `[magic][schedule][block][total_len][snapshot_hash][state_root]
/// [protocol_commitment]`, with schedule and block length-prefixed. The state
/// root and every consensus-relevant field feed [`summary_id`]; the physical
/// snapshot metadata does not, because its representation is provider-specific.
pub fn encode_summary_bytes(
    schedule_bytes: &[u8],
    block_bytes: &[u8],
    total_len: u64,
    hash: &[u8; 32],
    state_root: &[u8; 32],
    protocol_commitment: ProtocolScheduleCommitment,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        AUTHENTICATED_SUMMARY_MAGIC.len()
            + 8
            + schedule_bytes.len()
            + block_bytes.len()
            + 8
            + 32
            + STATE_ROOT_LEN
            + PROTOCOL_COMMITMENT_LEN,
    );
    bytes.extend_from_slice(AUTHENTICATED_SUMMARY_MAGIC);
    bytes.extend_from_slice(&(schedule_bytes.len() as u32).to_le_bytes());
    bytes.extend_from_slice(schedule_bytes);
    bytes.extend_from_slice(&(block_bytes.len() as u32).to_le_bytes());
    bytes.extend_from_slice(block_bytes);
    bytes.extend_from_slice(&total_len.to_le_bytes());
    bytes.extend_from_slice(hash);
    bytes.extend_from_slice(state_root);
    bytes.extend_from_slice(PROTOCOL_COMMITMENT_MAGIC);
    bytes.extend_from_slice(&protocol_commitment.protocol_version.to_le_bytes());
    bytes.extend_from_slice(&protocol_commitment.activated_schedule_hash);
    bytes
}

/// Calculate the id Avalanche validators vote on for a state summary.
///
/// Physical snapshot bytes are not canonical across nodes, but the logical arena
/// root is. Committing the root here lets validators agree on one id while still
/// rejecting a snapshot containing state other than the state they voted for.
pub fn summary_id(
    block: &SignedBlock,
    schedule: &ProducerSchedule,
    state_root: &[u8; 32],
    protocol_commitment: ProtocolScheduleCommitment,
) -> Result<crate::chain::id::Id, ChainError> {
    let block_id = block.id()?;
    let block_bytes = block
        .pack()
        .map_err(|e| ChainError::InternalError(format!("summary: pack block: {e}")))?;
    let block_hash = Digest::hash(&block_bytes);
    let schedule_bytes = schedule
        .pack()
        .map_err(|e| ChainError::InternalError(format!("summary: pack schedule: {e}")))?;
    let schedule_hash = Digest::hash(&schedule_bytes);
    let mut commitment = Vec::with_capacity(SUMMARY_ID_DOMAIN.len() + 32 * 5 + 8);
    commitment.extend_from_slice(SUMMARY_ID_DOMAIN);
    commitment.extend_from_slice(block_id.as_bytes());
    commitment.extend_from_slice(block_hash.as_bytes());
    commitment.extend_from_slice(&block.block_num().to_le_bytes());
    commitment.extend_from_slice(state_root);
    commitment.extend_from_slice(schedule_hash.as_bytes());
    commitment.extend_from_slice(&protocol_commitment.protocol_version.to_le_bytes());
    commitment.extend_from_slice(&protocol_commitment.activated_schedule_hash);
    Ok(crate::chain::id::Id::new(
        *Digest::hash(&commitment).as_bytes(),
    ))
}

/// Parse a state summary into a [`SyncTarget`].
pub fn decode_summary_bytes(bytes: &[u8]) -> Result<SyncTarget, ChainError> {
    let bytes = bytes
        .strip_prefix(AUTHENTICATED_SUMMARY_MAGIC)
        .ok_or_else(|| {
            ChainError::InternalError(
                "summary: unauthenticated legacy state summaries are not supported".into(),
            )
        })?;
    let mut pos = 0usize;
    let schedule = ProducerSchedule::read_bounded(take_section(bytes, &mut pos)?)
        .map_err(|e| ChainError::InternalError(format!("summary: read schedule: {}", e)))?;
    let block_bytes = take_section(bytes, &mut pos)?;
    let mut block_pos = 0usize;
    let block = SignedBlock::read(block_bytes, &mut block_pos)
        .map_err(|e| ChainError::InternalError(format!("summary: read block: {}", e)))?;
    if block_pos != block_bytes.len() {
        return Err(ChainError::InternalError(format!(
            "summary: packed block has {} trailing byte(s)",
            block_bytes.len() - block_pos
        )));
    }
    let trailer_len = 8 + 32 + STATE_ROOT_LEN + PROTOCOL_COMMITMENT_LEN;
    if pos + trailer_len != bytes.len() {
        return Err(ChainError::InternalError(
            "summary: invalid authenticated trailer length".into(),
        ));
    }
    let total_len = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap());
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes[pos + 8..pos + 40]);
    let mut state_root = [0u8; 32];
    state_root.copy_from_slice(&bytes[pos + 40..pos + 72]);
    pos += 72;
    if &bytes[pos..pos + 8] != PROTOCOL_COMMITMENT_MAGIC {
        return Err(ChainError::InternalError(
            "summary: invalid protocol commitment header".into(),
        ));
    }
    let protocol_version = u32::from_le_bytes(bytes[pos + 8..pos + 12].try_into().unwrap());
    let mut activated_schedule_hash = [0u8; 32];
    activated_schedule_hash.copy_from_slice(&bytes[pos + 12..pos + 44]);
    let protocol_commitment = Some(ProtocolScheduleCommitment {
        protocol_version,
        activated_schedule_hash,
    });
    Ok(SyncTarget {
        height: block.block_num() as u64,
        state_root,
        hash,
        total_len,
        block,
        schedule,
        protocol_commitment,
    })
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use pulsevm_serialization::Write;

    use crate::chain::{
        crypto::PrivateKey,
        name::Name,
        producer_schedule::ProducerKey,
    };

    fn packed_valid_schedule() -> Vec<u8> {
        ProducerSchedule {
            version: 0,
            producers: vec![ProducerKey {
                producer_name: Name::from_str("pulse").unwrap(),
                block_signing_key: PrivateKey::random().get_public_key(),
            }],
        }
        .pack()
        .unwrap()
    }

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

    #[test]
    fn authenticated_summary_round_trips_and_legacy_is_rejected() {
        let schedule = packed_valid_schedule();
        let block = SignedBlock::default().pack().unwrap();
        let commitment = ProtocolScheduleCommitment {
            protocol_version: 7,
            activated_schedule_hash: [9; 32],
        };
        let encoded = encode_summary_bytes(&schedule, &block, 123, &[4; 32], &[5; 32], commitment);
        assert!(encoded.starts_with(AUTHENTICATED_SUMMARY_MAGIC));
        let decoded = decode_summary_bytes(&encoded).unwrap();
        assert_eq!(decoded.total_len, 123);
        assert_eq!(decoded.hash, [4; 32]);
        assert_eq!(decoded.state_root, [5; 32]);
        assert_eq!(decoded.protocol_commitment, Some(commitment));

        // Dropping the v2 magic approximates the old unauthenticated layout.
        // It must fail closed rather than silently becoming a trusted transfer.
        assert!(decode_summary_bytes(&encoded[AUTHENTICATED_SUMMARY_MAGIC.len()..]).is_err());
    }

    #[test]
    fn summary_rejects_tampered_or_unknown_protocol_trailer() {
        let schedule = packed_valid_schedule();
        let block = SignedBlock::default().pack().unwrap();
        let commitment = ProtocolScheduleCommitment {
            protocol_version: 2,
            activated_schedule_hash: [0; 32],
        };
        let mut encoded =
            encode_summary_bytes(&schedule, &block, 0, &[0; 32], &[1; 32], commitment);
        let magic = encoded.len() - PROTOCOL_COMMITMENT_LEN;
        encoded[magic] ^= 0xff;
        assert!(decode_summary_bytes(&encoded).is_err());

        let mut trailing =
            encode_summary_bytes(&schedule, &block, 0, &[0; 32], &[1; 32], commitment);
        trailing.push(0);
        assert!(decode_summary_bytes(&trailing).is_err());
    }

    #[test]
    fn summary_id_commits_to_state_root_and_schedule() {
        let schedule_bytes = packed_valid_schedule();
        let schedule = ProducerSchedule::read_bounded(&schedule_bytes).unwrap();
        let block = SignedBlock::default();
        let commitment = ProtocolScheduleCommitment {
            protocol_version: 1,
            activated_schedule_hash: [0; 32],
        };
        let original = summary_id(&block, &schedule, &[1; 32], commitment).unwrap();
        let changed_root = summary_id(&block, &schedule, &[2; 32], commitment).unwrap();
        assert_ne!(original, changed_root);

        let other_schedule = ProducerSchedule::read_bounded(&packed_valid_schedule()).unwrap();
        let changed_schedule = summary_id(&block, &other_schedule, &[1; 32], commitment).unwrap();
        assert_ne!(original, changed_schedule);
    }

    #[tokio::test]
    async fn download_reassembles_and_verifies() {
        // A payload larger than one chunk, so the driver iterates.
        let payload: Vec<u8> = (0..(SNAPSHOT_CHUNK_LEN as usize * 2 + 777))
            .map(|i| i as u8)
            .collect();
        let target = SyncTarget {
            height: 1,
            state_root: [0u8; 32],
            hash: *Digest::hash(&payload).as_bytes(),
            total_len: payload.len() as u64,
            block: SignedBlock::default(),
            schedule: ProducerSchedule::default(),
            protocol_commitment: None,
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
            state_root: [0u8; 32],
            hash: [0u8; 32], // wrong
            total_len: payload.len() as u64,
            block: SignedBlock::default(),
            schedule: ProducerSchedule::default(),
            protocol_commitment: None,
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
            state_root: [0u8; 32],
            hash: [0u8; 32],
            total_len: MAX_SNAPSHOT_LEN + 1,
            block: SignedBlock::default(),
            schedule: ProducerSchedule::default(),
            protocol_commitment: None,
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
            state_root: [0u8; 32],
            hash: [0u8; 32],
            total_len: 100,
            block: SignedBlock::default(),
            schedule: ProducerSchedule::default(),
            protocol_commitment: None,
        };
        let r = download_snapshot(&target, |_off, _len| async { Ok(vec![0u8; 1]) }).await;
        assert!(r.is_err());
    }
}
