//! The state summaries a node offers to peers that need to state-sync, kept on disk.
//!
//! A summary is a full snapshot of the state at one block, plus a small
//! commitment to it. The host accepts a summary only if more than half of the
//! validator weight returns the SAME summary for the same height in one vote, so
//! every validator has to offer the same heights: those that are a multiple of a
//! fixed interval. A summary is built once, in the background, when the block at
//! such a height is accepted, and the newest two are kept here. Nothing is built
//! while a peer is waiting for one, and a chunk is read from the file, not copied
//! out of memory under any lock.
//!
//! On disk, in the store's directory: `<height>.snapshot` (the envelope peers
//! download) and `<height>.summary` (a small JSON file: the summary bytes, id, the
//! envelope's hash and length). The `.summary` file is written last, after the
//! snapshot is durable, so its presence means the pair is whole. A peer checks every
//! chunk against the hash in the summary it voted for, so a damaged file cannot
//! poison a peer; it only fails that download.

use std::{
    fs,
    io::{
        Read,
        Seek,
        SeekFrom,
        Write,
    },
    path::{
        Path,
        PathBuf,
    },
    sync::Mutex,
};

use serde::{
    Deserialize,
    Serialize,
};

use pulsevm_error::ChainError;

use crate::chain::{
    controller::BuiltSummary,
    id::Id,
    state_sync::SNAPSHOT_CHUNK_LEN,
};

/// How many summaries are kept: the newest and the one before it, so a peer that is
/// halfway through downloading the older one is not cut off the moment a newer one
/// appears.
pub const SUMMARIES_KEPT: usize = 2;

/// A summary on disk.
#[derive(Clone, Debug)]
pub struct StoredSummary {
    pub height: u64,
    pub id: Id,
    /// The summary as sent to a peer (`encode_summary_bytes`).
    pub bytes: Vec<u8>,
    /// The hash of the snapshot envelope the summary commits to.
    pub hash: [u8; 32],
    /// The length of the snapshot envelope.
    pub len: u64,
    /// One leaf hash per chunk, kept so a chunk request can be answered with
    /// its Merkle proof without re-reading and re-hashing the whole snapshot
    /// file (which the chunk itself already costs reading; the leaves are the
    /// few-hundred-KB-to-few-MB of metadata the proof is built from).
    chunk_merkle_leaves: Vec<[u8; 32]>,
    snapshot: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct Meta {
    height: u64,
    id: String,
    summary: String,
    hash: String,
    len: u64,
    #[serde(default)]
    chunk_merkle_leaves: Vec<String>,
}

pub struct SummaryStore {
    dir: PathBuf,
    entries: Mutex<Vec<StoredSummary>>,
}

fn io_error(what: &str, path: &Path, error: impl std::fmt::Display) -> ChainError {
    ChainError::InternalError(format!("summary store: {what} {}: {error}", path.display()))
}

fn sync_dir(dir: &Path) -> Result<(), ChainError> {
    fs::File::open(dir)
        .and_then(|handle| handle.sync_all())
        .map_err(|e| io_error("sync", dir, e))
}

fn names(height: u64) -> (String, String) {
    (format!("{height}.snapshot"), format!("{height}.summary"))
}

impl SummaryStore {
    /// Open (creating if needed) the store at `dir`, taking up the summaries a
    /// previous run left. Half-written files and orphaned/corrupt pairs are
    /// removed; they can be rebuilt from the accepted state.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, ChainError> {
        let dir = dir.into();
        fs::create_dir_all(&dir).map_err(|e| io_error("create", &dir, e))?;
        let mut entries = Vec::new();
        let listing = fs::read_dir(&dir).map_err(|e| io_error("list", &dir, e))?;
        let mut snapshots_with_valid_summaries = std::collections::BTreeSet::new();
        for entry in listing {
            let entry = entry.map_err(|e| io_error("list entry", &dir, e))?;
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".tmp") {
                remove_if_present(&path)?;
                continue;
            }
            if !name.ends_with(".summary") {
                continue;
            }
            if let Some(summary) = Self::load(&dir, &path) {
                snapshots_with_valid_summaries.insert(summary.height);
                entries.push(summary);
            } else {
                if let Some(height) = name
                    .strip_suffix(".summary")
                    .and_then(|height| height.parse::<u64>().ok())
                {
                    let (snapshot_name, _) = names(height);
                    remove_if_present(&dir.join(snapshot_name))?;
                }
                remove_if_present(&path)?;
            }
        }
        for entry in fs::read_dir(&dir).map_err(|e| io_error("list", &dir, e))? {
            let entry = entry.map_err(|e| io_error("list entry", &dir, e))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(height) = name
                .strip_suffix(".snapshot")
                .and_then(|height| height.parse::<u64>().ok())
                && !snapshots_with_valid_summaries.contains(&height)
            {
                remove_if_present(&entry.path())?;
            }
        }
        entries.sort_by_key(|summary| summary.height);
        let store = Self {
            dir,
            entries: Mutex::new(entries),
        };
        store.prune()?;
        Ok(store)
    }

    fn load(dir: &Path, meta_path: &Path) -> Option<StoredSummary> {
        let meta: Meta = serde_json::from_slice(&fs::read(meta_path).ok()?).ok()?;
        let (snapshot_name, _) = names(meta.height);
        let snapshot = dir.join(snapshot_name);
        if fs::metadata(&snapshot).ok()?.len() != meta.len {
            return None;
        }
        let id: [u8; 32] = hex::decode(&meta.id).ok()?.try_into().ok()?;
        let hash: [u8; 32] = hex::decode(&meta.hash).ok()?.try_into().ok()?;
        let chunk_merkle_leaves: Vec<[u8; 32]> = meta
            .chunk_merkle_leaves
            .iter()
            .map(|leaf| hex::decode(leaf).ok()?.try_into().ok())
            .collect::<Option<_>>()?;
        // A meta file from before this field existed, or a truncated one,
        // leaves this empty or short: a pair this node cannot correctly answer
        // chunk requests for, no different from a size mismatch above.
        if chunk_merkle_leaves.len() as u64
            != crate::chain::state_sync::chunk_count(meta.len)
        {
            return None;
        }
        Some(StoredSummary {
            height: meta.height,
            id: Id::new(id),
            bytes: hex::decode(&meta.summary).ok()?,
            hash,
            len: meta.len,
            chunk_merkle_leaves,
            snapshot,
        })
    }

    /// Write a built summary to disk and offer it. The snapshot is made durable
    /// first and the small `.summary` file last, so a kill part-way leaves either
    /// nothing or a whole pair. The older summaries beyond [`SUMMARIES_KEPT`] are
    /// then removed.
    pub fn register(&self, built: BuiltSummary) -> Result<StoredSummary, ChainError> {
        let (snapshot_name, meta_name) = names(built.height);
        let snapshot = self.dir.join(&snapshot_name);
        let write = |name: &str, bytes: &[u8]| -> Result<(), ChainError> {
            let tmp = self.dir.join(format!("{name}.tmp"));
            let mut file = fs::File::create(&tmp).map_err(|e| io_error("create", &tmp, e))?;
            file.write_all(bytes)
                .and_then(|()| file.sync_all())
                .map_err(|e| io_error("write", &tmp, e))?;
            fs::rename(&tmp, self.dir.join(name)).map_err(|e| io_error("rename", &tmp, e))
        };
        write(&snapshot_name, &built.envelope)?;
        let meta = Meta {
            height: built.height,
            id: hex::encode(built.id.as_bytes()),
            summary: hex::encode(&built.bytes),
            hash: hex::encode(built.hash),
            len: built.envelope.len() as u64,
            chunk_merkle_leaves: built
                .chunk_merkle_leaves
                .iter()
                .map(hex::encode)
                .collect(),
        };
        let meta_bytes = serde_json::to_vec(&meta)
            .map_err(|e| ChainError::InternalError(format!("summary store: encode: {e}")))?;
        write(&meta_name, &meta_bytes)?;
        sync_dir(&self.dir)?;
        let stored = StoredSummary {
            height: built.height,
            id: built.id,
            bytes: built.bytes,
            hash: built.hash,
            len: meta.len,
            chunk_merkle_leaves: built.chunk_merkle_leaves,
            snapshot,
        };
        {
            let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            entries.retain(|entry| entry.height != stored.height);
            entries.push(stored.clone());
            entries.sort_by_key(|entry| entry.height);
        }
        self.prune()?;
        Ok(stored)
    }

    fn prune(&self) -> Result<(), ChainError> {
        let doomed: Vec<StoredSummary> = {
            let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            let excess = entries.len().saturating_sub(SUMMARIES_KEPT);
            entries.drain(..excess).collect()
        };
        for old in doomed {
            let (snapshot_name, meta_name) = names(old.height);
            // The marker first: a kill between the two leaves a snapshot with no
            // summary, which is ignored, not a summary with no snapshot.
            let _ = fs::remove_file(self.dir.join(meta_name));
            let _ = fs::remove_file(self.dir.join(snapshot_name));
        }
        Ok(())
    }

    /// The newest summary at or below `max_height`.
    pub fn newest_at_or_below(&self, max_height: u64) -> Option<StoredSummary> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries
            .iter()
            .rev()
            .find(|entry| entry.height <= max_height)
            .cloned()
    }

    /// The summary for exactly `height`, if one is kept.
    pub fn at(&self, height: u64) -> Option<StoredSummary> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.iter().find(|entry| entry.height == height).cloned()
    }

    pub fn heights(&self) -> Vec<u64> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.iter().map(|entry| entry.height).collect()
    }

    /// One chunk of a kept snapshot, read from its file, followed by its
    /// Merkle proof against the summary's chunk commitment. At most
    /// [`SNAPSHOT_CHUNK_LEN`] bytes of chunk data: the length is chosen by the
    /// peer, and an unclamped request used to copy up to the whole snapshot.
    /// The proof length is derived from the snapshot's own total size, which
    /// the peer already knows from the summary it voted for, so it needs no
    /// framing of its own.
    pub fn read_chunk(
        &self,
        height: u64,
        hash: &[u8; 32],
        offset: u64,
        len: u32,
    ) -> Result<Vec<u8>, ChainError> {
        if len > SNAPSHOT_CHUNK_LEN {
            return Err(ChainError::InternalError(format!(
                "serve chunk: {len} bytes requested, at most {SNAPSHOT_CHUNK_LEN} are served per request"
            )));
        }
        let entry = self
            .at(height)
            .filter(|entry| &entry.hash == hash)
            .ok_or_else(|| {
                ChainError::InternalError(
                    "serve chunk: request does not match a summary this node keeps".into(),
                )
            })?;
        let end = offset
            .checked_add(u64::from(len))
            .filter(|end| *end <= entry.len)
            .ok_or_else(|| ChainError::InternalError("serve chunk: out of range".into()))?;
        if offset % u64::from(SNAPSHOT_CHUNK_LEN) != 0 {
            return Err(ChainError::InternalError(
                "serve chunk: offset is not chunk-aligned".into(),
            ));
        }
        let index = (offset / u64::from(SNAPSHOT_CHUNK_LEN)) as usize;
        if index >= entry.chunk_merkle_leaves.len() {
            return Err(ChainError::InternalError(
                "serve chunk: offset is out of range for this snapshot's chunk commitment".into(),
            ));
        }
        let proof = crate::chain::state_sync::chunk_proof(&entry.chunk_merkle_leaves, index);
        let mut file =
            fs::File::open(&entry.snapshot).map_err(|e| io_error("open", &entry.snapshot, e))?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| io_error("seek", &entry.snapshot, e))?;
        let mut chunk = vec![0u8; (end - offset) as usize];
        file.read_exact(&mut chunk)
            .map_err(|e| io_error("read", &entry.snapshot, e))?;
        for sibling in &proof {
            chunk.extend_from_slice(sibling);
        }
        Ok(chunk)
    }
}

fn remove_if_present(path: &Path) -> Result<(), ChainError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error("remove stale file", path, error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn built(height: u64, fill: u8, len: usize) -> BuiltSummary {
        let envelope: Vec<u8> = (0..len).map(|i| (i % 251) as u8 ^ fill).collect();
        let chunk_merkle_leaves = crate::chain::state_sync::chunk_leaves(&envelope);
        let chunk_merkle_root = crate::chain::state_sync::chunk_merkle_root(&chunk_merkle_leaves);
        BuiltSummary {
            height,
            id: Id::new([fill; 32]),
            bytes: vec![fill; 40],
            hash: [fill ^ 0x55; 32],
            chunk_merkle_root,
            chunk_merkle_leaves,
            state_root: [fill; 32],
            envelope,
        }
    }

    #[test]
    fn a_summary_is_kept_on_disk_and_found_by_height() {
        let dir = tempfile::tempdir().unwrap();
        let store = SummaryStore::open(dir.path().join("summaries")).unwrap();
        assert!(store.newest_at_or_below(u64::MAX).is_none());
        let stored = store.register(built(4096, 1, 1000)).unwrap();
        assert_eq!(stored.height, 4096);
        assert_eq!(store.at(4096).unwrap().id, Id::new([1; 32]));
        assert!(
            store.at(4097).is_none(),
            "only the aligned height is offered"
        );
        assert_eq!(store.newest_at_or_below(5000).unwrap().height, 4096);
        assert!(
            store.newest_at_or_below(4095).is_none(),
            "nothing older to offer"
        );
    }

    #[test]
    fn only_the_newest_two_are_kept_and_the_older_files_are_removed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("summaries");
        let store = SummaryStore::open(&path).unwrap();
        for (height, fill) in [(100u64, 1u8), (200, 2), (300, 3)] {
            store.register(built(height, fill, 500)).unwrap();
        }
        assert_eq!(store.heights(), vec![200, 300]);
        assert!(!path.join("100.snapshot").exists());
        assert!(!path.join("100.summary").exists());
        assert!(path.join("200.snapshot").exists() && path.join("300.summary").exists());
        // An older one is still offered while a newer one is not yet old enough.
        assert_eq!(store.newest_at_or_below(299).unwrap().height, 200);
    }

    #[test]
    fn a_restart_takes_up_what_was_kept_and_drops_half_written_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("summaries");
        {
            let store = SummaryStore::open(&path).unwrap();
            store.register(built(100, 1, 700)).unwrap();
            store.register(built(200, 2, 700)).unwrap();
        }
        // A kill part-way through writing the next one.
        fs::write(path.join("300.snapshot.tmp"), b"half").unwrap();
        // And a pair that is not whole: the summary file without its snapshot.
        fs::write(
            path.join("999.summary"),
            serde_json::to_vec(&Meta {
                height: 999,
                id: hex::encode([9u8; 32]),
                summary: hex::encode([9u8; 4]),
                hash: hex::encode([9u8; 32]),
                len: 10,
                chunk_merkle_leaves: vec![],
            })
            .unwrap(),
        )
        .unwrap();
        // A kill after the snapshot rename but before the summary rename.
        fs::write(path.join("400.snapshot"), b"orphan snapshot").unwrap();
        let reopened = SummaryStore::open(&path).unwrap();
        assert_eq!(reopened.heights(), vec![100, 200]);
        assert!(!path.join("300.snapshot.tmp").exists());
        assert!(!path.join("400.snapshot").exists());
        assert!(!path.join("999.summary").exists());
        assert_eq!(reopened.at(200).unwrap().bytes, vec![2u8; 40]);
    }

    #[test]
    fn a_chunk_is_read_from_the_file_and_the_request_is_checked() {
        let dir = tempfile::tempdir().unwrap();
        let store = SummaryStore::open(dir.path().join("summaries")).unwrap();
        let summary = built(100, 7, 3 * SNAPSHOT_CHUNK_LEN as usize);
        let envelope = summary.envelope.clone();
        let leaves = summary.chunk_merkle_leaves.clone();
        let root = summary.chunk_merkle_root;
        let stored = store.register(summary).unwrap();
        let chunk = SNAPSHOT_CHUNK_LEN;

        // Every chunk-aligned request returns the chunk's bytes followed by a
        // proof that verifies against the summary's own committed root.
        for index in 0..3u64 {
            let offset = index * u64::from(chunk);
            let response = store.read_chunk(100, &stored.hash, offset, chunk).unwrap();
            let (served_chunk, proof_bytes) = response.split_at(chunk as usize);
            assert_eq!(
                served_chunk,
                &envelope[offset as usize..offset as usize + chunk as usize]
            );
            let proof: Vec<[u8; 32]> = proof_bytes
                .chunks_exact(32)
                .map(|s| s.try_into().unwrap())
                .collect();
            assert!(crate::chain::state_sync::verify_chunk_proof(
                served_chunk,
                index,
                leaves.len() as u64,
                &proof,
                &root,
            ));
        }

        // The last bytes, exactly to the end, and one past it. Not
        // chunk-aligned (this snapshot is an exact multiple of the chunk
        // length), so it refuses before even reaching the length check.
        let len = envelope.len() as u64;
        assert!(store.read_chunk(100, &stored.hash, len - 10, 10).is_err());
        assert!(store.read_chunk(100, &stored.hash, len - 10, 11).is_err());
        // A chunk-misaligned offset, more than a chunk, the wrong hash, and a
        // height that is not kept are all refused.
        assert!(
            store
                .read_chunk(100, &stored.hash, u64::from(chunk) + 5, 100)
                .is_err()
        );
        assert!(store.read_chunk(100, &stored.hash, 0, chunk + 1).is_err());
        assert!(store.read_chunk(100, &stored.hash, 0, u32::MAX).is_err());
        assert!(store.read_chunk(100, &[0u8; 32], 0, 10).is_err());
        assert!(store.read_chunk(101, &stored.hash, 0, 10).is_err());
        assert!(store.read_chunk(100, &stored.hash, u64::MAX, 10).is_err());
    }

    #[test]
    fn a_chunk_is_read_with_the_exact_shorter_final_chunk_and_an_exact_proof() {
        let dir = tempfile::tempdir().unwrap();
        let store = SummaryStore::open(dir.path().join("summaries")).unwrap();
        // Not a multiple of the chunk length: the last chunk is short.
        let total_len = 2 * SNAPSHOT_CHUNK_LEN as usize + 777;
        let summary = built(100, 3, total_len);
        let envelope = summary.envelope.clone();
        let root = summary.chunk_merkle_root;
        let leaf_count = summary.chunk_merkle_leaves.len() as u64;
        assert_eq!(leaf_count, 3);
        let stored = store.register(summary).unwrap();
        let offset = 2 * u64::from(SNAPSHOT_CHUNK_LEN);
        let response = store.read_chunk(100, &stored.hash, offset, 777).unwrap();
        let (served_chunk, proof_bytes) = response.split_at(777);
        assert_eq!(served_chunk, &envelope[offset as usize..]);
        let proof: Vec<[u8; 32]> = proof_bytes
            .chunks_exact(32)
            .map(|s| s.try_into().unwrap())
            .collect();
        assert!(crate::chain::state_sync::verify_chunk_proof(
            served_chunk,
            2,
            leaf_count,
            &proof,
            &root,
        ));
        // A full chunk length at the final, short chunk's offset is refused:
        // it would read past the end of the file.
        assert!(
            store
                .read_chunk(100, &stored.hash, offset, SNAPSHOT_CHUNK_LEN)
                .is_err()
        );
    }
}
