//! The state summaries this node offers, and the building of them.
//!
//! The host takes a summary only if over half the validator weight returns the
//! same one for the same height in one vote, so a node offers summaries only at
//! heights every validator builds (multiples of `state_summary_interval`). They are
//! built in the background after the block at such a height is accepted, kept on
//! disk, and served from there: no request for a summary or a chunk builds anything
//! or waits for the controller. See `pulsevm_core::summary_store`.

use std::{
    path::PathBuf,
    sync::{
        Arc,
        OnceLock,
    },
};

use pulsevm_core::{
    ChainError,
    controller::StagedSummary,
    summary_store::{
        StoredSummary,
        SummaryStore,
    },
};

#[derive(Default)]
pub struct SummaryService {
    store: OnceLock<Arc<SummaryStore>>,
    /// One build at a time: a build holds a copy of the state and the encoded
    /// snapshot, gigabytes each at mainnet size, so two at once would be worse
    /// than one after the other.
    build: tokio::sync::Mutex<()>,
}

impl SummaryService {
    pub fn new() -> Self {
        Self::default()
    }

    /// Open the store in `dir`. Called once, when the chain is initialized.
    pub fn open(&self, dir: PathBuf) -> Result<(), ChainError> {
        let store = SummaryStore::open(dir)?;
        let _ = self.store.set(Arc::new(store));
        Ok(())
    }

    /// The newest summary that is at least `min_age` blocks below `tip`: a peer that
    /// picks it is not racing the head. `None` when none is old enough (the peer
    /// then catches up by fetching blocks).
    pub fn offer_latest(&self, tip: u64, min_age: u64) -> Option<StoredSummary> {
        self.store
            .get()?
            .newest_at_or_below(tip.saturating_sub(min_age))
    }

    /// The summary for exactly `height`, if this node keeps one. Peers vote on
    /// heights chosen by the host, so only the fixed heights are answered.
    pub fn offer_at(&self, height: u64) -> Option<StoredSummary> {
        self.store.get()?.at(height)
    }

    /// One chunk of a kept snapshot, read from its file off the async threads.
    pub async fn read_chunk(
        &self,
        height: u64,
        hash: [u8; 32],
        offset: u64,
        len: u32,
    ) -> Result<Vec<u8>, ChainError> {
        let store = self.store.get().cloned().ok_or_else(|| {
            ChainError::InternalError("serve chunk: this node keeps no summaries".into())
        })?;
        tokio::task::spawn_blocking(move || store.read_chunk(height, &hash, offset, len))
            .await
            .map_err(|e| ChainError::InternalError(format!("serve chunk: {e}")))?
    }

    /// Build a staged summary on a worker thread and keep it. The controller is not
    /// held: the copy of the state was made when it was staged.
    pub async fn build_and_keep(&self, staged: StagedSummary) -> Result<u64, ChainError> {
        let store = self.store.get().cloned().ok_or_else(|| {
            ChainError::InternalError("summary: this node keeps no summaries".into())
        })?;
        let _one_at_a_time = self.build.lock().await;
        tokio::task::spawn_blocking(move || {
            let built = staged.build()?;
            let height = built.height;
            store.register(built)?;
            Ok(height)
        })
        .await
        .map_err(|e| ChainError::InternalError(format!("summary build did not finish: {e}")))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pulsevm_core::{
        controller::BuiltSummary,
        id::Id,
    };

    fn built(height: u64) -> BuiltSummary {
        BuiltSummary {
            height,
            id: Id::new([height as u8; 32]),
            bytes: vec![height as u8; 16],
            hash: [height as u8 ^ 0x55; 32],
            state_root: [0; 32],
            envelope: vec![height as u8; 300],
        }
    }

    fn service_with(heights: &[u64]) -> (tempfile::TempDir, SummaryService) {
        let dir = tempfile::tempdir().unwrap();
        let service = SummaryService::new();
        service.open(dir.path().join("summaries")).unwrap();
        for &height in heights {
            service
                .store
                .get()
                .unwrap()
                .register(built(height))
                .unwrap();
        }
        (dir, service)
    }

    #[test]
    fn nothing_is_offered_before_a_summary_exists() {
        let (_dir, service) = service_with(&[]);
        assert!(service.offer_latest(10_000, 8).is_none());
        assert!(service.offer_at(4096).is_none());
        // And a service that was never opened offers nothing, without failing.
        let unopened = SummaryService::new();
        assert!(unopened.offer_latest(10_000, 8).is_none());
        assert!(unopened.offer_at(4096).is_none());
    }

    #[test]
    fn a_summary_is_offered_only_once_it_is_old_enough() {
        let (_dir, service) = service_with(&[4096, 8192]);
        // Tip 8199 is 7 past 8192: too young, so the older one is offered.
        assert_eq!(service.offer_latest(8199, 8).unwrap().height, 4096);
        // Exactly the minimum age is old enough.
        assert_eq!(service.offer_latest(8200, 8).unwrap().height, 8192);
        // A tip below every summary offers none.
        assert!(service.offer_latest(4100, 8).is_none());
    }

    #[test]
    fn only_the_kept_heights_answer_a_vote() {
        let (_dir, service) = service_with(&[4096, 8192]);
        assert_eq!(service.offer_at(8192).unwrap().height, 8192);
        assert!(
            service.offer_at(8193).is_none(),
            "the host asks for heights it chose"
        );
        assert!(service.offer_at(1).is_none());
    }

    #[tokio::test]
    async fn a_chunk_is_served_from_the_file_and_a_wrong_hash_is_refused() {
        let (_dir, service) = service_with(&[4096]);
        let stored = service.offer_at(4096).unwrap();
        let chunk = service.read_chunk(4096, stored.hash, 10, 20).await.unwrap();
        assert_eq!(chunk, vec![4096u64 as u8; 20]);
        assert!(service.read_chunk(4096, [0; 32], 10, 20).await.is_err());
        assert!(
            service
                .read_chunk(4096, stored.hash, 295, 20)
                .await
                .is_err()
        );
        let unopened = SummaryService::new();
        assert!(unopened.read_chunk(4096, stored.hash, 0, 1).await.is_err());
    }
}
