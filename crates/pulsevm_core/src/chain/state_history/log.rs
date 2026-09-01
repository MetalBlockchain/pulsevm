use std::{
    fmt,
    fs::{
        File,
        OpenOptions,
    },
    io::{
        self,
        BufReader,
        BufWriter,
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

#[cfg(test)]
use std::sync::atomic::{
    AtomicBool,
    AtomicUsize,
    Ordering,
};

use pulsevm_crypto::FixedBytes;
use spdlog::error;

use crate::chain::id::Id;

/* -------------------- errors -------------------- */

#[derive(Debug)]
#[non_exhaustive]
pub enum ShLogError {
    Io(io::Error),
    Corrupt(u64),
    MissedBlock(String),
    NotFound(u32),
    BadMagic { at: u64, found: u64, expect: u64 },
}

impl fmt::Display for ShLogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShLogError::Io(e) => write!(f, "io error: {e}"),
            ShLogError::Corrupt(off) => write!(f, "corrupt entry at offset {off}"),
            ShLogError::MissedBlock(msg) => write!(f, "missed a block in {msg}"),
            ShLogError::NotFound(b) => write!(f, "block {b} not found"),
            ShLogError::BadMagic { at, found, expect } => write!(
                f,
                "bad magic at offset {at}: found {found:#x}, expected {expect:#x}"
            ),
        }
    }
}
impl std::error::Error for ShLogError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ShLogError::Io(e) => Some(e),
            _ => None,
        }
    }
}
impl From<io::Error> for ShLogError {
    fn from(e: io::Error) -> Self {
        ShLogError::Io(e)
    }
}

/* -------------------- header + helpers -------------------- */

/// On-disk header layout used by EOS SHiP logs. UNCHANGED from the
/// previous version — same 48-byte layout, same little-endian fields:
///   struct state_history_log_header {
///      uint64_t magic;          // 8 bytes, LE
///      block_id_type block_id;  // 32 bytes, raw
///      uint64_t payload_size;   // 8 bytes, LE
///   };
#[derive(Clone, Copy, Debug)]
struct StateHistoryLogHeader {
    magic: u64,
    block_id: Id,
    payload_size: u64,
}

impl StateHistoryLogHeader {
    const SIZE: u64 = 8 + 32 + 8;

    fn write<W: Write>(&self, mut w: W) -> io::Result<()> {
        w.write_all(&self.magic.to_le_bytes())?;
        w.write_all(&self.block_id.0.0)?;
        w.write_all(&self.payload_size.to_le_bytes())?;
        Ok(())
    }

    /// Generic over any seekable reader so it works with both `File`
    /// and `BufReader<File>` (BufReader's `Seek` impl correctly
    /// discards its internal buffer on seek).
    fn read_at<R: Read + Seek>(r: &mut R, pos: u64) -> io::Result<Self> {
        r.seek(SeekFrom::Start(pos))?;
        let mut buf = [0u8; Self::SIZE as usize];
        r.read_exact(&mut buf)?;
        let magic = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let mut id_bytes = [0u8; 32];
        id_bytes.copy_from_slice(&buf[8..40]);
        let block_id = Id(FixedBytes(id_bytes));
        let payload_size = u64::from_le_bytes(buf[40..48].try_into().unwrap());
        Ok(Self {
            magic,
            block_id,
            payload_size,
        })
    }
}

/// Size of one index record: u32 block_num (LE) + u64 offset (LE).
/// UNCHANGED from the previous version.
const IDX_RECORD_SIZE: u64 = 12;
const INDEX_READ_BUFFER_SIZE: usize = 4 * 1024 * 1024;
const APPEND_BUFFER_SIZE: usize = 4 * 1024 * 1024;

/// Extract EOS block number from a block id (first 4 bytes big-endian)
#[inline]
fn num_from_block_id(id: &Id) -> u32 {
    u32::from_be_bytes(id.0.0[0..4].try_into().unwrap())
}

/// Validate a header at `pos` against the known total file length and
/// expected magic. Guarantees `pos + SIZE + payload_size <= len_total`,
/// which both detects torn writes and prevents allocating a payload
/// buffer from a garbage `payload_size`.
fn read_validated_header<R: Read + Seek>(
    r: &mut R,
    pos: u64,
    len_total: u64,
    expect_magic: u64,
) -> Result<StateHistoryLogHeader, ShLogError> {
    if pos + StateHistoryLogHeader::SIZE > len_total {
        return Err(ShLogError::Corrupt(pos));
    }
    let header = StateHistoryLogHeader::read_at(r, pos)?;
    if header.magic != expect_magic {
        return Err(ShLogError::BadMagic {
            at: pos,
            found: header.magic,
            expect: expect_magic,
        });
    }
    let end = pos
        .checked_add(StateHistoryLogHeader::SIZE)
        .and_then(|v| v.checked_add(header.payload_size))
        .ok_or(ShLogError::Corrupt(pos))?;
    if end > len_total {
        return Err(ShLogError::Corrupt(pos));
    }
    Ok(header)
}

/// fsync the parent directory so a rename survives a crash.
fn fsync_parent_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        if let Some(parent) = path.parent() {
            File::open(parent)?.sync_all()?;
        }
    }
    Ok(())
}

fn tmp_path(path: &Path) -> PathBuf {
    // Append ".tmp" to the full filename rather than using
    // `with_extension`, which swaps the last extension component.
    let mut os = path.as_os_str().to_owned();
    os.push(".tmp");
    PathBuf::from(os)
}

/* -------------------- log struct -------------------- */

/// All mutable state lives behind a single mutex. This removes the
/// `&self -> *mut Self` undefined behavior, the unsynchronized
/// `last_block` read in `append`, and the append/prune race in one go.
#[derive(Debug)]
struct Inner {
    log: BufWriter<File>,
    idx: BufWriter<File>,
    index: ContiguousIndex,
    log_len: u64, // logical end-of-log; running counter, no metadata() syscalls
    idx_len: u64, // logical end-of-index; avoids metadata() on every checkpoint
}

/// State-history logs are gapless by construction, so a tree keyed by every
/// block number wastes memory and turns append/lookups into `O(log n)` work.
/// Store only the first block and its contiguous file offsets instead.
#[derive(Debug, Default)]
struct ContiguousIndex {
    first: Option<u32>,
    offsets: Vec<u64>,
}

impl ContiguousIndex {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            first: None,
            offsets: Vec::with_capacity(capacity),
        }
    }

    fn len(&self) -> usize {
        self.offsets.len()
    }

    fn range(&self) -> Option<(u32, u32)> {
        let first = self.first?;
        let count = u32::try_from(self.offsets.len()).ok()?;
        Some((first, first.checked_add(count.checked_sub(1)?)?))
    }

    fn get(&self, block_num: u32) -> Option<u64> {
        let index = block_num.checked_sub(self.first?)? as usize;
        self.offsets.get(index).copied()
    }

    /// Add a record while enforcing the on-disk gapless/increasing invariant.
    fn push(&mut self, block_num: u32, offset: u64) -> bool {
        if let Some((_, last)) = self.range() {
            if last.checked_add(1) != Some(block_num)
                || self
                    .offsets
                    .last()
                    .is_some_and(|previous| offset <= *previous)
            {
                return false;
            }
        } else {
            self.first = Some(block_num);
        }
        self.offsets.push(offset);
        true
    }

    fn clear(&mut self) {
        self.first = None;
        self.offsets.clear();
    }

    fn restore_range(&mut self, range: Option<(u32, u32)>) -> bool {
        let Some((first, last)) = range else {
            self.clear();
            return true;
        };
        if self.first != Some(first) {
            return false;
        }
        let Some(len) = last
            .checked_sub(first)
            .and_then(|distance| distance.checked_add(1))
            .map(|len| len as usize)
        else {
            return false;
        };
        if len > self.offsets.len() {
            return false;
        }
        self.offsets.truncate(len);
        true
    }

    fn entries_from(&self, start_block: u32) -> Vec<(u32, u64)> {
        let Some((first, last)) = self.range() else {
            return Vec::new();
        };
        let start = start_block.max(first);
        if start > last {
            return Vec::new();
        }
        (start..=last)
            .map(|block| {
                (
                    block,
                    self.get(block)
                        .expect("block inside contiguous index range has an offset"),
                )
            })
            .collect()
    }
}

/// An exact append-only restore point. The controller takes one for each of its
/// three logs before accepting a block, then rolls every log back to its restore
/// point if any append fails.
#[derive(Clone, Copy, Debug)]
pub(crate) struct StateHistoryLogCheckpoint {
    log_len: u64,
    idx_len: u64,
    range: Option<(u32, u32)>,
}

#[derive(Debug)]
pub struct StateHistoryLog {
    name: String,
    log_path: PathBuf,
    idx_path: PathBuf,
    magic: u64,
    inner: Mutex<Inner>,
    #[cfg(test)]
    fail_next_append: AtomicBool,
    #[cfg(test)]
    fail_next_append_after_log_sync: AtomicBool,
    #[cfg(test)]
    data_sync_count: AtomicUsize,
}

/// A single-open, forward-only view over a contiguous state-history range.
///
/// Startup reconstruction can touch tens of millions of blocks. Keeping one
/// buffered file descriptor avoids an `open`/`stat`/`seek`/`close` cycle for
/// every block while still validating every record boundary and block number.
pub(crate) struct StateHistoryLogRange {
    reader: BufReader<File>,
    next_block: u32,
    last_block: u32,
    next_offset: u64,
    log_len: u64,
    magic: u64,
}

impl Iterator for StateHistoryLogRange {
    type Item = Result<(u32, Vec<u8>), ShLogError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_block > self.last_block {
            return None;
        }

        let block_num = self.next_block;
        let offset = self.next_offset;
        let result = (|| {
            if offset + StateHistoryLogHeader::SIZE > self.log_len {
                return Err(ShLogError::Corrupt(offset));
            }

            let mut header_bytes = [0u8; StateHistoryLogHeader::SIZE as usize];
            self.reader.read_exact(&mut header_bytes)?;
            let magic = u64::from_le_bytes(header_bytes[0..8].try_into().unwrap());
            if magic != self.magic {
                return Err(ShLogError::BadMagic {
                    at: offset,
                    found: magic,
                    expect: self.magic,
                });
            }
            let mut id_bytes = [0u8; 32];
            id_bytes.copy_from_slice(&header_bytes[8..40]);
            let block_id = Id(FixedBytes(id_bytes));
            if num_from_block_id(&block_id) != block_num {
                return Err(ShLogError::Corrupt(offset));
            }
            let payload_size = u64::from_le_bytes(header_bytes[40..48].try_into().unwrap());
            let end = offset
                .checked_add(StateHistoryLogHeader::SIZE)
                .and_then(|value| value.checked_add(payload_size))
                .ok_or(ShLogError::Corrupt(offset))?;
            if end > self.log_len {
                return Err(ShLogError::Corrupt(offset));
            }
            let mut payload =
                vec![0; usize::try_from(payload_size).map_err(|_| ShLogError::Corrupt(offset))?];
            self.reader.read_exact(&mut payload)?;
            self.next_offset = end;
            self.next_block = block_num
                .checked_add(1)
                .ok_or(ShLogError::Corrupt(offset))?;
            Ok((block_num, payload))
        })();
        Some(result)
    }
}

impl StateHistoryLog {
    /// Open with explicit magic — pass EOS' `ship_magic(ship_current_version)`.
    ///
    /// There is intentionally no `open()` with a default magic of 0:
    /// a zero magic would "validate" any zeroed or sparse file.
    pub fn open_with_magic<P: AsRef<Path>>(
        dir: P,
        name: &str,
        magic: u64,
    ) -> Result<Self, ShLogError> {
        let log_path = dir.as_ref().join(format!("{name}.log"));
        let idx_path = dir.as_ref().join(format!("{name}.index"));

        let mut log_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&log_path)?;
        let mut idx_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&idx_path)?;

        // ---- load index, tracking how many bytes were valid ----
        let index_file_len = idx_file.metadata()?.len();
        let index_capacity = usize::try_from(index_file_len / IDX_RECORD_SIZE)
            .map_err(|_| ShLogError::Corrupt(index_file_len))?;
        let mut index = ContiguousIndex::with_capacity(index_capacity);
        let mut index_shape_valid = true;
        let mut valid_idx_bytes = 0u64;
        {
            idx_file.seek(SeekFrom::Start(0))?;
            let mut r = BufReader::with_capacity(INDEX_READ_BUFFER_SIZE, &idx_file);
            loop {
                let mut buf = [0u8; IDX_RECORD_SIZE as usize];
                match r.read_exact(&mut buf) {
                    Ok(()) => {
                        let block = u32::from_le_bytes(buf[0..4].try_into().unwrap());
                        let pos = u64::from_le_bytes(buf[4..12].try_into().unwrap());
                        if index_shape_valid && !index.push(block, pos) {
                            index_shape_valid = false;
                        }
                        valid_idx_bytes += IDX_RECORD_SIZE;
                    }
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                    Err(e) => return Err(ShLogError::Io(e)),
                }
            }
        }
        // Truncate a torn trailing index record; otherwise the next
        // append lands after garbage and permanently corrupts the
        // index framing.
        if index_file_len > valid_idx_bytes {
            idx_file.set_len(valid_idx_bytes)?;
        }

        // `reset_to`/`clear` publish the log and index with two renames. A crash
        // between them can pair a new log with an old index (or vice versa), so
        // trusting only an invalid tail and deleting one record is unsafe: stale
        // earlier offsets could remain. Validate the pair's first and last entry,
        // its contiguous key/offset shape, and rebuild the *entire* index from the
        // log on any mismatch.
        let index_matches_log = if let Some((first, last)) = index.range() {
            let first_off = index
                .get(first)
                .expect("first block in contiguous index has an offset");
            let tail_off = index
                .get(last)
                .expect("last block in contiguous index has an offset");
            let len_total = log_file.metadata()?.len();
            let first_matches = first_off == 0
                && read_validated_header(&mut log_file, first_off, len_total, magic)
                    .map(|header| num_from_block_id(&header.block_id) == first)
                    .unwrap_or(false);
            let tail_matches = read_validated_header(&mut log_file, tail_off, len_total, magic)
                .map(|header| num_from_block_id(&header.block_id) == last)
                .unwrap_or(false);
            index_shape_valid && first_matches && tail_matches
        } else {
            false
        };

        if !index_matches_log {
            index = rebuild_index(&mut log_file, &mut idx_file, magic)?;
        } else {
            let (_, last) = index
                .range()
                .expect("validated non-empty index has a range");
            let tail_off = index
                .get(last)
                .expect("last block in contiguous index has an offset");
            let len_total = log_file.metadata()?.len();
            let tail = read_validated_header(&mut log_file, tail_off, len_total, magic)?;
            let ok_end = tail_off + StateHistoryLogHeader::SIZE + tail.payload_size;
            // Recover entries the log has but the index doesn't (crash after log
            // sync, before index write). This preserves acknowledged blocks while
            // keeping the index publication ordered after the log.
            let recovered = scan_entries(&mut log_file, ok_end, magic)?;
            if !recovered.is_empty() {
                idx_file.seek(SeekFrom::Start(valid_idx_bytes))?;
                let mut w = BufWriter::new(&idx_file);
                for (block, pos) in &recovered {
                    w.write_all(&block.to_le_bytes())?;
                    w.write_all(&pos.to_le_bytes())?;
                    if !index.push(*block, *pos) {
                        return Err(ShLogError::MissedBlock(format!(
                            "{name}.log recovery is not contiguous at block {block}"
                        )));
                    }
                }
                w.flush()?;
            }
        }

        let log_len = log_file.metadata()?.len();
        let idx_len = index.len() as u64 * IDX_RECORD_SIZE;

        log_file.seek(SeekFrom::End(0))?;
        idx_file.seek(SeekFrom::End(0))?;

        Ok(Self {
            name: name.to_string(),
            log_path,
            idx_path,
            magic,
            inner: Mutex::new(Inner {
                log: BufWriter::with_capacity(APPEND_BUFFER_SIZE, log_file),
                idx: BufWriter::with_capacity(APPEND_BUFFER_SIZE, idx_file),
                index,
                log_len,
                idx_len,
            }),
            #[cfg(test)]
            fail_next_append: AtomicBool::new(false),
            #[cfg(test)]
            fail_next_append_after_log_sync: AtomicBool::new(false),
            #[cfg(test)]
            data_sync_count: AtomicUsize::new(0),
        })
    }

    /// Capture the exact logical and physical tail of this log. Successful
    /// appends always flush their index record, so the index file length is a
    /// stable restore point without flushing (and therefore without changing)
    /// either writer here.
    pub(crate) fn checkpoint(&self) -> Result<StateHistoryLogCheckpoint, ShLogError> {
        let inner = self.inner.lock().unwrap();
        Ok(StateHistoryLogCheckpoint {
            log_len: inner.log_len,
            idx_len: inner.idx_len,
            range: inner.index.range(),
        })
    }

    /// Restore a checkpoint taken before one or more appends.
    ///
    /// A failed `BufWriter` write can leave bytes buffered in memory. Replacing
    /// the writers and dismantling the old ones with `into_parts` deliberately
    /// discards those bytes before truncating the files; dropping or seeking the
    /// old writers could otherwise flush the failed entry back after rollback.
    pub(crate) fn rollback_to(
        &self,
        checkpoint: &StateHistoryLogCheckpoint,
    ) -> Result<(), ShLogError> {
        let mut inner = self.inner.lock().unwrap();

        let replacement_log = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.log_path)?;
        let replacement_idx = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.idx_path)?;

        // Deferred migration appends may still be buffered. Flush the accepted
        // prefix before replacing the writers, then truncate the failing entry
        // below. If a flush itself fails, rollback remains fatal but we continue
        // every best-effort repair operation.
        let mut first_error = None;
        if let Err(error) = inner.log.flush() {
            first_error = Some(error);
        }
        if let Err(error) = inner.idx.flush()
            && first_error.is_none()
        {
            first_error = Some(error);
        }

        let old_log = std::mem::replace(
            &mut inner.log,
            BufWriter::with_capacity(APPEND_BUFFER_SIZE, replacement_log),
        );
        let old_idx = std::mem::replace(
            &mut inner.idx,
            BufWriter::with_capacity(APPEND_BUFFER_SIZE, replacement_idx),
        );
        let _ = old_log.into_parts();
        let _ = old_idx.into_parts();

        // Keep trying every operation after the first error. A rollback error is
        // fatal to the caller, but best-effort completion still minimizes the
        // amount of mixed state left for diagnosis/recovery.
        let mut record = |result: io::Result<()>| {
            if let Err(error) = result
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        };

        record(inner.log.get_ref().set_len(checkpoint.log_len));
        record(inner.idx.get_ref().set_len(checkpoint.idx_len));
        record(inner.log.get_ref().sync_data());
        record(inner.idx.get_ref().sync_data());
        record(
            inner
                .log
                .seek(SeekFrom::Start(checkpoint.log_len))
                .map(|_| ()),
        );
        record(
            inner
                .idx
                .seek(SeekFrom::Start(checkpoint.idx_len))
                .map(|_| ()),
        );

        if let Some(error) = first_error {
            return Err(ShLogError::Io(error));
        }

        inner.log_len = checkpoint.log_len;
        inner.idx_len = checkpoint.idx_len;
        if !inner.index.restore_range(checkpoint.range) {
            return Err(ShLogError::Corrupt(checkpoint.log_len));
        }
        Ok(())
    }

    /// Remove every record after `last_block`. Migration replay uses this to
    /// rewind its durable block journal to the last Arena checkpoint after an
    /// interrupted run. Normal node startup never calls it: there, a state/log
    /// mismatch remains a hard consistency failure.
    pub(crate) fn truncate_after(&self, last_block: u32) -> Result<(), ShLogError> {
        let checkpoint = {
            let inner = self.inner.lock().unwrap();
            let Some((first, last)) = inner.index.range() else {
                return Ok(());
            };
            if last_block >= last {
                return Ok(());
            }
            if last_block < first {
                drop(inner);
                return self.clear();
            }
            let first_removed = last_block
                .checked_add(1)
                .ok_or(ShLogError::NotFound(last_block))?;
            let log_len = inner
                .index
                .get(first_removed)
                .ok_or(ShLogError::NotFound(first_removed))?;
            StateHistoryLogCheckpoint {
                log_len,
                idx_len: u64::from(last_block - first + 1) * IDX_RECORD_SIZE,
                range: Some((first, last_block)),
            }
        };
        self.rollback_to(&checkpoint)
    }

    #[cfg(test)]
    pub(crate) fn fail_next_append(&self) {
        self.fail_next_append.store(true, Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn fail_next_append_after_log_sync(&self) {
        self.fail_next_append_after_log_sync
            .store(true, Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn data_sync_count(&self) -> usize {
        self.data_sync_count.load(Ordering::SeqCst)
    }

    /// Append one entry with EOS SHiP header and make its log payload durable
    /// before publishing the index record.
    ///
    /// Durability note: the log is `sync_data()`'d before the index
    /// record referencing it is written, so on-disk the index never
    /// points past valid log data. If per-append fsync is too costly
    /// for your workload, it can be relaxed — open-time recovery
    /// handles a log/index mismatch either way — but then `Ok(())`
    /// no longer implies the block survives a power loss.
    pub fn append(&self, block_id: Id, payload: &[u8]) -> Result<(), ShLogError> {
        self.append_impl(block_id, payload, true)
    }

    /// Append one entry without an immediate durability barrier.
    ///
    /// Bytes and index records remain in large userspace buffers until those
    /// buffers fill or the caller invokes [`Self::sync_data`]. The logical index
    /// and rollback checkpoints still advance immediately. This is used only by
    /// resumable bulk replay, where syncing once per checkpoint avoids per-block
    /// seeks, writes, and durability barriers while preserving log-before-state
    /// crash ordering.
    pub(crate) fn append_deferred_sync(
        &self,
        block_id: Id,
        payload: &[u8],
    ) -> Result<(), ShLogError> {
        self.append_impl(block_id, payload, false)
    }

    fn append_impl(&self, block_id: Id, payload: &[u8], sync_data: bool) -> Result<(), ShLogError> {
        #[cfg(test)]
        if self.fail_next_append.swap(false, Ordering::SeqCst) {
            return Err(ShLogError::Io(io::Error::other(
                "injected state-history append failure",
            )));
        }

        let block_num = num_from_block_id(&block_id);
        let mut inner = self.inner.lock().unwrap();

        if let Some((_, last)) = inner.index.range()
            && last.checked_add(1) != Some(block_num)
        {
            return Err(ShLogError::MissedBlock(format!(
                "{}.log: expected block {}, got {}",
                self.name,
                last.saturating_add(1),
                block_num
            )));
        }

        let pos = inner.log_len;

        if sync_data {
            // Normal node writes preserve the defensive repositioning guarantee.
            // Migration replay owns the writer exclusively and rollback replaces
            // it after any error, so seeking here would only flush every batch.
            inner.log.seek(SeekFrom::Start(pos))?;
        }

        let header = StateHistoryLogHeader {
            magic: self.magic,
            block_id,
            payload_size: payload.len() as u64,
        };
        header.write(&mut inner.log)?;
        inner.log.write_all(payload)?;
        if sync_data {
            inner.log.flush()?;
            inner.log.get_ref().sync_data()?;
            #[cfg(test)]
            self.data_sync_count.fetch_add(1, Ordering::SeqCst);
        }

        #[cfg(test)]
        if self
            .fail_next_append_after_log_sync
            .swap(false, Ordering::SeqCst)
        {
            return Err(ShLogError::Io(io::Error::other(
                "injected state-history append failure after log sync",
            )));
        }

        // Publish the index only after the log bytes have reached the kernel.
        // Durable mode additionally places the barrier above; deferred mode
        // makes the complete prefix durable through `sync_data` at checkpoint.
        inner.idx.write_all(&block_num.to_le_bytes())?;
        inner.idx.write_all(&pos.to_le_bytes())?;
        if sync_data {
            inner.idx.flush()?;
        }

        inner.log_len = pos + StateHistoryLogHeader::SIZE + payload.len() as u64;
        inner.idx_len += IDX_RECORD_SIZE;
        if !inner.index.push(block_num, pos) {
            return Err(ShLogError::Corrupt(pos));
        }

        Ok(())
    }

    /// Flush and make the complete log/index prefix durable. The log is synced
    /// first so an index record can never become durable before the entry it
    /// references; open-time recovery rebuilds an index that lags the log.
    pub(crate) fn sync_data(&self) -> Result<(), ShLogError> {
        let mut inner = self.inner.lock().unwrap();
        inner.log.flush()?;
        inner.idx.flush()?;
        inner.log.get_ref().sync_data()?;
        #[cfg(test)]
        self.data_sync_count.fetch_add(1, Ordering::SeqCst);
        inner.idx.get_ref().sync_data()?;
        Ok(())
    }

    /// Read payload for a given block number.
    pub fn read_block(&self, block_num: u32) -> Result<Vec<u8>, ShLogError> {
        // Open the reader handle while holding the lock so a concurrent
        // prune (which renames a new file over log_path) can't swap the
        // file out from under the offset we just looked up. Once we
        // hold an fd, the old inode stays valid for the read.
        let (pos, mut f) = {
            let inner = self.inner.lock().unwrap();
            let pos = inner
                .index
                .get(block_num)
                .ok_or(ShLogError::NotFound(block_num))?;
            let f = OpenOptions::new().read(true).open(&self.log_path)?;
            (pos, f)
        };

        let len_total = f.metadata()?.len();
        let header = match read_validated_header(&mut f, pos, len_total, self.magic) {
            Ok(h) => h,
            Err(e) => {
                error!(
                    "[ship][{}] read_block failed: block_num={} pos={} err={}",
                    self.name, block_num, pos, e
                );
                return Err(e);
            }
        };
        let stored_num = num_from_block_id(&header.block_id);
        if stored_num != block_num {
            error!(
                "[ship][{}] read_block Corrupt: requested block_num={} pos={} but stored id encodes block_num={} (id={:?})",
                self.name, block_num, pos, stored_num, header.block_id
            );
            return Err(ShLogError::Corrupt(pos));
        }
        // Allocation is safe: read_validated_header proved
        // pos + SIZE + payload_size <= len_total.
        let mut buf = vec![0u8; header.payload_size as usize];
        f.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Stream a [start, end] range (inclusive), callback gets (block_num, payload).
    ///
    /// The lock is NOT held while the callback runs, so the callback
    /// may call back into this log without deadlocking.
    pub fn read_range<F>(&self, start: u32, end: u32, mut cb: F) -> Result<(), ShLogError>
    where
        F: FnMut(u32, &[u8]) -> Result<(), ShLogError>,
    {
        for entry in self.block_range(start, end)? {
            let (block, payload) = entry?;
            cb(block, &payload)?;
        }
        Ok(())
    }

    pub(crate) fn block_range(
        &self,
        start: u32,
        end: u32,
    ) -> Result<StateHistoryLogRange, ShLogError> {
        if start > end {
            return Err(ShLogError::MissedBlock(format!(
                "{}.log: invalid range {start}..={end}",
                self.name
            )));
        }
        let (first, last, start_offset, f) = {
            let inner = self.inner.lock().unwrap();
            let (first, last) = inner.index.range().ok_or(ShLogError::NotFound(start))?;
            if start < first || end > last {
                return Err(ShLogError::NotFound(if start < first {
                    start
                } else {
                    end
                }));
            }
            let start_offset = inner.index.get(start).ok_or(ShLogError::NotFound(start))?;
            let f = OpenOptions::new().read(true).open(&self.log_path)?;
            (first, last, start_offset, f)
        };
        debug_assert!(start >= first && end <= last);
        let len_total = f.metadata()?.len();
        let mut reader = BufReader::with_capacity(INDEX_READ_BUFFER_SIZE, f);
        reader.seek(SeekFrom::Start(start_offset))?;
        Ok(StateHistoryLogRange {
            reader,
            next_block: start,
            last_block: end,
            next_offset: start_offset,
            log_len: len_total,
            magic: self.magic,
        })
    }

    /* -------------------- pruning -------------------- */

    pub fn prune_keep_last(&self, n: u32) -> Result<(), ShLogError> {
        let mut inner = self.inner.lock().unwrap();
        let Some((first, last)) = inner.index.range() else {
            return Ok(());
        };
        if n == 0 {
            return Ok(());
        }
        let start = last.saturating_sub(n).saturating_add(1);
        if start <= first {
            // Nothing to prune; don't rewrite the whole log for a no-op.
            return Ok(());
        }
        self.prune_locked(&mut inner, start)
    }

    pub fn prune_from(&self, start_block: u32) -> Result<(), ShLogError> {
        let mut inner = self.inner.lock().unwrap();
        self.prune_locked(&mut inner, start_block)
    }

    /// Runs with the state lock held for the whole rewrite, so appends
    /// can't land on the old inode between the copy and the rename.
    fn prune_locked(&self, inner: &mut Inner, start_block: u32) -> Result<(), ShLogError> {
        match inner.index.range() {
            None => return Ok(()),
            Some((first, _)) if start_block <= first => return Ok(()),
            _ => {}
        }

        let keep = inner.index.entries_from(start_block);
        if keep.is_empty() {
            return Ok(());
        }

        let tmp_log = tmp_path(&self.log_path);
        let tmp_idx = tmp_path(&self.idx_path);

        let out_log_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_log)?;
        let out_idx_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_idx)?;
        let mut out_log = BufWriter::new(&out_log_file);
        let mut out_idx = BufWriter::new(&out_idx_file);

        // Fresh read handle; BufReader's own Seek impl is used inside
        // read_at, which discards the buffer — no stale-buffer reads.
        let in_file = OpenOptions::new().read(true).open(&self.log_path)?;
        let in_len = in_file.metadata()?.len();
        let mut in_log = BufReader::new(in_file);

        // Running counter — never derived from metadata().len(), which
        // lags behind a BufWriter's logical position.
        let mut new_pos = 0u64;
        let mut new_index = ContiguousIndex::default();

        for (block, old_pos) in &keep {
            let header = read_validated_header(&mut in_log, *old_pos, in_len, self.magic)?;
            if num_from_block_id(&header.block_id) != *block {
                return Err(ShLogError::Corrupt(*old_pos));
            }
            let mut buf = vec![0u8; header.payload_size as usize];
            in_log.read_exact(&mut buf)?;

            header.write(&mut out_log)?;
            out_log.write_all(&buf)?;

            out_idx.write_all(&block.to_le_bytes())?;
            out_idx.write_all(&new_pos.to_le_bytes())?;

            if !new_index.push(*block, new_pos) {
                return Err(ShLogError::Corrupt(*old_pos));
            }
            new_pos += StateHistoryLogHeader::SIZE + header.payload_size;
        }

        out_log.flush()?;
        out_idx.flush()?;
        // Make the tmp files durable before the atomic rename, then
        // make the rename itself durable.
        out_log_file.sync_all()?;
        out_idx_file.sync_all()?;
        drop(out_log);
        drop(out_idx);

        std::fs::rename(&tmp_log, &self.log_path)?;
        std::fs::rename(&tmp_idx, &self.idx_path)?;
        fsync_parent_dir(&self.log_path)?;

        // Swap in-memory state to match the new files.
        let first_kept = keep.first().unwrap().0; // actual first, not start_block
        let last_kept = keep.last().unwrap().0;

        let log_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.log_path)?;
        let idx_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.idx_path)?;
        let mut log_w = BufWriter::new(log_file);
        let mut idx_w = BufWriter::new(idx_file);
        log_w.seek(SeekFrom::End(0))?;
        idx_w.seek(SeekFrom::End(0))?;

        inner.log = log_w;
        inner.idx = idx_w;
        inner.index = new_index;
        debug_assert_eq!(inner.index.range(), Some((first_kept, last_kept)));
        inner.log_len = new_pos;
        inner.idx_len = keep.len() as u64 * IDX_RECORD_SIZE;

        Ok(())
    }

    /// Discard the whole log and re-base it to a single entry — the block a
    /// state snapshot was taken at.
    ///
    /// State sync fast-forwards past blocks this node never downloaded, so the
    /// "gapless from genesis" invariant cannot be kept: the log must start again
    /// at the snapshot height. Afterwards `range()` is `(N, N)` where `N` is
    /// `block_id`'s height, so a restart reconstructs `last_accepted` from the
    /// snapshot's block, and the next accepted block (`N + 1`) appends
    /// contiguously. Both replacement files are made durable before publication.
    /// The log and index require separate renames, so startup validates the pair
    /// and rebuilds a stale index if a crash exposes different generations.
    pub fn reset_to(&self, block_id: Id, payload: &[u8]) -> Result<(), ShLogError> {
        let mut inner = self.inner.lock().unwrap();
        let block_num = num_from_block_id(&block_id);

        let tmp_log = tmp_path(&self.log_path);
        let tmp_idx = tmp_path(&self.idx_path);
        let out_log_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_log)?;
        let out_idx_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_idx)?;
        {
            let mut out_log = BufWriter::new(&out_log_file);
            let mut out_idx = BufWriter::new(&out_idx_file);

            let header = StateHistoryLogHeader {
                magic: self.magic,
                block_id,
                payload_size: payload.len() as u64,
            };
            header.write(&mut out_log)?;
            out_log.write_all(payload)?;
            out_idx.write_all(&block_num.to_le_bytes())?;
            out_idx.write_all(&0u64.to_le_bytes())?;

            out_log.flush()?;
            out_idx.flush()?;
        }
        out_log_file.sync_all()?;
        out_idx_file.sync_all()?;

        std::fs::rename(&tmp_log, &self.log_path)?;
        std::fs::rename(&tmp_idx, &self.idx_path)?;
        fsync_parent_dir(&self.log_path)?;

        let new_pos = StateHistoryLogHeader::SIZE + payload.len() as u64;
        let mut new_index = ContiguousIndex::default();
        let inserted = new_index.push(block_num, 0);
        debug_assert!(inserted);

        let log_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.log_path)?;
        let idx_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.idx_path)?;
        let mut log_w = BufWriter::new(log_file);
        let mut idx_w = BufWriter::new(idx_file);
        log_w.seek(SeekFrom::End(0))?;
        idx_w.seek(SeekFrom::End(0))?;

        inner.log = log_w;
        inner.idx = idx_w;
        inner.index = new_index;
        inner.log_len = new_pos;
        inner.idx_len = IDX_RECORD_SIZE;

        Ok(())
    }

    /// Truncate the log to empty, so the next append starts a fresh contiguous
    /// run at whatever height it carries.
    ///
    /// The trace and chain-state logs have no entries for a state-synced block,
    /// so on sync they are cleared rather than re-based: the state-history stream
    /// simply resumes at the first block accepted after the sync point.
    pub fn clear(&self) -> Result<(), ShLogError> {
        let mut inner = self.inner.lock().unwrap();
        inner.log.flush()?;
        inner.idx.flush()?;
        inner.log.get_ref().set_len(0)?;
        inner.idx.get_ref().set_len(0)?;
        inner.log.seek(SeekFrom::Start(0))?;
        inner.idx.seek(SeekFrom::Start(0))?;
        inner.log.get_ref().sync_data()?;
        inner.idx.get_ref().sync_data()?;
        inner.index.clear();
        inner.log_len = 0;
        inner.idx_len = 0;
        Ok(())
    }

    /* -------------------- getters -------------------- */

    /// Last appended block number, or 0 if the log is empty.
    /// Prefer `range()` for an unambiguous answer.
    pub fn last_block(&self) -> u32 {
        self.inner
            .lock()
            .unwrap()
            .index
            .range()
            .map(|(_, l)| l)
            .unwrap_or(0)
    }

    pub fn range(&self) -> Option<(u32, u32)> {
        self.inner.lock().unwrap().index.range()
    }

    pub fn get_block_id(&self, block_num: u32) -> Result<Id, ShLogError> {
        let (pos, mut f) = {
            let inner = self.inner.lock().unwrap();
            let pos = inner
                .index
                .get(block_num)
                .ok_or(ShLogError::NotFound(block_num))?;
            let f = OpenOptions::new().read(true).open(&self.log_path)?;
            (pos, f)
        };
        let len_total = f.metadata()?.len();
        let header = read_validated_header(&mut f, pos, len_total, self.magic)?;
        if num_from_block_id(&header.block_id) != block_num {
            return Err(ShLogError::Corrupt(pos));
        }
        Ok(header.block_id)
    }
}

/* -------------------- scan (header-aware) -------------------- */

fn rebuild_index(
    log_file: &mut File,
    idx_file: &mut File,
    expect_magic: u64,
) -> Result<ContiguousIndex, ShLogError> {
    let entries = scan_entries(log_file, 0, expect_magic)?;
    idx_file.set_len(0)?;
    idx_file.seek(SeekFrom::Start(0))?;
    let mut index = ContiguousIndex::default();
    {
        let mut writer = BufWriter::new(&mut *idx_file);
        for (block, pos) in entries {
            writer.write_all(&block.to_le_bytes())?;
            writer.write_all(&pos.to_le_bytes())?;
            if !index.push(block, pos) {
                return Err(ShLogError::MissedBlock(format!(
                    "rebuilt state-history log is not contiguous at block {block}"
                )));
            }
        }
        writer.flush()?;
    }
    Ok(index)
}

/// Scan entries from `start` to end of file, truncating a torn tail.
/// Returns (block_num, offset) pairs in file order. A wrong magic
/// anywhere other than a torn tail is a hard error — that's not a
/// crash artifact, it's corruption or a version mismatch.
fn scan_entries(
    file: &mut File,
    start: u64,
    expect_magic: u64,
) -> Result<Vec<(u32, u64)>, ShLogError> {
    let len_total = file.metadata()?.len();
    let mut pos = start;
    let mut out = Vec::new();

    while pos < len_total {
        // Partial header at the tail: torn write, truncate and stop.
        if pos + StateHistoryLogHeader::SIZE > len_total {
            file.set_len(pos)?;
            break;
        }
        let header = StateHistoryLogHeader::read_at(file, pos)?;
        if header.magic != expect_magic {
            return Err(ShLogError::BadMagic {
                at: pos,
                found: header.magic,
                expect: expect_magic,
            });
        }
        let end = pos
            .checked_add(StateHistoryLogHeader::SIZE)
            .and_then(|v| v.checked_add(header.payload_size))
            .ok_or(ShLogError::Corrupt(pos))?;
        if end > len_total {
            // Partial payload at the tail: torn write, truncate and stop.
            file.set_len(pos)?;
            break;
        }
        out.push((num_from_block_id(&header.block_id), pos));
        pos = end;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{
        AtomicU32,
        Ordering,
    };

    /// Number of blocks the generated fixture contains. Several tests
    /// require at least 3 (open, prune); 5 leaves comfortable margin.
    const FIXTURE_BLOCKS: u32 = 5;

    #[test]
    fn contiguous_index_rejects_gaps_and_non_increasing_offsets() {
        let mut index = ContiguousIndex::default();
        assert!(index.push(100, 0));
        assert!(index.push(101, 48));
        assert!(!index.push(103, 96));
        assert!(!index.push(102, 48));
        assert_eq!(index.range(), Some((100, 101)));
        assert_eq!(index.get(100), Some(0));
        assert_eq!(index.get(101), Some(48));
        assert_eq!(index.get(102), None);

        assert!(index.push(102, 96));
        assert!(index.restore_range(Some((100, 100))));
        assert_eq!(index.range(), Some((100, 100)));
        assert!(!index.restore_range(Some((99, 100))));
    }

    /// Magic stamped into the generated fixture. Must be non-zero: the
    /// log deliberately refuses a zero magic because it would "validate"
    /// any zeroed or sparse file (see `open_with_magic`). The exact value
    /// is arbitrary — it only has to be a fixed, non-zero tag the whole
    /// suite agrees on — but it mirrors EOS' `ship_magic(version)` shape.
    fn fixture_magic() -> u64 {
        0x5348_4950_0000_0001 // "SHIP" v1
    }

    /// Unique scratch dir per test, cleaned up on drop. std-only, no
    /// tempfile dependency.
    struct TestDir(PathBuf);
    impl TestDir {
        fn new(tag: &str) -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let dir = std::env::temp_dir().join(format!(
                "shlog-test-{tag}-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            TestDir(dir)
        }
        fn path(&self) -> &Path {
            &self.0
        }
        fn log_path(&self) -> PathBuf {
            self.0.join("block_log.log")
        }
        fn idx_path(&self) -> PathBuf {
            self.0.join("block_log.index")
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Build a fresh SHiP log fixture in a new dir and hand it back with
    /// its magic. The fixture is generated through the real writer rather
    /// than checked in as a binary blob, so the suite is hermetic. The
    /// index is then removed so each test's first `open` rebuilds it by
    /// scanning the log — the same code path a log-only fixture exercised,
    /// which `opens_fixture_and_builds_index` depends on.
    fn setup(tag: &str) -> (TestDir, u64) {
        let dir = TestDir::new(tag);
        let magic = fixture_magic();
        {
            let log = StateHistoryLog::open_with_magic(dir.path(), "block_log", magic).unwrap();
            for n in 1..=FIXTURE_BLOCKS {
                let payload = format!("ship-block-{n}-payload").into_bytes();
                log.append(make_id(n, n as u8), &payload).unwrap();
            }
        }
        std::fs::remove_file(dir.idx_path()).unwrap();
        (dir, magic)
    }

    fn make_id(block_num: u32, filler: u8) -> Id {
        let mut b = [filler; 32];
        b[0..4].copy_from_slice(&block_num.to_be_bytes());
        Id(FixedBytes(b))
    }

    /// Independent, minimal parser for the on-disk format. This is the
    /// ground truth the log implementation is compared against, so it
    /// deliberately shares no code with the implementation.
    fn parse_raw(path: &Path, magic: u64) -> Vec<(u32, u64, Vec<u8>)> {
        let mut f = File::open(path).unwrap();
        let len = f.metadata().unwrap().len();
        let mut pos = 0u64;
        let mut out = Vec::new();
        while pos + 48 <= len {
            f.seek(SeekFrom::Start(pos)).unwrap();
            let mut hdr = [0u8; 48];
            f.read_exact(&mut hdr).unwrap();
            assert_eq!(
                u64::from_le_bytes(hdr[0..8].try_into().unwrap()),
                magic,
                "raw parse: bad magic at {pos}"
            );
            let num = u32::from_be_bytes(hdr[8..12].try_into().unwrap());
            let payload_size = u64::from_le_bytes(hdr[40..48].try_into().unwrap());
            if pos + 48 + payload_size > len {
                break; // torn tail
            }
            let mut payload = vec![0u8; payload_size as usize];
            f.read_exact(&mut payload).unwrap();
            out.push((num, pos, payload));
            pos += 48 + payload_size;
        }
        out
    }

    #[test]
    fn opens_fixture_and_builds_index() {
        let (dir, magic) = setup("open");
        let log = StateHistoryLog::open_with_magic(dir.path(), "block_log", magic).unwrap();

        let raw = parse_raw(&dir.log_path(), magic);
        assert!(!raw.is_empty(), "fixture contains no entries");
        assert!(
            raw.len() >= 3,
            "fixture needs at least 3 blocks for the test suite"
        );

        let (first, last) = log.range().expect("fixture log should be non-empty");
        assert_eq!(first, raw.first().unwrap().0);
        assert_eq!(last, raw.last().unwrap().0);
        assert_eq!(log.last_block(), last);

        // The index file must have been created with one 12-byte
        // record per entry.
        let idx_len = std::fs::metadata(dir.idx_path()).unwrap().len();
        assert_eq!(idx_len, raw.len() as u64 * IDX_RECORD_SIZE);
    }

    #[test]
    fn read_block_matches_raw_parse() {
        let (dir, magic) = setup("readback");
        let log = StateHistoryLog::open_with_magic(dir.path(), "block_log", magic).unwrap();
        let raw = parse_raw(&dir.log_path(), magic);

        for (num, _pos, payload) in &raw {
            assert_eq!(
                &log.read_block(*num).unwrap(),
                payload,
                "payload mismatch for block {num}"
            );
            let id = log.get_block_id(*num).unwrap();
            assert_eq!(num_from_block_id(&id), *num);
        }

        // Unknown block -> NotFound, not a panic or a garbage read.
        let missing = raw.last().unwrap().0 + 1000;
        assert!(matches!(log.read_block(missing), Err(ShLogError::NotFound(b)) if b == missing));
    }

    #[test]
    fn read_range_streams_everything_in_order() {
        let (dir, magic) = setup("range");
        let log = StateHistoryLog::open_with_magic(dir.path(), "block_log", magic).unwrap();
        let raw = parse_raw(&dir.log_path(), magic);
        let (first, last) = log.range().unwrap();

        let mut seen = Vec::new();
        log.read_range(first, last, |num, payload| {
            seen.push((num, payload.to_vec()));
            Ok(())
        })
        .unwrap();

        assert_eq!(seen.len(), raw.len());
        for ((got_num, got_payload), (want_num, _, want_payload)) in seen.iter().zip(raw.iter()) {
            assert_eq!(got_num, want_num);
            assert_eq!(got_payload, want_payload);
        }
    }

    #[test]
    fn reopen_from_existing_index_is_consistent() {
        let (dir, magic) = setup("reopen");
        let range1 = {
            let log = StateHistoryLog::open_with_magic(dir.path(), "block_log", magic).unwrap();
            log.range().unwrap()
        };
        // Second open goes through the index-load path instead of the
        // full-scan path; results must be identical.
        let log = StateHistoryLog::open_with_magic(dir.path(), "block_log", magic).unwrap();
        assert_eq!(log.range().unwrap(), range1);

        // Deleting the index forces a rebuild-by-scan; still identical.
        drop(log);
        std::fs::remove_file(dir.idx_path()).unwrap();
        let log = StateHistoryLog::open_with_magic(dir.path(), "block_log", magic).unwrap();
        assert_eq!(log.range().unwrap(), range1);
    }

    #[test]
    fn torn_log_tail_is_truncated_on_open() {
        let (dir, magic) = setup("torntail");
        // First open builds the index.
        drop(StateHistoryLog::open_with_magic(dir.path(), "block_log", magic).unwrap());

        let raw = parse_raw(&dir.log_path(), magic);
        let (last_num, last_pos, _) = raw.last().unwrap().clone();

        // Chop one byte off the last entry's payload — a torn write.
        let len = std::fs::metadata(dir.log_path()).unwrap().len();
        OpenOptions::new()
            .write(true)
            .open(dir.log_path())
            .unwrap()
            .set_len(len - 1)
            .unwrap();

        let log = StateHistoryLog::open_with_magic(dir.path(), "block_log", magic).unwrap();

        // The torn entry is gone from range, map, log file, and index.
        let (_, new_last) = log.range().unwrap();
        assert_eq!(new_last, last_num - 1);
        assert!(matches!(
            log.read_block(last_num),
            Err(ShLogError::NotFound(_))
        ));
        assert_eq!(std::fs::metadata(dir.log_path()).unwrap().len(), last_pos);
        assert_eq!(
            std::fs::metadata(dir.idx_path()).unwrap().len(),
            (raw.len() as u64 - 1) * IDX_RECORD_SIZE
        );
        // The surviving tail still reads back fine.
        log.read_block(new_last).unwrap();
    }

    #[test]
    fn orphaned_log_entry_is_reindexed_on_open() {
        let (dir, magic) = setup("orphan");
        drop(StateHistoryLog::open_with_magic(dir.path(), "block_log", magic).unwrap());

        let raw = parse_raw(&dir.log_path(), magic);
        let last_num = raw.last().unwrap().0;

        // Simulate a crash after the log entry was synced but before
        // its index record was written: drop the last index record,
        // leave the log intact.
        let idx_len = std::fs::metadata(dir.idx_path()).unwrap().len();
        OpenOptions::new()
            .write(true)
            .open(dir.idx_path())
            .unwrap()
            .set_len(idx_len - IDX_RECORD_SIZE)
            .unwrap();

        let log = StateHistoryLog::open_with_magic(dir.path(), "block_log", magic).unwrap();

        // The orphaned block was recovered, not dropped.
        let (_, new_last) = log.range().unwrap();
        assert_eq!(new_last, last_num);
        assert_eq!(log.read_block(last_num).unwrap(), raw.last().unwrap().2);
        // And the index record was re-written.
        assert_eq!(std::fs::metadata(dir.idx_path()).unwrap().len(), idx_len);
    }

    #[test]
    fn torn_index_record_is_truncated_on_open() {
        let (dir, magic) = setup("tornidx");
        drop(StateHistoryLog::open_with_magic(dir.path(), "block_log", magic).unwrap());

        let raw = parse_raw(&dir.log_path(), magic);

        // Leave a partial (5-byte) index record at the tail.
        let idx_len = std::fs::metadata(dir.idx_path()).unwrap().len();
        OpenOptions::new()
            .write(true)
            .open(dir.idx_path())
            .unwrap()
            .set_len(idx_len - IDX_RECORD_SIZE + 5)
            .unwrap();

        let log = StateHistoryLog::open_with_magic(dir.path(), "block_log", magic).unwrap();

        // The partial record was discarded, the entry it would have
        // covered was recovered from the log, and the index is whole
        // 12-byte records again.
        assert_eq!(log.range().unwrap().1, raw.last().unwrap().0);
        assert_eq!(std::fs::metadata(dir.idx_path()).unwrap().len(), idx_len);
    }

    #[test]
    fn append_is_contiguous_and_durable_across_reopen() {
        let (dir, magic) = setup("append");
        let last = {
            let log = StateHistoryLog::open_with_magic(dir.path(), "block_log", magic).unwrap();
            let (_, last) = log.range().unwrap();

            // Skipping a block number is rejected.
            let err = log.append(make_id(last + 3, 0xAA), b"skip").unwrap_err();
            assert!(matches!(err, ShLogError::MissedBlock(_)));

            // The next block appends and reads back immediately.
            log.append(make_id(last + 1, 0xAB), b"hello ship").unwrap();
            assert_eq!(log.read_block(last + 1).unwrap(), b"hello ship");
            assert_eq!(log.range().unwrap().1, last + 1);
            last
        };

        // Survives a reopen through the index path...
        let log = StateHistoryLog::open_with_magic(dir.path(), "block_log", magic).unwrap();
        assert_eq!(log.read_block(last + 1).unwrap(), b"hello ship");

        // ...and the raw bytes on disk follow the exact same format.
        drop(log);
        let raw = parse_raw(&dir.log_path(), magic);
        let tail = raw.last().unwrap();
        assert_eq!(tail.0, last + 1);
        assert_eq!(tail.2, b"hello ship");
    }

    #[test]
    fn deferred_append_batches_the_durability_barrier() {
        let (dir, magic) = setup("deferred-sync");
        let log = StateHistoryLog::open_with_magic(dir.path(), "block_log", magic).unwrap();
        let last = log.range().unwrap().1;
        let syncs_before = log.data_sync_count();

        log.append_deferred_sync(make_id(last + 1, 0xA1), b"first")
            .unwrap();
        log.append_deferred_sync(make_id(last + 2, 0xA2), b"second")
            .unwrap();

        assert_eq!(log.data_sync_count(), syncs_before);
        assert_eq!(log.range().unwrap().1, last + 2);

        log.sync_data().unwrap();
        assert_eq!(log.data_sync_count(), syncs_before + 1);
        assert_eq!(log.read_block(last + 1).unwrap(), b"first");
        assert_eq!(log.read_block(last + 2).unwrap(), b"second");
        drop(log);

        let reopened = StateHistoryLog::open_with_magic(dir.path(), "block_log", magic).unwrap();
        assert_eq!(reopened.range().unwrap().1, last + 2);
        assert_eq!(reopened.read_block(last + 1).unwrap(), b"first");
        assert_eq!(reopened.read_block(last + 2).unwrap(), b"second");
    }

    #[test]
    fn rollback_preserves_buffered_deferred_prefix() {
        let (dir, magic) = setup("deferred-rollback");
        let log = StateHistoryLog::open_with_magic(dir.path(), "block_log", magic).unwrap();
        let last = log.range().unwrap().1;

        log.append_deferred_sync(make_id(last + 1, 0xA1), b"keep")
            .unwrap();
        let checkpoint = log.checkpoint().unwrap();
        log.append_deferred_sync(make_id(last + 2, 0xA2), b"discard")
            .unwrap();
        log.rollback_to(&checkpoint).unwrap();

        assert_eq!(log.range().unwrap().1, last + 1);
        assert_eq!(log.read_block(last + 1).unwrap(), b"keep");
        assert!(matches!(
            log.read_block(last + 2),
            Err(ShLogError::NotFound(block)) if block == last + 2
        ));
        drop(log);

        let reopened = StateHistoryLog::open_with_magic(dir.path(), "block_log", magic).unwrap();
        assert_eq!(reopened.range().unwrap().1, last + 1);
        assert_eq!(reopened.read_block(last + 1).unwrap(), b"keep");
    }

    #[test]
    fn checkpoint_rollback_removes_appends_from_memory_and_disk() {
        let (dir, magic) = setup("rollback");
        let log = StateHistoryLog::open_with_magic(dir.path(), "block_log", magic).unwrap();
        let original_range = log.range().unwrap();
        let checkpoint = log.checkpoint().unwrap();
        let appended = original_range.1 + 1;

        log.append(make_id(appended, 0xBC), b"must be rolled back")
            .unwrap();
        assert_eq!(log.range().unwrap().1, appended);
        assert_eq!(log.read_block(appended).unwrap(), b"must be rolled back");

        log.rollback_to(&checkpoint).unwrap();
        assert_eq!(log.range().unwrap(), original_range);
        assert!(matches!(
            log.read_block(appended),
            Err(ShLogError::NotFound(block)) if block == appended
        ));

        // Also cover the harder case: the data entry reached disk, but append
        // failed before its index/in-memory publication.
        log.fail_next_append_after_log_sync();
        assert!(
            log.append(make_id(appended, 0xBE), b"durable orphan")
                .is_err()
        );
        assert_eq!(log.range().unwrap(), original_range);
        assert_eq!(
            parse_raw(&dir.log_path(), magic).last().unwrap().0,
            appended
        );
        log.rollback_to(&checkpoint).unwrap();
        assert_eq!(
            parse_raw(&dir.log_path(), magic).last().unwrap().0,
            original_range.1
        );

        // The restored writers remain usable at the old tail.
        log.append(make_id(appended, 0xBD), b"replacement").unwrap();
        assert_eq!(log.read_block(appended).unwrap(), b"replacement");
        drop(log);

        // Reopening must not recover the discarded entry from either file.
        let reopened = StateHistoryLog::open_with_magic(dir.path(), "block_log", magic).unwrap();
        assert_eq!(reopened.range().unwrap().1, appended);
        assert_eq!(reopened.read_block(appended).unwrap(), b"replacement");
        assert_eq!(
            std::fs::metadata(dir.idx_path()).unwrap().len(),
            (original_range.1 - original_range.0 + 2) as u64 * IDX_RECORD_SIZE
        );
    }

    #[test]
    fn truncate_after_rewinds_a_durable_tail_and_can_resume() {
        let (dir, magic) = setup("truncate_after");
        let log = StateHistoryLog::open_with_magic(dir.path(), "block_log", magic).unwrap();
        let (first, last) = log.range().unwrap();
        let durable = last - 2;

        log.truncate_after(durable).unwrap();
        assert_eq!(log.range(), Some((first, durable)));
        assert!(matches!(
            log.read_block(durable + 1),
            Err(ShLogError::NotFound(block)) if block == durable + 1
        ));
        assert_eq!(parse_raw(&dir.log_path(), magic).last().unwrap().0, durable);
        assert_eq!(
            std::fs::metadata(dir.idx_path()).unwrap().len(),
            u64::from(durable - first + 1) * IDX_RECORD_SIZE
        );

        log.append(make_id(durable + 1, 0xCC), b"resumed").unwrap();
        assert_eq!(log.read_block(durable + 1).unwrap(), b"resumed");
    }

    #[test]
    fn prune_keep_last_preserves_format_and_offsets() {
        let (dir, magic) = setup("prune");
        let log = StateHistoryLog::open_with_magic(dir.path(), "block_log", magic).unwrap();
        let raw_before = parse_raw(&dir.log_path(), magic);
        assert!(
            raw_before.len() >= 3,
            "fixture needs >= 3 blocks to test pruning"
        );
        let (_, last) = log.range().unwrap();

        log.prune_keep_last(2).unwrap();

        // In-memory view: exactly the last two blocks remain.
        assert_eq!(log.range().unwrap(), (last - 1, last));
        assert!(matches!(
            log.read_block(last - 2),
            Err(ShLogError::NotFound(_))
        ));

        // On-disk view: same format, entries repacked from offset 0.
        let raw_after = parse_raw(&dir.log_path(), magic);
        assert_eq!(raw_after.len(), 2);
        assert_eq!(raw_after[0].1, 0, "first kept entry must start at offset 0");
        assert_eq!(raw_after[0].0, last - 1);
        assert_eq!(raw_after[1].0, last);
        // Payloads survived the rewrite byte-for-byte (this is the
        // regression test for the stale-BufReader prune bug).
        assert_eq!(raw_after[0].2, raw_before[raw_before.len() - 2].2);
        assert_eq!(raw_after[1].2, raw_before[raw_before.len() - 1].2);

        // Reads through the log agree with the raw parse.
        assert_eq!(log.read_block(last - 1).unwrap(), raw_after[0].2);
        assert_eq!(log.read_block(last).unwrap(), raw_after[1].2);

        // Appending after a prune continues seamlessly, and a reopen
        // sees a fully consistent log+index pair.
        log.append(make_id(last + 1, 0xCD), b"post-prune").unwrap();
        drop(log);
        let log = StateHistoryLog::open_with_magic(dir.path(), "block_log", magic).unwrap();
        assert_eq!(log.range().unwrap(), (last - 1, last + 1));
        assert_eq!(log.read_block(last + 1).unwrap(), b"post-prune");
    }

    #[test]
    fn prune_noop_when_nothing_to_drop() {
        let (dir, magic) = setup("prunenoop");
        let log = StateHistoryLog::open_with_magic(dir.path(), "block_log", magic).unwrap();
        let range = log.range().unwrap();
        let count = (range.1 - range.0 + 1) as u64;

        let mtime_before = std::fs::metadata(dir.log_path())
            .unwrap()
            .modified()
            .unwrap();
        // Keeping more blocks than exist must not rewrite the file.
        log.prune_keep_last(count as u32 + 10).unwrap();
        assert_eq!(log.range().unwrap(), range);
        let mtime_after = std::fs::metadata(dir.log_path())
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(mtime_before, mtime_after, "no-op prune rewrote the log");
    }

    #[test]
    fn wrong_magic_is_rejected() {
        let (dir, magic) = setup("badmagic");
        let err = StateHistoryLog::open_with_magic(dir.path(), "block_log", magic ^ 0xDEAD_BEEF)
            .unwrap_err();
        assert!(matches!(err, ShLogError::BadMagic { at: 0, .. }));
    }

    #[test]
    fn fresh_empty_log_roundtrip() {
        let dir = TestDir::new("fresh");
        let magic = fixture_magic(); // any non-zero magic works here
        let log = StateHistoryLog::open_with_magic(dir.path(), "block_log", magic).unwrap();
        assert_eq!(log.range(), None);
        assert_eq!(log.last_block(), 0);

        for n in 1u32..=3 {
            log.append(make_id(n, n as u8), format!("payload-{n}").as_bytes())
                .unwrap();
        }
        assert_eq!(log.range().unwrap(), (1, 3));
        drop(log);

        let log = StateHistoryLog::open_with_magic(dir.path(), "block_log", magic).unwrap();
        for n in 1u32..=3 {
            assert_eq!(
                log.read_block(n).unwrap(),
                format!("payload-{n}").as_bytes()
            );
        }
    }

    #[test]
    fn reset_to_rebases_log_to_snapshot_block() {
        let (dir, magic) = setup("reset");
        let log = StateHistoryLog::open_with_magic(dir.path(), "block_log", magic).unwrap();
        assert_eq!(log.range().unwrap(), (1, FIXTURE_BLOCKS));

        // Fast-forward to a block far past the tail — the height state sync
        // would land on.
        let payload = b"synced-block-100".to_vec();
        log.reset_to(make_id(100, 7), &payload).unwrap();

        assert_eq!(log.range().unwrap(), (100, 100));
        assert_eq!(log.last_block(), 100);
        assert_eq!(log.read_block(100).unwrap(), payload);
        // The pre-sync blocks are gone.
        assert!(matches!(log.read_block(3), Err(ShLogError::NotFound(3))));

        // The next block appends contiguously at 101.
        log.append(make_id(101, 8), b"post-sync-101").unwrap();
        assert_eq!(log.range().unwrap(), (100, 101));
        drop(log);

        // A restart recovers the re-based range and the on-disk framing is
        // clean (the independent parser agrees).
        let log = StateHistoryLog::open_with_magic(dir.path(), "block_log", magic).unwrap();
        assert_eq!(log.range().unwrap(), (100, 101));
        let raw = parse_raw(&dir.log_path(), magic);
        assert_eq!(
            raw.iter().map(|(n, ..)| *n).collect::<Vec<_>>(),
            vec![100, 101]
        );
        assert_eq!(log.read_block(100).unwrap(), payload);
    }

    #[test]
    fn open_rebuilds_old_index_paired_with_new_rebased_log() {
        let (dir, magic) = setup("reset-crash-pair");
        let payload = b"synced-block-100";
        let old_index;
        {
            let log = StateHistoryLog::open_with_magic(dir.path(), "block_log", magic).unwrap();
            old_index = std::fs::read(dir.idx_path()).unwrap();
            log.reset_to(make_id(100, 7), payload).unwrap();
        }

        // Simulate a crash after reset_to's log rename but before its index
        // rename: the durable paths expose the new one-entry log and old index.
        std::fs::write(dir.idx_path(), old_index).unwrap();

        let recovered = StateHistoryLog::open_with_magic(dir.path(), "block_log", magic).unwrap();
        assert_eq!(recovered.range(), Some((100, 100)));
        assert_eq!(recovered.read_block(100).unwrap(), payload);
        assert!(matches!(
            recovered.read_block(1),
            Err(ShLogError::NotFound(1))
        ));
        assert_eq!(
            std::fs::metadata(dir.idx_path()).unwrap().len(),
            IDX_RECORD_SIZE
        );
    }

    #[test]
    fn clear_empties_log_and_accepts_any_next_height() {
        let (dir, magic) = setup("clear");
        let log = StateHistoryLog::open_with_magic(dir.path(), "block_log", magic).unwrap();

        log.clear().unwrap();
        assert_eq!(log.range(), None);
        assert_eq!(log.last_block(), 0);
        assert!(matches!(log.read_block(1), Err(ShLogError::NotFound(1))));

        // An empty log accepts any starting height, so the state-history stream
        // can resume at the first post-sync block.
        log.append(make_id(50, 9), b"resume-50").unwrap();
        assert_eq!(log.range().unwrap(), (50, 50));
        drop(log);

        let log = StateHistoryLog::open_with_magic(dir.path(), "block_log", magic).unwrap();
        assert_eq!(log.range().unwrap(), (50, 50));
        assert_eq!(log.read_block(50).unwrap(), b"resume-50");
    }
}
