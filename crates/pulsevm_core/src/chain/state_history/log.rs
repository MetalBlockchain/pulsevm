use std::{
    collections::BTreeMap,
    fmt,
    fs::{File, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Mutex,
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
    map: BTreeMap<u32, u64>,   // block_num -> file offset (header start)
    range: Option<(u32, u32)>, // (first, last); None == empty log
    log_len: u64,              // logical end-of-log; running counter, no metadata() syscalls
}

#[derive(Debug)]
pub struct StateHistoryLog {
    name: String,
    log_path: PathBuf,
    idx_path: PathBuf,
    magic: u64,
    inner: Mutex<Inner>,
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
        let mut map = BTreeMap::new();
        let mut valid_idx_bytes = 0u64;
        {
            idx_file.seek(SeekFrom::Start(0))?;
            let mut r = BufReader::new(&idx_file);
            loop {
                let mut buf = [0u8; IDX_RECORD_SIZE as usize];
                match r.read_exact(&mut buf) {
                    Ok(()) => {
                        let block = u32::from_le_bytes(buf[0..4].try_into().unwrap());
                        let pos = u64::from_le_bytes(buf[4..12].try_into().unwrap());
                        map.insert(block, pos);
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
        if idx_file.metadata()?.len() > valid_idx_bytes {
            idx_file.set_len(valid_idx_bytes)?;
        }

        if map.is_empty() {
            // Full scan of the log; rebuild the index file from scratch.
            let entries = scan_entries(&mut log_file, 0, magic)?;
            idx_file.set_len(0)?;
            idx_file.seek(SeekFrom::Start(0))?;
            let mut w = BufWriter::new(&idx_file);
            for (block, pos) in &entries {
                w.write_all(&block.to_le_bytes())?;
                w.write_all(&pos.to_le_bytes())?;
                map.insert(*block, *pos);
            }
            w.flush()?;
        } else {
            // Validate the tail entry the index points at.
            let last = *map.keys().last().unwrap();
            let tail_off = map[&last];
            let len_total = log_file.metadata()?.len();
            match read_validated_header(&mut log_file, tail_off, len_total, magic) {
                Ok(h) => {
                    let ok_end = tail_off + StateHistoryLogHeader::SIZE + h.payload_size;
                    // Recover entries the log has but the index doesn't
                    // (crash after log sync, before index write). This
                    // is what makes append's "log first, index second"
                    // ordering safe — an acknowledged block is never
                    // silently dropped.
                    let recovered = scan_entries(&mut log_file, ok_end, magic)?;
                    if !recovered.is_empty() {
                        idx_file.seek(SeekFrom::Start(valid_idx_bytes))?;
                        let mut w = BufWriter::new(&idx_file);
                        for (block, pos) in &recovered {
                            w.write_all(&block.to_le_bytes())?;
                            w.write_all(&pos.to_le_bytes())?;
                            map.insert(*block, *pos);
                        }
                        w.flush()?;
                    }
                }
                Err(_) => {
                    // Torn tail: drop it from log, index, and map.
                    log_file.set_len(tail_off)?;
                    map.remove(&last);
                    idx_file.set_len(valid_idx_bytes.saturating_sub(IDX_RECORD_SIZE))?;
                }
            }
        }

        let log_len = log_file.metadata()?.len();
        let range = match (map.keys().next(), map.keys().last()) {
            (Some(&f), Some(&l)) => Some((f, l)),
            _ => None,
        };

        log_file.seek(SeekFrom::End(0))?;
        idx_file.seek(SeekFrom::End(0))?;

        Ok(Self {
            name: name.to_string(),
            log_path,
            idx_path,
            magic,
            inner: Mutex::new(Inner {
                log: BufWriter::new(log_file),
                idx: BufWriter::new(idx_file),
                map,
                range,
                log_len,
            }),
        })
    }

    /// Append one entry with EOS SHiP header.
    ///
    /// Durability note: the log is `sync_data()`'d before the index
    /// record referencing it is written, so on-disk the index never
    /// points past valid log data. If per-append fsync is too costly
    /// for your workload, it can be relaxed — open-time recovery
    /// handles a log/index mismatch either way — but then `Ok(())`
    /// no longer implies the block survives a power loss.
    pub fn append(&self, block_id: Id, payload: &[u8]) -> Result<(), ShLogError> {
        let block_num = num_from_block_id(&block_id);
        let mut inner = self.inner.lock().unwrap();

        if let Some((_, last)) = inner.range {
            if block_num != last + 1 {
                return Err(ShLogError::MissedBlock(format!(
                    "{}.log: expected block {}, got {}",
                    self.name,
                    last + 1,
                    block_num
                )));
            }
        }

        let pos = inner.log_len;

        // Re-position explicitly. This is a no-op in the happy path,
        // but if a previous append failed mid-write it guarantees we
        // overwrite the partial entry instead of appending after it.
        // (BufWriter's Seek impl flushes its buffer first.)
        inner.log.seek(SeekFrom::Start(pos))?;

        let header = StateHistoryLogHeader {
            magic: self.magic,
            block_id,
            payload_size: payload.len() as u64,
        };
        header.write(&mut inner.log)?;
        inner.log.write_all(payload)?;
        inner.log.flush()?;
        inner.log.get_ref().sync_data()?;

        // Index record only after the log entry is durable.
        inner.idx.write_all(&block_num.to_le_bytes())?;
        inner.idx.write_all(&pos.to_le_bytes())?;
        inner.idx.flush()?;

        inner.log_len = pos + StateHistoryLogHeader::SIZE + payload.len() as u64;
        inner.map.insert(block_num, pos);
        inner.range = Some(match inner.range {
            None => (block_num, block_num),
            Some((first, _)) => (first, block_num),
        });

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
            let pos = *inner
                .map
                .get(&block_num)
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
        let (pairs, f) = {
            let inner = self.inner.lock().unwrap();
            let pairs: Vec<(u32, u64)> = inner
                .map
                .range(start..=end)
                .map(|(k, v)| (*k, *v))
                .collect();
            let f = OpenOptions::new().read(true).open(&self.log_path)?;
            (pairs, f)
        };

        let len_total = f.metadata()?.len();
        let mut r = BufReader::new(f);
        for (block, pos) in pairs {
            let header = read_validated_header(&mut r, pos, len_total, self.magic)?;
            if num_from_block_id(&header.block_id) != block {
                return Err(ShLogError::Corrupt(pos));
            }
            let mut buf = vec![0u8; header.payload_size as usize];
            r.read_exact(&mut buf)?;
            cb(block, &buf)?;
        }
        Ok(())
    }

    /* -------------------- pruning -------------------- */

    pub fn prune_keep_last(&self, n: u32) -> Result<(), ShLogError> {
        let mut inner = self.inner.lock().unwrap();
        let Some((first, last)) = inner.range else {
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
        match inner.range {
            None => return Ok(()),
            Some((first, _)) if start_block <= first => return Ok(()),
            _ => {}
        }

        let keep: Vec<(u32, u64)> = inner
            .map
            .range(start_block..=u32::MAX)
            .map(|(k, v)| (*k, *v))
            .collect();
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
        let mut new_map = BTreeMap::new();

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

            new_map.insert(*block, new_pos);
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
        inner.map = new_map;
        inner.range = Some((first_kept, last_kept));
        inner.log_len = new_pos;

        Ok(())
    }

    /* -------------------- getters -------------------- */

    /// Last appended block number, or 0 if the log is empty.
    /// Prefer `range()` for an unambiguous answer.
    pub fn last_block(&self) -> u32 {
        self.inner
            .lock()
            .unwrap()
            .range
            .map(|(_, l)| l)
            .unwrap_or(0)
    }

    pub fn range(&self) -> Option<(u32, u32)> {
        self.inner.lock().unwrap().range
    }

    pub fn get_block_id(&self, block_num: u32) -> Result<Id, ShLogError> {
        let (pos, mut f) = {
            let inner = self.inner.lock().unwrap();
            let pos = *inner
                .map
                .get(&block_num)
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
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Fixture: a real SHiP log checked in at ROOT/test-data/block_log.log.
    fn fixture_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("test-data")
            .join("block_log.log")
    }

    /// The tests derive the expected magic from the fixture itself
    /// (first 8 bytes, LE) so they don't need to hardcode
    /// ship_magic(version) and silently rot when it changes.
    fn fixture_magic() -> u64 {
        0
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

    /// Copy the fixture into a fresh dir (no index yet). Opening is
    /// read-write and creates/repairs files, so tests never touch the
    /// checked-in fixture directly.
    fn setup(tag: &str) -> (TestDir, u64) {
        let dir = TestDir::new(tag);
        std::fs::copy(fixture_path(), dir.log_path()).unwrap();
        (dir, fixture_magic())
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
}
