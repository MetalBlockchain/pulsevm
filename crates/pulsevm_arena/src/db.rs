use std::{
    any::{
        Any,
        TypeId,
    },
    path::Path,
};

use crate::{
    object::{
        ArenaObject,
        BlobRef,
        IndexedBy,
    },
    table::{
        Table,
        TableError,
    },
};

/// Errors from the database layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbError {
    NotRegistered {
        type_name: &'static str,
    },
    TypeIdInUse {
        type_id: u16,
        type_name: &'static str,
    },
    Corrupted(String),
    Io(String),
    Table(TableError),
}

impl From<TableError> for DbError {
    fn from(e: TableError) -> Self {
        DbError::Table(e)
    }
}

fn read_u64(bytes: &[u8], pos: &mut usize) -> Result<u64, DbError> {
    let end = pos
        .checked_add(8)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| DbError::Corrupted("snapshot truncated".into()))?;
    let v = u64::from_le_bytes(bytes[*pos..end].try_into().unwrap());
    *pos = end;
    Ok(v)
}

fn read_u16(bytes: &[u8], pos: &mut usize) -> Result<u16, DbError> {
    let end = pos
        .checked_add(2)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| DbError::Corrupted("snapshot truncated".into()))?;
    let v = u16::from_le_bytes(bytes[*pos..end].try_into().unwrap());
    *pos = end;
    Ok(v)
}

fn read_i64(bytes: &[u8], pos: &mut usize) -> Result<i64, DbError> {
    Ok(read_u64(bytes, pos)? as i64)
}

/// Reads a u64 without advancing, or `None` if fewer than 8 bytes remain.
fn try_read_u64(bytes: &[u8], pos: usize) -> Option<u64> {
    bytes
        .get(pos..pos + 8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
}

/// Writes `bytes` to a temp file, fsyncs it, then renames it over `path`, so a
/// crash never leaves a half-written file in place.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), DbError> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp).map_err(|e| DbError::Io(e.to_string()))?;
    f.write_all(bytes).map_err(|e| DbError::Io(e.to_string()))?;
    f.sync_all().map_err(|e| DbError::Io(e.to_string()))?;
    std::fs::rename(&tmp, path).map_err(|e| DbError::Io(e.to_string()))?;
    // The rename is a directory change, and it is only durable once the directory
    // is. A power loss before that can bring back the old file (or none) even
    // though the data was fsynced, and the caller may be about to delete the log
    // this checkpoint replaces.
    sync_parent_dir(path)
}

/// Fsync the directory holding `path`, making a create, rename or unlink of an
/// entry in it durable. A no-op where directories cannot be opened for sync.
pub fn sync_parent_dir(path: &Path) -> Result<(), DbError> {
    #[cfg(unix)]
    {
        let dir = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        std::fs::File::open(dir)
            .and_then(|handle| handle.sync_all())
            .map_err(|e| DbError::Io(format!("sync directory {}: {e}", dir.display())))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Start of every write-ahead log: the format version, then a random key chosen
/// when the file is created. A log written before records carried a checksum, or
/// before the key, has a different start and is refused by name, not misread.
const WAL_MAGIC: &[u8; 8] = b"PVMWAL04";
/// The write-ahead log format a node writes, as a name. A node refuses a log in
/// any other format, so two nodes of different formats cannot exchange data
/// directories; `getInfo` reports it so a fleet can be checked for one build.
/// A test pins it to the bytes at the start of a real log.
pub const WAL_FORMAT: &str = "PVMWAL04";
const WAL_KEY_LEN: usize = 32;
const WAL_HEADER_LEN: usize = WAL_MAGIC.len() + WAL_KEY_LEN;
const WAL_DIGEST_LEN: usize = 32;

/// The checksum of a record. It covers the length as well as the payload: with
/// only the payload under it, a flipped bit in the length made a good record look
/// cut short, and everything behind it was treated as a torn tail and deleted.
///
/// It is also keyed with the file's own random key. A plain hash can be computed
/// by anyone, and the payload carries contract row bytes verbatim, so a
/// transaction could store 56 bytes that read as a valid record. Found inside a
/// torn final record, such a "record" proved the file was altered and the node
/// refused to start. The key lives only in this file's header, which a contract
/// cannot read, so no payload can contain a record that verifies.
fn wal_digest(key: &[u8], len: u64, payload: &[u8]) -> [u8; WAL_DIGEST_LEN] {
    use sha2::{
        Digest,
        Sha256,
    };
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.update(len.to_le_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

/// Smallest payload a record can carry: a revision and a table count.
const WAL_MIN_PAYLOAD: usize = 16;

/// The record that starts at `pos`, if one that verifies does:
/// `(payload start, payload end, record end)`.
fn wal_record_at(data: &[u8], key: &[u8], pos: usize) -> Option<(usize, usize, usize)> {
    let len = try_read_u64(data, pos)?;
    let payload_start = pos.checked_add(8)?;
    let payload_end = payload_start.checked_add(usize::try_from(len).ok()?)?;
    let record_end = payload_end.checked_add(WAL_DIGEST_LEN)?;
    if record_end > data.len() {
        return None;
    }
    if wal_digest(key, len, &data[payload_start..payload_end]) != data[payload_end..record_end] {
        return None;
    }
    Some((payload_start, payload_end, record_end))
}

/// Where a record that verifies starts, anywhere in `data[from..]`.
///
/// This is how a cut-short log is told from a damaged one. A crash leaves a
/// prefix of a record, then nothing or zeros: no intact record can follow it. If
/// one does, whatever stopped the scan was not a crash, and the bytes behind it
/// are data that must not be thrown away. Only run on the failure path; the cheap
/// length test keeps it linear.
fn wal_valid_record_follows(
    data: &[u8],
    key: &[u8],
    from: usize,
    expect: Option<FramePrefix>,
) -> Follows {
    wal_valid_record_follows_within(data, key, from, WAL_DAMAGE_SCAN_BUDGET, expect)
}

/// What every record of a log starts with, as the last good one showed it: the
/// revision it carried and how many tables it has a delta for. A genuine later
/// record continues the sequence and has the same table count; almost nothing else
/// does, which is what lets the damage scan skip hashing nearly every offset.
#[derive(Clone, Copy, Debug)]
struct FramePrefix {
    last_revision: i64,
    table_count: u64,
}

/// The furthest a later record's revision may be past the last good one. The next
/// record is the next revision; this leaves room for records lost to damage.
const WAL_MAX_REVISION_GAP: i64 = 1_000_000;

impl FramePrefix {
    fn of(payload: &[u8]) -> Option<Self> {
        Some(Self {
            last_revision: i64::from_le_bytes(payload.get(0..8)?.try_into().ok()?),
            table_count: u64::from_le_bytes(payload.get(8..16)?.try_into().ok()?),
        })
    }

    /// Whether a candidate record's payload could continue the log. Cheap: sixteen
    /// bytes, no hashing.
    fn could_follow(&self, candidate_payload: &[u8]) -> bool {
        let (Some(revision), Some(count)) = (
            candidate_payload
                .get(0..8)
                .and_then(|b| b.try_into().ok())
                .map(i64::from_le_bytes),
            candidate_payload
                .get(8..16)
                .and_then(|b| b.try_into().ok())
                .map(u64::from_le_bytes),
        ) else {
            return false;
        };
        count == self.table_count
            && revision > self.last_revision
            && revision <= self.last_revision.saturating_add(WAL_MAX_REVISION_GAP)
    }
}

fn wal_valid_record_follows_within(
    data: &[u8],
    key: &[u8],
    from: usize,
    budget: u64,
    expect: Option<FramePrefix>,
) -> Follows {
    let mut pos = from;
    let mut hashed = 0u64;
    while pos
        .checked_add(8 + WAL_MIN_PAYLOAD + WAL_DIGEST_LEN)
        .is_some_and(|end| end <= data.len())
    {
        if let Some(len) = try_read_u64(data, pos)
            && len >= WAL_MIN_PAYLOAD as u64
            && len <= (data.len() - pos) as u64
        {
            // A real torn record is a block's row data, full of small integers that
            // look like lengths, and hashing a candidate costs its whole claimed
            // length. So a candidate is looked at cheaply first: the sixteen bytes
            // that start every record must continue the log (the next revision, the
            // same table count). Honest data almost never does; only then is it
            // hashed. (Without this, an honest torn record of 256 KiB or more
            // exhausted the budget below and the node refused to start.)
            let plausible = match expect {
                Some(prefix) => data
                    .get(pos + 8..)
                    .is_some_and(|payload| prefix.could_follow(payload)),
                None => true, // nothing before it to compare with
            };
            if plausible {
                // A transaction can put chosen bytes into the log, including a
                // plausible prefix, so what is hashed is still bounded: past the
                // budget the answer is "cannot rule out damage", which refuses the
                // log instead of spending quadratic time on a hostile tail.
                hashed = hashed.saturating_add(len);
                if hashed > budget {
                    return Follows::BudgetExhausted;
                }
                if wal_record_at(data, key, pos).is_some() {
                    return Follows::At(pos);
                }
            }
        }
        pos += 1;
    }
    Follows::No
}

/// The most bytes the damage scan will hash. A torn record is one block's change,
/// and honest data has almost no offsets that look like a record, so this is far
/// above any real need.
const WAL_DAMAGE_SCAN_BUDGET: u64 = 256 * 1024 * 1024;

/// What the damage scan found after a record that failed to verify.
#[derive(Debug, PartialEq, Eq)]
enum Follows {
    /// An intact record starts here: the failure was damage, not a cut.
    At(usize),
    /// Nothing intact follows: what is left is a write that was cut short.
    No,
    /// The scan was stopped by its budget. Treated as damage, never as a tear.
    BudgetExhausted,
}

/// The complete records of a log, and what is left over after them.
struct WalScan {
    /// `(start, end)` of each record's payload.
    records: Vec<(usize, usize)>,
    /// Where the last good record ends.
    valid_len: usize,
    /// Bytes follow that do not form a complete, intact record.
    torn_tail: bool,
}

/// Split a log into records, checking each one's checksum.
///
/// A record cut short by a crash is the expected damage: it ends the log. A
/// record whose checksum fails is the same thing if nothing follows it (a write
/// that reached the file but not all of its pages), and is discarded as such. A
/// failure with intact data after it cannot be a crash: something altered the
/// file, and applying what follows would build state on a hole, so it is refused.
fn scan_wal(data: &[u8]) -> Result<WalScan, DbError> {
    let mut scan = WalScan {
        records: Vec::new(),
        valid_len: 0,
        torn_tail: false,
    };
    if data.is_empty() {
        return Ok(scan);
    }
    // A file of nothing but zeros is an append that never happened: the
    // filesystem made the file, or extended it, and no data landed. That window
    // opens once per checkpoint fold, between removing the log and the next
    // accept creating it. It is not an older build's log, and nothing in it is
    // lost.
    if data.iter().all(|byte| *byte == 0) {
        scan.torn_tail = true;
        return Ok(scan);
    }
    if data.len() < WAL_MAGIC.len() {
        if WAL_MAGIC.starts_with(data) {
            scan.torn_tail = true; // a header cut short
            return Ok(scan);
        }
        return Err(DbError::Corrupted(
            "write-ahead log has an unrecognised header".into(),
        ));
    }
    if &data[..WAL_MAGIC.len()] != WAL_MAGIC {
        return Err(DbError::Corrupted(
            "write-ahead log is not in the checksummed format (written by an earlier build?): stop that node cleanly with the build that wrote it, or resync".into(),
        ));
    }
    if data.len() < WAL_HEADER_LEN {
        scan.torn_tail = true; // the key was cut short
        return Ok(scan);
    }
    let key = &data[WAL_MAGIC.len()..WAL_HEADER_LEN];
    let mut pos = WAL_HEADER_LEN;
    scan.valid_len = pos;
    while pos < data.len() {
        let Some((payload_start, payload_end, record_end)) = wal_record_at(data, key, pos) else {
            // The record at `pos` cannot be completed or does not verify. If an
            // intact record starts anywhere after it, this is damage in the
            // middle of the file, not a crash: refuse, and leave the file as it
            // is. If none does, what is left is the remains of a write that was
            // cut short (a partial record, zeros, anything), and goes.
            let expect = scan
                .records
                .last()
                .and_then(|&(start, end)| FramePrefix::of(&data[start..end]));
            match wal_valid_record_follows(data, key, pos + 1, expect) {
                Follows::At(next) => {
                    return Err(DbError::Corrupted(format!(
                        "write-ahead log record at byte {pos} cannot be read and an intact record starts at byte {next}: the file was altered, not cut short, so nothing is discarded"
                    )));
                }
                Follows::BudgetExhausted => {
                    return Err(DbError::Corrupted(format!(
                        "write-ahead log record at byte {pos} cannot be read and the file after it is too large to rule out damage within the scan budget: it is refused rather than discarded"
                    )));
                }
                Follows::No => {}
            }
            scan.torn_tail = true;
            break;
        };
        scan.records.push((payload_start, payload_end));
        pos = record_end;
        scan.valid_len = pos;
    }
    Ok(scan)
}

/// Appends `[len][frame]` to the log and fsyncs.
/// What [`Db::replay_log_after`] did with a write-ahead log.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WalReplay {
    pub frames_applied: usize,
    /// Frames already covered by the checkpoint the log was replayed onto.
    pub frames_skipped: usize,
    /// End of the last complete frame; everything after it is a torn write.
    pub valid_len: u64,
    pub torn_tail: bool,
}

/// The key in the header of the log at `path`.
fn wal_key_of(path: &Path) -> Result<[u8; WAL_KEY_LEN], DbError> {
    use std::io::Read;
    let mut header = [0u8; WAL_HEADER_LEN];
    std::fs::File::open(path)
        .and_then(|mut file| file.read_exact(&mut header))
        .map_err(|e| DbError::Io(format!("read the write-ahead log header: {e}")))?;
    if &header[..WAL_MAGIC.len()] != WAL_MAGIC {
        return Err(DbError::Corrupted(
            "write-ahead log header is not the current format".into(),
        ));
    }
    let mut key = [0u8; WAL_KEY_LEN];
    key.copy_from_slice(&header[WAL_MAGIC.len()..]);
    Ok(key)
}

fn append_frame(path: &Path, frame: &[u8]) -> Result<(), DbError> {
    use std::io::Write;
    let existing = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    // One write per record, so a crash tears it at one point rather than leaving
    // a length with no payload behind it.
    let mut record = Vec::with_capacity(WAL_HEADER_LEN + 8 + frame.len() + WAL_DIGEST_LEN);
    let key = if existing == 0 {
        let mut key = [0u8; WAL_KEY_LEN];
        getrandom::fill(&mut key)
            .map_err(|e| DbError::Io(format!("no randomness for the write-ahead log key: {e}")))?;
        record.extend_from_slice(WAL_MAGIC);
        record.extend_from_slice(&key);
        key
    } else {
        wal_key_of(path)?
    };
    record.extend_from_slice(&(frame.len() as u64).to_le_bytes());
    record.extend_from_slice(frame);
    record.extend_from_slice(&wal_digest(&key, frame.len() as u64, frame));
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| DbError::Io(e.to_string()))?;
    f.write_all(&record)
        .map_err(|e| DbError::Io(e.to_string()))?;
    f.sync_all().map_err(|e| DbError::Io(e.to_string()))?;
    if existing == 0 {
        // A new file is a new directory entry.
        sync_parent_dir(path)?;
    }
    Ok(())
}

/// One table's frozen copy, type-erased so a frozen database can hold them all.
trait FrozenSection: Send {
    fn pack_canonical_into(&self, out: &mut Vec<u8>) -> Result<(), TableError>;
}

impl<T: ArenaObject> FrozenSection for crate::table::FrozenTable<T> {
    fn pack_canonical_into(&self, out: &mut Vec<u8>) -> Result<(), TableError> {
        crate::table::FrozenTable::pack_canonical_into(self, out)
    }
}

/// A copy of everything the canonical export reads, taken at one revision. Making
/// it is a memory copy of the rows and blob bytes, done while the database is
/// held; [`FrozenDb::canonical_bytes`], which repacks and hashes every byte, is
/// done afterwards, on any thread, without holding the database. The bytes are
/// exactly those [`Db::checkpoint_unmarked`] writes to a file (a test pins it).
pub struct FrozenDb {
    revision: i64,
    /// `(type_id, table)` in type-id order, as the checkpoint file lists them.
    sections: Vec<(u16, Box<dyn FrozenSection>)>,
}

impl FrozenDb {
    pub fn revision(&self) -> i64 {
        self.revision
    }

    /// The canonical checkpoint, in memory.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, DbError> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.revision.to_le_bytes());
        out.extend_from_slice(&(self.sections.len() as u64).to_le_bytes());
        for (type_id, section) in &self.sections {
            out.extend_from_slice(&type_id.to_le_bytes());
            let len_at = out.len();
            out.extend_from_slice(&0u64.to_le_bytes()); // section length placeholder
            let start = out.len();
            section.pack_canonical_into(&mut out)?;
            let len = (out.len() - start) as u64;
            out[len_at..len_at + 8].copy_from_slice(&len.to_le_bytes());
        }
        Ok(out)
    }
}

/// Type-erased view of a `Table<T>` so the database can drive the shared
/// revision/undo lifecycle across a heterogeneous set of tables.
trait AbstractTable: Send + Sync {
    fn start_undo_session(&mut self) -> i64;
    fn revision(&self) -> i64;
    fn set_revision(&mut self, revision: i64) -> Result<(), TableError>;
    fn undo(&mut self);
    fn squash(&mut self);
    fn commit(&mut self, revision: i64);
    fn undo_all(&mut self);
    fn undo_stack_revision_range(&self) -> (i64, i64);
    fn len(&self) -> usize;
    fn type_id_num(&self) -> u16;
    fn type_name(&self) -> &'static str;
    fn pack_into(&self, out: &mut Vec<u8>);
    fn pack_canonical_into(&self, out: &mut Vec<u8>) -> Result<(), TableError>;
    /// A copy of what the canonical export reads, to export without the table.
    fn freeze(&self) -> Box<dyn FrozenSection>;
    fn load_from(&mut self, bytes: &[u8]) -> Result<(), TableError>;
    fn pack_delta(&self, out: &mut Vec<u8>);
    fn apply_delta(&mut self, bytes: &[u8]) -> Result<(), TableError>;
    fn mark_flushed(&mut self);
    fn hash_state(&self, hasher: &mut sha2::Sha256);
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

impl<T: ArenaObject> AbstractTable for Table<T> {
    fn start_undo_session(&mut self) -> i64 {
        Table::start_undo_session(self)
    }
    fn revision(&self) -> i64 {
        Table::revision(self)
    }
    fn set_revision(&mut self, revision: i64) -> Result<(), TableError> {
        Table::set_revision(self, revision)
    }
    fn undo(&mut self) {
        Table::undo(self)
    }
    fn squash(&mut self) {
        Table::squash(self)
    }
    fn commit(&mut self, revision: i64) {
        Table::commit(self, revision)
    }
    fn undo_all(&mut self) {
        Table::undo_all(self)
    }
    fn undo_stack_revision_range(&self) -> (i64, i64) {
        Table::undo_stack_revision_range(self)
    }
    fn len(&self) -> usize {
        Table::len(self)
    }
    fn type_id_num(&self) -> u16 {
        T::TYPE_ID
    }
    fn type_name(&self) -> &'static str {
        T::type_name()
    }
    fn pack_into(&self, out: &mut Vec<u8>) {
        Table::pack_into(self, out)
    }
    fn pack_canonical_into(&self, out: &mut Vec<u8>) -> Result<(), TableError> {
        Table::pack_canonical_into(self, out)
    }
    fn freeze(&self) -> Box<dyn FrozenSection> {
        Box::new(Table::freeze(self))
    }
    fn load_from(&mut self, bytes: &[u8]) -> Result<(), TableError> {
        Table::load_from(self, bytes)
    }
    fn pack_delta(&self, out: &mut Vec<u8>) {
        Table::pack_delta(self, out)
    }
    fn apply_delta(&mut self, bytes: &[u8]) -> Result<(), TableError> {
        Table::apply_delta(self, bytes)
    }
    fn mark_flushed(&mut self) {
        Table::mark_flushed(self)
    }
    fn hash_state(&self, hasher: &mut sha2::Sha256) {
        Table::hash_state(self, hasher)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// A single-threaded set of [`Table`]s sharing one revision/undo lifecycle —
/// the recreation of chainbase `database`, without the lock. Reads hand out
/// references into the tables; there is no clone-out and no `RwLock`.
///
/// An undo session spans every table: [`Db::start_undo_session`] opens one on
/// all of them, and [`Db::undo`]/[`Db::squash`]/[`Db::commit`] fan out so the
/// tables stay at a single shared revision.
#[derive(Default)]
pub struct Db {
    tables: Vec<Box<dyn AbstractTable>>,
    // Arena type ids are compact consensus schema constants. Direct indexing
    // avoids hashing Rust TypeId on every row operation in the execution path.
    by_type_id: Vec<Option<(TypeId, usize)>>,
}

impl Db {
    pub fn new() -> Self {
        Db::default()
    }

    /// Registers the table for `T`. A freshly created table is brought up to the
    /// revision range of the already-registered tables, so every table shares
    /// one undo stack depth.
    pub fn add_table<T: ArenaObject>(&mut self) -> Result<(), DbError> {
        let type_id = usize::from(T::TYPE_ID);
        if self
            .by_type_id
            .get(type_id)
            .and_then(|entry| *entry)
            .is_some()
        {
            return Err(DbError::TypeIdInUse {
                type_id: T::TYPE_ID,
                type_name: T::type_name(),
            });
        }
        let mut table = Table::<T>::new();
        if let Some(first) = self.tables.first() {
            let (lo, hi) = first.undo_stack_revision_range();
            table.set_revision(lo)?;
            while table.revision() < hi {
                table.start_undo_session();
            }
        }
        let pos = self.tables.len();
        self.tables.push(Box::new(table));
        if self.by_type_id.len() <= type_id {
            self.by_type_id.resize(type_id + 1, None);
        }
        self.by_type_id[type_id] = Some((TypeId::of::<T>(), pos));
        Ok(())
    }

    fn pos<T: ArenaObject>(&self) -> Result<usize, DbError> {
        self.by_type_id
            .get(usize::from(T::TYPE_ID))
            .and_then(|entry| *entry)
            .filter(|(rust_type, _)| *rust_type == TypeId::of::<T>())
            .map(|(_, position)| position)
            .ok_or(DbError::NotRegistered {
                type_name: T::type_name(),
            })
    }

    /// Shared access to a whole table, for iteration and secondary-index scans.
    pub fn table<T: ArenaObject>(&self) -> Result<&Table<T>, DbError> {
        let pos = self.pos::<T>()?;
        Ok(self.tables[pos]
            .as_any()
            .downcast_ref::<Table<T>>()
            .expect("table registered under mismatching type"))
    }

    /// Mutable access to a whole table.
    pub fn table_mut<T: ArenaObject>(&mut self) -> Result<&mut Table<T>, DbError> {
        let pos = self.pos::<T>()?;
        Ok(self.tables[pos]
            .as_any_mut()
            .downcast_mut::<Table<T>>()
            .expect("table registered under mismatching type"))
    }

    // ----- object operations (conveniences over the table) ------------------

    pub fn create<T: ArenaObject>(&mut self, f: impl FnOnce(&mut T)) -> Result<&T, DbError> {
        Ok(self.table_mut::<T>()?.emplace(f)?)
    }

    pub fn modify<T: ArenaObject>(
        &mut self,
        id: crate::ObjectId<T>,
        m: impl FnOnce(&mut T),
    ) -> Result<(), DbError> {
        Ok(self.table_mut::<T>()?.modify(id, m)?)
    }

    pub fn remove<T: ArenaObject>(&mut self, id: crate::ObjectId<T>) -> Result<(), DbError> {
        Ok(self.table_mut::<T>()?.remove(id)?)
    }

    pub fn find<T: ArenaObject>(&self, id: crate::ObjectId<T>) -> Result<Option<&T>, DbError> {
        Ok(self.table::<T>()?.find(id))
    }

    pub fn get<T: ArenaObject>(&self, id: crate::ObjectId<T>) -> Result<&T, DbError> {
        Ok(self.table::<T>()?.get(id)?)
    }

    pub fn find_by<T: ArenaObject, Tag: IndexedBy<T>>(
        &self,
        key: &Tag::Key,
    ) -> Result<Option<&T>, DbError> {
        Ok(self.table::<T>()?.get_index::<Tag>().find(key))
    }

    /// Point lookup on a hash-backed index (declared with `hash_index`). O(1)
    /// where an ordered `find_by` is O(log n); use for indexes never scanned.
    pub fn find_by_hash<T: ArenaObject, Tag: IndexedBy<T>>(
        &self,
        key: &Tag::Key,
    ) -> Result<Option<&T>, DbError>
    where
        Tag::Key: std::hash::Hash + Eq,
    {
        Ok(self.table::<T>()?.get_hash_index::<Tag>().find(key))
    }

    /// Appends a variable-length value to `T`'s blob arena; store the returned
    /// ref on the object.
    pub fn alloc_blob<T: ArenaObject>(&mut self, bytes: &[u8]) -> Result<BlobRef, DbError> {
        Ok(self.table_mut::<T>()?.alloc_blob(bytes))
    }

    /// Frees `old` and allocates `bytes` in `T`'s blob arena — the update path
    /// for a blob field, reusing the abandoned span instead of only growing.
    pub fn realloc_blob<T: ArenaObject>(
        &mut self,
        old: BlobRef,
        bytes: &[u8],
    ) -> Result<BlobRef, DbError> {
        Ok(self.table_mut::<T>()?.realloc_blob(old, bytes))
    }

    /// Marks `T`'s blob span as reusable (call when a row carrying it is removed).
    pub fn free_blob<T: ArenaObject>(&mut self, r: BlobRef) -> Result<(), DbError> {
        self.table_mut::<T>()?.free_blob(r);
        Ok(())
    }

    /// Resolves a blob ref against `T`'s arena.
    pub fn blob<T: ArenaObject>(&self, r: BlobRef) -> Result<&[u8], DbError> {
        Ok(self.table::<T>()?.blob(r))
    }

    /// Total bytes in `T`'s blob arena — for checking reuse bounds growth.
    pub fn blob_arena_len<T: ArenaObject>(&self) -> Result<usize, DbError> {
        Ok(self.table::<T>()?.blob_arena_len())
    }

    // ----- revision / undo lifecycle ----------------------------------------

    pub fn revision(&self) -> i64 {
        self.tables.first().map(|t| t.revision()).unwrap_or(0)
    }

    pub fn set_revision(&mut self, revision: i64) -> Result<(), DbError> {
        for table in &mut self.tables {
            table.set_revision(revision)?;
        }
        Ok(())
    }

    /// Opens an undo session on every table. Returns the new shared revision.
    pub fn start_undo_session(&mut self) -> i64 {
        for table in &mut self.tables {
            table.start_undo_session();
        }
        self.revision()
    }

    pub fn undo(&mut self) {
        for table in &mut self.tables {
            table.undo();
        }
    }

    pub fn squash(&mut self) {
        for table in &mut self.tables {
            table.squash();
        }
    }

    pub fn commit(&mut self, revision: i64) {
        for table in &mut self.tables {
            table.commit(revision);
        }
    }

    pub fn undo_all(&mut self) {
        for table in &mut self.tables {
            table.undo_all();
        }
    }

    // ----- persistence ------------------------------------------------------

    /// Writes a full checkpoint of committed state to `path`: the revision plus
    /// every table's live rows as raw bytes, tagged by `type_id`. Fast because
    /// objects are POD — the per-row cost is a copy, not a serialization pass.
    /// The write is atomic (temp file + fsync + rename) so a crash mid-write
    /// leaves the previous checkpoint intact. Marks the tables flushed, so a
    /// following [`Db::flush_delta`] only records changes made after this.
    pub fn checkpoint(&mut self, path: impl AsRef<Path>) -> Result<(), DbError> {
        self.write_checkpoint(path.as_ref(), false)?;
        for table in &mut self.tables {
            table.mark_flushed();
        }
        Ok(())
    }

    /// Writes the same checkpoint as [`Db::checkpoint`] but leaves the flush
    /// bookkeeping alone. Use it to export state (a snapshot for a peer, a hash)
    /// from a database whose write-ahead log is live: marking the tables flushed
    /// there would make the next [`Db::flush_delta`] skip every change made
    /// before the export.
    ///
    /// The bytes are canonical: the same state gives the same file whatever the
    /// history that built it (see `Table::pack_canonical_into`). A node's own
    /// checkpoint ([`Db::checkpoint`]) is not, on purpose: the log that follows
    /// it is written in terms of the live layout.
    pub fn checkpoint_unmarked(&self, path: impl AsRef<Path>) -> Result<(), DbError> {
        self.write_checkpoint(path.as_ref(), true)
    }

    /// Copy out what the canonical export reads, so the export can run without
    /// holding this database (see [`FrozenDb`]).
    pub fn freeze(&self) -> FrozenDb {
        let mut ordered: Vec<usize> = (0..self.tables.len()).collect();
        ordered.sort_by_key(|&pos| self.tables[pos].type_id_num());
        FrozenDb {
            revision: self.revision(),
            sections: ordered
                .into_iter()
                .map(|pos| (self.tables[pos].type_id_num(), self.tables[pos].freeze()))
                .collect(),
        }
    }

    fn write_checkpoint(&self, path: &Path, canonical: bool) -> Result<(), DbError> {
        let mut ordered: Vec<usize> = (0..self.tables.len()).collect();
        ordered.sort_by_key(|&pos| self.tables[pos].type_id_num());

        let mut out = Vec::new();
        out.extend_from_slice(&self.revision().to_le_bytes());
        out.extend_from_slice(&(ordered.len() as u64).to_le_bytes());
        for pos in ordered {
            let table = &self.tables[pos];
            out.extend_from_slice(&table.type_id_num().to_le_bytes());
            let len_at = out.len();
            out.extend_from_slice(&0u64.to_le_bytes()); // section length placeholder
            let start = out.len();
            if canonical {
                table.pack_canonical_into(&mut out)?;
            } else {
                table.pack_into(&mut out);
            }
            let len = (out.len() - start) as u64;
            out[len_at..len_at + 8].copy_from_slice(&len.to_le_bytes());
        }
        write_atomic(path, &out)
    }

    /// Back-compat alias for [`Db::checkpoint`].
    pub fn save(&mut self, path: impl AsRef<Path>) -> Result<(), DbError> {
        self.checkpoint(path)
    }

    /// Loads a checkpoint written by [`Db::checkpoint`] into the already-
    /// registered (empty) tables and restores the revision. Every section must
    /// map to a registered table. Registered tables absent from an older
    /// checkpoint remain empty, making additive Arena schema changes (such as
    /// the deferred-transaction table) backward-compatible. Unknown checkpoint
    /// table ids remain a hard error so a checkpoint is never partially read.
    pub fn load(&mut self, path: impl AsRef<Path>) -> Result<(), DbError> {
        let data = std::fs::read(path.as_ref()).map_err(|e| DbError::Io(e.to_string()))?;
        let mut pos = 0usize;
        let revision = read_i64(&data, &mut pos)?;
        let count = read_u64(&data, &mut pos)? as usize;
        let mut seen_types = std::collections::HashSet::new();
        for _ in 0..count {
            let type_id = read_u16(&data, &mut pos)?;
            // A table split across two sections with one type id would load the
            // second over the first and leave the secondary indexes covering only
            // its rows, under a state root that still matches.
            if !seen_types.insert(type_id) {
                return Err(DbError::Corrupted(format!(
                    "checkpoint has two sections for type_id {type_id}"
                )));
            }
            let len = read_u64(&data, &mut pos)? as usize;
            let end = pos
                .checked_add(len)
                .filter(|end| *end <= data.len())
                .ok_or_else(|| DbError::Corrupted("section extends past checkpoint".into()))?;
            let table_pos = self
                .by_type_id
                .get(usize::from(type_id))
                .and_then(|entry| *entry)
                .map(|(_, position)| position)
                .ok_or_else(|| {
                    DbError::Corrupted(format!("checkpoint has unregistered type_id {type_id}"))
                })?;
            self.tables[table_pos].load_from(&data[pos..end])?;
            pos = end;
        }
        if pos != data.len() {
            return Err(DbError::Corrupted(
                "trailing bytes after the last section of the checkpoint".into(),
            ));
        }
        self.set_revision(revision)?;
        Ok(())
    }

    /// Appends the changes since the last flush/checkpoint to the write-ahead
    /// log at `path` as one framed record (length-prefixed, so a torn final
    /// frame from a crash is detectable), then fsyncs. Cost is O(rows changed),
    /// not O(total state) — the chainbase dirty-page profile, in software.
    pub fn flush_delta(&mut self, path: impl AsRef<Path>) -> Result<(), DbError> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&self.revision().to_le_bytes());
        frame.extend_from_slice(&(self.tables.len() as u64).to_le_bytes());
        for table in &self.tables {
            frame.extend_from_slice(&table.type_id_num().to_le_bytes());
            let len_at = frame.len();
            frame.extend_from_slice(&0u64.to_le_bytes());
            let start = frame.len();
            table.pack_delta(&mut frame);
            let len = (frame.len() - start) as u64;
            frame[len_at..len_at + 8].copy_from_slice(&len.to_le_bytes());
        }
        append_frame(path.as_ref(), &frame)?;
        for table in &mut self.tables {
            table.mark_flushed();
        }
        Ok(())
    }

    /// Replays every complete frame in the log at `path` onto the current state
    /// (typically right after [`Db::load`]), restoring the revision. A trailing
    /// partial frame — a crash during the last flush — is ignored.
    pub fn replay_log(&mut self, path: impl AsRef<Path>) -> Result<(), DbError> {
        let data = match std::fs::read(path.as_ref()) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(DbError::Io(e.to_string())),
        };
        let scan = scan_wal(&data)?;
        let mut last_revision: Option<i64> = None;
        for &(start, end) in &scan.records {
            let frame = &data[start..end];
            self.apply_frame(frame)?;
            let mut fp = 0usize;
            last_revision = Some(read_i64(frame, &mut fp)?);
        }
        if let Some(rev) = last_revision {
            for table in &mut self.tables {
                table.mark_flushed();
            }
            self.set_revision(rev)?;
        }
        Ok(())
    }

    /// Replays the write-ahead log at `path` on top of state already loaded
    /// at `after_revision` (a checkpoint). Frames at or below that revision are
    /// already in the state and are skipped, so a log that outlived a newer
    /// checkpoint is harmless. The frames that remain must follow on without a
    /// gap, one revision at a time: a missing frame means lost changes, and
    /// applying the later ones over it would build state no node agrees on.
    ///
    /// A torn final frame (a crash during the last flush) is ignored. The
    /// returned `valid_len` is where the last complete frame ends, so the caller
    /// can cut the file there before appending again; appending after the torn
    /// bytes would hide every later frame behind a bad length prefix.
    pub fn replay_log_after(
        &mut self,
        path: impl AsRef<Path>,
        after_revision: i64,
    ) -> Result<WalReplay, DbError> {
        let data = match std::fs::read(path.as_ref()) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(WalReplay::default());
            }
            Err(e) => return Err(DbError::Io(e.to_string())),
        };
        let scan = scan_wal(&data)?;
        let mut outcome = WalReplay::default();
        let mut last_revision = after_revision;
        let mut applied_any = false;
        for &(start, end) in &scan.records {
            let frame = &data[start..end];
            let mut fp = 0usize;
            let revision = read_i64(frame, &mut fp)?;
            if revision <= after_revision {
                outcome.frames_skipped += 1;
                continue;
            }
            if revision != last_revision + 1 {
                return Err(DbError::Corrupted(format!(
                    "write-ahead log jumps from revision {last_revision} to {revision}"
                )));
            }
            self.apply_frame(frame)?;
            last_revision = revision;
            applied_any = true;
            outcome.frames_applied += 1;
        }
        if applied_any {
            for table in &mut self.tables {
                table.mark_flushed();
            }
            self.set_revision(last_revision)?;
        }
        outcome.valid_len = scan.valid_len as u64;
        outcome.torn_tail = scan.torn_tail;
        Ok(outcome)
    }

    fn apply_frame(&mut self, frame: &[u8]) -> Result<(), DbError> {
        let mut pos = 0usize;
        let _revision = read_i64(frame, &mut pos)?;
        let count = read_u64(frame, &mut pos)? as usize;
        for _ in 0..count {
            let type_id = read_u16(frame, &mut pos)?;
            let len = read_u64(frame, &mut pos)? as usize;
            let end = pos
                .checked_add(len)
                .filter(|end| *end <= frame.len())
                .ok_or_else(|| DbError::Corrupted("delta extends past frame".into()))?;
            let table_pos = self
                .by_type_id
                .get(usize::from(type_id))
                .and_then(|entry| *entry)
                .map(|(_, position)| position)
                .ok_or_else(|| {
                    DbError::Corrupted(format!("delta for unregistered type_id {type_id}"))
                })?;
            self.tables[table_pos].apply_delta(&frame[pos..end])?;
            pos = end;
        }
        Ok(())
    }

    /// A deterministic SHA-256 over all committed state — every table's live
    /// rows (in id order) and blob arena, tables in `type_id` order. Equal state
    /// gives an equal root, so it is the fingerprint a block-level differential
    /// test compares after each block.
    ///
    /// This is canonical across reloads of this store. A cross-implementation
    /// root (vs C++ chainbase) additionally needs blob refs resolved to their
    /// bytes per object — a small extension once the object schemas are wired.
    pub fn state_root(&self) -> [u8; 32] {
        use sha2::{
            Digest,
            Sha256,
        };
        let mut ordered: Vec<usize> = (0..self.tables.len()).collect();
        ordered.sort_by_key(|&pos| self.tables[pos].type_id_num());
        let mut hasher = Sha256::new();
        for pos in ordered {
            hasher.update(self.tables[pos].type_id_num().to_le_bytes());
            self.tables[pos].hash_state(&mut hasher);
        }
        hasher.finalize().into()
    }

    /// The state hash of each table on its own, as `(type name, root)`, in the
    /// order [`Db::state_root`] combines them. When two nodes' roots differ this
    /// says which table to look in.
    pub fn table_roots(&self) -> Vec<(&'static str, [u8; 32])> {
        use sha2::{
            Digest,
            Sha256,
        };
        let mut ordered: Vec<usize> = (0..self.tables.len()).collect();
        ordered.sort_by_key(|&pos| self.tables[pos].type_id_num());
        ordered
            .into_iter()
            .map(|pos| {
                let mut hasher = Sha256::new();
                self.tables[pos].hash_state(&mut hasher);
                (self.tables[pos].type_name(), hasher.finalize().into())
            })
            .collect()
    }

    /// Rows per table as `(count, type name)`, sorted like chainbase
    /// `row_count_per_index`.
    pub fn row_count_per_table(&self) -> Vec<(usize, &'static str)> {
        let mut rows: Vec<(usize, &'static str)> = self
            .tables
            .iter()
            .map(|t| (t.len(), t.type_name()))
            .collect();
        rows.sort();
        rows
    }
}

#[cfg(test)]
mod damage_scan_tests {
    use super::*;

    // Contract row bytes land verbatim in the log, so a transaction can plant a
    // plausible length at every aligned offset of a torn tail. Each would be
    // hashed over its claimed length: quadratic work at start-up. The scan has a
    // budget and answers "cannot rule out damage" when it runs out.
    #[test]
    fn a_hostile_tail_exhausts_the_budget_instead_of_being_hashed_in_full() {
        let key = [3u8; WAL_KEY_LEN];
        let len: u64 = 1 << 20;
        // 4 MiB of 8-byte words, each claiming 1 MiB: a candidate at every 8th byte.
        let mut data = Vec::new();
        for _ in 0..(4 << 20) / 8 {
            data.extend_from_slice(&len.to_le_bytes());
        }
        assert_eq!(
            wal_valid_record_follows_within(&data, &key, 0, 4 << 20, None),
            Follows::BudgetExhausted
        );
        // With a budget for all of it the same data is searched and found empty.
        let mut small = Vec::new();
        for _ in 0..8 {
            small.extend_from_slice(&16u64.to_le_bytes());
        }
        assert_eq!(
            wal_valid_record_follows_within(&small, &key, 0, 1 << 30, None),
            Follows::No
        );
    }

    fn frame(revision: i64, tables: u64, filler: usize) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&revision.to_le_bytes());
        frame.extend_from_slice(&tables.to_le_bytes());
        frame.extend(std::iter::repeat_n(0x5Au8, filler));
        frame
    }

    fn log_with_frames(revisions: &[i64]) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wal");
        for &revision in revisions {
            append_frame(&path, &frame(revision, 19, 300)).unwrap();
        }
        (dir, path)
    }

    // The failure Paul measured on real data: an honest torn record of 256 KiB or
    // more was refused by the scan budget, because the row data in it is full of
    // small integers that look like lengths and each one was hashed over its claimed
    // length. A candidate must now first continue the log (next revision, same table
    // count), which almost no row data does.
    #[test]
    fn an_honest_torn_record_full_of_plausible_lengths_is_recovered_whatever_its_size() {
        let (_dir, path) = log_with_frames(&[2_000_001, 2_000_002, 2_000_003]);
        let good_len = std::fs::metadata(&path).unwrap().len();
        let mut data = std::fs::read(&path).unwrap();
        // A record that claims 512 KiB and has 90% of it: u64 words that are all
        // plausible lengths, like the integers in real row data.
        let claimed: u64 = 512 * 1024;
        data.extend_from_slice(&claimed.to_le_bytes());
        let mut word = 7u64;
        while data.len() < good_len as usize + 8 + (claimed as f64 * 0.9) as usize {
            word = 16 + (word.wrapping_mul(6364136223846793005).wrapping_add(1) >> 33) % 40_000;
            data.extend_from_slice(&word.to_le_bytes());
        }
        let scan = scan_wal(&data).expect("an honest torn tail must not be refused");
        assert!(scan.torn_tail);
        assert_eq!(
            scan.valid_len as u64, good_len,
            "cut back to the last good record"
        );
        assert_eq!(scan.records.len(), 3);
    }

    // The filter must not hide real damage: an intact later record continues the
    // sequence, so it is still found and the log refused.
    #[test]
    fn an_intact_record_after_a_damaged_one_is_still_found() {
        let (_dir, path) = log_with_frames(&[2_000_001, 2_000_002, 2_000_003, 2_000_004]);
        let mut data = std::fs::read(&path).unwrap();
        // Damage the second record's length so it cannot be read.
        let first_end = scan_wal(&data).unwrap().records[0].1 + WAL_DIGEST_LEN;
        data[first_end] ^= 0x40;
        let error = scan_wal(&data)
            .err()
            .expect("damage in the middle is refused");
        assert!(
            format!("{error:?}").contains("altered, not cut short"),
            "{error:?}"
        );
    }

    // An adversary who knows the filter can plant the sixteen bytes it looks for at
    // every candidate. That is still bounded by the budget and still refused, not
    // hashed in full.
    #[test]
    fn a_tail_that_imitates_the_start_of_a_record_still_hits_the_budget() {
        let key = [3u8; WAL_KEY_LEN];
        let expect = FramePrefix {
            last_revision: 2_000_000,
            table_count: 19,
        };
        let len: u64 = 1 << 20;
        let mut data = Vec::new();
        while data.len() < 4 << 20 {
            data.extend_from_slice(&len.to_le_bytes());
            data.extend_from_slice(&(expect.last_revision + 1).to_le_bytes());
            data.extend_from_slice(&expect.table_count.to_le_bytes());
            data.extend_from_slice(&[0u8; 8]);
        }
        assert_eq!(
            wal_valid_record_follows_within(&data, &key, 0, 4 << 20, Some(expect)),
            Follows::BudgetExhausted
        );
        // The same bytes without that imitation are not even looked at.
        let plain = vec![0xA5u8; 4 << 20];
        assert_eq!(
            wal_valid_record_follows_within(&plain, &key, 0, 4 << 20, Some(expect)),
            Follows::No
        );
    }

    #[test]
    fn an_ordinary_torn_tail_is_a_tear_within_the_default_budget() {
        let key = [3u8; WAL_KEY_LEN];
        let tail = vec![0xA5u8; 300];
        assert_eq!(wal_valid_record_follows(&tail, &key, 0, None), Follows::No);
    }
}
