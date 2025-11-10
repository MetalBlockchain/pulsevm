use std::{
    collections::BTreeMap,
    fmt,
    fs::{File, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};

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
            ShLogError::MissedBlock(name) => write!(f, "missed a block in {name}"),
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

/// On-disk header layout used by EOS SHiP logs.
/// Matches:
///   struct state_history_log_header {
///      uint64_t magic;
///      block_id_type block_id; // 32 bytes
///      uint64_t payload_size;
///   };
#[derive(Clone, Copy, Debug)]
#[repr(C)]
struct StateHistoryLogHeader {
    magic: u64,
    block_id: Id,
    payload_size: u64,
}

impl StateHistoryLogHeader {
    const SIZE: usize = 8 + 32 + 8;

    fn write<W: Write>(&self, mut w: W) -> io::Result<()> {
        w.write_all(&self.magic.to_le_bytes())?;
        w.write_all(&self.block_id.0)?;
        w.write_all(&self.payload_size.to_le_bytes())?;
        Ok(())
    }

    fn read_at(file: &mut File, pos: u64) -> io::Result<Self> {
        file.seek(SeekFrom::Start(pos))?;
        let mut buf = [0u8; Self::SIZE];
        file.read_exact(&mut buf)?;
        let magic = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let mut id_bytes = [0u8; 32];
        id_bytes.copy_from_slice(&buf[8..40]);
        let block_id = Id(id_bytes);
        let payload_size = u64::from_le_bytes(buf[40..48].try_into().unwrap());
        Ok(Self {
            magic,
            block_id,
            payload_size,
        })
    }
}

/// Extract EOS block number from a block id (first 4 bytes big-endian)
#[inline]
fn num_from_block_id(id: &Id) -> u32 {
    // EOS stores block num in first 4 bytes (big-endian) of the id
    u32::from_be_bytes(id.0[0..4].try_into().unwrap())
}

/* -------------------- log struct -------------------- */

#[derive(Debug)]
pub struct StateHistoryLog {
    name: String,
    log_path: PathBuf,
    idx_path: PathBuf,
    log: Mutex<BufWriter<File>>,
    idx: Mutex<BufWriter<File>>,
    map: Mutex<BTreeMap<u32, u64>>, // block_num -> file offset (header start)
    first_block: u32,
    last_block: u32,
    magic: u64, // expected magic to write/validate
}

impl StateHistoryLog {
    /// Open with explicit magic (use EOS' `ship_magic(ship_current_version)`).
    pub fn open_with_magic<P: AsRef<Path>>(
        dir: P,
        name: &str,
        magic: u64,
    ) -> Result<Self, ShLogError> {
        let log_path = dir.as_ref().join(format!("{name}.log"));
        let idx_path = dir.as_ref().join(format!("{name}.index"));

        // open/create files
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

        // load index
        let mut map = BTreeMap::new();
        let mut r = BufReader::new(&idx_file);
        loop {
            let mut buf = [0u8; 12]; // u32 + u64
            match r.read_exact(&mut buf) {
                Ok(()) => {
                    let block = u32::from_le_bytes(buf[0..4].try_into().unwrap());
                    let pos = u64::from_le_bytes(buf[4..12].try_into().unwrap());
                    map.insert(block, pos);
                }
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(ShLogError::Io(e)),
            }
        }

        // If index empty: scan log to build it
        let (first_block, last_block) = if map.is_empty() {
            let (fb, lb, scanned_map) = scan_log_build_index_with_header(&mut log_file, magic)?;
            map = scanned_map;
            (fb, lb)
        } else {
            // validate the tail header/payload; truncate torn writes
            let (fb, lb) = (
                *map.keys().next().unwrap_or(&0),
                *map.keys().last().unwrap(),
            );
            if let Some(&tail_off) = map.get(&lb) {
                let ok_end = match validate_entry_at_with_header(&mut log_file, tail_off, magic) {
                    Ok(end) => end,
                    Err(_) => tail_off, // drop the bad tail
                };
                let len = log_file.metadata()?.len();
                if ok_end < len {
                    log_file.set_len(ok_end)?;
                }
            }
            (fb, lb)
        };

        // move cursors to end
        log_file.seek(SeekFrom::End(0))?;
        idx_file.seek(SeekFrom::End(0))?;

        Ok(Self {
            name: name.to_string(),
            log_path,
            idx_path,
            log: Mutex::new(BufWriter::new(log_file)),
            idx: Mutex::new(BufWriter::new(idx_file)),
            map: Mutex::new(map),
            first_block,
            last_block,
            magic,
        })
    }

    /// Convenience if you control the magic constant in your crate.
    #[inline]
    pub fn open<P: AsRef<Path>>(dir: P, name: &str) -> Result<Self, ShLogError> {
        // TODO: replace with your actual EOS ship_magic(current_version)
        const DEFAULT_MAGIC: u64 = 0; // <--- set to your real magic
        Self::open_with_magic(dir, name, DEFAULT_MAGIC)
    }

    /// Append one entry with EOS SHiP header.
    ///
    /// `block_id` is the 32-byte block id; `payload` are the packed SHiP bytes.
    pub fn append(&self, block_id: Id, payload: &[u8]) -> Result<(), ShLogError> {
        let block_num = num_from_block_id(&block_id);

        if self.last_block != 0 && block_num != self.last_block + 1 {
            return Err(ShLogError::MissedBlock(format!(
                "{}_history.log",
                self.name
            )));
        }

        let mut log_guard = self.log.lock().unwrap();
        let pos = log_guard.get_ref().metadata()?.len();

        let header = StateHistoryLogHeader {
            magic: self.magic,
            block_id, // <— Id
            payload_size: payload.len() as u64,
        };
        header.write(&mut *log_guard)?;
        log_guard.write_all(payload)?;
        log_guard.flush()?;

        let mut idx_guard = self.idx.lock().unwrap();
        idx_guard.write_all(&block_num.to_le_bytes())?;
        idx_guard.write_all(&(pos as u64).to_le_bytes())?;
        idx_guard.flush()?;

        let mut m = self.map.lock().unwrap();
        m.insert(block_num, pos);
        drop(m);

        if self.first_block == 0 {
            unsafe {
                (*(self as *const _ as *mut Self)).first_block = block_num;
            }
        }
        unsafe {
            (*(self as *const _ as *mut Self)).last_block = block_num;
        }

        Ok(())
    }

    /// Read payload for a given block number.
    pub fn read_block(&self, block_num: u32) -> Result<Vec<u8>, ShLogError> {
        let pos = {
            let m = self.map.lock().unwrap();
            *m.get(&block_num).ok_or(ShLogError::NotFound(block_num))?
        };
        let mut f = OpenOptions::new().read(true).open(&self.log_path)?;
        let header = StateHistoryLogHeader::read_at(&mut f, pos)?;
        if header.magic != self.magic {
            return Err(ShLogError::BadMagic {
                at: pos,
                found: header.magic,
                expect: self.magic,
            });
        }
        if num_from_block_id(&header.block_id) != block_num {
            return Err(ShLogError::Corrupt(pos));
        }
        let mut buf = vec![0u8; header.payload_size as usize];
        f.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Stream a [start, end] range (inclusive), callback gets (block_num, payload).
    pub fn read_range<F>(&self, start: u32, end: u32, mut cb: F) -> Result<(), ShLogError>
    where
        F: FnMut(u32, &[u8]) -> Result<(), ShLogError>,
    {
        let map = self.map.lock().unwrap();
        let mut f = OpenOptions::new().read(true).open(&self.log_path)?;
        for (&block, &pos) in map.range(start..=end) {
            let header = StateHistoryLogHeader::read_at(&mut f, pos)?;
            if header.magic != self.magic {
                return Err(ShLogError::BadMagic {
                    at: pos,
                    found: header.magic,
                    expect: self.magic,
                });
            }
            if num_from_block_id(&header.block_id) != block {
                return Err(ShLogError::Corrupt(pos));
            }
            let mut buf = vec![0u8; header.payload_size as usize];
            f.read_exact(&mut buf)?;
            cb(block, &buf)?;
        }
        Ok(())
    }

    /* ----- pruning stays the same conceptually, but copies header+payload ----- */

    pub fn prune_keep_last(&self, n: u32) -> Result<(), ShLogError> {
        if self.last_block == 0 || n == 0 {
            return Ok(());
        }
        let start = self.last_block.saturating_sub(n).saturating_add(1);
        self.prune_from(start)
    }

    pub fn prune_from(&self, start_block: u32) -> Result<(), ShLogError> {
        let old_map = self.map.lock().unwrap().clone();
        let keep: Vec<(u32, u64)> = old_map
            .range(start_block..=u32::MAX)
            .map(|(k, v)| (*k, *v))
            .collect();
        if keep.is_empty() {
            return Ok(());
        }

        let tmp_log = self.log_path.with_extension("log.tmp");
        let tmp_idx = self.idx_path.with_extension("index.tmp");

        let mut out_log = BufWriter::new(
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp_log)?,
        );
        let mut out_idx = BufWriter::new(
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp_idx)?,
        );
        let mut in_log = BufReader::new(OpenOptions::new().read(true).open(&self.log_path)?);

        for (block, old_pos) in &keep {
            in_log.get_mut().seek(SeekFrom::Start(*old_pos))?;
            let header = StateHistoryLogHeader::read_at(in_log.get_mut(), *old_pos)?;
            let mut buf = vec![0u8; header.payload_size as usize];
            in_log.read_exact(&mut buf)?;

            let new_pos = out_log.get_ref().metadata()?.len();
            header.write(&mut out_log)?;
            out_log.write_all(&buf)?;

            out_idx.write_all(&block.to_le_bytes())?;
            out_idx.write_all(&(new_pos as u64).to_le_bytes())?;
        }
        out_log.flush()?;
        out_idx.flush()?;

        std::fs::rename(tmp_log, &self.log_path)?;
        std::fs::rename(tmp_idx, &self.idx_path)?;

        // rebuild in-memory map
        let mut map = self.map.lock().unwrap();
        map.clear();
        for (block, new_pos) in keep {
            map.insert(block, new_pos);
        }
        drop(map);

        // reset append handles
        let mut log_lock = self.log.lock().unwrap();
        let mut idx_lock = self.idx.lock().unwrap();
        *log_lock = BufWriter::new(
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(&self.log_path)?,
        );
        *idx_lock = BufWriter::new(
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(&self.idx_path)?,
        );
        log_lock.get_ref().seek(SeekFrom::End(0))?;
        idx_lock.get_ref().seek(SeekFrom::End(0))?;

        unsafe {
            (*(self as *const _ as *mut Self)).first_block = start_block;
        }
        Ok(())
    }

    pub fn range(&self) -> Option<(u32, u32)> {
        if self.last_block == 0 {
            None
        } else {
            Some((self.first_block, self.last_block))
        }
    }

    pub fn get_block_id(&self, block_num: u32) -> Result<Id, ShLogError> {
        // Look up the on-disk offset from the in-memory map
        let pos = {
            let m = self.map.lock().unwrap();
            *m.get(&block_num).ok_or(ShLogError::NotFound(block_num))?
        };

        // Read and validate the header at that position
        let mut f = OpenOptions::new().read(true).open(&self.log_path)?;
        let header = StateHistoryLogHeader::read_at(&mut f, pos)?;

        if header.magic != self.magic {
            return Err(ShLogError::BadMagic {
                at: pos,
                found: header.magic,
                expect: self.magic,
            });
        }
        if num_from_block_id(&header.block_id) != block_num {
            return Err(ShLogError::Corrupt(pos));
        }

        // Guard against torn writes (header present but payload incomplete)
        let len_total = f.metadata()?.len();
        let end = pos + (StateHistoryLogHeader::SIZE as u64) + header.payload_size;
        if end > len_total {
            return Err(ShLogError::Corrupt(pos));
        }

        Ok(header.block_id)
    }
}

/* -------------------- validation & scan (header-aware) -------------------- */

/// Validate one header+payload at `pos`. Return end offset if valid.
fn validate_entry_at_with_header(
    file: &mut File,
    pos: u64,
    expect_magic: u64,
) -> Result<u64, ShLogError> {
    file.seek(SeekFrom::Start(pos))?;
    let len_total = file.metadata()?.len();
    if pos + (StateHistoryLogHeader::SIZE as u64) > len_total {
        return Err(ShLogError::Corrupt(pos));
    }
    let header = StateHistoryLogHeader::read_at(file, pos)?;
    if header.magic != expect_magic {
        return Err(ShLogError::BadMagic {
            at: pos,
            found: header.magic,
            expect: expect_magic,
        });
    }
    let end = pos + (StateHistoryLogHeader::SIZE as u64) + header.payload_size;
    if end > len_total {
        return Err(ShLogError::Corrupt(pos));
    }
    Ok(end)
}

/// Full scan: build map from on-disk log with headers.
fn scan_log_build_index_with_header(
    file: &mut File,
    expect_magic: u64,
) -> Result<(u32, u32, BTreeMap<u32, u64>), ShLogError> {
    let mut pos = 0u64;
    let len_total = file.metadata()?.len();
    let mut map = BTreeMap::new();
    let mut first = 0u32;
    let mut last = 0u32;

    while pos < len_total {
        file.seek(SeekFrom::Start(pos))?;
        // If we cannot read a full header, truncate and stop
        if pos + (StateHistoryLogHeader::SIZE as u64) > len_total {
            file.set_len(pos)?;
            break;
        }
        let header = match StateHistoryLogHeader::read_at(file, pos) {
            Ok(h) => h,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                file.set_len(pos)?;
                break;
            }
            Err(e) => return Err(ShLogError::Io(e)),
        };

        if header.magic != expect_magic {
            return Err(ShLogError::BadMagic {
                at: pos,
                found: header.magic,
                expect: expect_magic,
            });
        }

        let block = num_from_block_id(&header.block_id);
        let end = pos + (StateHistoryLogHeader::SIZE as u64) + header.payload_size;

        if end > len_total {
            // torn write; truncate at pos and stop
            file.set_len(pos)?;
            break;
        }

        if first == 0 {
            first = block;
        }
        last = block;
        map.insert(block, pos);
        pos = end;
    }
    Ok((first, last, map))
}
