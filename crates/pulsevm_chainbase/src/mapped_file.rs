//! The persistence layer, standing in for C++ `chainbase::pinnable_mapped_file`.
//!
//! The database file is memory mapped and carries chainbase's lifecycle: a
//! dirty flag is set the moment the file is opened read-write and only cleared
//! by a graceful close, so a crash leaves the file dirty and a later open
//! refuses it unless `allow_dirty` is passed.
//!
//! Unlike the C++ segment — where the live containers are laid out inside the
//! mapping via offset pointers — the live state here is in process memory and
//! is serialized into the mapping on [`MappedFile::write_payload`] (called by
//! `Database::flush` and by the clean close).

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use memmap2::{Mmap, MmapMut};

use crate::error::ChainbaseError;

const MAGIC: &[u8; 8] = b"PULSECDB";
const FORMAT_VERSION: u32 = 1;

// magic (8) + version (4) + dirty (1) + padding (3) + payload_len (8)
pub(crate) const HEADER_SIZE: usize = 24;
const DIRTY_OFFSET: usize = 12;
const PAYLOAD_LEN_OFFSET: usize = 16;

enum Map {
    ReadOnly(Mmap),
    ReadWrite(MmapMut),
}

impl Map {
    fn bytes(&self) -> &[u8] {
        match self {
            Map::ReadOnly(map) => map,
            Map::ReadWrite(map) => map,
        }
    }
}

pub(crate) struct MappedFile {
    file: File,
    map: Map,
    path: PathBuf,
    read_only: bool,
}

fn io_err(path: &Path, err: std::io::Error) -> ChainbaseError {
    ChainbaseError::Io(format!("{}: {}", path.display(), err))
}

impl MappedFile {
    /// Opens or creates the database file and returns it together with the
    /// payload persisted by the last clean close (or last flush when opening
    /// dirty with `allow_dirty`).
    pub(crate) fn open(
        path: &Path,
        size: u64,
        read_only: bool,
        allow_dirty: bool,
    ) -> Result<(Self, Option<Vec<u8>>), ChainbaseError> {
        let file = if read_only {
            File::open(path).map_err(|e| io_err(path, e))?
        } else {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(path)
                .map_err(|e| io_err(path, e))?
        };
        let file_len = file.metadata().map_err(|e| io_err(path, e))?.len();
        let fresh = file_len == 0;
        if fresh {
            if read_only {
                return Err(ChainbaseError::Io(format!(
                    "{}: cannot open an empty database read-only",
                    path.display()
                )));
            }
            file.set_len(size.max(HEADER_SIZE as u64))
                .map_err(|e| io_err(path, e))?;
        }

        // SAFETY: the mapping is private to this process for its lifetime; the
        // file is only resized through `grow_to`, which remaps afterwards.
        let map = if read_only {
            Map::ReadOnly(unsafe { Mmap::map(&file) }.map_err(|e| io_err(path, e))?)
        } else {
            Map::ReadWrite(unsafe { MmapMut::map_mut(&file) }.map_err(|e| io_err(path, e))?)
        };

        let mut mapped = MappedFile {
            file,
            map,
            path: path.to_path_buf(),
            read_only,
        };

        let payload = if fresh {
            mapped.init_header()?;
            None
        } else {
            mapped.validate_header(allow_dirty)?
        };

        if !read_only {
            // As in chainbase, the file is dirty from the moment it is opened
            // for writing until it is closed gracefully.
            mapped.set_dirty(true)?;
        }
        Ok((mapped, payload))
    }

    fn rw(&mut self) -> &mut MmapMut {
        match &mut self.map {
            Map::ReadWrite(map) => map,
            Map::ReadOnly(_) => unreachable!("write access to a read-only mapping"),
        }
    }

    fn init_header(&mut self) -> Result<(), ChainbaseError> {
        let map = self.rw();
        map[..8].copy_from_slice(MAGIC);
        map[8..12].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        map[DIRTY_OFFSET] = 0;
        map[DIRTY_OFFSET + 1..PAYLOAD_LEN_OFFSET].fill(0);
        map[PAYLOAD_LEN_OFFSET..HEADER_SIZE].copy_from_slice(&0u64.to_le_bytes());
        self.sync()
    }

    fn validate_header(&self, allow_dirty: bool) -> Result<Option<Vec<u8>>, ChainbaseError> {
        let bytes = self.map.bytes();
        if bytes.len() < HEADER_SIZE || &bytes[..8] != MAGIC {
            return Err(ChainbaseError::Corrupted(format!(
                "{}: not a pulsevm chainbase database",
                self.path.display()
            )));
        }
        let version = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        if version != FORMAT_VERSION {
            return Err(ChainbaseError::Corrupted(format!(
                "{}: format version {} does not match expected {}",
                self.path.display(),
                version,
                FORMAT_VERSION
            )));
        }
        if bytes[DIRTY_OFFSET] != 0 && !allow_dirty {
            return Err(ChainbaseError::Dirty {
                path: self.path.display().to_string(),
            });
        }
        let payload_len =
            u64::from_le_bytes(bytes[PAYLOAD_LEN_OFFSET..HEADER_SIZE].try_into().unwrap()) as usize;
        if payload_len > bytes.len() - HEADER_SIZE {
            return Err(ChainbaseError::Corrupted(format!(
                "{}: payload length {} exceeds file size",
                self.path.display(),
                payload_len
            )));
        }
        if payload_len == 0 {
            Ok(None)
        } else {
            Ok(Some(bytes[HEADER_SIZE..HEADER_SIZE + payload_len].to_vec()))
        }
    }

    /// Serializes the given payload into the mapping and syncs it to disk,
    /// growing the file if needed. The dirty flag is left untouched.
    pub(crate) fn write_payload(&mut self, payload: &[u8]) -> Result<(), ChainbaseError> {
        let needed = HEADER_SIZE + payload.len();
        if needed > self.map.bytes().len() {
            self.grow_to(needed as u64)?;
        }
        let map = self.rw();
        map[HEADER_SIZE..needed].copy_from_slice(payload);
        map[PAYLOAD_LEN_OFFSET..HEADER_SIZE]
            .copy_from_slice(&(payload.len() as u64).to_le_bytes());
        self.sync()
    }

    fn grow_to(&mut self, needed: u64) -> Result<(), ChainbaseError> {
        // C++ chainbase fails with bad_alloc when the segment is full and is
        // resized offline; growing in place is friendlier and safe here since
        // the mapping holds no live data structures.
        let new_size = needed.next_power_of_two();
        self.file
            .set_len(new_size)
            .map_err(|e| io_err(&self.path, e))?;
        // SAFETY: same as in `open`; the old mapping is replaced immediately.
        self.map = Map::ReadWrite(
            unsafe { MmapMut::map_mut(&self.file) }.map_err(|e| io_err(&self.path, e))?,
        );
        Ok(())
    }

    pub(crate) fn set_dirty(&mut self, dirty: bool) -> Result<(), ChainbaseError> {
        self.rw()[DIRTY_OFFSET] = dirty as u8;
        self.sync()
    }

    fn sync(&mut self) -> Result<(), ChainbaseError> {
        let path = self.path.clone();
        self.rw().flush().map_err(|e| io_err(&path, e))
    }

    pub(crate) fn is_read_only(&self) -> bool {
        self.read_only
    }
}
