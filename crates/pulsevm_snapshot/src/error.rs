use core::fmt;
use std::error::Error;

use pulsevm_serialization::ReadError;

/// Error raised while reading a portable snapshot.
#[derive(Debug, Clone)]
pub enum SnapshotError {
    /// The file does not start with the Leap snapshot magic number.
    BadMagic(u32),
    /// The container version is not one this reader understands.
    UnsupportedContainerVersion(u32),
    /// The `chain_snapshot_header` row carries an unsupported chainstate schema version.
    UnsupportedChainVersion(u32),
    /// The file ended (or a section boundary was crossed) mid-structure.
    Truncated(&'static str),
    /// A section name was not valid UTF-8.
    BadSectionName,
    /// The requested section does not exist in this snapshot.
    SectionNotFound(String),
    /// A row failed to decode.
    Decode {
        section: String,
        row: u64,
        source: ReadError,
    },
    /// A section decoded fewer/more rows than its header declared.
    RowCountMismatch {
        section: String,
        expected: u64,
        actual: u64,
    },
    /// Rows decoded cleanly but did not consume the section exactly — the row
    /// schema disagrees with the writer.
    TrailingBytes { section: String, remaining: usize },
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnapshotError::BadMagic(m) => {
                write!(f, "not a Leap snapshot: bad magic number 0x{m:08x}")
            }
            SnapshotError::UnsupportedContainerVersion(v) => {
                write!(f, "unsupported snapshot container version {v}")
            }
            SnapshotError::UnsupportedChainVersion(v) => {
                write!(f, "unsupported chain snapshot version {v}")
            }
            SnapshotError::Truncated(what) => write!(f, "snapshot truncated while reading {what}"),
            SnapshotError::BadSectionName => write!(f, "section name is not valid UTF-8"),
            SnapshotError::SectionNotFound(name) => write!(f, "section not found: {name}"),
            SnapshotError::Decode {
                section,
                row,
                source,
            } => {
                write!(
                    f,
                    "failed to decode row {row} of section {section}: {source}"
                )
            }
            SnapshotError::RowCountMismatch {
                section,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "section {section} declared {expected} rows but decoded {actual}"
                )
            }
            SnapshotError::TrailingBytes { section, remaining } => {
                write!(
                    f,
                    "section {section} fully decoded with {remaining} bytes left over"
                )
            }
        }
    }
}

impl Error for SnapshotError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            SnapshotError::Decode { source, .. } => Some(source),
            _ => None,
        }
    }
}
