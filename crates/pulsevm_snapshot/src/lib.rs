//! Reader for Antelope (Leap/Spring) portable chainstate snapshots.
//!
//! These are the `.bin` files produced by nodeos `create_snapshot` — the file a
//! chain operator hands to `nodeos --snapshot` to boot a node with the full
//! chainstate at a given head block. Reading one natively is the first step of
//! PulseVM's "start from snapshot" migration path: every account, permission,
//! contract, table row and resource line of an existing Antelope chain becomes
//! available for import without replaying the source chain.
//!
//! # File format
//!
//! The container (Leap `ostream_snapshot_writer`) is section-based:
//!
//! ```text
//! u32 magic (0x30510550)  u32 container version (1)
//! repeat {
//!   u64 section_size   // bytes from just after this field to the section end
//!   u64 row_count
//!   c-string section name
//!   rows... (fc::raw / Antelope binary encoding)
//! }
//! u64 end marker (u64::MAX)
//! ```
//!
//! Row payloads use the same Antelope binary encoding `pulsevm_serialization`
//! already implements, so row types here simply derive [`Read`]. The row
//! schemas correspond to `chain_snapshot_header` version 6 (Leap 5.0.x); see
//! [`rows`] for the per-section types and [`SUPPORTED_CHAIN_SNAPSHOT_VERSIONS`]
//! for the accepted range.
//!
//! The one section that is not a plain row list is `contract_tables`, where
//! each `table_id_object` row is followed by six (count, rows...) groups — one
//! per index family. [`ContractTablesReader`] decodes that interleaving.
//!
//! # Example
//!
//! ```no_run
//! use pulsevm_snapshot::SnapshotReader;
//!
//! let bytes = std::fs::read("snapshot.bin").unwrap();
//! let snapshot = SnapshotReader::new(&bytes).unwrap();
//! for account in snapshot.accounts().unwrap() {
//!     let account = account.unwrap();
//!     println!("{}", account.name);
//! }
//! ```

mod contract_tables;
mod error;
mod reader;
mod rows;
mod types;

pub use contract_tables::{
    ContractTablesReader,
    TableSnapshot,
};
pub use error::SnapshotError;
pub use reader::{
    CONTAINER_VERSION,
    RowIter,
    SNAPSHOT_MAGIC,
    SUPPORTED_CHAIN_SNAPSHOT_VERSIONS,
    SectionInfo,
    SectionReader,
    SnapshotReader,
};
pub use rows::*;
pub use types::{
    BlockSigningAuthority,
    SnapshotPublicKey,
    SnapshotSignature,
    U256Key,
    WebAuthnPublicKey,
    WebAuthnSignature,
};
