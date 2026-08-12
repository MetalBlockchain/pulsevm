//! The arena-backed chain database now lives in the standalone `pulsevm_chaindb`
//! crate so it builds and is tested without the C++ toolchain. It is re-exported
//! here as `crate::shadow` so the existing `crate::shadow::*` paths in
//! `database.rs` keep resolving unchanged.
pub use pulsevm_chaindb::*;
