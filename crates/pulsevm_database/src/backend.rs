//! Re-export of the arena-backed chain database implementation.
//!
//! The compatibility database facade in this crate delegates all state access
//! to `pulsevm_chaindb`; there is no secondary backend or native bridge.
pub use pulsevm_chaindb::*;
