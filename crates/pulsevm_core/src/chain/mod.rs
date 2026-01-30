pub mod abi;
pub mod account;
pub mod apply_context;
pub mod asset;
pub mod authority_checker;
pub mod authorization_manager;
pub mod block;
pub mod config;
pub mod controller;
pub mod crypto;
pub mod id;
pub mod mempool;
pub mod pulse_contract;
pub mod resource;
pub mod resource_limits;
pub mod state_history;
pub mod transaction;
pub mod transaction_context;
pub mod utils;
pub mod wasm_runtime;
mod webassembly;

// Re-export types for easier access
pub mod name {
    pub use pulsevm_name::Name;
}
pub mod authority {
    pub use pulsevm_ffi::{Authority, KeyWeight, PermissionLevel, PermissionLevelWeight, WaitWeight};
}

pub use pulsevm_error::ChainError;
use pulsevm_name::Name;
use pulsevm_name_macro::name;

pub const PULSE_NAME: Name = Name::new(name!("pulse"));
pub const OWNER_NAME: Name = Name::new(name!("owner"));
pub const ACTIVE_NAME: Name = Name::new(name!("active"));
pub const ANY_NAME: Name = Name::new(name!("pulse.any"));
pub const CODE_NAME: Name = Name::new(name!("pulse.code"));