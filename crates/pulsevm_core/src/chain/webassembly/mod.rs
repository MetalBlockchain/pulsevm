mod action;
pub use action::*;

mod authorization;
pub use authorization::*;

mod builtins;
pub use builtins::*;

mod console;
pub use console::*;

mod crypto;
pub use crypto::*;

mod database;
pub use database::*;

mod memory;
pub use memory::*;

mod permission;
pub use permission::*;

mod privileged;
pub use privileged::*;

mod system;
use pulsevm_ffi::{I128, U128};
pub use system::*;

mod transaction;
pub use transaction::*;
use wasmer::{MemoryView, RuntimeError, WasmPtr};

fn read_u64(view: &MemoryView, ptr: WasmPtr<u64>) -> Result<u64, RuntimeError> {
    let mut bytes = [0u8; 8];
    view.read(ptr.offset() as u64, &mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_u128(view: &MemoryView, ptr: WasmPtr<u128>) -> Result<u128, RuntimeError> {
    let mut bytes = [0u8; 16];
    view.read(ptr.offset() as u64, &mut bytes)?;
    Ok(u128::from_le_bytes(bytes))
}

fn write_u64(view: &MemoryView, ptr: WasmPtr<u64>, val: u64) -> Result<(), RuntimeError> {
    view.write(ptr.offset() as u64, &val.to_le_bytes())?;
    Ok(())
}

fn write_u128(view: &MemoryView, ptr: WasmPtr<u128>, val: u128) -> Result<(), RuntimeError> {
    view.write(ptr.offset() as u64, &val.to_le_bytes())?;
    Ok(())
}

fn write_u128_ffi(view: &MemoryView, ptr: WasmPtr<u128>, val: U128) -> Result<(), RuntimeError> {
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&val.lo.to_le_bytes());
    out[8..16].copy_from_slice(&val.hi.to_le_bytes());
    view.write(ptr.offset() as u64, &out)?;
    Ok(())
}

fn write_i128_ffi(view: &MemoryView, ptr: WasmPtr<i128>, val: I128) -> Result<(), RuntimeError> {
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&val.lo.to_le_bytes());
    out[8..16].copy_from_slice(&val.hi.to_le_bytes());
    view.write(ptr.offset() as u64, &out)?;
    Ok(())
}
