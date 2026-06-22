mod action;
pub use action::*;

mod authorization;
pub use authorization::*;

mod builtins;
pub use builtins::*;

mod console;
pub use console::*;

mod context_free;
pub use context_free::*;

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

mod producer;
pub use producer::*;

mod system;
use pulsevm_ffi::{Float128, I128, U128, U256};
pub use system::*;

mod transaction;
pub use transaction::*;
use wasmer::{FunctionEnvMut, MemoryView, RuntimeError, WasmPtr};

use crate::wasm_runtime::WasmContext;

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

fn read_u256(view: &MemoryView, ptr: WasmPtr<u8>) -> Result<U256, RuntimeError> {
    let mut bytes = [0u8; 32];
    view.read(ptr.offset() as u64, &mut bytes)?;
    Ok(U256 { value: bytes })
}

fn read_float128(view: &MemoryView, ptr: WasmPtr<u8>) -> Result<Float128, RuntimeError> {
    let mut bytes = [0u8; 16];
    view.read(ptr.offset() as u64, &mut bytes)?;

    let mut lo = [0u8; 8];
    let mut hi = [0u8; 8];
    lo.copy_from_slice(&bytes[0..8]); // v[0] — least-significant limb
    hi.copy_from_slice(&bytes[8..16]); // v[1] — most-significant limb

    Ok(Float128 {
        lo: u64::from_le_bytes(lo),
        hi: u64::from_le_bytes(hi),
    })
}

fn write_u64(view: &MemoryView, ptr: WasmPtr<u64>, val: u64) -> Result<(), RuntimeError> {
    view.write(ptr.offset() as u64, &val.to_le_bytes())?;
    Ok(())
}

fn write_u128(view: &MemoryView, ptr: WasmPtr<u128>, val: u128) -> Result<(), RuntimeError> {
    view.write(ptr.offset() as u64, &val.to_le_bytes())?;
    Ok(())
}

fn write_u256(view: &MemoryView, ptr: WasmPtr<u8>, val: U256) -> Result<(), RuntimeError> {
    view.write(ptr.offset() as u64, &val.value)?;
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

fn write_float128(view: &MemoryView, ptr: WasmPtr<u8>, val: Float128) -> Result<(), RuntimeError> {
    let mut bytes = [0u8; 16];
    bytes[0..8].copy_from_slice(&val.lo.to_le_bytes()); // v[0] — least-significant
    bytes[8..16].copy_from_slice(&val.hi.to_le_bytes()); // v[1] — most-significant
    view.write(ptr.offset() as u64, &bytes)?;
    Ok(())
}

pub fn context_aware_check(env: &FunctionEnvMut<WasmContext>) -> Result<(), RuntimeError> {
    if env.data().apply_context().is_context_free() {
        return Err(RuntimeError::new(
            "cannot call this function from a context-free action",
        ));
    }

    Ok(())
}
