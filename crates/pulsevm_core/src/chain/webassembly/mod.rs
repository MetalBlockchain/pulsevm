mod action;
pub use action::*;

mod authorization;
pub use authorization::*;

mod crypto;
pub use crypto::*;

mod database;
pub use database::*;

mod memory;
pub use memory::*;

mod privileged;
pub use privileged::*;

mod system;
pub use system::*;

mod transaction;
pub use transaction::*;
use wasmer::{MemoryView, RuntimeError, WasmPtr};

fn read_u64(view: &MemoryView, ptr: WasmPtr<u64>) -> Result<u64, RuntimeError> {
    let mut bytes = [0u8; 8];
    view.read(ptr.offset() as u64, &mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

fn write_u64(view: &MemoryView, ptr: WasmPtr<u64>, val: u64) -> Result<(), RuntimeError> {
    view.write(ptr.offset() as u64, &val.to_le_bytes())?;
    Ok(())
}