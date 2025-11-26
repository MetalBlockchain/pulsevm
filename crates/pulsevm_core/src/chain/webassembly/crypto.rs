use std::{
    cell::RefCell,
    rc::Rc,
    sync::{Arc, RwLock},
};

use sha2::Digest;
use wasmtime::{Caller, Func, Store, WasmTy};

use crate::{apply_context::ApplyContext, chain::wasm_runtime::WasmContext};

pub fn sha224() -> impl Fn(Caller<WasmContext>, i32, i32, i32) -> Result<u32, anyhow::Error> {
    move |mut caller: Caller<WasmContext>,
          msg_ptr: i32,
          msg_size: i32,
          out_ptr: i32|
          -> Result<u32, anyhow::Error> {
        let memory = caller
            .get_export("memory")
            .and_then(|e| e.into_memory())
            .ok_or_else(|| anyhow::anyhow!("memory export not found"))?;

        let mut src_bytes = vec![0; msg_size as usize];
        memory.read(&caller, msg_ptr as usize, &mut src_bytes)?;

        let hasher = sha2::Sha224::digest(&src_bytes);
        memory.write(&mut caller, out_ptr as usize, &hasher)?;

        Ok(28u32)
    }
}

pub fn sha256() -> impl Fn(Caller<WasmContext>, u32, u32, u32) -> Result<u32, wasmtime::Error> {
    |mut caller, msg_ptr, msg_size, out_ptr| {
        // Now caller can be mutably borrowed safely
        let memory = caller
            .get_export("memory")
            .and_then(|ext| ext.into_memory())
            .ok_or_else(|| anyhow::anyhow!("memory export not found"))?;

        let mut src_bytes = vec![0u8; msg_size as usize];
        memory.read(&caller, msg_ptr as usize, &mut src_bytes)?;

        let hasher = sha2::Sha256::digest(&src_bytes);
        memory.write(&mut caller, out_ptr as usize, hasher.as_ref())?;

        Ok(32 as u32)
    }
}

pub fn sha512() -> impl Fn(Caller<'_, WasmContext>, u32, u32, u32) -> Result<u32, wasmtime::Error> {
    |mut caller, msg_ptr, msg_size, out_ptr| {
        // Now caller can be mutably borrowed safely
        let memory = caller
            .get_export("memory")
            .and_then(|ext| ext.into_memory())
            .ok_or_else(|| anyhow::anyhow!("memory export not found"))?;

        let mut src_bytes = vec![0u8; msg_size as usize];
        memory.read(&caller, msg_ptr as usize, &mut src_bytes)?;

        let hasher = sha2::Sha512::digest(&src_bytes);
        memory.write(&mut caller, out_ptr as usize, hasher.as_ref())?;

        Ok(64 as u32)
    }
}
