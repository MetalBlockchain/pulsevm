use secp256k1::hashes::{Hash, sha1};
use sha2::Digest;
use wasmtime::Caller;

use crate::chain::wasm_runtime::WasmContext;

pub fn sha224() -> impl Fn(Caller<'_, WasmContext>, u32, u32, u32) -> Result<u32, wasmtime::Error> {
    |mut caller, msg_ptr, msg_size, out_ptr| {
        // Now caller can be mutably borrowed safely
        let memory = caller
            .get_export("memory")
            .and_then(|ext| ext.into_memory())
            .ok_or_else(|| anyhow::anyhow!("memory export not found"))?;

        let mut src_bytes = vec![0u8; msg_size as usize];
        memory.read(&caller, msg_ptr as usize, &mut src_bytes)?;

        let hasher = sha2::Sha224::digest(&src_bytes);
        memory.write(&mut caller, out_ptr as usize, hasher.as_ref())?;

        Ok(28 as u32)
    }
}

pub fn sha256() -> impl Fn(Caller<'_, WasmContext>, u32, u32, u32) -> Result<u32, wasmtime::Error> {
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
