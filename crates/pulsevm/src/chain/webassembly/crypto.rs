use secp256k1::hashes::{sha1, sha256, sha512, Hash};
use wasmtime::Caller;

use crate::chain::wasm_runtime::WasmContext;

pub fn sha1()
-> impl Fn(Caller<'_, WasmContext>, u32, u32, u32) -> Result<u32, wasmtime::Error> {
    |mut caller, msg_ptr, msg_size, out_ptr| {
        // Now caller can be mutably borrowed safely
        let memory = caller
            .get_export("memory")
            .and_then(|ext| ext.into_memory())
            .ok_or_else(|| anyhow::anyhow!("memory export not found"))?;

        let mut src_bytes = vec![0u8; msg_size as usize];
        memory.read(&caller, msg_ptr as usize, &mut src_bytes)?;

        let hasher = sha1::Hash::hash(&src_bytes);
        memory.write(&mut caller, out_ptr as usize, &hasher.to_byte_array())?;

        Ok(sha1::Hash::LEN as u32)
    }
}

pub fn sha256()
-> impl Fn(Caller<'_, WasmContext>, u32, u32, u32) -> Result<u32, wasmtime::Error> {
    |mut caller, msg_ptr, msg_size, out_ptr| {
        // Now caller can be mutably borrowed safely
        let memory = caller
            .get_export("memory")
            .and_then(|ext| ext.into_memory())
            .ok_or_else(|| anyhow::anyhow!("memory export not found"))?;

        let mut src_bytes = vec![0u8; msg_size as usize];
        memory.read(&caller, msg_ptr as usize, &mut src_bytes)?;

        let hasher = sha256::Hash::hash(&src_bytes);
        memory.write(&mut caller, out_ptr as usize, &hasher.to_byte_array())?;

        Ok(sha256::Hash::LEN as u32)
    }
}

pub fn sha512()
-> impl Fn(Caller<'_, WasmContext>, u32, u32, u32) -> Result<u32, wasmtime::Error> {
    |mut caller, msg_ptr, msg_size, out_ptr| {
        // Now caller can be mutably borrowed safely
        let memory = caller
            .get_export("memory")
            .and_then(|ext| ext.into_memory())
            .ok_or_else(|| anyhow::anyhow!("memory export not found"))?;

        let mut src_bytes = vec![0u8; msg_size as usize];
        memory.read(&caller, msg_ptr as usize, &mut src_bytes)?;

        let hasher = sha512::Hash::hash(&src_bytes);
        memory.write(&mut caller, out_ptr as usize, &hasher.to_byte_array())?;

        Ok(sha512::Hash::LEN as u32)
    }
}