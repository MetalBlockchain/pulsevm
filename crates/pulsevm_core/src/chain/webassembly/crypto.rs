use sha2::Digest;
use wasmer::{FunctionEnvMut, RuntimeError, WasmPtr};

use crate::chain::wasm_runtime::WasmContext;

pub fn sha224(
    mut env: FunctionEnvMut<WasmContext>,
    msg_ptr: WasmPtr<u8>,
    msg_size: u32,
    out_ptr: WasmPtr<u8>,
) -> Result<(), RuntimeError> {
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let slice = msg_ptr.slice(&view, msg_size)?;
    let mut src_bytes = vec![0u8; msg_size as usize];
    slice.read_slice(&mut src_bytes)?;

    let hasher = sha2::Sha224::digest(&src_bytes);
    let slice_out = out_ptr.slice(&view, hasher.len() as u32)?;
    slice_out.write_slice(hasher.as_ref())?;

    Ok(())
}

pub fn sha256(
    mut env: FunctionEnvMut<WasmContext>,
    msg_ptr: WasmPtr<u8>,
    msg_size: u32,
    out_ptr: WasmPtr<u8>,
) -> Result<(), RuntimeError> {
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let slice = msg_ptr.slice(&view, msg_size)?;
    let mut src_bytes = vec![0u8; msg_size as usize];
    slice.read_slice(&mut src_bytes)?;

    let hasher = sha2::Sha256::digest(&src_bytes);
    let slice_out = out_ptr.slice(&view, hasher.len() as u32)?;
    slice_out.write_slice(hasher.as_ref())?;

    Ok(())
}

pub fn sha512(
    mut env: FunctionEnvMut<WasmContext>,
    msg_ptr: WasmPtr<u8>,
    msg_size: u32,
    out_ptr: WasmPtr<u8>,
) -> Result<(), RuntimeError> {
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let slice = msg_ptr.slice(&view, msg_size)?;
    let mut src_bytes = vec![0u8; msg_size as usize];
    slice.read_slice(&mut src_bytes)?;

    let hasher = sha2::Sha512::digest(&src_bytes);
    let slice_out = out_ptr.slice(&view, hasher.len() as u32)?;
    slice_out.write_slice(hasher.as_ref())?;

    Ok(())
}

pub fn assert_sha224(
    mut env: FunctionEnvMut<WasmContext>,
    data_ptr: WasmPtr<u8>,
    data_size: u32,
    hash_val_ptr: WasmPtr<u8>,
) -> Result<(), RuntimeError> {
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data.memory().as_ref().ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    // Borrow the input bytes from guest memory
    let data_slice = data_ptr.slice(&view, data_size)?;
    let data_access = data_slice
        .access()
        .map_err(|e| RuntimeError::new(format!("failed to access data pointer: {e}")))?;
    let data_bytes: &[u8] = data_access.as_ref();
    let digest = sha2::Sha224::digest(data_bytes); // 28 bytes

    // Borrow the expected hash bytes from guest memory (must be 28 bytes)
    let hash_slice = hash_val_ptr.slice(&view, digest.len() as u32)?;
    let hash_access = hash_slice
        .access()
        .map_err(|e| RuntimeError::new(format!("failed to access hash value pointer: {e}")))?;

    let expected_hash: &[u8] = hash_access.as_ref();

    if expected_hash.len() != digest.len() {
        return Err(RuntimeError::new("assertion failed: hash length mismatch"));
    }

    if expected_hash != digest.as_slice() {
        return Err(RuntimeError::new("assertion failed: sha224 hash mismatch"));
    }

    Ok(())
}

pub fn assert_sha256(
    mut env: FunctionEnvMut<WasmContext>,
    data_ptr: WasmPtr<u8>,
    data_size: u32,
    hash_val_ptr: WasmPtr<u8>,
) -> Result<(), RuntimeError> {
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data.memory().as_ref().ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    // Borrow the input bytes from guest memory
    let data_slice = data_ptr.slice(&view, data_size)?;
    let data_access = data_slice
        .access()
        .map_err(|e| RuntimeError::new(format!("failed to access data pointer: {e}")))?;
    let data_bytes: &[u8] = data_access.as_ref();
    let digest = sha2::Sha256::digest(data_bytes); // 32 bytes

    // Borrow the expected hash bytes from guest memory (must be 32 bytes)
    let hash_slice = hash_val_ptr.slice(&view, digest.len() as u32)?;
    let hash_access = hash_slice
        .access()
        .map_err(|e| RuntimeError::new(format!("failed to access hash value pointer: {e}")))?;

    let expected_hash: &[u8] = hash_access.as_ref();

    if expected_hash.len() != digest.len() {
        return Err(RuntimeError::new("assertion failed: hash length mismatch"));
    }

    if expected_hash != digest.as_slice() {
        return Err(RuntimeError::new("assertion failed: sha256 hash mismatch"));
    }

    Ok(())
}

pub fn assert_sha512(
    mut env: FunctionEnvMut<WasmContext>,
    data_ptr: WasmPtr<u8>,
    data_size: u32,
    hash_val_ptr: WasmPtr<u8>,
) -> Result<(), RuntimeError> {
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data.memory().as_ref().ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    // Borrow the input bytes from guest memory
    let data_slice = data_ptr.slice(&view, data_size)?;
    let data_access = data_slice
        .access()
        .map_err(|e| RuntimeError::new(format!("failed to access data pointer: {e}")))?;
    let data_bytes: &[u8] = data_access.as_ref();
    let digest = sha2::Sha512::digest(data_bytes); // 64 bytes

    // Borrow the expected hash bytes from guest memory (must be 64 bytes)
    let hash_slice = hash_val_ptr.slice(&view, digest.len() as u32)?;
    let hash_access = hash_slice
        .access()
        .map_err(|e| RuntimeError::new(format!("failed to access hash value pointer: {e}")))?;

    let expected_hash: &[u8] = hash_access.as_ref();

    if expected_hash.len() != digest.len() {
        return Err(RuntimeError::new("assertion failed: hash length mismatch"));
    }

    if expected_hash != digest.as_slice() {
        return Err(RuntimeError::new("assertion failed: sha512 hash mismatch"));
    }

    Ok(())
}