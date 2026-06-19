use pulsevm_serialization::{Read, Write};
use sha1::Digest as Sha1Digest;
use wasmer::{FunctionEnvMut, RuntimeError, WasmPtr};

use crate::{chain::wasm_runtime::WasmContext, crypto::{PublicKey, Signature}, utils::Digest};

pub fn assert_recover_key(
    mut env: FunctionEnvMut<WasmContext>,
    digest_ptr: WasmPtr<u8>,
    sig_ptr: WasmPtr<u8>,
    sig_len: u32,
    pub_ptr: WasmPtr<u8>,
    pub_len: u32,
) -> Result<(), RuntimeError> {
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let sig_slice = sig_ptr.slice(&view, sig_len)?;
    let mut sig_bytes = vec![0u8; sig_len as usize];
    sig_slice.read_slice(&mut sig_bytes)?;
    let signature = Signature::read(sig_bytes.as_slice(), &mut 0).map_err(|e| {
        RuntimeError::new(format!("failed to read signature from wasm memory: {}", e))
    })?;
    let digest_slice = digest_ptr.slice(&view, 32)?;
    let mut digest_bytes = vec![0u8; 32];
    digest_slice.read_slice(&mut digest_bytes)?;
    let digest: Digest = Digest::from_data(&digest_bytes);
    let pub_slice = pub_ptr.slice(&view, pub_len)?;
    let mut pubkey_bytes = vec![0u8; pub_len as usize];
    pub_slice.read_slice(&mut pubkey_bytes)?;
    let pubkey = PublicKey::read(pubkey_bytes.as_slice(), &mut 0).map_err(|e| {
        RuntimeError::new(format!("failed to read public key from wasm memory: {}", e))
    })?;
    let recovered_pubkey = signature.recover_public_key(&digest)?;

    if recovered_pubkey != pubkey {
        return Err(RuntimeError::new(
            "assertion failed: recovered public key does not match expected public key",
        ));
    }

    Ok(())
}

pub fn recover_key(
    mut env: FunctionEnvMut<WasmContext>,
    digest_ptr: WasmPtr<u8>,
    sig_ptr: WasmPtr<u8>,
    sig_len: u32,
    pub_ptr: WasmPtr<u8>,
    pub_len: u32,
) -> Result<i32, RuntimeError> {
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let sig_slice = sig_ptr.slice(&view, sig_len)?;
    let mut sig_bytes = vec![0u8; sig_len as usize];
    sig_slice.read_slice(&mut sig_bytes)?;
    let signature = Signature::read(sig_bytes.as_slice(), &mut 0).map_err(|e| {
        RuntimeError::new(format!("failed to read signature from wasm memory: {}", e))
    })?;
    let digest_slice = digest_ptr.slice(&view, 32)?;
    let mut digest_bytes = vec![0u8; 32];
    digest_slice.read_slice(&mut digest_bytes)?;
    let digest: Digest = Digest::from_data(&digest_bytes);
    let public_key = signature.recover_public_key(&digest)?;
    let packed_public_key = public_key.pack().map_err(|e| {
        RuntimeError::new(format!("failed to pack public key: {}", e))
    })?;
    let copy_size = std::cmp::min(pub_len as usize, packed_public_key.len());
    let slice_out = pub_ptr.slice(&view, copy_size as u32)?;
    slice_out.write_slice(&packed_public_key[..copy_size])?;
    Ok(packed_public_key.len() as i32)
}

pub fn sha1(
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

    let hasher = sha1::Sha1::digest(&src_bytes);
    let slice_out = out_ptr.slice(&view, hasher.len() as u32)?;
    slice_out.write_slice(hasher.as_ref())?;

    Ok(())
}

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

pub fn ripemd160(
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

    let hasher = ripemd::Ripemd160::digest(&src_bytes);
    let slice_out = out_ptr.slice(&view, hasher.len() as u32)?;
    slice_out.write_slice(hasher.as_ref())?;

    Ok(())
}

pub fn assert_sha1(
    mut env: FunctionEnvMut<WasmContext>,
    data_ptr: WasmPtr<u8>,
    data_size: u32,
    hash_val_ptr: WasmPtr<u8>,
) -> Result<(), RuntimeError> {
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    // Borrow the input bytes from guest memory
    let data_slice = data_ptr.slice(&view, data_size)?;
    let data_access = data_slice
        .access()
        .map_err(|e| RuntimeError::new(format!("failed to access data pointer: {e}")))?;
    let data_bytes: &[u8] = data_access.as_ref();
    let digest = sha1::Sha1::digest(data_bytes); // 20 bytes

    // Borrow the expected hash bytes from guest memory (must be 20 bytes)
    let hash_slice = hash_val_ptr.slice(&view, digest.len() as u32)?;
    let hash_access = hash_slice
        .access()
        .map_err(|e| RuntimeError::new(format!("failed to access hash value pointer: {e}")))?;

    let expected_hash: &[u8] = hash_access.as_ref();

    if expected_hash.len() != digest.len() {
        return Err(RuntimeError::new("assertion failed: hash length mismatch"));
    }

    if expected_hash != digest.as_slice() {
        return Err(RuntimeError::new("assertion failed: sha1 hash mismatch"));
    }

    Ok(())
}

pub fn assert_sha224(
    mut env: FunctionEnvMut<WasmContext>,
    data_ptr: WasmPtr<u8>,
    data_size: u32,
    hash_val_ptr: WasmPtr<u8>,
) -> Result<(), RuntimeError> {
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
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
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
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
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
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

pub fn assert_ripemd160(
    mut env: FunctionEnvMut<WasmContext>,
    data_ptr: WasmPtr<u8>,
    data_size: u32,
    hash_val_ptr: WasmPtr<u8>,
) -> Result<(), RuntimeError> {
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    // Borrow the input bytes from guest memory
    let data_slice = data_ptr.slice(&view, data_size)?;
    let data_access = data_slice
        .access()
        .map_err(|e| RuntimeError::new(format!("failed to access data pointer: {e}")))?;
    let data_bytes: &[u8] = data_access.as_ref();
    let digest = ripemd::Ripemd160::digest(data_bytes); // 20 bytes

    // Borrow the expected hash bytes from guest memory (must be 20 bytes)
    let hash_slice = hash_val_ptr.slice(&view, digest.len() as u32)?;
    let hash_access = hash_slice
        .access()
        .map_err(|e| RuntimeError::new(format!("failed to access hash value pointer: {e}")))?;

    let expected_hash: &[u8] = hash_access.as_ref();

    if expected_hash.len() != digest.len() {
        return Err(RuntimeError::new("assertion failed: hash length mismatch"));
    }

    if expected_hash != digest.as_slice() {
        return Err(RuntimeError::new("assertion failed: ripemd160 hash mismatch"));
    }

    Ok(())
}