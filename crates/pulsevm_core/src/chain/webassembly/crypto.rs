use bn::{
    AffineG1,
    Fq,
    Fr,
    G1,
    Group,
};
use num_bigint::BigUint;
use pulsevm_crypto::AuthorityPublicKey;
use pulsevm_serialization::{
    Read,
    Write,
};
use sha1::Digest as Sha1Digest;
use wasmer::{
    FunctionEnvMut,
    RuntimeError,
    WasmPtr,
};

use super::cost;
use crate::{
    chain::wasm_runtime::WasmContext,
    crypto::Signature,
};

/// Antelope's activated CRYPTO_PRIMITIVES feature (canonical feature digest).
pub(crate) const CRYPTO_PRIMITIVES_FEATURE_DIGEST: [u8; 32] = [
    0x6b, 0xcb, 0x40, 0xa2, 0x4e, 0x49, 0xc2, 0x6d, 0x0a, 0x60, 0x51, 0x3b, 0x6a, 0xeb, 0x85, 0x51,
    0xd2, 0x64, 0xe4, 0x71, 0x7f, 0x30, 0x6b, 0x81, 0xa3, 0x7a, 0x5a, 0xfb, 0x3b, 0x47, 0xce, 0xdc,
];

/// Antelope CDT `mod_exp(base, exp, modulus, result)` host intrinsic.
/// Operands and the minimal result are unsigned, big-endian byte strings.
pub fn mod_exp(
    mut env: FunctionEnvMut<WasmContext>,
    base_ptr: WasmPtr<u8>,
    base_len: u32,
    exp_ptr: WasmPtr<u8>,
    exp_len: u32,
    mod_ptr: WasmPtr<u8>,
    mod_len: u32,
    result_ptr: WasmPtr<u8>,
    result_len: u32,
) -> Result<i32, RuntimeError> {
    let (env_data, mut store) = env.data_and_store_mut();
    if !env_data
        .db()
        .protocol_feature_activated(CRYPTO_PRIMITIVES_FEATURE_DIGEST)
    {
        return Err(RuntimeError::new(
            "mod_exp requires the CRYPTO_PRIMITIVES protocol feature",
        ));
    }

    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    env_data.charge(
        &mut store,
        cost::mod_exp(base_len.into(), exp_len.into(), mod_len.into()),
    )?;

    let view = memory.view(&store);
    let base_slice = base_ptr.slice(&view, base_len)?;
    let exp_slice = exp_ptr.slice(&view, exp_len)?;
    let mod_slice = mod_ptr.slice(&view, mod_len)?;
    let _ = result_ptr.slice(&view, result_len)?;

    let mut base_bytes = vec![0u8; base_len as usize];
    let mut exp_bytes = vec![0u8; exp_len as usize];
    let mut mod_bytes = vec![0u8; mod_len as usize];
    base_slice.read_slice(&mut base_bytes)?;
    exp_slice.read_slice(&mut exp_bytes)?;
    mod_slice.read_slice(&mut mod_bytes)?;

    let base = BigUint::from_bytes_be(&base_bytes);
    let exponent = BigUint::from_bytes_be(&exp_bytes);
    let modulus = BigUint::from_bytes_be(&mod_bytes);
    if modulus == BigUint::default() {
        return Ok(1);
    }
    let result = base.modpow(&exponent, &modulus).to_bytes_be();
    if result.len() > result_len as usize {
        return Ok(1);
    }
    view.write(result_ptr.offset() as u64, &result)?;
    Ok(0)
}

/// Antelope `alt_bn128_mul` host intrinsic using 32-byte big-endian field
/// elements and scalars, and the 64-byte uncompressed (x || y) G1 encoding.
pub fn alt_bn128_mul(
    mut env: FunctionEnvMut<WasmContext>,
    point_ptr: WasmPtr<u8>,
    point_len: u32,
    scalar_ptr: WasmPtr<u8>,
    scalar_len: u32,
    result_ptr: WasmPtr<u8>,
    result_len: u32,
) -> Result<i32, RuntimeError> {
    let (env_data, mut store) = env.data_and_store_mut();
    if !env_data
        .db()
        .protocol_feature_activated(CRYPTO_PRIMITIVES_FEATURE_DIGEST)
    {
        return Err(RuntimeError::new(
            "alt_bn128_mul requires the CRYPTO_PRIMITIVES protocol feature",
        ));
    }

    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    env_data.charge(&mut store, cost::ALT_BN128_MUL)?;

    let view = memory.view(&store);
    if point_len != 64 || scalar_len != 32 || result_len < 64 {
        return Ok(1);
    }
    let point_slice = point_ptr.slice(&view, 64)?;
    let scalar_slice = scalar_ptr.slice(&view, 32)?;
    let _ = result_ptr.slice(&view, 64)?;

    let mut point_bytes = [0u8; 64];
    let mut scalar_bytes = [0u8; 32];
    point_slice.read_slice(&mut point_bytes)?;
    scalar_slice.read_slice(&mut scalar_bytes)?;

    // Antelope represents the point at infinity as (0, 0).
    let point = if point_bytes.iter().all(|byte| *byte == 0) {
        G1::zero()
    } else {
        let x = match Fq::from_slice(&point_bytes[..32]) {
            Ok(value) => value,
            Err(_) => return Ok(1),
        };
        let y = match Fq::from_slice(&point_bytes[32..]) {
            Ok(value) => value,
            Err(_) => return Ok(1),
        };
        let affine = match AffineG1::new(x, y) {
            Ok(value) => value,
            Err(_) => return Ok(1),
        };
        G1::from(affine)
    };
    let scalar = Fr::from_slice(&scalar_bytes)
        .map_err(|_| RuntimeError::new("invalid alt_bn128_mul scalar encoding"))?;
    let product = point * scalar;

    let mut result = [0u8; 64];
    if let Some(affine) = AffineG1::from_jacobian(product) {
        affine
            .x()
            .to_big_endian(&mut result[..32])
            .map_err(|_| RuntimeError::new("failed to encode alt_bn128_mul x coordinate"))?;
        affine
            .y()
            .to_big_endian(&mut result[32..])
            .map_err(|_| RuntimeError::new("failed to encode alt_bn128_mul y coordinate"))?;
    }
    view.write(result_ptr.offset() as u64, &result)?;
    Ok(0)
}

pub fn assert_recover_key(
    mut env: FunctionEnvMut<WasmContext>,
    digest_ptr: WasmPtr<u8>,
    sig_ptr: WasmPtr<u8>,
    sig_len: u32,
    pub_ptr: WasmPtr<u8>,
    pub_len: u32,
) -> Result<(), RuntimeError> {
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::RECOVER_KEY)?;
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
    let digest = pulsevm_crypto::Digest(
        digest_bytes
            .as_slice()
            .try_into()
            .expect("digest buffer is exactly 32 bytes"),
    );
    let pub_slice = pub_ptr.slice(&view, pub_len)?;
    let mut pubkey_bytes = vec![0u8; pub_len as usize];
    pub_slice.read_slice(&mut pubkey_bytes)?;
    let pubkey = AuthorityPublicKey::read(pubkey_bytes.as_slice(), &mut 0).map_err(|e| {
        RuntimeError::new(format!("failed to read public key from wasm memory: {}", e))
    })?;
    // fc passes `check_canonical = false` for this intrinsic, so a contract must
    // see a non-canonical signature recover rather than fail. Consensus paths use
    // the checked form; this one deliberately does not.
    let recovered_pubkey = signature.recover_authority_key_non_canonical(&digest)?;

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
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::RECOVER_KEY)?;
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
    let digest = pulsevm_crypto::Digest(
        digest_bytes
            .as_slice()
            .try_into()
            .expect("digest buffer is exactly 32 bytes"),
    );
    // As in `assert_recover_key`: fc passes `check_canonical = false` here.
    let public_key = signature.recover_authority_key_non_canonical(&digest)?;
    let packed_public_key = public_key
        .pack()
        .map_err(|e| RuntimeError::new(format!("failed to pack public key: {}", e)))?;
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
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::sha1(msg_size as u64))?;
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
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::sha256(msg_size as u64))?;
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
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::sha256(msg_size as u64))?;
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
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::sha512(msg_size as u64))?;
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
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::ripemd160(msg_size as u64))?;
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
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::sha1(data_size as u64))?;
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
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::sha256(data_size as u64))?;
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
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::sha256(data_size as u64))?;
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
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::sha512(data_size as u64))?;
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
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::ripemd160(data_size as u64))?;
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
        return Err(RuntimeError::new(
            "assertion failed: ripemd160 hash mismatch",
        ));
    }

    Ok(())
}
