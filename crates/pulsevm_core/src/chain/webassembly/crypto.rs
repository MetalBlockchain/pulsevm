use bn::{
    AffineG1,
    AffineG2,
    Fq,
    Fq2,
    Fr,
    G1,
    G2,
    Group,
    Gt,
    pairing_batch,
};
use num_bigint::BigUint;
use pulsevm_crypto::{
    AuthorityPublicKey,
    MlDsaParameterSet,
};
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
    protocol_features::ProtocolFeature,
};

/// Maximum message size for the new FIPS 204 host ABI. See `docs/ml-dsa.md`.
pub const MAX_ML_DSA_MESSAGE_BYTES: u32 = 1_048_576;

/// Verify a detached FIPS 204 signature with a packed ML-DSA public key.
/// Returns 1 for a valid signature and 0 for a cryptographic failure.
#[allow(
    clippy::too_many_arguments,
    reason = "WASM ABI uses pointer/length pairs"
)]
pub fn verify_mldsa(
    mut env: FunctionEnvMut<WasmContext>,
    message_ptr: WasmPtr<u8>,
    message_len: u32,
    signature_ptr: WasmPtr<u8>,
    signature_len: u32,
    key_ptr: WasmPtr<u8>,
    key_len: u32,
    context_ptr: WasmPtr<u8>,
    context_len: u32,
) -> Result<i32, RuntimeError> {
    let (data, mut store) = env.data_and_store_mut();
    if !data.protocol_feature_enabled(ProtocolFeature::MlDsa) {
        return Err(RuntimeError::new(
            "ML-DSA intrinsics require protocol version 2",
        ));
    }
    if message_len > MAX_ML_DSA_MESSAGE_BYTES || context_len > 255 {
        return Err(RuntimeError::new(
            "ML-DSA message or context exceeds its size limit",
        ));
    }
    let memory = data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);
    let mut tag = [0u8; 1];
    key_ptr.slice(&view, 1)?.read_slice(&mut tag)?;
    let parameters =
        MlDsaParameterSet::from_tag(tag[0]).map_err(|e| RuntimeError::new(e.to_string()))?;
    if key_len as usize != 1 + parameters.public_key_len()
        || signature_len as usize != parameters.signature_len()
    {
        return Err(RuntimeError::new("invalid ML-DSA key or signature length"));
    }
    // Bill before expanding the key or scanning any message bytes.
    data.charge(
        &mut store,
        cost::ml_dsa_verify(parameters, message_len.into(), context_len.into()),
    )?;
    let view = memory.view(&store);
    let key_slice = key_ptr.slice(&view, key_len)?;
    let key = key_slice
        .access()
        .map_err(|e| RuntimeError::new(e.to_string()))?;
    let AuthorityPublicKey::MlDsa(key) = AuthorityPublicKey::from_packed(key.as_ref())
        .map_err(|e| RuntimeError::new(e.to_string()))?
    else {
        return Err(RuntimeError::new("expected an ML-DSA public key"));
    };
    let message_slice = message_ptr.slice(&view, message_len)?;
    let message = message_slice
        .access()
        .map_err(|e| RuntimeError::new(e.to_string()))?;
    let signature_slice = signature_ptr.slice(&view, signature_len)?;
    let signature = signature_slice
        .access()
        .map_err(|e| RuntimeError::new(e.to_string()))?;
    let context_slice = context_ptr.slice(&view, context_len)?;
    let context = context_slice
        .access()
        .map_err(|e| RuntimeError::new(e.to_string()))?;
    Ok(i32::from(key.verify(
        message.as_ref(),
        context.as_ref(),
        signature.as_ref(),
    )))
}

#[allow(
    clippy::too_many_arguments,
    reason = "WASM ABI uses pointer/length pairs"
)]
pub fn assert_verify_mldsa(
    env: FunctionEnvMut<WasmContext>,
    message_ptr: WasmPtr<u8>,
    message_len: u32,
    signature_ptr: WasmPtr<u8>,
    signature_len: u32,
    key_ptr: WasmPtr<u8>,
    key_len: u32,
    context_ptr: WasmPtr<u8>,
    context_len: u32,
) -> Result<(), RuntimeError> {
    if verify_mldsa(
        env,
        message_ptr,
        message_len,
        signature_ptr,
        signature_len,
        key_ptr,
        key_len,
        context_ptr,
        context_len,
    )? != 1
    {
        return Err(RuntimeError::new(
            "assertion failed: invalid ML-DSA signature",
        ));
    }
    Ok(())
}

fn charge_ml_dsa_recovery(
    data: &WasmContext,
    store: &mut impl wasmer::AsStoreMut,
    signature: &Signature,
    signature_len: u32,
) -> Result<(), RuntimeError> {
    if let Some(parameters) = signature.ml_dsa_parameters() {
        if !data.protocol_feature_enabled(ProtocolFeature::MlDsa) {
            return Err(RuntimeError::new(
                "ML-DSA signatures require protocol version 2",
            ));
        }
        if signature_len as usize != 1 + parameters.public_key_len() + parameters.signature_len() {
            return Err(RuntimeError::new("trailing bytes in ML-DSA signature"));
        }
        data.charge(
            store,
            cost::ml_dsa_verify(
                parameters,
                32,
                pulsevm_crypto::ML_DSA_TRANSACTION_CONTEXT.len() as u64,
            ) - cost::RECOVER_KEY,
        )?;
    }
    Ok(())
}

fn check_ml_dsa_envelope(
    data: &WasmContext,
    tag: u8,
    signature_len: u32,
) -> Result<(), RuntimeError> {
    if matches!(tag, 3..=5) {
        if !data.protocol_feature_enabled(ProtocolFeature::MlDsa) {
            return Err(RuntimeError::new(
                "ML-DSA signatures require protocol version 2",
            ));
        }
        let parameters =
            MlDsaParameterSet::from_tag(tag).map_err(|e| RuntimeError::new(e.to_string()))?;
        if signature_len as usize != 1 + parameters.public_key_len() + parameters.signature_len() {
            return Err(RuntimeError::new(
                "invalid ML-DSA signature envelope length",
            ));
        }
    }
    Ok(())
}

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
    if mod_len == 0 {
        return Ok(1);
    }
    if result_len < mod_len {
        return Ok(1);
    }
    // Antelope returns exactly the modulus width, including leading zeroes.
    // A zero modulus also returns a zero-filled buffer of that width.
    let mut result = vec![0u8; mod_len as usize];
    if modulus != BigUint::default() {
        let value = base.modpow(&exponent, &modulus).to_bytes_be();
        result[mod_len as usize - value.len()..].copy_from_slice(&value);
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

    let point = match decode_g1(&point_bytes) {
        Ok(point) => point,
        Err(()) => return Ok(1),
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

/// Antelope `alt_bn128_add` host intrinsic using two 64-byte uncompressed
/// (x || y) G1 points and a 64-byte output.
pub fn alt_bn128_add(
    mut env: FunctionEnvMut<WasmContext>,
    lhs_ptr: WasmPtr<u8>,
    lhs_len: u32,
    rhs_ptr: WasmPtr<u8>,
    rhs_len: u32,
    result_ptr: WasmPtr<u8>,
    result_len: u32,
) -> Result<i32, RuntimeError> {
    let (env_data, mut store) = env.data_and_store_mut();
    if !env_data
        .db()
        .protocol_feature_activated(CRYPTO_PRIMITIVES_FEATURE_DIGEST)
    {
        return Err(RuntimeError::new(
            "alt_bn128_add requires the CRYPTO_PRIMITIVES protocol feature",
        ));
    }

    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    env_data.charge(&mut store, cost::ALT_BN128_ADD)?;

    let view = memory.view(&store);
    if lhs_len != 64 || rhs_len != 64 || result_len < 64 {
        return Ok(1);
    }
    let lhs_slice = lhs_ptr.slice(&view, 64)?;
    let rhs_slice = rhs_ptr.slice(&view, 64)?;
    let _ = result_ptr.slice(&view, 64)?;

    let mut lhs_bytes = [0u8; 64];
    let mut rhs_bytes = [0u8; 64];
    lhs_slice.read_slice(&mut lhs_bytes)?;
    rhs_slice.read_slice(&mut rhs_bytes)?;

    let lhs = match decode_g1(&lhs_bytes) {
        Ok(point) => point,
        Err(()) => return Ok(1),
    };
    let rhs = match decode_g1(&rhs_bytes) {
        Ok(point) => point,
        Err(()) => return Ok(1),
    };
    let sum = lhs + rhs;

    let mut result = [0u8; 64];
    if let Some(affine) = AffineG1::from_jacobian(sum) {
        affine
            .x()
            .to_big_endian(&mut result[..32])
            .map_err(|_| RuntimeError::new("failed to encode alt_bn128_add x coordinate"))?;
        affine
            .y()
            .to_big_endian(&mut result[32..])
            .map_err(|_| RuntimeError::new("failed to encode alt_bn128_add y coordinate"))?;
    }
    view.write(result_ptr.offset() as u64, &result)?;
    Ok(0)
}

fn decode_g1(bytes: &[u8; 64]) -> Result<G1, ()> {
    // Antelope represents the point at infinity as (0, 0).
    if bytes.iter().all(|byte| *byte == 0) {
        return Ok(G1::zero());
    }
    let x = Fq::from_slice(&bytes[..32]).map_err(|_| ())?;
    let y = Fq::from_slice(&bytes[32..]).map_err(|_| ())?;
    let affine = AffineG1::new(x, y).map_err(|_| ())?;
    Ok(G1::from(affine))
}

/// Antelope `alt_bn128_pair` host intrinsic. Inputs are concatenated 192-byte
/// (G1, G2) pairs; a zero result means their product pairing is one.
pub fn alt_bn128_pair(
    mut env: FunctionEnvMut<WasmContext>,
    pairs_ptr: WasmPtr<u8>,
    pairs_len: u32,
) -> Result<i32, RuntimeError> {
    let (env_data, mut store) = env.data_and_store_mut();
    if !env_data
        .db()
        .protocol_feature_activated(CRYPTO_PRIMITIVES_FEATURE_DIGEST)
    {
        return Err(RuntimeError::new(
            "alt_bn128_pair requires the CRYPTO_PRIMITIVES protocol feature",
        ));
    }

    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    env_data.charge(&mut store, cost::alt_bn128_pair(pairs_len.into()))?;
    if pairs_len % 192 != 0 {
        return Ok(1);
    }

    let view = memory.view(&store);
    let pair_slice = pairs_ptr.slice(&view, pairs_len)?;
    let mut bytes = vec![0u8; pairs_len as usize];
    pair_slice.read_slice(&mut bytes)?;
    let mut pairs = Vec::with_capacity((pairs_len / 192) as usize);
    for encoded in bytes.chunks_exact(192) {
        let g1_bytes: &[u8; 64] = encoded[..64]
            .try_into()
            .map_err(|_| RuntimeError::new("invalid alt_bn128_pair G1 length"))?;
        let g2_bytes: &[u8; 128] = encoded[64..]
            .try_into()
            .map_err(|_| RuntimeError::new("invalid alt_bn128_pair G2 length"))?;
        let g1 = match decode_g1(g1_bytes) {
            Ok(point) => point,
            Err(()) => return Ok(1),
        };
        let g2 = match decode_g2(g2_bytes) {
            Ok(point) => point,
            Err(()) => return Ok(1),
        };
        pairs.push((g1, g2));
    }

    Ok(if pairing_batch(&pairs) == Gt::one() {
        0
    } else {
        1
    })
}

fn decode_g2(bytes: &[u8; 128]) -> Result<G2, ()> {
    // Antelope represents the point at infinity as (0, 0).
    if bytes.iter().all(|byte| *byte == 0) {
        return Ok(G2::zero());
    }
    // Antelope stores each Fq2 coefficient imaginary first, while this crate's
    // constructor takes real then imaginary.
    let x_imaginary = Fq::from_slice(&bytes[..32]).map_err(|_| ())?;
    let x_real = Fq::from_slice(&bytes[32..64]).map_err(|_| ())?;
    let y_imaginary = Fq::from_slice(&bytes[64..96]).map_err(|_| ())?;
    let y_real = Fq::from_slice(&bytes[96..]).map_err(|_| ())?;
    let x = Fq2::new(x_real, x_imaginary);
    let y = Fq2::new(y_real, y_imaginary);
    let affine = AffineG2::new(x, y).map_err(|_| ())?;
    Ok(G2::from(affine))
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
    if sig_len > 0 {
        let mut tag = [0u8; 1];
        sig_ptr.slice(&view, 1)?.read_slice(&mut tag)?;
        check_ml_dsa_envelope(env_data, tag[0], sig_len)?;
    }
    let sig_slice = sig_ptr.slice(&view, sig_len)?;
    let mut sig_bytes = vec![0u8; sig_len as usize];
    sig_slice.read_slice(&mut sig_bytes)?;
    let signature = Signature::read(sig_bytes.as_slice(), &mut 0).map_err(|e| {
        RuntimeError::new(format!("failed to read signature from wasm memory: {}", e))
    })?;
    charge_ml_dsa_recovery(env_data, &mut store, &signature, sig_len)?;
    let view = memory.view(&store);
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
    if let Some(parameters) = signature.ml_dsa_parameters()
        && pub_len as usize != 1 + parameters.public_key_len()
    {
        return Err(RuntimeError::new("invalid ML-DSA public key length"));
    }
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
    if sig_len > 0 {
        let mut tag = [0u8; 1];
        sig_ptr.slice(&view, 1)?.read_slice(&mut tag)?;
        check_ml_dsa_envelope(env_data, tag[0], sig_len)?;
    }
    let sig_slice = sig_ptr.slice(&view, sig_len)?;
    let mut sig_bytes = vec![0u8; sig_len as usize];
    sig_slice.read_slice(&mut sig_bytes)?;
    let signature = Signature::read(sig_bytes.as_slice(), &mut 0).map_err(|e| {
        RuntimeError::new(format!("failed to read signature from wasm memory: {}", e))
    })?;
    charge_ml_dsa_recovery(env_data, &mut store, &signature, sig_len)?;
    let view = memory.view(&store);
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
