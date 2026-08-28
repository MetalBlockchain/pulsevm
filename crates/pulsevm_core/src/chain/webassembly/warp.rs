//! WASM host functions exposing Avalanche Interchain Messaging (ICM / warp) to
//! contracts.
//!
//! Two intrinsics, mirroring AvalancheGo's Warp precompile:
//!
//! * [`pulse_send_warp_message`] — a contract emits a cross-chain message. The VM
//!   builds an `AddressedCall` from the *calling contract account* and the given
//!   payload, wraps it in an `UnsignedMessage` stamped with this chain's Avalanche
//!   network and blockchain id, records it for the node to sign / a relayer to
//!   carry, and returns the message id.
//! * [`pulse_verify_warp_message`] — a contract verifies a fully-signed inbound
//!   message. Verification is *stateless* (aggregate BLS + weighted quorum
//!   against the source subnet's validator set); on success the authenticated
//!   `(id, source_chain_id, source_address, payload)` is returned for the
//!   contract to act on and to dedup against replays.
//!
//! Both require the node to have been configured with its Avalanche network
//! context (see `WasmRuntime::set_warp_manager`); without it they trap.

use wasmer::{
    FunctionEnvMut,
    RuntimeError,
    WasmPtr,
};

use super::{
    context_aware_check,
    cost,
};
use crate::chain::{
    warp::VerifiedMessage,
    wasm_runtime::WasmContext,
};

/// Serialize a verified inbound message for return to wasm. Little-endian, EOS
/// host-ABI style so a contract can parse it with the same conventions as the
/// rest of the intrinsics:
///
/// `id[32] | source_chain_id[32] | source_address_len(u32 LE) | source_address | payload`
///
/// The payload length is whatever remains after the header — the contract learns
/// the total length from the function's return value.
fn encode_verified(v: &VerifiedMessage) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(32 + 32 + 4 + v.source_address.len() + v.payload.len());
    out.extend_from_slice(&v.id);
    out.extend_from_slice(&v.source_chain_id);
    out.extend_from_slice(&(v.source_address.len() as u32).to_le_bytes());
    out.extend_from_slice(&v.source_address);
    out.extend_from_slice(&v.payload);
    out
}

/// `pulse_send_warp_message(payload, payload_len, id)`.
///
/// Emits a cross-chain message carrying `payload`, from the calling contract
/// account. Writes the 32-byte message id to `id_ptr` (a contract uses it as the
/// key a relayer will request a signature for). Traps if ICM is not configured.
pub fn pulse_send_warp_message(
    mut env: FunctionEnvMut<WasmContext>,
    payload_ptr: WasmPtr<u8>,
    payload_len: u32,
    id_ptr: WasmPtr<u8>,
) -> Result<(), RuntimeError> {
    context_aware_check(&env)?;

    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::warp_send(payload_len as u64))?;

    let manager = env_data.warp_manager().cloned().ok_or_else(|| {
        RuntimeError::new("cross-chain messaging is not configured on this chain")
    })?;

    // The source address is the executing contract account (8-byte little-endian
    // name), so a destination contract can authenticate exactly which account on
    // this chain sent the message.
    let source_address = env_data.receiver().to_le_bytes().to_vec();

    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);

    let payload_slice = payload_ptr.slice(&view, payload_len)?;
    let mut payload = vec![0u8; payload_len as usize];
    payload_slice.read_slice(&mut payload)?;

    let unsigned = manager.emit(source_address, payload);
    let id = unsigned.id();

    env_data
        .apply_context()
        .emit_warp_message(unsigned.to_bytes())
        .map_err(|e| RuntimeError::new(format!("failed to record warp message: {e}")))?;

    let id_slice = id_ptr.slice(&view, 32)?;
    id_slice.write_slice(&id)?;
    Ok(())
}

/// `pulse_verify_warp_message(message, message_len, out, out_len) -> i32`.
///
/// Verifies a signed inbound warp message. Returns:
/// * `-1` if the message is malformed or fails verification (bad signature,
///   insufficient validator weight, unknown source chain, wrong network);
/// * otherwise the total length of the encoded [`encode_verified`] result. Up to
///   `out_len` bytes are written to `out_ptr`; if the return value exceeds
///   `out_len` the contract should retry with a larger buffer.
///
/// Verification holds no state — replay protection is the contract's job, keyed
/// on the returned message id.
pub fn pulse_verify_warp_message(
    mut env: FunctionEnvMut<WasmContext>,
    msg_ptr: WasmPtr<u8>,
    msg_len: u32,
    out_ptr: WasmPtr<u8>,
    out_len: u32,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;

    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::warp_verify(msg_len as u64))?;

    let manager = env_data.warp_manager().cloned().ok_or_else(|| {
        RuntimeError::new("cross-chain messaging is not configured on this chain")
    })?;

    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);

    let msg_slice = msg_ptr.slice(&view, msg_len)?;
    let mut msg_bytes = vec![0u8; msg_len as usize];
    msg_slice.read_slice(&mut msg_bytes)?;

    // A verification failure is a normal, contract-observable outcome (return
    // -1), not a trap — the contract decides how to handle an unauthenticated
    // message.
    let verified = match manager.verify(&msg_bytes) {
        Ok(v) => v,
        Err(_) => return Ok(-1),
    };

    let encoded = encode_verified(&verified);
    let total = encoded.len();
    let copy = std::cmp::min(out_len as usize, total);
    if copy > 0 {
        let out_slice = out_ptr.slice(&view, copy as u32)?;
        out_slice.write_slice(&encoded[..copy])?;
    }
    Ok(total as i32)
}
