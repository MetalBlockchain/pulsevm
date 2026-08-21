use pulsevm_error::ChainError;
use wasmer::{
    FunctionEnvMut,
    RuntimeError,
    WasmPtr,
};

use crate::chain::{
    utils::pulse_assert,
    wasm_runtime::WasmContext,
    webassembly::context_aware_check,
};

use super::cost;

const ACTION_RETURN_VALUE_FEATURE_DIGEST: [u8; 32] = [
    0x69, 0xb0, 0x64, 0xc5, 0x17, 0x8e, 0x27, 0x38, 0xe1, 0x44, 0xed, 0x6c, 0xaa, 0x93, 0x49,
    0xa3, 0x99, 0x53, 0x70, 0xd7, 0x8d, 0xb2, 0x9e, 0x49, 0x4b, 0x31, 0x26, 0xeb, 0xd9, 0x11,
    0x19, 0x66,
];

#[inline]
pub fn action_data_size(mut env: FunctionEnvMut<WasmContext>) -> Result<i32, RuntimeError> {
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::BASE)?;
    Ok(env_data.action().data().len() as i32)
}

#[inline]
pub fn read_action_data(
    mut env: FunctionEnvMut<WasmContext>,
    buffer_ptr: WasmPtr<u8>,
    buffer_len: u32,
) -> Result<i32, RuntimeError> {
    let (env_data, mut store) = env.data_and_store_mut();
    // Charge for the bytes actually copied, not the guest-declared buffer: this
    // intrinsic writes straight into guest memory (no host allocation to bound),
    // and copies only min(buffer_len, data_len). A large buffer_len over small
    // action data must not be billed for bytes it never touches.
    let total_len = env_data.action().data().len() as u32;
    let copy_size = buffer_len.min(total_len);
    env_data.charge(&mut store, cost::BASE + cost::per_byte(copy_size as u64))?;

    if copy_size == 0 {
        return Ok(total_len as i32);
    }

    let action_data = env_data.action().data();

    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let slice = buffer_ptr.slice(&view, copy_size)?;
    slice.write_slice(&action_data[..copy_size as usize])?;
    Ok(copy_size as i32)
}

#[inline]
pub fn current_receiver(mut env: FunctionEnvMut<WasmContext>) -> Result<u64, RuntimeError> {
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::BASE)?;
    Ok(env_data.receiver())
}

#[inline]
pub fn set_action_return_value(
    mut env: FunctionEnvMut<WasmContext>,
    buffer_ptr: WasmPtr<u8>,
    buffer_len: u32,
) -> Result<(), RuntimeError> {
    context_aware_check(&env)?;

    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::BASE + cost::per_byte(buffer_len as u64))?;

    if !env_data
        .db()
        .protocol_feature_activated(ACTION_RETURN_VALUE_FEATURE_DIGEST)
    {
        return Err(RuntimeError::new(
            "set_action_return_value is unavailable before the ACTION_RETURN_VALUE protocol feature is activated",
        ));
    }

    {
        let db = env_data.db_mut();
        let max_action_return_value_size = db.max_action_return_value_size()?;
        pulse_assert(
            buffer_len <= max_action_return_value_size,
            ChainError::WasmRuntimeError(format!(
                "action return value size must be less or equal to {} bytes",
                max_action_return_value_size
            )),
        )?;
    }

    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let slice = buffer_ptr.slice(&view, buffer_len)?;
    let mut return_value = vec![0u8; buffer_len as usize];
    slice.read_slice(&mut return_value)?;
    env_data.set_action_return_value(return_value.into());
    Ok(())
}
