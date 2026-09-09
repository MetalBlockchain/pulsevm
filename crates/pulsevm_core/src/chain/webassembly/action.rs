use pulsevm_error::ChainError;
use pulsevm_proc_macros::{
    NumBytes,
    Write,
};
use pulsevm_serialization::{
    VarUint32,
    Write as SerializationWrite,
};
use wasmer::{
    FunctionEnvMut,
    RuntimeError,
    WasmPtr,
};

use crate::chain::{
    id::Id,
    utils::pulse_assert,
    wasm_runtime::WasmContext,
    webassembly::context_aware_check,
};

use super::cost;

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

#[derive(NumBytes, Write)]
struct CodeHashResult {
    struct_version: VarUint32,
    code_sequence: u64,
    code_hash: Id,
    vm_type: u8,
    vm_version: u8,
}

/// Return the receiver that created the currently executing action, or the
/// zero name for a top-level transaction action.
#[inline]
pub fn get_sender(mut env: FunctionEnvMut<WasmContext>) -> Result<u64, RuntimeError> {
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::BASE)?;
    env_data
        .apply_context()
        .get_sender()
        .map_err(|e| RuntimeError::new(format!("get_sender failed: {e}")))
}

/// Pack the current code metadata for `account` using nodeos' version-0
/// `code_hash_result` layout. The return value is always the packed size; the
/// result is written only when the supplied buffer is large enough.
#[inline]
pub fn get_code_hash(
    mut env: FunctionEnvMut<WasmContext>,
    account: u64,
    _struct_version: u32,
    result_ptr: WasmPtr<u8>,
    buffer_size: u32,
) -> Result<u32, RuntimeError> {
    let (env_data, mut store) = env.data_and_store_mut();
    // The metadata lookup is a database read; charge its fixed cost before
    // touching the arena so a failing budget cannot run the lookup for free.
    env_data.charge(&mut store, cost::DB_FIND)?;
    let result = match env_data.db().arena_account_metadata(account) {
        Some(metadata) => CodeHashResult {
            struct_version: VarUint32(0),
            code_sequence: metadata.code_sequence,
            code_hash: Id::new(metadata.code_hash),
            vm_type: metadata.vm_type,
            vm_version: metadata.vm_version,
        },
        None => CodeHashResult {
            struct_version: VarUint32(0),
            code_sequence: 0,
            code_hash: Id::zero(),
            vm_type: 0,
            vm_version: 0,
        },
    };
    let packed = result
        .pack()
        .map_err(|e| RuntimeError::new(format!("failed to pack code hash result: {e}")))?;
    env_data.charge(&mut store, cost::per_byte(packed.len() as u64))?;

    if buffer_size >= packed.len() as u32 {
        let memory = env_data
            .memory()
            .as_ref()
            .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
        let view = memory.view(&store);
        result_ptr
            .slice(&view, packed.len() as u32)
            .map_err(|e| RuntimeError::new(format!("get_code_hash: invalid result range: {e}")))?
            .write_slice(&packed)
            .map_err(|e| {
                RuntimeError::new(format!("get_code_hash: failed to write result: {e}"))
            })?;
    }

    Ok(packed.len() as u32)
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
