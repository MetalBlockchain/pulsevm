use wasmer::{FunctionEnvMut, RuntimeError, WasmPtr};

use crate::chain::{
    controller::Controller, error::ChainError, utils::pulse_assert, wasm_runtime::WasmContext,
};

#[inline]
pub fn action_data_size(env: FunctionEnvMut<WasmContext>) -> i32 {
    env.data().action().data().len() as i32
}

#[inline]
pub fn read_action_data(
    mut env: FunctionEnvMut<WasmContext>,
    buffer_ptr: WasmPtr<u8>,
    buffer_len: u32,
) -> Result<i32, RuntimeError> {
    // Extract the data early
    let action_data = env.data().action().data();
    let total_len = action_data.len() as u32;
    let copy_size = buffer_len.min(total_len);

    if copy_size == 0 {
        return Ok(total_len as i32);
    }

    let (env_data, store) = env.data_and_store_mut();
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
pub fn current_receiver(env: FunctionEnvMut<WasmContext>) -> u64 {
    env.data().receiver().as_u64()
}

#[inline]
pub fn set_action_return_value(
    mut env: FunctionEnvMut<WasmContext>,
    buffer_ptr: WasmPtr<u8>,
    buffer_len: u32,
) -> Result<(), RuntimeError> {
    let (env_data, store) = env.data_and_store_mut();

    {
        let context = env_data.apply_context();
        let mut session = context.undo_session();
        let gpo = Controller::get_global_properties(&mut session)?;
        pulse_assert(
            buffer_len <= gpo.configuration.max_action_return_value_size,
            ChainError::WasmRuntimeError(format!(
                "action return value size must be less or equal to {} bytes",
                gpo.configuration.max_action_return_value_size
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
