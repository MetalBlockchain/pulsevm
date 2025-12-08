use wasmer::FunctionEnvMut;
use wasmtime::Caller;

use crate::chain::{
    controller::Controller, error::ChainError, utils::pulse_assert, wasm_runtime::WasmContext,
};

#[inline]
pub fn action_data_size(env: FunctionEnvMut<WasmContext>) -> i32 {
    env.data().action().data().len() as i32
}

#[inline]
pub fn read_action_data(env: FunctionEnvMut<WasmContext>, buffer: u32, buffer_size: u32) -> i32 {
    // Extract the data early
    let action_data = env.data().action().data();
    let total_len = action_data.len() as u32;
    let copy_size = buffer_size.min(total_len);

    if copy_size == 0 {
        return total_len as i32;
    }

    let memory = env
        .data()
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&env);
    let start = buffer as u64;
    view.write(start, &action_data[..copy_size as usize])
        .expect("Failed to write action data to wasm memory");
    copy_size as i32
}

#[inline]
pub fn current_receiver(env: FunctionEnvMut<WasmContext>) -> u64 {
    env.data().receiver().as_u64()
}

#[inline]
pub fn set_action_return_value()
-> impl Fn(Caller<'_, WasmContext>, u32, u32) -> Result<(), wasmtime::Error> {
    |mut caller, buffer_ptr, buffer_len| {
        {
            let context = caller.data().apply_context();
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

        let memory = caller
            .get_export("memory")
            .and_then(|ext| ext.into_memory())
            .ok_or_else(|| anyhow::anyhow!("memory export not found"))?;
        let mut src_bytes = vec![0u8; buffer_len as usize];
        memory.read(&caller, buffer_ptr as usize, &mut src_bytes)?;
        let context = caller.data().apply_context();
        context.set_action_return_value(src_bytes);

        return Ok(());
    }
}
