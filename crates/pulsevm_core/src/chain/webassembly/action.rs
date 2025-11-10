use std::cmp::min;

use wasmtime::Caller;

use crate::chain::{
    controller::Controller, error::ChainError, utils::pulse_assert, wasm_runtime::WasmContext,
};

pub fn action_data_size() -> impl Fn(Caller<'_, WasmContext>) -> Result<i32, wasmtime::Error> {
    |caller| {
        return Ok(caller.data().action().data().len() as i32);
    }
}

pub fn read_action_data()
-> impl Fn(Caller<'_, WasmContext>, u32, u32) -> Result<i32, wasmtime::Error> {
    |mut caller, buffer, buffer_size| {
        // Extract the data early
        let context = caller.data().apply_context();
        let action_data = context.get_action().data();
        let total_len = action_data.len() as u32;
        let copy_size = min(buffer_size, total_len);

        if copy_size == 0 {
            return Ok(total_len as i32);
        }

        // Clone the slice you want to write
        let bytes_to_write = action_data[..copy_size as usize].to_vec();

        // Now caller can be mutably borrowed safely
        let memory = caller
            .get_export("memory")
            .and_then(|ext| ext.into_memory())
            .ok_or_else(|| anyhow::anyhow!("memory export not found"))?;

        memory.write(&mut caller, buffer as usize, &bytes_to_write)?;

        Ok(copy_size as i32)
    }
}

pub fn current_receiver() -> impl Fn(Caller<'_, WasmContext>) -> Result<u64, wasmtime::Error> {
    |caller| {
        return Ok(caller.data().receiver().as_u64());
    }
}

pub fn get_self() -> impl Fn(Caller<'_, WasmContext>) -> Result<u64, wasmtime::Error> {
    |caller| {
        return Ok(caller.data().receiver().as_u64());
    }
}

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
