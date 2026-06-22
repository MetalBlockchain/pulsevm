use wasmer::{FunctionEnvMut, RuntimeError, WasmPtr};

use crate::wasm_runtime::WasmContext;

pub fn get_context_free_data(
    mut env: FunctionEnvMut<WasmContext>,
    index: u32,
    buffer_ptr: WasmPtr<u8>,
    buffer_size: u32,
) -> Result<i32, RuntimeError> {
    let (env_data, store) = env.data_and_store_mut();

    let mut scratch = vec![0u8; buffer_size as usize];

    let written = env_data
        .apply_context()
        .get_context_free_data(index, &mut scratch, buffer_size as usize)
        .map_err(|e| RuntimeError::new(format!("get_context_free_data failed: {}", e)))?;

    // Only write back when the context actually filled scratch:
    // -1 => out-of-range index, buffer_size == 0 => size query (nothing to copy).
    if written > 0 && buffer_size > 0 {
        let memory = env_data
            .memory()
            .as_ref()
            .expect("Wasm memory not initialized");
        let view = memory.view(&store);

        let copy = (written as usize).min(scratch.len());
        view.write(buffer_ptr.offset() as u64, &scratch[..copy])
            .map_err(|e| RuntimeError::new(format!("failed to write cfd: {}", e)))?;
    }

    Ok(written)
}
