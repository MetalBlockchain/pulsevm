use wasmer::{FunctionEnvMut, RuntimeError, WasmPtr};

use crate::wasm_runtime::WasmContext;

pub fn get_context_free_data(
    mut env: FunctionEnvMut<WasmContext>,
    index: u32,
    buffer_ptr: WasmPtr<u8>,
    buffer_size: u32,
) -> Result<i32, RuntimeError> {
    let (env_data, store) = env.data_and_store_mut();

    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    // Bounds-check the destination before allocating a host buffer of the
    // guest-supplied size. `slice` uses checked arithmetic, so offset + len
    // near u32::MAX cannot wrap into a valid range.
    //
    // buffer_size == 0 is the size-query form: nodeos returns the packed size
    // without touching the buffer, so skip the range check entirely.
    if buffer_size > 0 {
        buffer_ptr
            .slice(&view, buffer_size)
            .map_err(|e| {
                RuntimeError::new(format!("get_context_free_data: invalid buffer range: {e}"))
            })?;
    }

    // Safe to allocate now: buffer_size is bounded by linear memory size.
    let mut scratch = vec![0u8; buffer_size as usize];

    let written = env_data
        .apply_context()
        .get_context_free_data(index, &mut scratch, buffer_size as usize)
        .map_err(|e| RuntimeError::new(format!("get_context_free_data failed: {}", e)))?;

    // Only write back when the context actually filled scratch:
    // -1 => out-of-range index, buffer_size == 0 => size query (nothing to copy).
    if written > 0 && buffer_size > 0 {
        let copy = (written as usize).min(scratch.len());
        buffer_ptr
            .slice(&view, copy as u32)
            .map_err(|e| {
                RuntimeError::new(format!("get_context_free_data: invalid buffer range: {e}"))
            })?
            .write_slice(&scratch[..copy])
            .map_err(|e| RuntimeError::new(format!("failed to write cfd: {}", e)))?;
    }

    Ok(written)
}
