use wasmer::{FunctionEnvMut, RuntimeError, WasmPtr};

use crate::wasm_runtime::WasmContext;

#[inline]
pub fn memmove(
    mut env: FunctionEnvMut<WasmContext>,
    dest_ptr: WasmPtr<u8>,
    src_ptr: WasmPtr<u8>,
    src_size: u32,
) -> Result<WasmPtr<u8>, RuntimeError> {
    if src_size == 0 {
        return Ok(dest_ptr);
    }

    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    // Bounds-check + obtain access guards (no Vec)
    let mut dest_access = dest_ptr
        .slice(&view, src_size)
        .map_err(|e| RuntimeError::new(format!("memmove: invalid dest range: {e}")))?
        .access()
        .map_err(|e| RuntimeError::new(format!("memmove: cannot access dest: {e}")))?;

    let src_access = src_ptr
        .slice(&view, src_size)
        .map_err(|e| RuntimeError::new(format!("memmove: invalid src range: {e}")))?
        .access()
        .map_err(|e| RuntimeError::new(format!("memmove: cannot access src: {e}")))?;

    let dst: &mut [u8] = dest_access.as_mut();
    let src: &[u8] = src_access.as_ref();

    // memmove semantics: overlap-safe
    unsafe {
        std::ptr::copy(src.as_ptr(), dst.as_mut_ptr(), src_size as usize);
    }

    Ok(dest_ptr)
}
