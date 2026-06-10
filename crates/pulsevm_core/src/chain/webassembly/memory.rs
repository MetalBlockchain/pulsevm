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
    let mut data = vec![0u8; src_size as usize];
    view.read(src_ptr.offset() as u64, &mut data)?;
    view.write(dest_ptr.offset() as u64, &data)?;

    Ok(dest_ptr)
}

#[inline]
pub fn memcpy(
    mut env: FunctionEnvMut<WasmContext>,
    dest_ptr: WasmPtr<u8>,
    src_ptr: WasmPtr<u8>,
    src_size: u32,
) -> Result<WasmPtr<u8>, RuntimeError> {
    // EOSIO overlap check, before anything else: |dest - src| >= length,
    // else overlapping_memory_error. dest == src with size > 0 must fail.
    let diff = (dest_ptr.offset() as i64 - src_ptr.offset() as i64).unsigned_abs();
    if diff < src_size as u64 {
        return Err(RuntimeError::new(
            "memcpy can only accept non-aliasing pointers",
        ));
    }

    if src_size == 0 {
        return Ok(dest_ptr);
    }

    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);
    let mut data = vec![0u8; src_size as usize];
    view.read(src_ptr.offset() as u64, &mut data)?;
    view.write(dest_ptr.offset() as u64, &data)?;

    Ok(dest_ptr)
}

#[inline]
pub fn memset(
    mut env: FunctionEnvMut<WasmContext>,
    dest_ptr: WasmPtr<u8>,
    value: i32,
    size: u32,
) -> Result<WasmPtr<u8>, RuntimeError> {
    if size == 0 {
        return Ok(dest_ptr);
    }

    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    // std::memset semantics: int -> unsigned char (low byte only)
    let data = vec![value as u8; size as usize];
    view.write(dest_ptr.offset() as u64, &data)?;

    Ok(dest_ptr)
}

#[inline]
pub fn memcmp(
    mut env: FunctionEnvMut<WasmContext>,
    dest_ptr: WasmPtr<u8>,
    src_ptr: WasmPtr<u8>,
    length: u32,
) -> Result<i32, RuntimeError> {
    if length == 0 {
        return Ok(0);
    }

    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    let mut dest = vec![0u8; length as usize];
    view.read(dest_ptr.offset() as u64, &mut dest)?;
    let mut src = vec![0u8; length as usize];
    view.read(src_ptr.offset() as u64, &mut src)?;

    // Normalized to -1/0/1, matching nodeos (raw memcmp magnitude is
    // implementation-defined and would be a determinism leak)
    Ok(match dest.cmp(&src) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    })
}