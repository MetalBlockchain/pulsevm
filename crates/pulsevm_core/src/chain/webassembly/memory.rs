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

    // Bounds-check both ranges before allocating anything. `slice` uses checked
    // arithmetic, so offset + len near u32::MAX cannot wrap into a valid range.
    let src = src_ptr
        .slice(&view, src_size)
        .map_err(|e| RuntimeError::new(format!("memmove: invalid source range: {e}")))?;
    let dest = dest_ptr
        .slice(&view, src_size)
        .map_err(|e| RuntimeError::new(format!("memmove: invalid destination range: {e}")))?;

    // Safe to allocate now: src_size is bounded by linear memory size.
    let mut buf = vec![0u8; src_size as usize];
    src.read_slice(&mut buf)
        .map_err(|e| RuntimeError::new(format!("memmove: read failed: {e}")))?;
    dest.write_slice(&buf)
        .map_err(|e| RuntimeError::new(format!("memmove: write failed: {e}")))?;

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

    // Bounds-check both ranges before allocating anything. `slice` uses checked
    // arithmetic, so offset + len near u32::MAX cannot wrap into a valid range.
    let src = src_ptr
        .slice(&view, src_size)
        .map_err(|e| RuntimeError::new(format!("memcpy: invalid source range: {e}")))?;
    let dest = dest_ptr
        .slice(&view, src_size)
        .map_err(|e| RuntimeError::new(format!("memcpy: invalid destination range: {e}")))?;

    // Safe to allocate now: src_size is bounded by linear memory size.
    let mut buf = vec![0u8; src_size as usize];
    src.read_slice(&mut buf)
        .map_err(|e| RuntimeError::new(format!("memcpy: read failed: {e}")))?;
    dest.write_slice(&buf)
        .map_err(|e| RuntimeError::new(format!("memcpy: write failed: {e}")))?;

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

    // Bounds-check before allocating anything. `slice` uses checked arithmetic,
    // so offset + len near u32::MAX cannot wrap into a valid range.
    let dest = dest_ptr
        .slice(&view, size)
        .map_err(|e| RuntimeError::new(format!("memset: invalid destination range: {e}")))?;

    // std::memset semantics: int -> unsigned char (low byte only).
    // Safe to allocate now: size is bounded by linear memory size.
    let buf = vec![value as u8; size as usize];
    dest.write_slice(&buf)
        .map_err(|e| RuntimeError::new(format!("memset: write failed: {e}")))?;

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

    // Bounds-check both ranges before allocating anything. `slice` uses checked
    // arithmetic, so offset + len near u32::MAX cannot wrap into a valid range.
    let dest = dest_ptr
        .slice(&view, length)
        .map_err(|e| RuntimeError::new(format!("memcmp: invalid destination range: {e}")))?;
    let src = src_ptr
        .slice(&view, length)
        .map_err(|e| RuntimeError::new(format!("memcmp: invalid source range: {e}")))?;

    // Safe to allocate now: length is bounded by linear memory size.
    let mut dest_buf = vec![0u8; length as usize];
    dest.read_slice(&mut dest_buf)
        .map_err(|e| RuntimeError::new(format!("memcmp: read failed: {e}")))?;
    let mut src_buf = vec![0u8; length as usize];
    src.read_slice(&mut src_buf)
        .map_err(|e| RuntimeError::new(format!("memcmp: read failed: {e}")))?;

    // Normalized to -1/0/1, matching nodeos (raw memcmp magnitude is
    // implementation-defined and would be a determinism leak)
    Ok(match dest_buf.cmp(&src_buf) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    })
}
