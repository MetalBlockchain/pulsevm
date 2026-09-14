use wasmer::{
    FunctionEnvMut,
    MemoryView,
    RuntimeError,
    WasmPtr,
};

use super::cost;
use crate::wasm_runtime::WasmContext;

#[inline]
pub(crate) fn checked_range(
    operation: &str,
    role: &str,
    ptr: WasmPtr<u8>,
    length: u32,
    view: &MemoryView<'_>,
) -> Result<std::ops::Range<usize>, RuntimeError> {
    let start = ptr.offset() as u64;
    let end = start.checked_add(length as u64).ok_or_else(|| {
        RuntimeError::new(format!(
            "{operation}: invalid {role} range: offset overflow"
        ))
    })?;
    if end > view.data_size() {
        return Err(RuntimeError::new(format!(
            "{operation}: invalid {role} range: out of bounds memory access"
        )));
    }
    let start = usize::try_from(start).map_err(|_| {
        RuntimeError::new(format!(
            "{operation}: invalid {role} range: offset does not fit the host"
        ))
    })?;
    let end = usize::try_from(end).map_err(|_| {
        RuntimeError::new(format!(
            "{operation}: invalid {role} range: end does not fit the host"
        ))
    })?;
    Ok(start..end)
}

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

    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::memory(src_size as u64))?;
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);
    let src = checked_range("memmove", "source", src_ptr, src_size, &view)?;
    let dest = checked_range("memmove", "destination", dest_ptr, src_size, &view)?;

    // A host intrinsic executes synchronously while WASM is suspended, so the
    // memory cannot grow or be accessed by guest code until this slice is
    // dropped. `copy_within` deliberately supports overlapping ranges.
    let data = unsafe { view.data_unchecked_mut() };
    data.copy_within(src, dest.start);

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

    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::memory(src_size as u64))?;
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);
    let src = checked_range("memcpy", "source", src_ptr, src_size, &view)?;
    let dest = checked_range("memcpy", "destination", dest_ptr, src_size, &view)?;

    // The explicit overlap check above means the source and destination can be
    // split into disjoint slices. WASM is suspended for the host call, so the
    // view remains stable for the copy.
    let data = unsafe { view.data_unchecked_mut() };
    if dest.start < src.start {
        let (before_src, from_src) = data.split_at_mut(src.start);
        before_src[dest].copy_from_slice(&from_src[..src_size as usize]);
    } else {
        let (before_dest, from_dest) = data.split_at_mut(dest.start);
        from_dest[..src_size as usize].copy_from_slice(&before_dest[src]);
    }

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

    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::memory(size as u64))?;
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);
    let dest = checked_range("memset", "destination", dest_ptr, size, &view)?;

    // std::memset semantics: int -> unsigned char (low byte only). WASM is
    // suspended for the host call, so this mutable view cannot alias guest work.
    let data = unsafe { view.data_unchecked_mut() };
    data[dest].fill(value as u8);

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

    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::memory(length as u64))?;
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);
    let dest = checked_range("memcmp", "destination", dest_ptr, length, &view)?;
    let src = checked_range("memcmp", "source", src_ptr, length, &view)?;

    // WASM is suspended for the host call, so the immutable view stays stable.
    let data = unsafe { view.data_unchecked() };

    // Normalized to -1/0/1, matching nodeos (raw memcmp magnitude is
    // implementation-defined and would be a determinism leak)
    Ok(match data[dest].cmp(&data[src]) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    })
}
