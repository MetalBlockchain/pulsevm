use pulsevm_builtins::floatuntidf;
use wasmer::{FunctionEnvMut, RuntimeError, WasmPtr};

use crate::wasm_runtime::WasmContext;

pub fn __ashlti3(
    mut env: FunctionEnvMut<WasmContext>,
    ret_ptr: WasmPtr<u8>,
    low: u64,
    high: u64,
    shift: u32,
) -> Result<(), RuntimeError> {
    let value = ((high as u128) << 64) | (low as u128);

    // fc::uint128::operator<<= explicitly defines shift >= 128 as zero —
    // NOT shift-masking like __ashrti3. checked_shl returns None at >= 128.
    let result = value.checked_shl(shift).unwrap_or(0);

    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    view.write(ret_ptr.offset() as u64, &result.to_le_bytes())?;

    Ok(())
}

pub fn __ashrti3(
    mut env: FunctionEnvMut<WasmContext>,
    ret_ptr: WasmPtr<u8>,
    low: u64,
    high: u64,
    shift: u32,
) -> Result<(), RuntimeError> {
    // Reassemble the i128: high word shifted up, low word OR'd in,
    // then *signed* shift right ("retain the signedness")
    let value = (((high as u128) << 64) | (low as u128)) as i128;

    // wrapping_shr masks the shift amount to & 127, matching what x86-64
    // codegen of the C++ does for shift >= 128 (hardware shifts mask cl,
    // branch tests bit 6) — see note below
    let result = value.wrapping_shr(shift);

    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    // legacy_ptr<__int128>: 16-byte write, bounds-checked, no alignment requirement
    view.write(ret_ptr.offset() as u64, &result.to_le_bytes())?;

    Ok(())
}

pub fn __lshlti3(
    mut env: FunctionEnvMut<WasmContext>,
    ret_ptr: WasmPtr<u8>,
    low: u64,
    high: u64,
    shift: u32,
) -> Result<(), RuntimeError> {
    let value = ((high as u128) << 64) | (low as u128);

    // Same fc::uint128 semantics as __ashlti3: shift >= 128 is defined as zero
    let result = value.checked_shl(shift).unwrap_or(0);

    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    view.write(ret_ptr.offset() as u64, &result.to_le_bytes())?;

    Ok(())
}

pub fn __lshrti3(
    mut env: FunctionEnvMut<WasmContext>,
    ret_ptr: WasmPtr<u8>,
    low: u64,
    high: u64,
    shift: u32,
) -> Result<(), RuntimeError> {
    let value = ((high as u128) << 64) | (low as u128);

    // Logical (zero-filling) right shift in u128, through the fc::uint128
    // path: operator>>= explicitly defines shift >= 128 as zero
    let result = value.checked_shr(shift).unwrap_or(0);

    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    view.write(ret_ptr.offset() as u64, &result.to_le_bytes())?;

    Ok(())
}

pub fn __divti3(
    mut env: FunctionEnvMut<WasmContext>,
    ret_ptr: WasmPtr<u8>,
    la: u64,
    ha: u64,
    lb: u64,
    hb: u64,
) -> Result<(), RuntimeError> {
    let lhs = (((ha as u128) << 64) | (la as u128)) as i128;
    let rhs = (((hb as u128) << 64) | (lb as u128)) as i128;

    if rhs == 0 {
        // EOS_ASSERT(..., arithmetic_exception, "divide by zero") —
        // a host-side error aborting the action, not a WASM trap
        return Err(RuntimeError::new("divide by zero"));
    }

    // i128::MIN / -1 must wrap to i128::MIN, matching compiler-rt's
    // sign-and-unsigned-divide implementation; a bare `/` would panic
    let result = lhs.wrapping_div(rhs);

    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    view.write(ret_ptr.offset() as u64, &result.to_le_bytes())?;

    Ok(())
}

pub fn __udivti3(
    mut env: FunctionEnvMut<WasmContext>,
    ret_ptr: WasmPtr<u8>,
    la: u64,
    ha: u64,
    lb: u64,
    hb: u64,
) -> Result<(), RuntimeError> {
    let lhs = ((ha as u128) << 64) | (la as u128);
    let rhs = ((hb as u128) << 64) | (lb as u128);

    if rhs == 0 {
        // arithmetic_exception, same classification as __divti3
        return Err(RuntimeError::new("divide by zero"));
    }

    // Unsigned: no MIN/-1 overflow case exists, plain division is total
    let result = lhs / rhs;

    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    view.write(ret_ptr.offset() as u64, &result.to_le_bytes())?;

    Ok(())
}

pub fn __multi3(
    mut env: FunctionEnvMut<WasmContext>,
    ret_ptr: WasmPtr<u8>,
    la: u64,
    ha: u64,
    lb: u64,
    hb: u64,
) -> Result<(), RuntimeError> {
    let lhs = (((ha as u128) << 64) | (la as u128)) as i128;
    let rhs = (((hb as u128) << 64) | (lb as u128)) as i128;

    // No assert in nodeos, and overflow truncates to the low 128 bits —
    // compiler-rt's __multi3 is a wrapping word multiply. Bare `*` would
    // panic in debug builds on overflow.
    let result = lhs.wrapping_mul(rhs);

    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    view.write(ret_ptr.offset() as u64, &result.to_le_bytes())?;

    Ok(())
}

pub fn __modti3(
    mut env: FunctionEnvMut<WasmContext>,
    ret_ptr: WasmPtr<u8>,
    la: u64,
    ha: u64,
    lb: u64,
    hb: u64,
) -> Result<(), RuntimeError> {
    let lhs = (((ha as u128) << 64) | (la as u128)) as i128;
    let rhs = (((hb as u128) << 64) | (lb as u128)) as i128;

    if rhs == 0 {
        // arithmetic_exception, same as the division pair
        return Err(RuntimeError::new("divide by zero"));
    }

    // i128::MIN % -1 must yield 0 without panicking (the lone overflow case)
    let result = lhs.wrapping_rem(rhs);

    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    view.write(ret_ptr.offset() as u64, &result.to_le_bytes())?;

    Ok(())
}

pub fn __umodti3(
    mut env: FunctionEnvMut<WasmContext>,
    ret_ptr: WasmPtr<u8>,
    la: u64,
    ha: u64,
    lb: u64,
    hb: u64,
) -> Result<(), RuntimeError> {
    let lhs = ((ha as u128) << 64) | (la as u128);
    let rhs = ((hb as u128) << 64) | (lb as u128);

    if rhs == 0 {
        return Err(RuntimeError::new("divide by zero"));
    }

    // Unsigned remainder is total once the divisor is nonzero — no
    // overflow case, bare % cannot panic
    let result = lhs % rhs;

    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    view.write(ret_ptr.offset() as u64, &result.to_le_bytes())?;

    Ok(())
}

pub fn __floatuntidf(
    _env: FunctionEnvMut<WasmContext>,
    la: u64,
    ha: u64,
) -> Result<f64, RuntimeError> {
    Ok(floatuntidf(((ha as u128) << 64) | (la as u128)))
}