use pulsevm_ffi::{
    addtf3, cmptf2, divtf3, eqtf2, extenddftf2, extendsftf2, fixdfti, fixsfti, fixtfdi, fixtfsi, fixtfti, fixunsdfti, fixunssfti, fixunstfdi, fixunstfsi, fixunstfti, floatditf, floatsidf, floatsitf, floattidf, floatunditf, floatunsitf, floatuntidf, getf2, gttf2, letf2, lttf2, multf3, negtf2, netf2, subtf3, trunctfdf2, trunctfsf2, unordtf2
};
use wasmer::{FunctionEnvMut, RuntimeError, WasmPtr};

use crate::{
    chain::webassembly::{write_i128_ffi, write_u128_ffi},
    wasm_runtime::WasmContext,
};

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

pub fn __addtf3(
    mut env: FunctionEnvMut<WasmContext>,
    ret_ptr: WasmPtr<u8>,
    la: u64,
    ha: u64,
    lb: u64,
    hb: u64,
) -> Result<(), RuntimeError> {
    let result = addtf3(la, ha, lb, hb);
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    let mut bytes = [0u8; 16];
    bytes[0..8].copy_from_slice(&result.lo.to_le_bytes());
    bytes[8..16].copy_from_slice(&result.hi.to_le_bytes());

    view.write(ret_ptr.offset() as u64, &bytes)
        .map_err(|e| RuntimeError::new(e.to_string()))?;
    Ok(())
}

pub fn __subtf3(
    mut env: FunctionEnvMut<WasmContext>,
    ret_ptr: WasmPtr<u8>,
    la: u64,
    ha: u64,
    lb: u64,
    hb: u64,
) -> Result<(), RuntimeError> {
    let result = subtf3(la, ha, lb, hb);
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    let mut bytes = [0u8; 16];
    bytes[0..8].copy_from_slice(&result.lo.to_le_bytes());
    bytes[8..16].copy_from_slice(&result.hi.to_le_bytes());

    view.write(ret_ptr.offset() as u64, &bytes)
        .map_err(|e| RuntimeError::new(e.to_string()))?;
    Ok(())
}

pub fn __multf3(
    mut env: FunctionEnvMut<WasmContext>,
    ret_ptr: WasmPtr<u8>,
    la: u64,
    ha: u64,
    lb: u64,
    hb: u64,
) -> Result<(), RuntimeError> {
    let result = multf3(la, ha, lb, hb);
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    let mut bytes = [0u8; 16];
    bytes[0..8].copy_from_slice(&result.lo.to_le_bytes());
    bytes[8..16].copy_from_slice(&result.hi.to_le_bytes());

    view.write(ret_ptr.offset() as u64, &bytes)
        .map_err(|e| RuntimeError::new(e.to_string()))?;
    Ok(())
}

pub fn __divtf3(
    mut env: FunctionEnvMut<WasmContext>,
    ret_ptr: WasmPtr<u8>,
    la: u64,
    ha: u64,
    lb: u64,
    hb: u64,
) -> Result<(), RuntimeError> {
    let result = divtf3(la, ha, lb, hb);
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    let mut bytes = [0u8; 16];
    bytes[0..8].copy_from_slice(&result.lo.to_le_bytes());
    bytes[8..16].copy_from_slice(&result.hi.to_le_bytes());

    view.write(ret_ptr.offset() as u64, &bytes)
        .map_err(|e| RuntimeError::new(e.to_string()))?;
    Ok(())
}

pub fn __negtf2(
    mut env: FunctionEnvMut<WasmContext>,
    ret_ptr: WasmPtr<u8>,
    la: u64,
    ha: u64,
) -> Result<(), RuntimeError> {
    // Flip the sign bit (bit 63 of the high limb); low limb unchanged.
    let result = negtf2(la, ha);
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    let mut bytes = [0u8; 16];
    bytes[0..8].copy_from_slice(&result.lo.to_le_bytes());
    bytes[8..16].copy_from_slice(&result.hi.to_le_bytes());

    view.write(ret_ptr.offset() as u64, &bytes)
        .map_err(|e| RuntimeError::new(e.to_string()))?;
    Ok(())
}

pub fn __extendsftf2(
    mut env: FunctionEnvMut<WasmContext>,
    ret_ptr: WasmPtr<u8>,
    f: f32,
) -> Result<(), RuntimeError> {
    let result = extendsftf2(f);
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    // float128_t is two little-endian u64 limbs: lo (low) then hi (high).
    let mut bytes = [0u8; 16];
    bytes[0..8].copy_from_slice(&result.lo.to_le_bytes());
    bytes[8..16].copy_from_slice(&result.hi.to_le_bytes());

    view.write(ret_ptr.offset() as u64, &bytes)
        .map_err(|e| RuntimeError::new(e.to_string()))?;
    Ok(())
}

pub fn __extenddftf2(
    mut env: FunctionEnvMut<WasmContext>,
    ret_ptr: WasmPtr<u8>,
    d: f64,
) -> Result<(), RuntimeError> {
    let result = extenddftf2(d);
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    let mut bytes = [0u8; 16];
    bytes[0..8].copy_from_slice(&result.lo.to_le_bytes());
    bytes[8..16].copy_from_slice(&result.hi.to_le_bytes());

    view.write(ret_ptr.offset() as u64, &bytes)
        .map_err(|e| RuntimeError::new(e.to_string()))?;
    Ok(())
}

pub fn __trunctfdf2(
    env: FunctionEnvMut<WasmContext>,
    la: u64,
    ha: u64,
) -> Result<f64, RuntimeError> {
    Ok(trunctfdf2(la, ha))
}

pub fn __trunctfsf2(
    env: FunctionEnvMut<WasmContext>,
    la: u64,
    ha: u64,
) -> Result<f32, RuntimeError> {
    Ok(trunctfsf2(la, ha))
}

pub fn __fixtfsi(_env: FunctionEnvMut<WasmContext>, la: u64, ha: u64) -> Result<i32, RuntimeError> {
    Ok(fixtfsi(la, ha))
}

pub fn __fixtfdi(_env: FunctionEnvMut<WasmContext>, la: u64, ha: u64) -> Result<i64, RuntimeError> {
    Ok(fixtfdi(la, ha))
}

pub fn __fixtfti(
    mut env: FunctionEnvMut<WasmContext>,
    ret_ptr: WasmPtr<i128>,
    l: u64,
    h: u64,
) -> Result<(), RuntimeError> {
    let result = fixtfti(l, h); // the f128 -> i128 core function ported earlier
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    write_i128_ffi(&view, ret_ptr, result)?;
    Ok(())
}

pub fn __fixunstfsi(
    _env: FunctionEnvMut<WasmContext>,
    la: u64,
    ha: u64,
) -> Result<u32, RuntimeError> {
    Ok(fixunstfsi(la, ha))
}

pub fn __fixunstfdi(
    _env: FunctionEnvMut<WasmContext>,
    la: u64,
    ha: u64,
) -> Result<u64, RuntimeError> {
    Ok(fixunstfdi(la, ha))
}

pub fn __fixunstfti(
    mut env: FunctionEnvMut<WasmContext>,
    ret_ptr: WasmPtr<u128>,
    l: u64,
    h: u64,
) -> Result<(), RuntimeError> {
    let result = fixunstfti(l, h); // the f128 -> u128 core function ported earlier
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);
    write_u128_ffi(&view, ret_ptr, result)?;
    Ok(())
}

pub fn __fixsfti(
    mut env: FunctionEnvMut<WasmContext>,
    ret_ptr: WasmPtr<i128>,
    a: f32,
) -> Result<(), RuntimeError> {
    let result = fixsfti(a);
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);
    write_i128_ffi(&view, ret_ptr, result)?;
    Ok(())
}

pub fn __fixdfti(
    mut env: FunctionEnvMut<WasmContext>,
    ret_ptr: WasmPtr<i128>,
    a: f64,
) -> Result<(), RuntimeError> {
    let result = fixdfti(a); // to_softfloat64 -> u64 bit pattern
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);
    write_i128_ffi(&view, ret_ptr, result)?;
    Ok(())
}

pub fn __fixunssfti(
    mut env: FunctionEnvMut<WasmContext>,
    ret_ptr: WasmPtr<u128>,
    a: f32,
) -> Result<(), RuntimeError> {
    let result = fixunssfti(a);
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);
    write_u128_ffi(&view, ret_ptr, result)?;
    Ok(())
}

pub fn __fixunsdfti(
    mut env: FunctionEnvMut<WasmContext>,
    ret_ptr: WasmPtr<u128>,
    a: f64,
) -> Result<(), RuntimeError> {
    let result = fixunsdfti(a);
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);
    write_u128_ffi(&view, ret_ptr, result)?;
    Ok(())
}

pub fn __floatsidf(_env: FunctionEnvMut<WasmContext>, i: i32) -> Result<f64, RuntimeError> {
    Ok(floatsidf(i))
}

pub fn __floatsitf(
    mut env: FunctionEnvMut<WasmContext>,
    ret_ptr: WasmPtr<u8>,
    i: i32,
) -> Result<(), RuntimeError> {
    let result = floatsitf(i);

    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    let mut bytes = [0u8; 16];
    bytes[0..8].copy_from_slice(&result.lo.to_le_bytes());
    bytes[8..16].copy_from_slice(&result.hi.to_le_bytes());

    view.write(ret_ptr.offset() as u64, &bytes)
        .map_err(|e| RuntimeError::new(e.to_string()))?;
    Ok(())
}

pub fn __floatditf(
    mut env: FunctionEnvMut<WasmContext>,
    ret_ptr: WasmPtr<u8>,
    i: u64,
) -> Result<(), RuntimeError> {
    let result = floatditf(i);
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    let mut bytes = [0u8; 16];
    bytes[0..8].copy_from_slice(&result.lo.to_le_bytes());
    bytes[8..16].copy_from_slice(&result.hi.to_le_bytes());

    view.write(ret_ptr.offset() as u64, &bytes)
        .map_err(|e| RuntimeError::new(e.to_string()))?;
    Ok(())
}

pub fn __floatunsitf(
    mut env: FunctionEnvMut<WasmContext>,
    ret_ptr: WasmPtr<u8>,
    i: u32,
) -> Result<(), RuntimeError> {
    let result = floatunsitf(i);

    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    let mut bytes = [0u8; 16];
    bytes[0..8].copy_from_slice(&result.lo.to_le_bytes());
    bytes[8..16].copy_from_slice(&result.hi.to_le_bytes());

    view.write(ret_ptr.offset() as u64, &bytes)
        .map_err(|e| RuntimeError::new(e.to_string()))?;
    Ok(())
}

pub fn __floatunditf(
    mut env: FunctionEnvMut<WasmContext>,
    ret_ptr: WasmPtr<u8>,
    i: u64,
) -> Result<(), RuntimeError> {
    let result = floatunditf(i);

    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    let mut bytes = [0u8; 16];
    bytes[0..8].copy_from_slice(&result.lo.to_le_bytes());
    bytes[8..16].copy_from_slice(&result.hi.to_le_bytes());

    view.write(ret_ptr.offset() as u64, &bytes)
        .map_err(|e| RuntimeError::new(e.to_string()))?;
    Ok(())
}

pub fn __floattidf(
    _env: FunctionEnvMut<WasmContext>,
    la: u64,
    ha: u64,
) -> Result<f64, RuntimeError> {
    Ok(floattidf(la, ha))
}

pub fn __floatuntidf(
    _env: FunctionEnvMut<WasmContext>,
    la: u64,
    ha: u64,
) -> Result<f64, RuntimeError> {
    Ok(floatuntidf(la, ha))
}

pub fn __eqtf2(
    _env: FunctionEnvMut<WasmContext>,
    la: u64,
    ha: u64,
    lb: u64,
    hb: u64,
) -> Result<i32, RuntimeError> {
    Ok(eqtf2(la, ha, lb, hb))
}

pub fn __netf2(
    _env: FunctionEnvMut<WasmContext>,
    la: u64,
    ha: u64,
    lb: u64,
    hb: u64,
) -> Result<i32, RuntimeError> {
    Ok(netf2(la, ha, lb, hb))
}

pub fn __getf2(
    _env: FunctionEnvMut<WasmContext>,
    la: u64,
    ha: u64,
    lb: u64,
    hb: u64,
) -> Result<i32, RuntimeError> {
    Ok(getf2(la, ha, lb, hb))
}

pub fn __gttf2(
    _env: FunctionEnvMut<WasmContext>,
    la: u64,
    ha: u64,
    lb: u64,
    hb: u64,
) -> Result<i32, RuntimeError> {
    Ok(gttf2(la, ha, lb, hb))
}

pub fn __letf2(
    _env: FunctionEnvMut<WasmContext>,
    la: u64,
    ha: u64,
    lb: u64,
    hb: u64,
) -> Result<i32, RuntimeError> {
    Ok(letf2(la, ha, lb, hb))
}

pub fn __lttf2(
    _env: FunctionEnvMut<WasmContext>,
    la: u64,
    ha: u64,
    lb: u64,
    hb: u64,
) -> Result<i32, RuntimeError> {
    Ok(lttf2(la, ha, lb, hb))
}

pub fn __cmptf2(
    _env: FunctionEnvMut<WasmContext>,
    la: u64,
    ha: u64,
    lb: u64,
    hb: u64,
) -> Result<i32, RuntimeError> {
    Ok(cmptf2(la, ha, lb, hb))
}

pub fn __unordtf2(
    _env: FunctionEnvMut<WasmContext>,
    la: u64,
    ha: u64,
    lb: u64,
    hb: u64,
) -> Result<i32, RuntimeError> {
    Ok(unordtf2(la, ha, lb, hb))
}
