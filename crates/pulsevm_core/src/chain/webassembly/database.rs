use pulsevm_database::{
    Float128,
    U256,
};
use pulsevm_error::ChainError;
use wasmer::{
    FunctionEnvMut,
    RuntimeError,
    WasmPtr,
};

use super::cost;
use crate::chain::{
    wasm_runtime::WasmContext,
    webassembly::{
        context_aware_check,
        memory::checked_range,
        read_float128,
        read_u64,
        read_u128,
        read_u256,
        write_float128,
        write_u64,
        write_u128,
        write_u256,
    },
};

// A NaN is never a valid idx_double / idx_long_double secondary key. chainbase
// orders these with a raw f64_lt / f128_lt (soft_double_less in
// contract_table_objects.hpp); NaN compares false both ways, so it breaks the
// strict-weak ordering boost's multi_index needs — UB. The arena mirror orders
// by total_cmp (shadow.rs), which does give NaN a slot, so the same key would
// sort differently there and fork. The reference intrinsics reject it too, so we
// match them here, at the one boundary every contract key crosses. store/update/
// find_secondary/lowerbound/upperbound check it; find_primary doesn't (secondary
// is an output). Message text matches the reference.
const SECONDARY_KEY_NAN_MSG: &str = "NaN is not an allowed value for a secondary key";

/// Reject a NaN 64-bit (`f64` / `idx_double`) secondary key.
fn reject_nan_f64(secondary: u64) -> Result<(), RuntimeError> {
    if f64::from_bits(secondary).is_nan() {
        return Err(ChainError::TransactionError(SECONDARY_KEY_NAN_MSG.into()).into());
    }
    Ok(())
}

/// Reject a NaN 128-bit (`long double` / `idx_long_double`) secondary key. No
/// native f128, so classify from the bits.
fn reject_nan_f128(secondary: &Float128) -> Result<(), RuntimeError> {
    // binary128 = sign(1) | exponent(15) | mantissa(112). NaN is exponent all
    // ones with a non-zero mantissa: exponent is bits 48..=62 of the high word,
    // mantissa is the low 48 bits of hi plus all of lo.
    let exponent = (secondary.hi >> 48) & 0x7FFF;
    let mantissa_nonzero = (secondary.hi & 0x0000_FFFF_FFFF_FFFF) != 0 || secondary.lo != 0;
    if exponent == 0x7FFF && mantissa_nonzero {
        return Err(ChainError::TransactionError(SECONDARY_KEY_NAN_MSG.into()).into());
    }
    Ok(())
}

pub fn db_find_i64(
    mut env: FunctionEnvMut<WasmContext>,
    code: u64,
    scope: u64,
    table: u64,
    id: u64,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_FIND)?;
    let context = env_data.apply_context_mut();
    let result = context.db_find_i64(code, scope, table, id)?;
    Ok(result)
}

pub fn db_store_i64(
    mut env: FunctionEnvMut<WasmContext>,
    scope: u64,
    table: u64,
    payer: u64,
    id: u64,
    buffer_ptr: WasmPtr<u8>,
    buffer_len: u32,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(
        &mut store,
        cost::DB_STORE + cost::db_value_per_byte(buffer_len as u64),
    )?;
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized")
        .clone();
    let view = memory.view(&store);
    let source = checked_range("db_store_i64", "source", buffer_ptr, buffer_len, &view)?;
    // The row owns its bytes, so one allocation remains necessary. Copying from
    // the suspended guest's stable linear-memory slice avoids Wasmer's slower
    // element-wise WasmSlice read path.
    let data = unsafe { view.data_unchecked() };
    let src_bytes = data[source].to_vec();

    let context = env_data.apply_context_mut();
    let result = context.db_store_i64(scope, table, payer, id, src_bytes.into())?;
    Ok(result)
}

pub fn db_get_i64(
    mut env: FunctionEnvMut<WasmContext>,
    itr: i32,
    buffer_ptr: WasmPtr<u8>,
    buffer_len: u32,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(
        &mut store,
        cost::DB_ITERATE + cost::db_value_per_byte(buffer_len as u64),
    )?;
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized")
        .clone();
    let view = memory.view(&store);
    let destination = checked_range("db_get_i64", "destination", buffer_ptr, buffer_len, &view)?;
    // WASM is suspended for the host call, so the database can copy the row
    // directly into guest memory without an intermediate allocation and copy.
    let data = unsafe { view.data_unchecked_mut() };
    let context = env_data.apply_context();
    let result = context.db_get_i64(itr, &mut data[destination])?;
    Ok(result)
}

pub fn db_update_i64(
    mut env: FunctionEnvMut<WasmContext>,
    itr: i32,
    payer: u64,
    buffer_ptr: WasmPtr<u8>,
    buffer_len: u32,
) -> Result<(), RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(
        &mut store,
        cost::DB_STORE + cost::db_value_per_byte(buffer_len as u64),
    )?;
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized")
        .clone();
    let view = memory.view(&store);
    let source = checked_range("db_update_i64", "source", buffer_ptr, buffer_len, &view)?;
    // WASM is suspended for the host call and database mutation cannot touch
    // guest memory, so the stable source slice needs no temporary Vec.
    let data = unsafe { view.data_unchecked() };

    let context = env_data.apply_context_mut();
    context.db_update_i64(itr, &payer.into(), &data[source])?;
    Ok(())
}

pub fn db_remove_i64(mut env: FunctionEnvMut<WasmContext>, itr: i32) -> Result<(), RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_STORE)?;
    let context = env_data.apply_context_mut();
    context.db_remove_i64(itr)?;
    Ok(())
}

pub fn db_next_i64(
    mut env: FunctionEnvMut<WasmContext>,
    itr: i32,
    primary_ptr: WasmPtr<u8>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_ITERATE)?;
    let context = env_data.apply_context_mut();
    let mut next_primary = 0u64;
    let res = context.db_next_i64(itr, &mut next_primary)?;

    if res >= 0 {
        let (env_data, store) = env.data_and_store_mut();
        let memory = env_data
            .memory()
            .as_ref()
            .expect("Wasm memory not initialized");
        let view = memory.view(&store);
        let slice = primary_ptr.slice(&view, 8)?;
        let dest_bytes = next_primary.to_le_bytes(); // Convert to little-endian bytes, which is standard for WASM
        slice.write_slice(&dest_bytes)?;
    }

    Ok(res)
}

pub fn db_previous_i64(
    mut env: FunctionEnvMut<WasmContext>,
    itr: i32,
    primary_ptr: WasmPtr<u8>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_ITERATE)?;
    let context = env_data.apply_context_mut();
    let mut next_primary = 0u64;
    let res = context.db_previous_i64(itr, &mut next_primary)?;

    if res >= 0 {
        let (env_data, store) = env.data_and_store_mut();
        let memory = env_data
            .memory()
            .as_ref()
            .expect("Wasm memory not initialized");
        let view = memory.view(&store);
        let slice = primary_ptr.slice(&view, 8)?;
        let dest_bytes = next_primary.to_le_bytes(); // Convert to little-endian bytes, which is standard for WASM
        slice.write_slice(&dest_bytes)?;
    }

    Ok(res)
}

pub fn db_lowerbound_i64(
    mut env: FunctionEnvMut<WasmContext>,
    code: u64,
    scope: u64,
    table: u64,
    primary: u64,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_FIND)?;
    let context = env_data.apply_context_mut();
    let res = context.db_lowerbound_i64(code.into(), scope.into(), table.into(), primary)?;
    Ok(res)
}

pub fn db_upperbound_i64(
    mut env: FunctionEnvMut<WasmContext>,
    code: u64,
    scope: u64,
    table: u64,
    primary: u64,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_FIND)?;
    let context = env_data.apply_context_mut();
    let res = context.db_upperbound_i64(code.into(), scope.into(), table.into(), primary)?;
    Ok(res)
}

pub fn db_end_i64(
    mut env: FunctionEnvMut<WasmContext>,
    code: u64,
    scope: u64,
    table: u64,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_FIND)?;
    let context = env_data.apply_context_mut();
    Ok(context.db_end_i64(code.into(), scope.into(), table.into())?)
}

pub fn db_idx64_store(
    mut env: FunctionEnvMut<WasmContext>,
    scope: u64,
    table: u64,
    payer: u64,
    id: u64,
    secondary_ptr: WasmPtr<u64>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_STORE)?;
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let secondary: u64 = read_u64(&view, secondary_ptr)?;
    let context = env_data.apply_context_mut();
    let result = context.db_idx64_store(scope, table, payer, id, secondary)?;
    Ok(result)
}

pub fn db_idx64_update(
    mut env: FunctionEnvMut<WasmContext>,
    itr: i32,
    payer: u64,
    secondary_ptr: WasmPtr<u64>,
) -> Result<(), RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_STORE)?;
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let secondary: u64 = read_u64(&view, secondary_ptr)?;

    let context = env_data.apply_context_mut();
    context.db_idx64_update(itr, &payer.into(), secondary)?;
    Ok(())
}

pub fn db_idx64_remove(mut env: FunctionEnvMut<WasmContext>, itr: i32) -> Result<(), RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_STORE)?;
    let context = env_data.apply_context_mut();
    context.db_idx64_remove(itr)?;
    Ok(())
}

pub fn db_idx64_find_secondary(
    mut env: FunctionEnvMut<WasmContext>,
    code: u64,
    scope: u64,
    table: u64,
    secondary_ptr: WasmPtr<u64>,
    primary_ptr: WasmPtr<u64>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_FIND)?;

    // Clone the memory handle so the borrow on env_data is released
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized")
        .clone();

    // Read input from Wasm memory
    let view = memory.view(&store);
    let secondary: u64 = read_u64(&view, secondary_ptr)?;

    // Now safe to borrow env_data mutably
    let mut primary: u64 = read_u64(&view, primary_ptr)?;
    let context = env_data.apply_context_mut();
    let res = context.db_idx64_find_secondary(
        code.into(),
        scope.into(),
        table.into(),
        secondary,
        &mut primary,
    )?;

    // Write result back to Wasm memory
    write_u64(&view, primary_ptr, primary)?;

    Ok(res)
}

pub fn db_idx64_find_primary(
    mut env: FunctionEnvMut<WasmContext>,
    code: u64,
    scope: u64,
    table: u64,
    secondary_ptr: WasmPtr<u64>,
    primary: u64,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_FIND)?;

    // Clone the memory handle so the borrow on env_data is released
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized")
        .clone();

    // Now safe to borrow env_data mutably
    let view = memory.view(&store);
    let mut secondary: u64 = read_u64(&view, secondary_ptr)?;
    let context = env_data.apply_context_mut();
    let res = context.db_idx64_find_primary(
        code.into(),
        scope.into(),
        table.into(),
        &mut secondary,
        primary,
    )?;

    // Write result back to Wasm memory
    write_u64(&view, secondary_ptr, secondary)?;

    Ok(res)
}

pub fn db_idx64_lowerbound(
    mut env: FunctionEnvMut<WasmContext>,
    code: u64,
    scope: u64,
    table: u64,
    secondary_ptr: WasmPtr<u64>,
    primary_ptr: WasmPtr<u64>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_FIND)?;

    // Clone the memory handle so the borrow on env_data is released
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized")
        .clone();

    // Read input from Wasm memory
    let view = memory.view(&store);
    let mut primary: u64 = read_u64(&view, primary_ptr)?;
    let mut secondary: u64 = read_u64(&view, secondary_ptr)?;

    // Now safe to borrow env_data mutably
    let context = env_data.apply_context_mut();
    let res = context.db_idx64_lowerbound(
        code.into(),
        scope.into(),
        table.into(),
        &mut secondary,
        &mut primary,
    )?;

    // Write result back to Wasm memory
    write_u64(&view, secondary_ptr, secondary)?;
    write_u64(&view, primary_ptr, primary)?;

    Ok(res)
}

pub fn db_idx64_upperbound(
    mut env: FunctionEnvMut<WasmContext>,
    code: u64,
    scope: u64,
    table: u64,
    secondary_ptr: WasmPtr<u64>,
    primary_ptr: WasmPtr<u64>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_FIND)?;

    // Clone the memory handle so the borrow on env_data is released
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized")
        .clone();

    // Read input from Wasm memory
    let view = memory.view(&store);
    let mut primary: u64 = read_u64(&view, primary_ptr)?;
    let mut secondary: u64 = read_u64(&view, secondary_ptr)?;

    // Now safe to borrow env_data mutably
    let context = env_data.apply_context_mut();
    let res = context.db_idx64_upperbound(
        code.into(),
        scope.into(),
        table.into(),
        &mut secondary,
        &mut primary,
    )?;

    // Write result back to Wasm memory
    write_u64(&view, secondary_ptr, secondary)?;
    write_u64(&view, primary_ptr, primary)?;

    Ok(res)
}

pub fn db_idx64_end(
    mut env: FunctionEnvMut<WasmContext>,
    code: u64,
    scope: u64,
    table: u64,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_FIND)?;
    let context = env_data.apply_context_mut();
    Ok(context.db_idx64_end(code.into(), scope.into(), table.into())?)
}

pub fn db_idx64_next(
    mut env: FunctionEnvMut<WasmContext>,
    itr: i32,
    primary_ptr: WasmPtr<u64>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_ITERATE)?;
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let mut next_primary = read_u64(&view, primary_ptr)?;
    let context = env_data.apply_context_mut();
    let res = context.db_idx64_next(itr, &mut next_primary)?;
    write_u64(&view, primary_ptr, next_primary)?;

    Ok(res)
}

pub fn db_idx64_previous(
    mut env: FunctionEnvMut<WasmContext>,
    itr: i32,
    primary_ptr: WasmPtr<u64>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_ITERATE)?;
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let mut next_primary = read_u64(&view, primary_ptr)?;
    let context = env_data.apply_context_mut();
    let res = context.db_idx64_previous(itr, &mut next_primary)?;
    write_u64(&view, primary_ptr, next_primary)?;

    Ok(res)
}

pub fn db_idx128_store(
    mut env: FunctionEnvMut<WasmContext>,
    scope: u64,
    table: u64,
    payer: u64,
    id: u64,
    secondary_ptr: WasmPtr<u128>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_STORE)?;
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let secondary: u128 = read_u128(&view, secondary_ptr)?;
    let context = env_data.apply_context_mut();
    let result = context.db_idx128_store(scope, table, payer, id, secondary)?;
    Ok(result)
}

pub fn db_idx128_update(
    mut env: FunctionEnvMut<WasmContext>,
    itr: i32,
    payer: u64,
    secondary_ptr: WasmPtr<u128>,
) -> Result<(), RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_STORE)?;
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let secondary: u128 = read_u128(&view, secondary_ptr)?;

    let context = env_data.apply_context_mut();
    context.db_idx128_update(itr, &payer.into(), secondary)?;
    Ok(())
}

pub fn db_idx128_remove(
    mut env: FunctionEnvMut<WasmContext>,
    itr: i32,
) -> Result<(), RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_STORE)?;
    let context = env_data.apply_context_mut();
    context.db_idx128_remove(itr)?;
    Ok(())
}

pub fn db_idx128_find_secondary(
    mut env: FunctionEnvMut<WasmContext>,
    code: u64,
    scope: u64,
    table: u64,
    secondary_ptr: WasmPtr<u128>,
    primary_ptr: WasmPtr<u64>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_FIND)?;

    // Clone the memory handle so the borrow on env_data is released
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized")
        .clone();

    // Read input from Wasm memory
    let view = memory.view(&store);
    let secondary: u128 = read_u128(&view, secondary_ptr)?;

    // Now safe to borrow env_data mutably
    let mut primary: u64 = read_u64(&view, primary_ptr)?;
    let context = env_data.apply_context_mut();
    let res = context.db_idx128_find_secondary(
        code.into(),
        scope.into(),
        table.into(),
        secondary,
        &mut primary,
    )?;

    // Write result back to Wasm memory
    write_u64(&view, primary_ptr, primary)?;

    Ok(res)
}

pub fn db_idx128_find_primary(
    mut env: FunctionEnvMut<WasmContext>,
    code: u64,
    scope: u64,
    table: u64,
    secondary_ptr: WasmPtr<u128>,
    primary: u64,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_FIND)?;

    // Clone the memory handle so the borrow on env_data is released
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized")
        .clone();

    // Now safe to borrow env_data mutably
    let view = memory.view(&store);
    let mut secondary: u128 = read_u128(&view, secondary_ptr)?;
    let context = env_data.apply_context_mut();
    let res = context.db_idx128_find_primary(
        code.into(),
        scope.into(),
        table.into(),
        &mut secondary,
        primary,
    )?;

    // Write result back to Wasm memory
    write_u128(&view, secondary_ptr, secondary)?;

    Ok(res)
}

pub fn db_idx128_lowerbound(
    mut env: FunctionEnvMut<WasmContext>,
    code: u64,
    scope: u64,
    table: u64,
    secondary_ptr: WasmPtr<u128>,
    primary_ptr: WasmPtr<u64>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_FIND)?;

    // Clone the memory handle so the borrow on env_data is released
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized")
        .clone();

    // Read input from Wasm memory
    let view = memory.view(&store);
    let mut primary: u64 = read_u64(&view, primary_ptr)?;
    let mut secondary: u128 = read_u128(&view, secondary_ptr)?;

    // Now safe to borrow env_data mutably
    let context = env_data.apply_context_mut();
    let res = context.db_idx128_lowerbound(
        code.into(),
        scope.into(),
        table.into(),
        &mut secondary,
        &mut primary,
    )?;

    // Write result back to Wasm memory
    write_u128(&view, secondary_ptr, secondary)?;
    write_u64(&view, primary_ptr, primary)?;

    Ok(res)
}

pub fn db_idx128_upperbound(
    mut env: FunctionEnvMut<WasmContext>,
    code: u64,
    scope: u64,
    table: u64,
    secondary_ptr: WasmPtr<u128>,
    primary_ptr: WasmPtr<u64>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_FIND)?;

    // Clone the memory handle so the borrow on env_data is released
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized")
        .clone();

    // Read input from Wasm memory
    let view = memory.view(&store);
    let mut primary: u64 = read_u64(&view, primary_ptr)?;
    let mut secondary: u128 = read_u128(&view, secondary_ptr)?;

    // Now safe to borrow env_data mutably
    let context = env_data.apply_context_mut();
    let res = context.db_idx128_upperbound(
        code.into(),
        scope.into(),
        table.into(),
        &mut secondary,
        &mut primary,
    )?;

    // Write result back to Wasm memory
    write_u128(&view, secondary_ptr, secondary)?;
    write_u64(&view, primary_ptr, primary)?;

    Ok(res)
}

pub fn db_idx128_end(
    mut env: FunctionEnvMut<WasmContext>,
    code: u64,
    scope: u64,
    table: u64,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_FIND)?;
    let context = env_data.apply_context_mut();
    Ok(context.db_idx128_end(code.into(), scope.into(), table.into())?)
}

pub fn db_idx128_next(
    mut env: FunctionEnvMut<WasmContext>,
    itr: i32,
    primary_ptr: WasmPtr<u64>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_ITERATE)?;
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let mut next_primary = read_u64(&view, primary_ptr)?;
    let context = env_data.apply_context_mut();
    let res = context.db_idx128_next(itr, &mut next_primary)?;
    write_u64(&view, primary_ptr, next_primary)?;

    Ok(res)
}

pub fn db_idx128_previous(
    mut env: FunctionEnvMut<WasmContext>,
    itr: i32,
    primary_ptr: WasmPtr<u64>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_ITERATE)?;
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let mut next_primary = read_u64(&view, primary_ptr)?;
    let context = env_data.apply_context_mut();
    let res = context.db_idx128_previous(itr, &mut next_primary)?;
    write_u64(&view, primary_ptr, next_primary)?;

    Ok(res)
}

pub fn db_idx256_store(
    mut env: FunctionEnvMut<WasmContext>,
    scope: u64,
    table: u64,
    payer: u64,
    id: u64,
    secondary_ptr: WasmPtr<u8>,
    _secondary_len: u32,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_STORE)?;
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let secondary: U256 = read_u256(&view, secondary_ptr)?;
    let context = env_data.apply_context_mut();
    let result = context.db_idx256_store(scope, table, payer, id, secondary)?;
    Ok(result)
}

pub fn db_idx256_update(
    mut env: FunctionEnvMut<WasmContext>,
    itr: i32,
    payer: u64,
    secondary_ptr: WasmPtr<u8>,
    _secondary_len: u32,
) -> Result<(), RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_STORE)?;
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let secondary: U256 = read_u256(&view, secondary_ptr)?;

    let context = env_data.apply_context_mut();
    context.db_idx256_update(itr, &payer.into(), secondary)?;
    Ok(())
}

pub fn db_idx256_remove(
    mut env: FunctionEnvMut<WasmContext>,
    itr: i32,
) -> Result<(), RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_STORE)?;
    let context = env_data.apply_context_mut();
    context.db_idx256_remove(itr)?;
    Ok(())
}

pub fn db_idx256_find_secondary(
    mut env: FunctionEnvMut<WasmContext>,
    code: u64,
    scope: u64,
    table: u64,
    secondary_ptr: WasmPtr<u8>,
    _secondary_len: u32,
    primary_ptr: WasmPtr<u64>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_FIND)?;

    // Clone the memory handle so the borrow on env_data is released
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized")
        .clone();

    // Read input from Wasm memory
    let view = memory.view(&store);
    let secondary: U256 = read_u256(&view, secondary_ptr)?;

    // Now safe to borrow env_data mutably
    let mut primary: u64 = read_u64(&view, primary_ptr)?;
    let context = env_data.apply_context_mut();
    let res = context.db_idx256_find_secondary(
        code.into(),
        scope.into(),
        table.into(),
        secondary,
        &mut primary,
    )?;

    // Write result back to Wasm memory
    write_u64(&view, primary_ptr, primary)?;

    Ok(res)
}

pub fn db_idx256_find_primary(
    mut env: FunctionEnvMut<WasmContext>,
    code: u64,
    scope: u64,
    table: u64,
    secondary_ptr: WasmPtr<u8>,
    _secondary_len: u32,
    primary: u64,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_FIND)?;

    // Clone the memory handle so the borrow on env_data is released
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized")
        .clone();

    // Now safe to borrow env_data mutably
    let view = memory.view(&store);
    let mut secondary: U256 = read_u256(&view, secondary_ptr)?;
    let context = env_data.apply_context_mut();
    let res = context.db_idx256_find_primary(
        code.into(),
        scope.into(),
        table.into(),
        &mut secondary,
        primary,
    )?;

    // Write result back to Wasm memory
    write_u256(&view, secondary_ptr, secondary)?;

    Ok(res)
}

pub fn db_idx256_lowerbound(
    mut env: FunctionEnvMut<WasmContext>,
    code: u64,
    scope: u64,
    table: u64,
    secondary_ptr: WasmPtr<u8>,
    _secondary_len: u32,
    primary_ptr: WasmPtr<u64>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_FIND)?;

    // Clone the memory handle so the borrow on env_data is released
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized")
        .clone();

    // Read input from Wasm memory
    let view = memory.view(&store);
    let mut primary: u64 = read_u64(&view, primary_ptr)?;
    let mut secondary: U256 = read_u256(&view, secondary_ptr)?;

    // Now safe to borrow env_data mutably
    let context = env_data.apply_context_mut();
    let res = context.db_idx256_lowerbound(
        code.into(),
        scope.into(),
        table.into(),
        &mut secondary,
        &mut primary,
    )?;

    // Write result back to Wasm memory
    write_u256(&view, secondary_ptr, secondary)?;
    write_u64(&view, primary_ptr, primary)?;

    Ok(res)
}

pub fn db_idx256_upperbound(
    mut env: FunctionEnvMut<WasmContext>,
    code: u64,
    scope: u64,
    table: u64,
    secondary_ptr: WasmPtr<u8>,
    _secondary_len: u32,
    primary_ptr: WasmPtr<u64>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_FIND)?;

    // Clone the memory handle so the borrow on env_data is released
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized")
        .clone();

    // Read input from Wasm memory
    let view = memory.view(&store);
    let mut primary: u64 = read_u64(&view, primary_ptr)?;
    let mut secondary: U256 = read_u256(&view, secondary_ptr)?;

    // Now safe to borrow env_data mutably
    let context = env_data.apply_context_mut();
    let res = context.db_idx256_upperbound(
        code.into(),
        scope.into(),
        table.into(),
        &mut secondary,
        &mut primary,
    )?;

    // Write result back to Wasm memory
    write_u256(&view, secondary_ptr, secondary)?;
    write_u64(&view, primary_ptr, primary)?;

    Ok(res)
}

pub fn db_idx256_end(
    mut env: FunctionEnvMut<WasmContext>,
    code: u64,
    scope: u64,
    table: u64,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_FIND)?;
    let context = env_data.apply_context_mut();
    Ok(context.db_idx256_end(code.into(), scope.into(), table.into())?)
}

pub fn db_idx256_next(
    mut env: FunctionEnvMut<WasmContext>,
    itr: i32,
    primary_ptr: WasmPtr<u64>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_ITERATE)?;
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let mut next_primary = read_u64(&view, primary_ptr)?;
    let context = env_data.apply_context_mut();
    let res = context.db_idx256_next(itr, &mut next_primary)?;
    write_u64(&view, primary_ptr, next_primary)?;

    Ok(res)
}

pub fn db_idx256_previous(
    mut env: FunctionEnvMut<WasmContext>,
    itr: i32,
    primary_ptr: WasmPtr<u64>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_ITERATE)?;
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let mut next_primary = read_u64(&view, primary_ptr)?;
    let context = env_data.apply_context_mut();
    let res = context.db_idx256_previous(itr, &mut next_primary)?;
    write_u64(&view, primary_ptr, next_primary)?;

    Ok(res)
}

pub fn db_idx_double_store(
    mut env: FunctionEnvMut<WasmContext>,
    scope: u64,
    table: u64,
    payer: u64,
    id: u64,
    secondary_ptr: WasmPtr<u64>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_STORE)?;
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let secondary: u64 = read_u64(&view, secondary_ptr)?;
    reject_nan_f64(secondary)?;
    let context = env_data.apply_context_mut();
    let result = context.db_idx_double_store(scope, table, payer, id, secondary)?;
    Ok(result)
}

pub fn db_idx_double_update(
    mut env: FunctionEnvMut<WasmContext>,
    itr: i32,
    payer: u64,
    secondary_ptr: WasmPtr<u64>,
) -> Result<(), RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_STORE)?;
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let secondary: u64 = read_u64(&view, secondary_ptr)?;
    reject_nan_f64(secondary)?;

    let context = env_data.apply_context_mut();
    context.db_idx_double_update(itr, &payer.into(), secondary)?;
    Ok(())
}

pub fn db_idx_double_remove(
    mut env: FunctionEnvMut<WasmContext>,
    itr: i32,
) -> Result<(), RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_STORE)?;
    let context = env_data.apply_context_mut();
    context.db_idx_double_remove(itr)?;
    Ok(())
}

pub fn db_idx_double_find_secondary(
    mut env: FunctionEnvMut<WasmContext>,
    code: u64,
    scope: u64,
    table: u64,
    secondary_ptr: WasmPtr<u64>,
    primary_ptr: WasmPtr<u64>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_FIND)?;

    // Clone the memory handle so the borrow on env_data is released
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized")
        .clone();

    // Read input from Wasm memory
    let view = memory.view(&store);
    let secondary: u64 = read_u64(&view, secondary_ptr)?;
    reject_nan_f64(secondary)?;

    // Now safe to borrow env_data mutably
    let mut primary: u64 = read_u64(&view, primary_ptr)?;
    let context = env_data.apply_context_mut();
    let res = context.db_idx_double_find_secondary(
        code.into(),
        scope.into(),
        table.into(),
        secondary,
        &mut primary,
    )?;

    // Write result back to Wasm memory
    write_u64(&view, primary_ptr, primary)?;

    Ok(res)
}

pub fn db_idx_double_find_primary(
    mut env: FunctionEnvMut<WasmContext>,
    code: u64,
    scope: u64,
    table: u64,
    secondary_ptr: WasmPtr<u64>,
    primary: u64,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_FIND)?;

    // Clone the memory handle so the borrow on env_data is released
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized")
        .clone();

    // Now safe to borrow env_data mutably
    let view = memory.view(&store);
    let mut secondary: u64 = read_u64(&view, secondary_ptr)?;
    let context = env_data.apply_context_mut();
    let res = context.db_idx_double_find_primary(
        code.into(),
        scope.into(),
        table.into(),
        &mut secondary,
        primary,
    )?;

    // Write result back to Wasm memory
    write_u64(&view, secondary_ptr, secondary)?;

    Ok(res)
}

pub fn db_idx_double_lowerbound(
    mut env: FunctionEnvMut<WasmContext>,
    code: u64,
    scope: u64,
    table: u64,
    secondary_ptr: WasmPtr<u64>,
    primary_ptr: WasmPtr<u64>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_FIND)?;

    // Clone the memory handle so the borrow on env_data is released
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized")
        .clone();

    // Read input from Wasm memory
    let view = memory.view(&store);
    let mut primary: u64 = read_u64(&view, primary_ptr)?;
    let mut secondary: u64 = read_u64(&view, secondary_ptr)?;
    reject_nan_f64(secondary)?;

    // Now safe to borrow env_data mutably
    let context = env_data.apply_context_mut();
    let res = context.db_idx_double_lowerbound(
        code.into(),
        scope.into(),
        table.into(),
        &mut secondary,
        &mut primary,
    )?;

    // Write result back to Wasm memory
    write_u64(&view, secondary_ptr, secondary)?;
    write_u64(&view, primary_ptr, primary)?;

    Ok(res)
}

pub fn db_idx_double_upperbound(
    mut env: FunctionEnvMut<WasmContext>,
    code: u64,
    scope: u64,
    table: u64,
    secondary_ptr: WasmPtr<u64>,
    primary_ptr: WasmPtr<u64>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_FIND)?;

    // Clone the memory handle so the borrow on env_data is released
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized")
        .clone();

    // Read input from Wasm memory
    let view = memory.view(&store);
    let mut primary: u64 = read_u64(&view, primary_ptr)?;
    let mut secondary: u64 = read_u64(&view, secondary_ptr)?;
    reject_nan_f64(secondary)?;

    // Now safe to borrow env_data mutably
    let context = env_data.apply_context_mut();
    let res = context.db_idx_double_upperbound(
        code.into(),
        scope.into(),
        table.into(),
        &mut secondary,
        &mut primary,
    )?;

    // Write result back to Wasm memory
    write_u64(&view, secondary_ptr, secondary)?;
    write_u64(&view, primary_ptr, primary)?;

    Ok(res)
}

pub fn db_idx_double_end(
    mut env: FunctionEnvMut<WasmContext>,
    code: u64,
    scope: u64,
    table: u64,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_FIND)?;
    let context = env_data.apply_context_mut();
    Ok(context.db_idx_double_end(code.into(), scope.into(), table.into())?)
}

pub fn db_idx_double_next(
    mut env: FunctionEnvMut<WasmContext>,
    itr: i32,
    primary_ptr: WasmPtr<u64>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_ITERATE)?;
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let mut next_primary = read_u64(&view, primary_ptr)?;
    let context = env_data.apply_context_mut();
    let res = context.db_idx_double_next(itr, &mut next_primary)?;
    write_u64(&view, primary_ptr, next_primary)?;

    Ok(res)
}

pub fn db_idx_double_previous(
    mut env: FunctionEnvMut<WasmContext>,
    itr: i32,
    primary_ptr: WasmPtr<u64>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_ITERATE)?;
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let mut next_primary = read_u64(&view, primary_ptr)?;
    let context = env_data.apply_context_mut();
    let res = context.db_idx_double_previous(itr, &mut next_primary)?;
    write_u64(&view, primary_ptr, next_primary)?;

    Ok(res)
}

pub fn db_idx_long_double_store(
    mut env: FunctionEnvMut<WasmContext>,
    scope: u64,
    table: u64,
    payer: u64,
    id: u64,
    secondary_ptr: WasmPtr<u8>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_STORE)?;
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let secondary: Float128 = read_float128(&view, secondary_ptr)?;
    reject_nan_f128(&secondary)?;
    let context = env_data.apply_context_mut();
    let result = context.db_idx_long_double_store(scope, table, payer, id, secondary)?;
    Ok(result)
}

pub fn db_idx_long_double_update(
    mut env: FunctionEnvMut<WasmContext>,
    itr: i32,
    payer: u64,
    secondary_ptr: WasmPtr<u8>,
) -> Result<(), RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_STORE)?;
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let secondary: Float128 = read_float128(&view, secondary_ptr)?;
    reject_nan_f128(&secondary)?;

    let context = env_data.apply_context_mut();
    context.db_idx_long_double_update(itr, &payer.into(), secondary)?;
    Ok(())
}

pub fn db_idx_long_double_remove(
    mut env: FunctionEnvMut<WasmContext>,
    itr: i32,
) -> Result<(), RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_STORE)?;
    let context = env_data.apply_context_mut();
    context.db_idx_long_double_remove(itr)?;
    Ok(())
}

pub fn db_idx_long_double_find_secondary(
    mut env: FunctionEnvMut<WasmContext>,
    code: u64,
    scope: u64,
    table: u64,
    secondary_ptr: WasmPtr<u8>,
    primary_ptr: WasmPtr<u64>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_FIND)?;

    // Clone the memory handle so the borrow on env_data is released
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized")
        .clone();

    // Read input from Wasm memory
    let view = memory.view(&store);
    let secondary: Float128 = read_float128(&view, secondary_ptr)?;
    reject_nan_f128(&secondary)?;

    // Now safe to borrow env_data mutably
    let mut primary: u64 = read_u64(&view, primary_ptr)?;
    let context = env_data.apply_context_mut();
    let res = context.db_idx_long_double_find_secondary(
        code.into(),
        scope.into(),
        table.into(),
        secondary,
        &mut primary,
    )?;

    // Write result back to Wasm memory
    write_u64(&view, primary_ptr, primary)?;

    Ok(res)
}

pub fn db_idx_long_double_find_primary(
    mut env: FunctionEnvMut<WasmContext>,
    code: u64,
    scope: u64,
    table: u64,
    secondary_ptr: WasmPtr<u8>,
    primary: u64,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_FIND)?;

    // Clone the memory handle so the borrow on env_data is released
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized")
        .clone();

    // Now safe to borrow env_data mutably
    let view = memory.view(&store);
    let mut secondary: Float128 = read_float128(&view, secondary_ptr)?;
    let context = env_data.apply_context_mut();
    let res = context.db_idx_long_double_find_primary(
        code.into(),
        scope.into(),
        table.into(),
        &mut secondary,
        primary,
    )?;

    // Write result back to Wasm memory
    write_float128(&view, secondary_ptr, secondary)?;

    Ok(res)
}

pub fn db_idx_long_double_lowerbound(
    mut env: FunctionEnvMut<WasmContext>,
    code: u64,
    scope: u64,
    table: u64,
    secondary_ptr: WasmPtr<u8>,
    primary_ptr: WasmPtr<u64>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_FIND)?;

    // Clone the memory handle so the borrow on env_data is released
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized")
        .clone();

    // Read input from Wasm memory
    let view = memory.view(&store);
    let mut primary: u64 = read_u64(&view, primary_ptr)?;
    let mut secondary: Float128 = read_float128(&view, secondary_ptr)?;
    reject_nan_f128(&secondary)?;

    // Now safe to borrow env_data mutably
    let context = env_data.apply_context_mut();
    let res = context.db_idx_long_double_lowerbound(
        code.into(),
        scope.into(),
        table.into(),
        &mut secondary,
        &mut primary,
    )?;

    // Write result back to Wasm memory
    write_float128(&view, secondary_ptr, secondary)?;
    write_u64(&view, primary_ptr, primary)?;

    Ok(res)
}

pub fn db_idx_long_double_upperbound(
    mut env: FunctionEnvMut<WasmContext>,
    code: u64,
    scope: u64,
    table: u64,
    secondary_ptr: WasmPtr<u8>,
    primary_ptr: WasmPtr<u64>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_FIND)?;

    // Clone the memory handle so the borrow on env_data is released
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized")
        .clone();

    // Read input from Wasm memory
    let view = memory.view(&store);
    let mut primary: u64 = read_u64(&view, primary_ptr)?;
    let mut secondary: Float128 = read_float128(&view, secondary_ptr)?;
    reject_nan_f128(&secondary)?;

    // Now safe to borrow env_data mutably
    let context = env_data.apply_context_mut();
    let res = context.db_idx_long_double_upperbound(
        code.into(),
        scope.into(),
        table.into(),
        &mut secondary,
        &mut primary,
    )?;

    // Write result back to Wasm memory
    write_float128(&view, secondary_ptr, secondary)?;
    write_u64(&view, primary_ptr, primary)?;

    Ok(res)
}

pub fn db_idx_long_double_end(
    mut env: FunctionEnvMut<WasmContext>,
    code: u64,
    scope: u64,
    table: u64,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_FIND)?;
    let context = env_data.apply_context_mut();
    Ok(context.db_idx_long_double_end(code.into(), scope.into(), table.into())?)
}

pub fn db_idx_long_double_next(
    mut env: FunctionEnvMut<WasmContext>,
    itr: i32,
    primary_ptr: WasmPtr<u64>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_ITERATE)?;
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let mut next_primary = read_u64(&view, primary_ptr)?;
    let context = env_data.apply_context_mut();
    let res = context.db_idx_long_double_next(itr, &mut next_primary)?;
    write_u64(&view, primary_ptr, next_primary)?;

    Ok(res)
}

pub fn db_idx_long_double_previous(
    mut env: FunctionEnvMut<WasmContext>,
    itr: i32,
    primary_ptr: WasmPtr<u64>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::DB_ITERATE)?;
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let mut next_primary = read_u64(&view, primary_ptr)?;
    let context = env_data.apply_context_mut();
    let res = context.db_idx_long_double_previous(itr, &mut next_primary)?;
    write_u64(&view, primary_ptr, next_primary)?;

    Ok(res)
}

#[cfg(test)]
mod tests {
    use pulsevm_database::Float128;

    use super::{
        reject_nan_f64,
        reject_nan_f128,
    };

    #[test]
    fn f64_secondary_rejects_nan_only() {
        // NaN bit patterns are rejected.
        assert!(reject_nan_f64(f64::NAN.to_bits()).is_err());
        assert!(reject_nan_f64(0x7FF0_0000_0000_0001).is_err()); // signaling NaN
        assert!(reject_nan_f64(0xFFF8_0000_0000_0000).is_err()); // negative quiet NaN

        // Everything else is allowed, including both infinities and both zeros.
        for v in [
            0.0_f64,
            -0.0,
            1.5,
            -1.5,
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::MAX,
            f64::MIN_POSITIVE,
        ] {
            assert!(reject_nan_f64(v.to_bits()).is_ok(), "{v} must be allowed");
        }
    }

    fn f128(lo: u64, hi: u64) -> Float128 {
        Float128 { lo, hi }
    }

    #[test]
    fn f128_secondary_rejects_nan_only() {
        // Exponent all ones + non-zero mantissa = NaN (rejected).
        assert!(reject_nan_f128(&f128(0, 0x7FFF_8000_0000_0000)).is_err()); // quiet NaN
        assert!(reject_nan_f128(&f128(1, 0x7FFF_0000_0000_0000)).is_err()); // mantissa in low word
        assert!(reject_nan_f128(&f128(0, 0xFFFF_0000_0000_0001)).is_err()); // negative NaN

        // Infinities (exponent all ones, mantissa zero) are NOT NaN — allowed.
        assert!(reject_nan_f128(&f128(0, 0x7FFF_0000_0000_0000)).is_ok());
        assert!(reject_nan_f128(&f128(0, 0xFFFF_0000_0000_0000)).is_ok());

        // Zero and an ordinary finite value.
        assert!(reject_nan_f128(&f128(0, 0)).is_ok());
        assert!(reject_nan_f128(&f128(0, 0x3FFF_0000_0000_0000)).is_ok());
    }
}
