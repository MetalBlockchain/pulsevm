use pulsevm_ffi::{Float128, U256};
use wasmer::{FunctionEnvMut, RuntimeError, WasmPtr};

use crate::chain::{
    wasm_runtime::WasmContext,
    webassembly::{
        context_aware_check, read_float128, read_u64, read_u128, read_u256, write_float128,
        write_u64, write_u128, write_u256,
    },
};

pub fn db_find_i64(
    mut env: FunctionEnvMut<WasmContext>,
    code: u64,
    scope: u64,
    table: u64,
    id: u64,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let context = env.data_mut().apply_context_mut();
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
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let slice = buffer_ptr.slice(&view, buffer_len)?;

    // Read source bytes safely
    let mut src_bytes = vec![0u8; buffer_len as usize];
    slice.read_slice(&mut src_bytes)?;

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
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let slice = buffer_ptr.slice(&view, buffer_len)?;
    let mut dest_bytes = vec![0u8; buffer_len as usize];
    let context = env_data.apply_context();
    let result = context.db_get_i64(itr, &mut dest_bytes, buffer_len as usize)?;
    slice.write_slice(&dest_bytes)?;
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
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let slice = buffer_ptr.slice(&view, buffer_len)?;

    // Read source bytes safely
    let mut src_bytes = vec![0u8; buffer_len as usize];
    slice.read_slice(&mut src_bytes)?;

    let context = env_data.apply_context_mut();
    context.db_update_i64(itr, &payer.into(), &src_bytes)?;
    Ok(())
}

pub fn db_remove_i64(mut env: FunctionEnvMut<WasmContext>, itr: i32) -> Result<(), RuntimeError> {
    context_aware_check(&env)?;
    let context = env.data_mut().apply_context_mut();
    context.db_remove_i64(itr)?;
    Ok(())
}

pub fn db_next_i64(
    mut env: FunctionEnvMut<WasmContext>,
    itr: i32,
    primary_ptr: WasmPtr<u8>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let context = env.data_mut().apply_context_mut();
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
    let context = env.data_mut().apply_context_mut();
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
    let context = env.data_mut().apply_context_mut();
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
    let context = env.data_mut().apply_context_mut();
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
    let context = env.data_mut().apply_context_mut();
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
    let (env_data, store) = env.data_and_store_mut();
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
    let (env_data, store) = env.data_and_store_mut();
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
    let context = env.data_mut().apply_context_mut();
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
    let (env_data, store) = env.data_and_store_mut();

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
    let (env_data, store) = env.data_and_store_mut();

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
    let (env_data, store) = env.data_and_store_mut();

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
    let (env_data, store) = env.data_and_store_mut();

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
    let context = env.data_mut().apply_context_mut();
    Ok(context.db_idx64_end(code.into(), scope.into(), table.into())?)
}

pub fn db_idx64_next(
    mut env: FunctionEnvMut<WasmContext>,
    itr: i32,
    primary_ptr: WasmPtr<u64>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, store) = env.data_and_store_mut();
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
    let (env_data, store) = env.data_and_store_mut();
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
    let (env_data, store) = env.data_and_store_mut();
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
    let (env_data, store) = env.data_and_store_mut();
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
    let context = env.data_mut().apply_context_mut();
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
    let (env_data, store) = env.data_and_store_mut();

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
    let (env_data, store) = env.data_and_store_mut();

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
    let (env_data, store) = env.data_and_store_mut();

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
    let (env_data, store) = env.data_and_store_mut();

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
    let context = env.data_mut().apply_context_mut();
    Ok(context.db_idx128_end(code.into(), scope.into(), table.into())?)
}

pub fn db_idx128_next(
    mut env: FunctionEnvMut<WasmContext>,
    itr: i32,
    primary_ptr: WasmPtr<u64>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, store) = env.data_and_store_mut();
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
    let (env_data, store) = env.data_and_store_mut();
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
    secondary_len: u32,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, store) = env.data_and_store_mut();
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
    secondary_len: u32,
) -> Result<(), RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, store) = env.data_and_store_mut();
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
    let context = env.data_mut().apply_context_mut();
    context.db_idx256_remove(itr)?;
    Ok(())
}

pub fn db_idx256_find_secondary(
    mut env: FunctionEnvMut<WasmContext>,
    code: u64,
    scope: u64,
    table: u64,
    secondary_ptr: WasmPtr<u8>,
    secondary_len: u32,
    primary_ptr: WasmPtr<u64>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, store) = env.data_and_store_mut();

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
    secondary_len: u32,
    primary: u64,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, store) = env.data_and_store_mut();

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
    secondary_len: u32,
    primary_ptr: WasmPtr<u64>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, store) = env.data_and_store_mut();

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
    secondary_len: u32,
    primary_ptr: WasmPtr<u64>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, store) = env.data_and_store_mut();

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
    let context = env.data_mut().apply_context_mut();
    Ok(context.db_idx256_end(code.into(), scope.into(), table.into())?)
}

pub fn db_idx256_next(
    mut env: FunctionEnvMut<WasmContext>,
    itr: i32,
    primary_ptr: WasmPtr<u64>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, store) = env.data_and_store_mut();
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
    let (env_data, store) = env.data_and_store_mut();
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
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let secondary: u64 = read_u64(&view, secondary_ptr)?;
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
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let secondary: u64 = read_u64(&view, secondary_ptr)?;

    let context = env_data.apply_context_mut();
    context.db_idx_double_update(itr, &payer.into(), secondary)?;
    Ok(())
}

pub fn db_idx_double_remove(
    mut env: FunctionEnvMut<WasmContext>,
    itr: i32,
) -> Result<(), RuntimeError> {
    context_aware_check(&env)?;
    let context = env.data_mut().apply_context_mut();
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
    let (env_data, store) = env.data_and_store_mut();

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
    let (env_data, store) = env.data_and_store_mut();

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
    let (env_data, store) = env.data_and_store_mut();

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
    let (env_data, store) = env.data_and_store_mut();

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
    let context = env.data_mut().apply_context_mut();
    Ok(context.db_idx_double_end(code.into(), scope.into(), table.into())?)
}

pub fn db_idx_double_next(
    mut env: FunctionEnvMut<WasmContext>,
    itr: i32,
    primary_ptr: WasmPtr<u64>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, store) = env.data_and_store_mut();
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
    let (env_data, store) = env.data_and_store_mut();
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
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let secondary: Float128 = read_float128(&view, secondary_ptr)?;
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
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let secondary: Float128 = read_float128(&view, secondary_ptr)?;

    let context = env_data.apply_context_mut();
    context.db_idx_long_double_update(itr, &payer.into(), secondary)?;
    Ok(())
}

pub fn db_idx_long_double_remove(
    mut env: FunctionEnvMut<WasmContext>,
    itr: i32,
) -> Result<(), RuntimeError> {
    context_aware_check(&env)?;
    let context = env.data_mut().apply_context_mut();
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
    let (env_data, store) = env.data_and_store_mut();

    // Clone the memory handle so the borrow on env_data is released
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized")
        .clone();

    // Read input from Wasm memory
    let view = memory.view(&store);
    let secondary: Float128 = read_float128(&view, secondary_ptr)?;

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
    let (env_data, store) = env.data_and_store_mut();

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
    let (env_data, store) = env.data_and_store_mut();

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
    let (env_data, store) = env.data_and_store_mut();

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
    let context = env.data_mut().apply_context_mut();
    Ok(context.db_idx_long_double_end(code.into(), scope.into(), table.into())?)
}

pub fn db_idx_long_double_next(
    mut env: FunctionEnvMut<WasmContext>,
    itr: i32,
    primary_ptr: WasmPtr<u64>,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, store) = env.data_and_store_mut();
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
    let (env_data, store) = env.data_and_store_mut();
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
