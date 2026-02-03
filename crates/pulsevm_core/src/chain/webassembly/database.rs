use pulsevm_name::Name;
use wasmer::{FunctionEnvMut, RuntimeError, WasmPtr};

use crate::chain::wasm_runtime::WasmContext;

pub fn db_find_i64(
    mut env: FunctionEnvMut<WasmContext>,
    code: u64,
    scope: u64,
    table: u64,
    id: u64,
) -> Result<i32, RuntimeError> {
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
    let context = env.data_mut().apply_context_mut();
    context.db_remove_i64(itr)?;
    Ok(())
}

pub fn db_next_i64(
    mut env: FunctionEnvMut<WasmContext>,
    itr: i32,
    primary_ptr: WasmPtr<u8>,
) -> Result<i32, RuntimeError> {
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
    let context = env.data_mut().apply_context_mut();
    Ok(context.db_end_i64(code.into(), scope.into(), table.into())?)
}
