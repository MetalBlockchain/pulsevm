use pulsevm_error::ChainError;
use pulsevm_serialization::{NumBytes, Read, Write};
use wasmer::{FunctionEnvMut, RuntimeError, WasmPtr};

use crate::chain::{
    controller::Controller, transaction::Action, utils::pulse_assert, wasm_runtime::WasmContext,
    webassembly::context_aware_check,
};

pub fn send_inline(
    mut env: FunctionEnvMut<WasmContext>,
    ptr: WasmPtr<u8>,
    length: u32,
) -> Result<(), RuntimeError> {
    context_aware_check(&env)?;

    {
        let (env_data, _) = env.data_and_store_mut();
        let mut db = env_data.db_mut();
        let gpo = Controller::get_global_properties(&mut db)?;
        pulse_assert(
            length < gpo.get_chain_config().get_max_inline_action_size(),
            ChainError::WasmRuntimeError(format!("inline action too big")),
        )?;
    }

    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let slice = ptr.slice(&view, length)?;
    let mut src_bytes = vec![0u8; length as usize];
    slice.read_slice(&mut src_bytes)?;
    let action = Action::read(&src_bytes, &mut 0)
        .map_err(|e| RuntimeError::new(format!("failed to deserialize inline action: {}", e)))?;

    let context = env_data.apply_context_mut();
    context.execute_inline(&action)?;

    Ok(())
}

pub fn send_context_free_inline(
    mut env: FunctionEnvMut<WasmContext>,
    ptr: WasmPtr<u8>,
    length: u32,
) -> Result<(), RuntimeError> {
    context_aware_check(&env)?;
    {
        let (env_data, _) = env.data_and_store_mut();
        let mut db = env_data.db_mut();
        let gpo = Controller::get_global_properties(&mut db)?;
        pulse_assert(
            length < gpo.get_chain_config().get_max_inline_action_size(),
            ChainError::WasmRuntimeError(format!("inline action too big")),
        )?;
    }

    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let slice = ptr.slice(&view, length)?;
    let mut src_bytes = vec![0u8; length as usize];
    slice.read_slice(&mut src_bytes)?;
    let action = Action::read(&src_bytes, &mut 0)
        .map_err(|e| RuntimeError::new(format!("failed to deserialize inline action: {}", e)))?;

    let context = env_data.apply_context_mut();
    context.execute_context_free_inline(&action)?;

    Ok(())
}

pub fn read_transaction(
    mut env: FunctionEnvMut<WasmContext>,
    trx_ptr: WasmPtr<u8>,
    trx_length: u32,
) -> Result<u32, RuntimeError> {
    let (env_data, store) = env.data_and_store_mut();

    // Pack the (base) transaction — exact pack format is part of consensus.
    let packed = env_data
        .apply_context()
        .get_packed_transaction()
        .get_transaction()
        .pack()
        .map_err(|e| RuntimeError::new(format!("failed to pack transaction: {}", e)))?;

    // data.size() == 0 returns transaction_size()
    if trx_length == 0 {
        return Ok(packed.len() as u32);
    }

    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);

    let copy_size = (trx_length as usize).min(packed.len());

    view.write(trx_ptr.offset() as u64, &packed[..copy_size])
        .map_err(|e| RuntimeError::new(format!("failed to write transaction data: {}", e)))?;

    Ok(copy_size as u32)
}

pub fn transaction_size(env: FunctionEnvMut<WasmContext>) -> Result<u32, RuntimeError> {
    let env_data = env.data();
    let size = env_data
        .apply_context()
        .get_packed_transaction()
        .get_transaction()
        .num_bytes();

    Ok(size as u32)
}

pub fn expiration(env: FunctionEnvMut<WasmContext>) -> Result<u32, RuntimeError> {
    let env_data = env.data();
    let trx = env_data
        .apply_context()
        .get_packed_transaction()
        .get_transaction();
    let expiration = trx.header.expiration();

    Ok(expiration.sec_since_epoch())
}

pub fn tapos_block_num(env: FunctionEnvMut<WasmContext>) -> Result<u32, RuntimeError> {
    let env_data = env.data();
    let trx = env_data
        .apply_context()
        .get_packed_transaction()
        .get_transaction();
    let ref_block_num = trx.header.ref_block_num;

    Ok(ref_block_num as u32)
}

pub fn tapos_block_prefix(env: FunctionEnvMut<WasmContext>) -> Result<u32, RuntimeError> {
    let env_data = env.data();
    let trx = env_data
        .apply_context()
        .get_packed_transaction()
        .get_transaction();
    let ref_block_prefix = trx.header.ref_block_prefix;

    Ok(ref_block_prefix)
}

pub fn get_action(
    mut env: FunctionEnvMut<WasmContext>,
    action_type: u32,
    index: u32,
    buffer_ptr: WasmPtr<u8>,
    buffer_size: u32,
) -> Result<i32, RuntimeError> {
    let (env_data, store) = env.data_and_store_mut();

    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);

    // Read the wasm buffer out into a host-side scratch buffer, run get_action
    // against it, then write back. Avoids holding a MemoryView borrow across
    // the apply_context call.
    let mut scratch = vec![0u8; buffer_size as usize];

    let written = env_data
        .apply_context()
        .get_action(action_type, index, &mut scratch, buffer_size as usize)
        .map_err(|e| RuntimeError::new(format!("get_action failed: {}", e)))?;

    // get_action returns the packed size; it only filled scratch if it fit.
    if written >= 0 {
        let copy = (written as usize).min(scratch.len());
        view.write(buffer_ptr.offset() as u64, &scratch[..copy])
            .map_err(|e| RuntimeError::new(format!("failed to write action data: {}", e)))?;
    }

    Ok(written)
}
