use std::collections::{BTreeSet, HashSet};

use pulsevm_error::ChainError;
use pulsevm_serialization::{NumBytes, Read, Write};
use wasmer::{FunctionEnvMut, RuntimeError, WasmPtr};

use crate::{
    authorization_manager::AuthorizationManager,
    chain::{
        authority::PermissionLevel,
        controller::Controller,
        transaction::{Action, Transaction},
        utils::pulse_assert,
        wasm_runtime::WasmContext,
    },
    crypto::PublicKey,
};

pub fn send_inline(
    mut env: FunctionEnvMut<WasmContext>,
    ptr: WasmPtr<u8>,
    length: u32,
) -> Result<(), RuntimeError> {
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

pub fn check_transaction_authorization(
    mut env: FunctionEnvMut<WasmContext>,
    trx_ptr: WasmPtr<u8>,
    trx_length: u32,
    pubkeys_ptr: WasmPtr<u8>,
    pubkeys_length: u32,
    perms_ptr: WasmPtr<u8>,
    perms_length: u32,
) -> Result<u32, RuntimeError> {
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let mut trx_bytes = vec![0u8; trx_length as usize];
    trx_ptr
        .slice(&view, trx_length)?
        .read_slice(&mut trx_bytes)?;
    let transaction = Transaction::read(&trx_bytes, &mut 0)
        .map_err(|e| RuntimeError::new(format!("failed to deserialize transaction: {}", e)))?;
    let mut provided_keys: BTreeSet<PublicKey> = BTreeSet::new();
    let mut provided_permissions: BTreeSet<PermissionLevel> = BTreeSet::new();

    if pubkeys_length > 0 {
        let mut pubkeys_bytes = vec![0u8; pubkeys_length as usize];
        pubkeys_ptr
            .slice(&view, pubkeys_length)?
            .read_slice(&mut pubkeys_bytes)?;
        provided_keys = BTreeSet::<PublicKey>::read(&pubkeys_bytes, &mut 0).map_err(|e| {
            RuntimeError::new(format!("failed to deserialize provided public keys: {}", e))
        })?;
    }

    if perms_length > 0 {
        let mut perms_bytes = vec![0u8; perms_length as usize];
        perms_ptr
            .slice(&view, perms_length)?
            .read_slice(&mut perms_bytes)?;
        provided_permissions =
            BTreeSet::<PermissionLevel>::read(&perms_bytes, &mut 0).map_err(|e| {
                RuntimeError::new(format!(
                    "failed to deserialize provided permission levels: {}",
                    e
                ))
            })?;
    }

    let mut db = env_data.db_mut();

    match AuthorizationManager::check_authorization(
        &mut db,
        &transaction.actions,
        &provided_keys,
        &provided_permissions,
        &BTreeSet::new(),
    ) {
        Ok(_) => return Ok(1),
        Err(_) => return Ok(0),
    }
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

pub fn transaction_size(
    env: FunctionEnvMut<WasmContext>,
) -> Result<u32, RuntimeError> {
    let env_data = env.data();
    let size = env_data
        .apply_context()
        .get_packed_transaction()
        .get_transaction()
        .num_bytes();

    Ok(size as u32)
}

pub fn expiration(
    env: FunctionEnvMut<WasmContext>,
) -> Result<u32, RuntimeError> {
    let env_data = env.data();
    let trx = env_data
        .apply_context()
        .get_packed_transaction()
        .get_transaction();
    let expiration = trx.header.expiration();

    Ok(expiration.sec_since_epoch())
}

pub fn tapos_block_num(
    env: FunctionEnvMut<WasmContext>,
) -> Result<u32, RuntimeError> {
    let env_data = env.data();
    let trx = env_data
        .apply_context()
        .get_packed_transaction()
        .get_transaction();
    let ref_block_num = trx.header.ref_block_num;

    Ok(ref_block_num as u32)
}

pub fn tapos_block_prefix(
    env: FunctionEnvMut<WasmContext>,
) -> Result<u32, RuntimeError> {
    let env_data = env.data();
    let trx = env_data
        .apply_context()
        .get_packed_transaction()
        .get_transaction();
    let ref_block_prefix = trx.header.ref_block_prefix;

    Ok(ref_block_prefix)
}