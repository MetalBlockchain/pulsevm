use std::{
    collections::HashSet,
};

use pulsevm_error::ChainError;
use pulsevm_serialization::Read;
use wasmer::{FunctionEnvMut, RuntimeError, WasmPtr};

use crate::{
    authorization_manager::AuthorizationManager, chain::{
        authority::PermissionLevel,
        controller::Controller,
        transaction::{Action, Transaction},
        utils::pulse_assert,
        wasm_runtime::WasmContext,
    }, crypto::PublicKey
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
    let mut provided_keys: HashSet<PublicKey> = HashSet::new();
    let mut provided_permissions: HashSet<PermissionLevel> = HashSet::new();

    if pubkeys_length > 0 {
        let mut pubkeys_bytes = vec![0u8; pubkeys_length as usize];
        pubkeys_ptr
            .slice(&view, pubkeys_length)?
            .read_slice(&mut pubkeys_bytes)?;
        provided_keys = HashSet::<PublicKey>::read(&pubkeys_bytes, &mut 0).map_err(|e| {
            RuntimeError::new(format!("failed to deserialize provided public keys: {}", e))
        })?;
    }

    if perms_length > 0 {
        let mut perms_bytes = vec![0u8; perms_length as usize];
        perms_ptr
            .slice(&view, perms_length)?
            .read_slice(&mut perms_bytes)?;
        provided_permissions =
            HashSet::<PermissionLevel>::read(&perms_bytes, &mut 0).map_err(|e| {
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
        &HashSet::new(),
    ) {
        Ok(_) => return Ok(1),
        Err(_) => return Ok(0),
    }
}
