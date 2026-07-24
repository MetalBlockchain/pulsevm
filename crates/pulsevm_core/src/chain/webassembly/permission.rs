use std::collections::BTreeSet;

use pulsevm_ffi::{PermissionLevel, microseconds, seconds};
use pulsevm_serialization::Read;
use wasmer::{FunctionEnvMut, RuntimeError, WasmPtr};

use crate::{
    authorization_manager::AuthorizationManager, chain::webassembly::context_aware_check,
    crypto::PublicKey, transaction::Transaction, wasm_runtime::WasmContext,
};

pub fn check_transaction_authorization(
    mut env: FunctionEnvMut<WasmContext>,
    trx_ptr: WasmPtr<u8>,
    trx_length: u32,
    pubkeys_ptr: WasmPtr<u8>,
    pubkeys_length: u32,
    perms_ptr: WasmPtr<u8>,
    perms_length: u32,
) -> Result<u32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    // Bounds-check before allocating: `slice` first, then size the host buffer.
    // Doing the `vec!` first lets a guest request ~4 GiB on an invalid range.
    let trx_slice = trx_ptr
        .slice(&view, trx_length)
        .map_err(|e| RuntimeError::new(format!("invalid transaction range: {e}")))?;
    let mut trx_bytes = vec![0u8; trx_length as usize];
    trx_slice
        .read_slice(&mut trx_bytes)
        .map_err(|e| RuntimeError::new(format!("failed to read transaction: {e}")))?;

    let transaction = Transaction::read(&trx_bytes, &mut 0)
        .map_err(|e| RuntimeError::new(format!("failed to deserialize transaction: {}", e)))?;

    let mut provided_keys: BTreeSet<PublicKey> = BTreeSet::new();
    let mut provided_permissions: BTreeSet<PermissionLevel> = BTreeSet::new();

    if pubkeys_length > 0 {
        let pubkeys_slice = pubkeys_ptr
            .slice(&view, pubkeys_length)
            .map_err(|e| RuntimeError::new(format!("invalid public keys range: {e}")))?;
        let mut pubkeys_bytes = vec![0u8; pubkeys_length as usize];
        pubkeys_slice
            .read_slice(&mut pubkeys_bytes)
            .map_err(|e| RuntimeError::new(format!("failed to read public keys: {e}")))?;
        provided_keys = BTreeSet::<PublicKey>::read(&pubkeys_bytes, &mut 0).map_err(|e| {
            RuntimeError::new(format!("failed to deserialize provided public keys: {}", e))
        })?;
    }

    if perms_length > 0 {
        let perms_slice = perms_ptr
            .slice(&view, perms_length)
            .map_err(|e| RuntimeError::new(format!("invalid permission levels range: {e}")))?;
        let mut perms_bytes = vec![0u8; perms_length as usize];
        perms_slice
            .read_slice(&mut perms_bytes)
            .map_err(|e| RuntimeError::new(format!("failed to read permission levels: {e}")))?;
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
        seconds(transaction.header.delay_sec.into()),
        &BTreeSet::new(),
    ) {
        Ok(_) => Ok(1),
        Err(_) => Ok(0),
    }
}

pub fn check_permission_authorization(
    mut env: FunctionEnvMut<WasmContext>,
    account: u64,
    permission: u64,
    pubkeys_ptr: WasmPtr<u8>,
    pubkeys_size: u32,
    perms_ptr: WasmPtr<u8>,
    perms_size: u32,
    delay_us: u64,
) -> Result<u32, RuntimeError> {
    context_aware_check(&env)?;
    // EOS_ASSERT: delay must fit in an i64.
    if delay_us > i64::MAX as u64 {
        return Err(RuntimeError::new("provided delay is too large"));
    }

    let (env_data, store) = env.data_and_store_mut();
    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);

    // Read the two spans out of wasm linear memory. Bounds-check with `slice`
    // before sizing each host buffer — allocating first lets a guest request
    // ~4 GiB on a range that was never valid.
    let mut provided_keys: BTreeSet<PublicKey> = BTreeSet::new();
    if pubkeys_size > 0 {
        let pubkeys_slice = pubkeys_ptr
            .slice(&view, pubkeys_size)
            .map_err(|e| RuntimeError::new(format!("invalid pubkeys range: {e}")))?;
        let mut pubkeys_data = vec![0u8; pubkeys_size as usize];
        pubkeys_slice
            .read_slice(&mut pubkeys_data)
            .map_err(|e| RuntimeError::new(format!("failed to read pubkeys: {}", e)))?;
        provided_keys = BTreeSet::<PublicKey>::read(pubkeys_data.as_slice(), &mut 0)
            .map_err(|e| RuntimeError::new(format!("failed to unpack pubkeys: {}", e)))?;
    }

    let mut provided_permissions: BTreeSet<PermissionLevel> = BTreeSet::new();
    if perms_size > 0 {
        let perms_slice = perms_ptr
            .slice(&view, perms_size)
            .map_err(|e| RuntimeError::new(format!("invalid perms range: {e}")))?;
        let mut perms_data = vec![0u8; perms_size as usize];
        perms_slice
            .read_slice(&mut perms_data)
            .map_err(|e| RuntimeError::new(format!("failed to read perms: {}", e)))?;
        provided_permissions = BTreeSet::<PermissionLevel>::read(perms_data.as_slice(), &mut 0)
            .map_err(|e| RuntimeError::new(format!("failed to unpack perms: {}", e)))?;
    }

    let permission = PermissionLevel::new(account, permission);

    match AuthorizationManager::check_permission_authorization(
        env_data.db(),
        permission,
        &provided_keys,
        &provided_permissions,
        microseconds(delay_us as i64),
        false,
    ) {
        Ok(_) => Ok(1),
        Err(_) => Ok(0),
    }
}

pub fn get_permission_last_used(
    env: FunctionEnvMut<WasmContext>,
    account: u64,
    permission: u64,
) -> Result<i64, RuntimeError> {
    context_aware_check(&env)?;
    let env_data = env.data();
    let db = env_data.db();
    let permission = AuthorizationManager::get_permission(db, account, permission)?;
    let last_used = db.get_permission_last_used(permission)?;
    Ok(last_used.time_since_epoch().count())
}

pub fn get_account_creation_time(
    env: FunctionEnvMut<WasmContext>,
    account: u64,
) -> Result<i64, RuntimeError> {
    context_aware_check(&env)?;
    let env_data = env.data();
    let db = env_data.db();
    let account = db.get_account(account)?;
    Ok(account
        .get_creation_date()
        .to_time_point()
        .time_since_epoch()
        .count())
}
