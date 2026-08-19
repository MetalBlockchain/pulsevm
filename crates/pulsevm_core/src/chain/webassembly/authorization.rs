use wasmer::{
    FunctionEnvMut,
    RuntimeError,
};

use crate::chain::{
    wasm_runtime::WasmContext,
    webassembly::context_aware_check,
};

use super::cost;

pub fn require_auth(
    mut env: FunctionEnvMut<WasmContext>,
    account: u64,
) -> Result<(), RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::AUTH)?;
    let context = env_data.apply_context();

    if let Err(err) = context.require_authorization(&account.into(), None) {
        return Err(err.into());
    } else {
        Ok(())
    }
}

pub fn has_auth(mut env: FunctionEnvMut<WasmContext>, account: u64) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::AUTH)?;
    let context = env_data.apply_context();
    let result = context.has_authorization(&account.into())?;

    if result { Ok(1) } else { Ok(0) }
}

pub fn require_auth2(
    mut env: FunctionEnvMut<WasmContext>,
    account: u64,
    permission: u64,
) -> Result<(), RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::AUTH)?;
    let context = env_data.apply_context_mut();

    if let Err(err) = context.require_authorization(&account.into(), Some(permission.into())) {
        return Err(err.into());
    } else {
        Ok(())
    }
}

pub fn require_recipient(
    mut env: FunctionEnvMut<WasmContext>,
    recipient: u64,
) -> Result<(), RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::AUTH)?;
    let context = env_data.apply_context_mut();

    if let Err(err) = context.require_recipient(&recipient.into()) {
        return Err(err.into());
    } else {
        Ok(())
    }
}

pub fn is_account(
    mut env: FunctionEnvMut<WasmContext>,
    recipient: u64,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    // is_account hits the database, unlike the auth scans above, so it is priced as a lookup.
    env_data.charge(&mut store, cost::DB_FIND)?;
    let context = env_data.apply_context();
    let result = context.is_account(&recipient.into())?;

    if result { Ok(1) } else { Ok(0) }
}
