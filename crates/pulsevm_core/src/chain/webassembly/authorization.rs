use wasmer::{FunctionEnvMut, RuntimeError};

use crate::chain::wasm_runtime::WasmContext;

pub fn require_auth(env: FunctionEnvMut<WasmContext>, account: u64) -> Result<(), RuntimeError> {
    let context = env.data().apply_context();

    if let Err(err) = context.require_authorization(account.into(), None) {
        return Err(err.into());
    } else {
        Ok(())
    }
}

pub fn has_auth(env: FunctionEnvMut<WasmContext>, account: u64) -> Result<i32, RuntimeError> {
    let context = env.data().apply_context();
    let result = context.has_authorization(account.into());

    if result { Ok(1) } else { Ok(0) }
}

pub fn require_auth2(
    mut env: FunctionEnvMut<WasmContext>,
    account: u64,
    permission: u64,
) -> Result<(), RuntimeError> {
    let context = env.data_mut().apply_context_mut();

    if let Err(err) = context.require_authorization(account.into(), Some(permission.into())) {
        return Err(err.into());
    } else {
        Ok(())
    }
}

pub fn require_recipient(
    mut env: FunctionEnvMut<WasmContext>,
    recipient: u64,
) -> Result<(), RuntimeError> {
    let context = env.data_mut().apply_context_mut();

    if let Err(err) = context.require_recipient(recipient.into()) {
        return Err(err.into());
    } else {
        Ok(())
    }
}

pub fn is_account(
    mut env: FunctionEnvMut<WasmContext>,
    recipient: u64,
) -> Result<i32, RuntimeError> {
    let context = env.data_mut().apply_context_mut();
    let result = context.is_account(recipient.into());

    match result {
        Ok(exists) => {
            if exists { Ok(1) } else { Ok(0) }
        }
        Err(err) => return Err(err.into()),
    }
}
