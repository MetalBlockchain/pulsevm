use anyhow::bail;
use wasmtime::Caller;

use crate::chain::wasm_runtime::WasmContext;

pub fn require_auth() -> impl Fn(Caller<'_, WasmContext>, u64) -> Result<(), wasmtime::Error> {
    |caller, account| {
        if caller
            .data()
            .context
            .require_authorization(account.into())
            .is_err()
        {
            bail!("authorization failed");
        } else {
            Ok(())
        }
    }
}

pub fn has_auth() -> impl Fn(Caller<'_, WasmContext>, u64) -> i32 {
    |caller, account| {
        let result = caller.data().context.has_authorization(account.into());

        if result { 1 } else { 0 }
    }
}

pub fn require_auth2() -> impl Fn(Caller<'_, WasmContext>, u64, u64) -> Result<(), wasmtime::Error>
{
    |caller, account, permission| {
        if caller
            .data()
            .context
            .require_authorization_with_permission(account.into(), permission.into())
            .is_err()
        {
            bail!("authorization failed");
        } else {
            Ok(())
        }
    }
}

pub fn require_recipient() -> impl Fn(Caller<'_, WasmContext>, u64) -> Result<(), wasmtime::Error> {
    |mut caller, recipient| {
        if caller
            .data_mut()
            .context
            .require_recipient(recipient.into())
            .is_err()
        {
            bail!("failed to require recipient");
        } else {
            Ok(())
        }
    }
}
