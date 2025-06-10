use anyhow::{anyhow, bail};
use wasmtime::Caller;

use crate::chain::wasm_runtime::WasmContext;

pub fn require_auth() -> impl Fn(Caller<'_, WasmContext>, u64) -> Result<(), wasmtime::Error> {
    |caller, account| {
        let context = caller
            .data()
            .context
            .read()
            .map_err(|e| anyhow!("failed to read context: {}", e))?;

        if context.require_authorization(account.into()).is_err() {
            bail!("authorization failed");
        } else {
            Ok(())
        }
    }
}

pub fn has_auth() -> impl Fn(Caller<'_, WasmContext>, u64) -> Result<i32, wasmtime::Error> {
    |caller, account| {
        let context = caller
            .data()
            .context
            .read()
            .map_err(|e| anyhow!("failed to read context: {}", e))?;
        let result = context.has_authorization(account.into());

        if result { Ok(1) } else { Ok(0) }
    }
}

pub fn require_auth2() -> impl Fn(Caller<'_, WasmContext>, u64, u64) -> Result<(), wasmtime::Error>
{
    |caller, account, permission| {
        let context = caller
            .data()
            .context
            .read()
            .map_err(|e| anyhow!("failed to read context: {}", e))?;
        if context
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
        let mut context = caller
            .data_mut()
            .context
            .write()
            .map_err(|e| anyhow!("failed to read context: {}", e))?;
        if context.require_recipient(recipient.into()).is_err() {
            bail!("failed to require recipient");
        } else {
            Ok(())
        }
    }
}

pub fn is_account() -> impl Fn(Caller<'_, WasmContext>, u64) -> Result<i32, wasmtime::Error> {
    |caller, recipient| {
        let context = caller
            .data()
            .context
            .read()
            .map_err(|e| anyhow!("failed to read context: {}", e))?;
        let session = caller
            .data()
            .session
            .read()
            .map_err(|e| anyhow!("failed to read context: {}", e))?;
        let result = context.is_account(&session, recipient.into());

        if result.is_err() {
            bail!("failed to check if account exists");
        } else {
            Ok(result.unwrap() as i32)
        }
    }
}
