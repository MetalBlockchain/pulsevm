use anyhow::bail;
use wasmtime::Caller;

use crate::chain::{AccountMetadata, apply_context::ApplyContext, wasm_runtime::WasmContext};

fn privileged_check(context: &ApplyContext) -> Result<(), wasmtime::Error> {
    if !context.is_privileged() {
        bail!("this function can only be called by privileged accounts");
    }
    Ok(())
}

pub fn is_privileged() -> impl Fn(Caller<'_, WasmContext>, u64) -> Result<i32, wasmtime::Error> {
    |mut caller, account| {
        let context = caller.data_mut().apply_context_mut();
        privileged_check(context)?;
        let session = context.undo_session();
        let mut session = session.borrow_mut();
        let account = session
            .get::<AccountMetadata>(account.into())
            .map_err(|_| anyhow::anyhow!("account not found: {}", account))?;

        Ok(account.is_privileged() as i32)
    }
}

pub fn set_privileged() -> impl Fn(Caller<'_, WasmContext>, u64, i32) -> Result<(), wasmtime::Error>
{
    |mut caller, account, is_priv| {
        let context = caller.data_mut().apply_context_mut();
        privileged_check(context)?;
        let session = context.undo_session();
        let mut session = session.borrow_mut();
        let mut account = session
            .get::<AccountMetadata>(account.into())
            .map_err(|_| anyhow::anyhow!("account not found: {}", account))?;
        session
            .modify(&mut account, |acc| {
                acc.set_privileged(is_priv == 1);
            })
            .map_err(|_| anyhow::anyhow!("failed to set privileged status for account"))?;

        Ok(())
    }
}
