use std::sync::{Arc, RwLock};

use anyhow::bail;
use wasmtime::{Caller, Trap};

use crate::{apply_context::ApplyContext, chain::wasm_runtime::WasmContext};

pub fn require_auth() -> impl Fn(Caller<WasmContext>, u64) -> Result<(), wasmtime::Error> {
    move |caller, account| {
        let context = caller.data().context();

        if let Err(err) = context.require_authorization(account.into(), None) {
            return Err(err.into());
        } else {
            Ok(())
        }
    }
}

pub fn has_auth() -> impl Fn(Caller<WasmContext>, u64) -> Result<i32, wasmtime::Error> {
    move |caller, account| {
        let context = caller.data().context();
        let result = context.has_authorization(account.into());

        if result { Ok(1) } else { Ok(0) }
    }
}

pub fn require_auth2() -> impl Fn(Caller<WasmContext>, u64, u64) -> Result<(), wasmtime::Error> {
    move |mut caller, account, permission| {
        let context = caller.data_mut().context_mut();

        if let Err(err) = context.require_authorization(account.into(), Some(permission.into())) {
            bail!("{}", err);
        } else {
            Ok(())
        }
    }
}

pub fn require_recipient() -> impl Fn(Caller<WasmContext>, u64) -> Result<(), wasmtime::Error> {
    move |mut caller, recipient| {
        let context = caller.data_mut().context_mut();

        if context.require_recipient(recipient.into()).is_err() {
            bail!("failed to require recipient");
        } else {
            Ok(())
        }
    }
}

pub fn is_account() -> impl Fn(Caller<WasmContext>, u64) -> Result<i32, wasmtime::Error> {
    move |caller, recipient| {
        let context = caller.data().context();
        let session = caller.data().session();
        let result = context.is_account(&session, recipient.into());

        match result {
            Ok(true) => Ok(1),
            Ok(false) => Ok(0),
            Err(err) => {
                bail!("failed to check if account exists: {}", err);
            }
        }
    }
}
