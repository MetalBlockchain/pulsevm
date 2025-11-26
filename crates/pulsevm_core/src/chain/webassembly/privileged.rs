use anyhow::bail;
use pulsevm_chainbase::Session;
use wasmtime::Caller;

use crate::chain::{
    account::AccountMetadata, apply_context::ApplyContext, error::ChainError,
    resource_limits::ResourceLimitsManager, utils::pulse_assert, wasm_runtime::WasmContext,
};

fn privileged_check(context: &ApplyContext) -> Result<(), wasmtime::Error> {
    if !context.is_privileged() {
        bail!("this function can only be called by privileged accounts");
    }
    Ok(())
}

pub fn is_privileged() -> impl Fn(Caller<WasmContext>, u64) -> Result<i32, wasmtime::Error> {
    move |mut caller, account| {
        let context = caller.data().context().clone();
        privileged_check(&context)?;
        let session = caller.data_mut().session_mut();
        let account = session
            .get::<AccountMetadata>(account.into())
            .map_err(|_| anyhow::anyhow!("account not found: {}", account))?;

        Ok(account.is_privileged() as i32)
    }
}

pub fn set_privileged() -> impl Fn(Caller<WasmContext>, u64, i32) -> Result<(), wasmtime::Error> {
    move |mut caller, account, is_priv| {
        let context = caller.data().context().clone();
        privileged_check(&context)?;
        let session = caller.data_mut().session_mut();
        let mut account = session
            .get::<AccountMetadata>(account.into())
            .map_err(|_| anyhow::anyhow!("account not found: {}", account))?;
        session
            .modify(&mut account, |acc| {
                acc.set_privileged(is_priv == 1);
                Ok(())
            })
            .map_err(|_| anyhow::anyhow!("failed to set privileged status for account"))?;

        Ok(())
    }
}

pub fn set_resource_limits()
-> impl Fn(Caller<WasmContext>, u64, i64, i64, i64) -> Result<(), wasmtime::Error> {
    move |mut caller, account, ram_bytes, net_weight, cpu_weight| {
        pulse_assert(
            ram_bytes >= -1,
            ChainError::WasmRuntimeError(format!(
                "invalid value for ram resource limit expected [-1,INT64_MAX]"
            )),
        )?;
        pulse_assert(
            net_weight >= -1,
            ChainError::WasmRuntimeError(format!(
                "invalid value for net resource limit expected [-1,INT64_MAX]"
            )),
        )?;
        pulse_assert(
            cpu_weight >= -1,
            ChainError::WasmRuntimeError(format!(
                "invalid value for cpu resource limit expected [-1,INT64_MAX]"
            )),
        )?;
        let context = caller.data().context().clone();
        privileged_check(&context)?;
        let mut session = caller.data_mut().session_mut();
        ResourceLimitsManager::set_account_limits(
            &mut session,
            &account.into(),
            net_weight,
            cpu_weight,
            ram_bytes,
        )?;
        // TODO: Validate ram usage
        Ok(())
    }
}

pub fn get_resource_limits()
-> impl Fn(Caller<WasmContext>, u64, i32, i32, i32) -> Result<(), wasmtime::Error> {
    move |mut caller, account, ram_bytes_ptr, net_weight_ptr, cpu_weight_ptr| {
        let context = caller.data().context().clone();
        privileged_check(&context)?;
        let session = caller.data_mut().session_mut();
        let mut ram_bytes = 0;
        let mut net_weight = 0;
        let mut cpu_weight = 0;
        ResourceLimitsManager::get_account_limits(
            session,
            &account.into(),
            &mut ram_bytes,
            &mut net_weight,
            &mut cpu_weight,
        )?;
        let memory = caller
            .get_export("memory")
            .and_then(|ext| ext.into_memory())
            .ok_or_else(|| anyhow::anyhow!("memory export not found"))?;
        memory.write(
            &mut caller,
            ram_bytes_ptr as usize,
            &ram_bytes.to_le_bytes(),
        )?;
        memory.write(
            &mut caller,
            net_weight_ptr as usize,
            &net_weight.to_le_bytes(),
        )?;
        memory.write(
            &mut caller,
            cpu_weight_ptr as usize,
            &cpu_weight.to_le_bytes(),
        )?;
        Ok(())
    }
}
