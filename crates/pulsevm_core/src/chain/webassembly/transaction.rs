use std::{
    collections::HashSet,
    sync::{Arc, RwLock},
};

use pulsevm_chainbase::UndoSession;
use pulsevm_serialization::Read;
use wasmtime::{Caller, Func};

use crate::{
    apply_context::ApplyContext,
    chain::{
        authority::PermissionLevel,
        authorization_manager::AuthorizationManager,
        controller::Controller,
        error::ChainError,
        secp256k1::PublicKey,
        transaction::{Action, Transaction},
        utils::pulse_assert,
        wasm_runtime::WasmContext,
    },
};

pub fn send_inline() -> impl Fn(Caller<'_, WasmContext>, u32, u32) -> Result<(), wasmtime::Error> {
    move |mut caller, ptr, length| {
        {
            let mut session = caller.data_mut().session_mut();
            let gpo = Controller::get_global_properties(&mut session)?;
            pulse_assert(
                length < gpo.configuration.max_inline_action_size,
                ChainError::WasmRuntimeError(format!("inline action too big")),
            )?;
        }

        let memory = caller
            .get_export("memory")
            .and_then(|ext| ext.into_memory())
            .ok_or_else(|| anyhow::anyhow!("memory export not found"))?;
        let mut src_bytes = vec![0u8; length as usize];
        memory.read(&caller, ptr as usize, &mut src_bytes)?;
        let action = Action::read(&src_bytes, &mut 0)?;

        let mut context = caller.data().context().clone();
        let mut session = caller.data_mut().session_mut();
        context.execute_inline(&mut session, &action)?;

        Ok(())
    }
}

pub fn check_transaction_authorization()
-> impl Fn(Caller<WasmContext>, u32, u32, u32, u32, u32, u32) -> Result<u32, wasmtime::Error> {
    move |mut caller: Caller<WasmContext>,
          trx_ptr,
          trx_length,
          pubkeys_ptr,
          pubkeys_length,
          perms_ptr,
          perms_length| {
        let memory = caller
            .get_export("memory")
            .and_then(|ext| ext.into_memory())
            .ok_or_else(|| anyhow::anyhow!("memory export not found"))?;
        let mut trx_bytes = vec![0u8; trx_length as usize];
        memory.read(&caller, trx_ptr as usize, &mut trx_bytes)?;
        let transaction = Transaction::read(&trx_bytes, &mut 0)?;
        let mut provided_keys: HashSet<PublicKey> = HashSet::new();
        let mut provided_permissions: HashSet<PermissionLevel> = HashSet::new();

        if pubkeys_length > 0 {
            let mut pubkeys_bytes = vec![0u8; pubkeys_length as usize];
            memory.read(&caller, pubkeys_ptr as usize, &mut pubkeys_bytes)?;
            provided_keys = HashSet::<PublicKey>::read(&pubkeys_bytes, &mut 0)?;
        }

        if perms_length > 0 {
            let mut perms_bytes = vec![0u8; perms_length as usize];
            memory.read(&caller, perms_ptr as usize, &mut perms_bytes)?;
            provided_permissions = HashSet::<PermissionLevel>::read(&perms_bytes, &mut 0)?;
        }

        let context = caller.data().context().clone();
        let mut session = caller.data_mut().session_mut();
        let result = AuthorizationManager::check_authorization(
            &context.chain_config,
            &mut session,
            &transaction.actions,
            &provided_keys,
            &provided_permissions,
            &HashSet::new(),
        );

        if result.is_ok() {
            return Ok(1);
        }

        Ok(0)
    }
}
