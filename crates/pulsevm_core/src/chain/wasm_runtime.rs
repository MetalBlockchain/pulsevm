use std::{
    num::NonZeroUsize,
    sync::{Arc, RwLock},
};

use lru::LruCache;
use pulsevm_crypto::Bytes;
use pulsevm_error::ChainError;
use pulsevm_ffi::{CxxDigest, Database};
use wasmer::{Engine, Function, FunctionEnv, Instance, Memory, Module, Store, imports};
use wasmer_compiler_cranelift::Cranelift;

use crate::{
    block::BlockTimestamp,
    chain::{
        apply_context::ApplyContext,
        id::Id,
        name::Name,
        transaction::Action,
        webassembly::{
            check_transaction_authorization, current_time, db_end_i64, db_find_i64, db_get_i64, db_lowerbound_i64, db_next_i64, db_previous_i64,
            db_remove_i64, db_store_i64, db_update_i64, db_upperbound_i64, get_resource_limits, is_privileged, pulse_assert, read_action_data,
            require_auth2, require_recipient, set_action_return_value, set_privileged, set_resource_limits, sha224, sha256, sha512,
        },
    },
};

use super::webassembly::{action_data_size, current_receiver, has_auth, is_account, require_auth, send_inline};

pub struct WasmContext {
    receiver: u64,
    action: Action,
    pending_block_timestamp: BlockTimestamp,
    context: ApplyContext,
    db: Database,
    memory: Option<Memory>,
    return_value: Option<Bytes>,
}

impl WasmContext {
    pub fn new(receiver: Name, action: Action, pending_block_timestamp: BlockTimestamp, context: ApplyContext, db: Database) -> Self {
        WasmContext {
            receiver: receiver.as_u64(),
            action,
            pending_block_timestamp,
            context,
            db,
            memory: None,
            return_value: None,
        }
    }

    pub fn receiver(&self) -> u64 {
        self.receiver
    }

    pub fn action(&self) -> &Action {
        &self.action
    }

    pub fn pending_block_timestamp(&self) -> &BlockTimestamp {
        &self.pending_block_timestamp
    }

    pub fn apply_context(&self) -> &ApplyContext {
        &self.context
    }

    pub fn apply_context_mut(&mut self) -> &mut ApplyContext {
        &mut self.context
    }

    pub fn db(&self) -> &Database {
        &self.db
    }

    pub fn db_mut(&mut self) -> &mut Database {
        &mut self.db
    }

    pub fn memory(&self) -> &Option<Memory> {
        &self.memory
    }

    pub fn set_action_return_value(&mut self, return_value: Bytes) {
        self.return_value = Some(return_value);
    }
}

struct InnerWasmRuntime {
    engine: Engine,
    code_cache: LruCache<Id, Module>,
}

#[derive(Clone)]
pub struct WasmRuntime {
    inner: Arc<RwLock<InnerWasmRuntime>>,
}

impl WasmRuntime {
    pub fn new() -> Result<Self, ChainError> {
        let compiler = Cranelift::default();

        Ok(Self {
            inner: Arc::new(RwLock::new(InnerWasmRuntime {
                engine: compiler.into(),
                code_cache: LruCache::new(NonZeroUsize::new(1024).unwrap()),
            })),
        })
    }

    pub fn run(
        &mut self,
        receiver: Name,
        action: Action,
        apply_context: ApplyContext,
        db: Database,
        code_hash: &CxxDigest,
    ) -> Result<(), ChainError> {
        // Pause timer
        apply_context.pause_billing_timer()?;

        let mut inner = self.inner.write()?;
        let id = Id::from(code_hash);

        // Different scope so session is released before running the wasm code.
        {
            if !inner.code_cache.contains(&id) {
                println!("Wasm module not found in cache, loading from db: {}", id);
                let code_object = db.get_code_object_by_hash(code_hash, 0, 0)?;
                let code_object = unsafe { &*code_object };
                // Create a temporary store just for module compilation
                let temp_store = Store::new(inner.engine.clone());
                let module =
                    Module::new(temp_store.engine(), code_object.get_code().as_slice()).map_err(|e| ChainError::WasmRuntimeError(e.to_string()))?;
                inner.code_cache.put(id, module);
            } else {
                println!("Wasm module found in cache: {}", id);
            }
        }

        let mut store = Store::new(inner.engine.clone());
        let module = inner
            .code_cache
            .get(&id)
            .ok_or_else(|| ChainError::WasmRuntimeError(format!("wasm module not found in cache: {}", id)))?;
        let wasm_context = WasmContext::new(
            receiver.clone(),
            action.clone(),
            apply_context.pending_block_timestamp().clone(),
            apply_context.clone(),
            db.clone(),
        );
        let env = FunctionEnv::new(&mut store, wasm_context);
        let import_object = imports! {
            "env" => {
                "action_data_size" => Function::new_typed_with_env(&mut store, &env, action_data_size),
                "read_action_data" => Function::new_typed_with_env(&mut store, &env, read_action_data),
                "current_receiver" => Function::new_typed_with_env(&mut store, &env, current_receiver),
                "set_action_return_value" => Function::new_typed_with_env(&mut store, &env, set_action_return_value),
                "require_auth" => Function::new_typed_with_env(&mut store, &env, require_auth),
                "has_auth" => Function::new_typed_with_env(&mut store, &env, has_auth),
                "require_auth2" => Function::new_typed_with_env(&mut store, &env, require_auth2),
                "require_recipient" => Function::new_typed_with_env(&mut store, &env, require_recipient),
                "is_account" => Function::new_typed_with_env(&mut store, &env, is_account),
                "db_find_i64" => Function::new_typed_with_env(&mut store, &env, db_find_i64),
                "db_store_i64" => Function::new_typed_with_env(&mut store, &env, db_store_i64),
                "db_get_i64" => Function::new_typed_with_env(&mut store, &env, db_get_i64),
                "db_update_i64" => Function::new_typed_with_env(&mut store, &env, db_update_i64),
                "db_remove_i64" => Function::new_typed_with_env(&mut store, &env, db_remove_i64),
                "db_next_i64" => Function::new_typed_with_env(&mut store, &env, db_next_i64),
                "db_previous_i64" => Function::new_typed_with_env(&mut store, &env, db_previous_i64),
                "db_end_i64" => Function::new_typed_with_env(&mut store, &env, db_end_i64),
                "db_lowerbound_i64" => Function::new_typed_with_env(&mut store, &env, db_lowerbound_i64),
                "db_upperbound_i64" => Function::new_typed_with_env(&mut store, &env, db_upperbound_i64),
                "pulse_assert" => Function::new_typed_with_env(&mut store, &env, pulse_assert),
                "current_time" => Function::new_typed_with_env(&mut store, &env, current_time),
                "sha224" => Function::new_typed_with_env(&mut store, &env, sha224),
                "sha256" => Function::new_typed_with_env(&mut store, &env, sha256),
                "sha512" => Function::new_typed_with_env(&mut store, &env, sha512),
                "is_privileged" => Function::new_typed_with_env(&mut store, &env, is_privileged),
                "set_privileged" => Function::new_typed_with_env(&mut store, &env, set_privileged),
                "set_resource_limits" => Function::new_typed_with_env(&mut store, &env, set_resource_limits),
                "get_resource_limits" => Function::new_typed_with_env(&mut store, &env, get_resource_limits),
                "send_inline" => Function::new_typed_with_env(&mut store, &env, send_inline),
                "check_transaction_authorization" => Function::new_typed_with_env(&mut store, &env, check_transaction_authorization),
            }
        };
        let instance = Instance::new(&mut store, &module, &import_object)
            .map_err(|e| ChainError::WasmRuntimeError(format!("failed to create wasm instance: {}", e)))?;

        match instance.exports.get_memory("memory") {
            Ok(mem) => {
                let ctx = env.as_mut(&mut store);
                ctx.memory = Some(mem.clone());
            }
            Err(_) => {
                return Err(ChainError::WasmRuntimeError("wasm memory export not found".to_string()));
            }
        }

        let apply_func = instance
            .exports
            .get_typed_function::<(i64, i64, i64), ()>(&store, "apply")
            .map_err(|_| ChainError::WasmRuntimeError(format!("failed to find apply function")))?;

        // Resume timer
        apply_context.resume_billing_timer()?;

        apply_func
            .call(
                &mut store,
                receiver.as_u64() as i64,
                action.account().as_u64() as i64,
                action.name().as_u64() as i64,
            )
            .map_err(|e| {
                // If this was originally `Err(ChainError)`, restore it
                if let Some(chain_err) = e.downcast_ref::<ChainError>() {
                    return chain_err.clone();
                }

                // Otherwise wrap it
                ChainError::WasmRuntimeError(format!("apply error: {}", e))
            })?;

        Ok(())
    }
}
