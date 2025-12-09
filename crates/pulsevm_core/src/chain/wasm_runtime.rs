use std::{
    num::NonZeroUsize,
    sync::{Arc, RwLock},
};

use lru::LruCache;
use pulsevm_crypto::Bytes;
use wasmer::{imports, sys::NativeEngineExt, Engine, Function, FunctionEnv, Instance, Memory, Module, Store, Value};
use wasmer_compiler_llvm::LLVM;

use crate::{
    block::BlockTimestamp,
    chain::{
        account::CodeObject,
        apply_context::ApplyContext,
        id::Id,
        name::Name,
        transaction::Action,
        webassembly::{
            check_transaction_authorization, current_time, db_end_i64, db_find_i64, db_get_i64,
            db_lowerbound_i64, db_next_i64, db_previous_i64, db_remove_i64, db_store_i64,
            db_update_i64, db_upperbound_i64, get_resource_limits, is_privileged, pulse_assert,
            read_action_data, require_auth2, require_recipient, set_action_return_value,
            set_privileged, set_resource_limits, sha224, sha256, sha512,
        },
    },
};

use super::{
    error::ChainError,
    webassembly::{
        action_data_size, current_receiver, has_auth, is_account, memcmp, memcpy, memmove, memset,
        require_auth, send_inline,
    },
};

pub struct WasmContext {
    receiver: Name,
    action: Action,
    pending_block_timestamp: BlockTimestamp,
    context: ApplyContext,
    memory: Option<Memory>,
    return_value: Option<Bytes>,
}

impl WasmContext {
    pub fn new(
        receiver: Name,
        action: Action,
        pending_block_timestamp: BlockTimestamp,
        context: ApplyContext,
    ) -> Self {
        WasmContext {
            receiver,
            action,
            pending_block_timestamp,
            context,
            memory: None,
            return_value: None,
        }
    }

    pub fn receiver(&self) -> &Name {
        &self.receiver
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
        let compiler = LLVM::default();

        /* let mut config = Config::default();

        // Enable the Cranelift optimizing compiler.
        config.strategy(Strategy::Cranelift);

        // Enable signals-based traps. This is required to elide explicit
        // bounds-checking.
        config.signals_based_traps(true);

        // Configure linear memories such that explicit bounds-checking can be
        // elided.
        config.memory_reservation(1 << 32);
        config.memory_guard_size(1 << 32);

        // Enable copy-on-write heap images.
        config.memory_init_cow(true);

        // Enable parallel compilation.
        config.parallel_compilation(true);

        // Non-deterministic interruption
        //config.epoch_interruption(true);
        config.consume_fuel(true);

        let engine = Engine::new(&config)
            .map_err(|e| ChainError::WasmRuntimeError(e.to_string()))
            .unwrap();

        // Add host functions to the linker.
        let mut linker = Linker::<WasmContext>::new(&engine);
        // Action functions
        Self::add_host_function(&mut linker, "env", "action_data_size", action_data_size())?;
        Self::add_host_function(&mut linker, "env", "read_action_data", read_action_data())?;
        Self::add_host_function(&mut linker, "env", "current_receiver", current_receiver())?;
        Self::add_host_function(&mut linker, "env", "get_self", get_self())?;
        Self::add_host_function(
            &mut linker,
            "env",
            "set_action_return_value",
            set_action_return_value(),
        )?;
        // Authorization functions
        Self::add_host_function(&mut linker, "env", "require_auth", require_auth())?;
        Self::add_host_function(&mut linker, "env", "has_auth", has_auth())?;
        Self::add_host_function(&mut linker, "env", "require_auth2", require_auth2())?;
        Self::add_host_function(&mut linker, "env", "require_recipient", require_recipient())?;
        Self::add_host_function(&mut linker, "env", "is_account", is_account())?;
        // Memory functions
        Self::add_host_function(&mut linker, "env", "memcpy", memcpy())?;
        Self::add_host_function(&mut linker, "env", "memmove", memmove())?;
        Self::add_host_function(&mut linker, "env", "memcmp", memcmp())?;
        Self::add_host_function(&mut linker, "env", "memset", memset())?;
        // Transaction functions
        Self::add_host_function(&mut linker, "env", "send_inline", send_inline())?;
        Self::add_host_function(
            &mut linker,
            "env",
            "check_transaction_authorization",
            check_transaction_authorization(),
        )?;
        // Database functions
        Self::add_host_function(&mut linker, "env", "db_find_i64", db_find_i64())?;
        Self::add_host_function(&mut linker, "env", "db_store_i64", db_store_i64())?;
        Self::add_host_function(&mut linker, "env", "db_get_i64", db_get_i64())?;
        Self::add_host_function(&mut linker, "env", "db_update_i64", db_update_i64())?;
        Self::add_host_function(&mut linker, "env", "db_remove_i64", db_remove_i64())?;
        Self::add_host_function(&mut linker, "env", "db_next_i64", db_next_i64())?;
        Self::add_host_function(&mut linker, "env", "db_previous_i64", db_previous_i64())?;
        Self::add_host_function(&mut linker, "env", "db_end_i64", db_end_i64())?;
        Self::add_host_function(&mut linker, "env", "db_lowerbound_i64", db_lowerbound_i64())?;
        Self::add_host_function(&mut linker, "env", "db_upperbound_i64", db_upperbound_i64())?;
        // System functions
        Self::add_host_function(&mut linker, "env", "pulse_assert", pulse_assert())?;
        Self::add_host_function(&mut linker, "env", "current_time", current_time())?;
        // Privileged functions
        Self::add_host_function(&mut linker, "env", "is_privileged", is_privileged())?;
        Self::add_host_function(&mut linker, "env", "set_privileged", set_privileged())?;
        Self::add_host_function(
            &mut linker,
            "env",
            "set_resource_limits",
            set_resource_limits(),
        )?;
        Self::add_host_function(
            &mut linker,
            "env",
            "get_resource_limits",
            get_resource_limits(),
        )?;
        // Crypto functions
        Self::add_host_function(&mut linker, "env", "sha224", sha224())?;
        Self::add_host_function(&mut linker, "env", "sha256", sha256())?;
        Self::add_host_function(&mut linker, "env", "sha512", sha512())?; */

        Ok(Self {
            inner: Arc::new(RwLock::new(InnerWasmRuntime {
                engine: compiler.into(),
                code_cache: LruCache::new(NonZeroUsize::new(1024).unwrap()),
            })),
        })
    }

    /* #[must_use]
    fn add_host_function<Params, Args>(
        linker: &mut Linker<WasmContext>,
        module: &str,
        name: &str,
        func: impl IntoFunc<WasmContext, Params, Args>,
    ) -> Result<(), ChainError>
    where
        WasmContext: 'static,
    {
        linker
            .func_wrap(module, name, func)
            .map_err(|e| ChainError::WasmRuntimeError(e.to_string()))?;
        Ok(())
    } */

    pub fn run(
        &mut self,
        receiver: Name,
        action: Action,
        apply_context: ApplyContext,
        code_hash: Id,
    ) -> Result<(), ChainError> {
        // Pause timer
        apply_context.pause_billing_timer()?;

        let mut inner = self.inner.write()?;
        let mut store = Store::new(inner.engine.clone());

        // Different scope so session is released before running the wasm code.
        {
            let mut session = apply_context.undo_session();

            if !inner.code_cache.contains(&code_hash) {
                let code_object = session.get::<CodeObject>(code_hash).map_err(|e| {
                    ChainError::WasmRuntimeError(format!("failed to get wasm code: {}", e))
                })?;
                let module = Module::new(store.engine(), code_object.code.as_ref())
                    .map_err(|e| ChainError::WasmRuntimeError(e.to_string()))?;
                inner.code_cache.put(code_hash, module);
            }
        }

        let module = inner.code_cache.get(&code_hash).ok_or_else(|| {
            ChainError::WasmRuntimeError(format!("wasm module not found in cache: {}", code_hash))
        })?;
        let wasm_context = WasmContext::new(
            receiver,
            action.clone(),
            apply_context.pending_block_timestamp(),
            apply_context.clone(),
        );
        let env = FunctionEnv::new(&mut store, wasm_context);
        let import_object = imports! {
            "env" => {
                "action_data_size" => Function::new_typed_with_env(&mut store, &env, action_data_size),
                "read_action_data" => Function::new_typed_with_env(&mut store, &env, read_action_data),
                "current_receiver" => Function::new_typed_with_env(&mut store, &env, current_receiver),
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
            }
        };
        let instance = Instance::new(&mut store, &module, &import_object).map_err(|e| {
            ChainError::WasmRuntimeError(format!("failed to create wasm instance: {}", e))
        })?;

        match instance.exports.get_memory("memory") {
            Ok(mem) => {
                let ctx = env.as_mut(&mut store);
                ctx.memory = Some(mem.clone());
            }
            Err(_) => {
                return Err(ChainError::WasmRuntimeError(
                    "wasm memory export not found".to_string(),
                ));
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
