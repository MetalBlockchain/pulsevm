use std::{
    num::NonZeroUsize,
    sync::{Arc, RwLock},
};

use chrono::Utc;
use lru::LruCache;
use wasmer::{Engine, Function, FunctionEnv, Instance, Memory, Module, Store, Value, imports};
use wasmer_compiler_llvm::LLVM;

use crate::chain::{
    account::CodeObject,
    apply_context::ApplyContext,
    id::Id,
    name::Name,
    transaction::Action,
    webassembly::{
        check_transaction_authorization, current_time, db_end_i64, db_find_i64, db_get_i64,
        db_lowerbound_i64, db_next_i64, db_previous_i64, db_remove_i64, db_store_i64,
        db_update_i64, db_upperbound_i64, get_resource_limits, get_self, is_privileged,
        pulse_assert, read_action_data, require_auth2, require_recipient, set_action_return_value,
        set_privileged, set_resource_limits, sha224, sha256, sha512,
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
    memory: Option<Memory>,
}

impl WasmContext {
    pub fn new(receiver: Name, action: Action) -> Self {
        WasmContext {
            receiver,
            action,
            memory: None,
        }
    }

    pub fn receiver(&self) -> &Name {
        &self.receiver
    }

    pub fn action(&self) -> &Action {
        &self.action
    }

    pub fn memory(&self) -> &Option<Memory> {
        &self.memory
    }
}

struct InnerWasmRuntime {
    compiler: LLVM,
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
                compiler,
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
        action: &Action,
        apply_context: &ApplyContext,
        code_hash: Id,
    ) -> Result<(), ChainError> {
        // Pause timer
        apply_context.pause_billing_timer();

        let mut inner = self.inner.write()?;

        // Different scope so session is released before running the wasm code.
        {
            let mut session = apply_context.undo_session();

            if !inner.code_cache.contains(&code_hash) {
                let code_object = session.get::<CodeObject>(code_hash).map_err(|e| {
                    ChainError::WasmRuntimeError(format!("failed to get wasm code: {}", e))
                })?;
                let module = Module::new(&inner.compiler, code_object.code.as_ref())
                    .map_err(|e| ChainError::WasmRuntimeError(e.to_string()))?;
                inner.code_cache.put(code_hash, module);
            }
        }

        let mut store = Store::new(inner.compiler.clone());
        let module = inner.code_cache.get(&code_hash).ok_or_else(|| {
            ChainError::WasmRuntimeError(format!("wasm module not found in cache: {}", code_hash))
        })?;
        let wasm_context = WasmContext::new(receiver, action.clone());
        let env = FunctionEnv::new(&mut store, wasm_context);
        let import_object = imports! {
            "env" => {
                "action_data_size" => Function::new_typed_with_env(&mut store, &env, action_data_size),
                "read_action_data" => Function::new_typed_with_env(&mut store, &env, read_action_data),
                "current_receiver" => Function::new_typed_with_env(&mut store, &env, current_receiver),
            }
        };
        let instance = Instance::new(&mut store, &module, &import_object).map_err(|e| {
            ChainError::WasmRuntimeError(format!("failed to create wasm instance: {}", e))
        })?;
        
        match instance.exports.get_memory("memory") {
            Ok(mem) => {
                let mut ctx = env.as_mut(&mut store);
                ctx.memory = Some(mem.clone());
            }
            Err(_) => {
                return Err(ChainError::WasmRuntimeError(
                    "wasm memory export not found".to_string(),
                ));
            }
        }

        let apply_func = instance.exports.get_function("apply").unwrap();

        // Resume timer
        apply_context.resume_billing_timer();

        apply_func
            .call(
                &mut store,
                &[
                    Value::I64(receiver.as_u64() as i64),
                    Value::I64(action.account().as_u64() as i64),
                    Value::I64(action.name().as_u64() as i64),
                ],
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
