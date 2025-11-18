use std::num::NonZeroUsize;

use chrono::Utc;
use lru::LruCache;
use wasmtime::{Config, Engine, IntoFunc, Linker, Module, Store, Strategy};

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
    apply_context: ApplyContext,
}

impl WasmContext {
    pub fn new(receiver: Name, action: Action, apply_context: ApplyContext) -> Self {
        WasmContext {
            receiver,
            action,
            apply_context,
        }
    }

    pub fn receiver(&self) -> &Name {
        &self.receiver
    }

    pub fn action(&self) -> &Action {
        &self.action
    }

    pub fn apply_context(&self) -> &ApplyContext {
        &self.apply_context
    }

    pub fn apply_context_mut(&mut self) -> &mut ApplyContext {
        &mut self.apply_context
    }
}

pub struct WasmRuntime {
    engine: Engine,
    linker: Linker<WasmContext>,
    code_cache: LruCache<Id, Module>,
}

impl WasmRuntime {
    pub fn new() -> Result<Self, ChainError> {
        let mut config = Config::default();

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
        Self::add_host_function(&mut linker, "env", "sha512", sha512())?;

        Ok(Self {
            engine: engine,
            linker,
            code_cache: LruCache::new(NonZeroUsize::new(1024).unwrap()),
        })
    }

    #[must_use]
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
    }

    pub fn run(
        &mut self,
        receiver: Name,
        action: &Action,
        apply_context: &ApplyContext,
        code_hash: Id,
    ) -> Result<(), ChainError> {
        // Pause timer
        apply_context.pause_billing_timer();

        // Different scope so session is released before running the wasm code.
        {
            let mut session = apply_context.undo_session();

            if !self.code_cache.contains(&code_hash) {
                let code_object = session.get::<CodeObject>(code_hash).map_err(|e| {
                    ChainError::WasmRuntimeError(format!("failed to get wasm code: {}", e))
                })?;
                let module = Module::new(&self.engine, code_object.code.as_ref())
                    .map_err(|e| ChainError::WasmRuntimeError(e.to_string()))?;
                self.code_cache.put(code_hash, module);
            }
        }

        let context = WasmContext::new(receiver, action.clone(), apply_context.clone());
        let mut store = Store::new(&self.engine, context);
        store.set_fuel(32_000_000).map_err(|e| {
            ChainError::WasmRuntimeError(format!("failed to set fuel for wasm store: {}", e))
        })?;
        let module = self.code_cache.get(&code_hash).ok_or_else(|| {
            ChainError::WasmRuntimeError(format!("wasm module not found in cache: {}", code_hash))
        })?;
        let instance = self
            .linker
            .instantiate(&mut store, &module)
            .map_err(|e| ChainError::WasmRuntimeError(e.to_string()))?;
        let apply_func = instance
            .get_typed_func::<(u64, u64, u64), ()>(&mut store, "apply")
            .map_err(|e| ChainError::WasmRuntimeError(e.to_string()))?;
        let start = Utc::now().timestamp_micros();

        // Resume timer
        apply_context.resume_billing_timer();

        apply_func
            .call(
                &mut store,
                (
                    receiver.as_u64(),
                    action.account().as_u64(),
                    action.name().as_u64(),
                ),
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
