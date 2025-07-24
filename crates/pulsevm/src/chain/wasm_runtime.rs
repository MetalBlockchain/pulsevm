use std::num::NonZeroUsize;

use lru::LruCache;
use wasmtime::{Config, Engine, IntoFunc, Linker, Module, Store, Strategy};

use crate::chain::{
    Action, Name,
    apply_context::ApplyContext,
    webassembly::{
        db_end_i64, db_find_i64, db_get_i64, db_next_i64, db_remove_i64, db_store_i64,
        db_update_i64, get_self, pulse_assert, read_action_data, require_auth2, require_recipient,
        set_action_return_value,
    },
};

use super::{
    CodeObject, Id,
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

        // Enable fuel consumption to limit the execution time of the contract.
        config.consume_fuel(true);

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

        //config.coredump_on_trap(true);

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
        // Database functions
        Self::add_host_function(&mut linker, "env", "db_find_i64", db_find_i64())?;
        Self::add_host_function(&mut linker, "env", "db_store_i64", db_store_i64())?;
        Self::add_host_function(&mut linker, "env", "db_get_i64", db_get_i64())?;
        Self::add_host_function(&mut linker, "env", "db_update_i64", db_update_i64())?;
        Self::add_host_function(&mut linker, "env", "db_remove_i64", db_remove_i64())?;
        Self::add_host_function(&mut linker, "env", "db_next_i64", db_next_i64())?;
        Self::add_host_function(&mut linker, "env", "db_end_i64", db_end_i64())?;
        // System functions
        Self::add_host_function(&mut linker, "env", "pulse_assert", pulse_assert())?;

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
        action: Action,
        apply_context: ApplyContext,
        code_hash: Id,
    ) -> Result<(), ChainError> {
        // Different scope so session is released before running the wasm code.
        {
            let session = apply_context.undo_session();
            let mut session = session.borrow_mut();

            if !self.code_cache.contains(&code_hash) {
                let code_object = session.get::<CodeObject>(code_hash).map_err(|e| {
                    ChainError::WasmRuntimeError(format!("failed to get wasm code: {}", e))
                })?;
                let module = Module::new(&self.engine, code_object.code)
                    .map_err(|e| ChainError::WasmRuntimeError(e.to_string()))?;
                self.code_cache.put(code_hash, module);
            }
        }

        let context = WasmContext::new(receiver, action.clone(), apply_context);
        let mut store = Store::new(&self.engine, context);
        store.set_fuel(100000); // Set a fuel limit for the execution
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
                ChainError::WasmRuntimeError(format!("apply error: {}", e.root_cause()))
            })?;
        Ok(())
    }
}
