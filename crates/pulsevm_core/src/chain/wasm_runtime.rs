use std::{
    cell::RefCell,
    collections::HashMap,
    num::NonZeroUsize,
    rc::Rc,
    sync::{Arc, RwLock},
};

use chrono::Utc;
use lru::LruCache;
use pulsevm_chainbase::{Session, UndoSession};
use wasmtime::{
    Caller, Config, Engine, Extern, ExternType, Func, Instance, IntoFunc, Linker, Module, Store,
    Strategy,
};

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
            db_update_i64, db_upperbound_i64, get_resource_limits, get_self, is_privileged,
            pulse_assert, read_action_data, require_auth2, require_recipient,
            set_action_return_value, set_privileged, set_resource_limits, sha224, sha256, sha512,
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
    pub receiver: Name,
    pub action: Action,
    pub pending_block_time: BlockTimestamp,
    pub context: ApplyContext,
    pub session: UndoSession<'static>,
}

impl WasmContext {
    pub fn new(
        receiver: Name,
        action: Action,
        pending_block_time: BlockTimestamp,
        context: ApplyContext,
        session: UndoSession<'static>,
    ) -> Self {
        WasmContext {
            receiver,
            action,
            pending_block_time,
            context,
            session,
        }
    }

    pub fn receiver(&self) -> Name {
        self.receiver
    }

    pub fn action(&self) -> &Action {
        &self.action
    }

    pub fn pending_block_time(&self) -> BlockTimestamp {
        self.pending_block_time
    }

    pub fn context(&self) -> &ApplyContext {
        &self.context
    }

    pub fn context_mut(&mut self) -> &mut ApplyContext {
        &mut self.context
    }

    pub fn session(&self) -> &UndoSession<'static> {
        &self.session
    }

    pub fn session_mut(&mut self) -> &mut UndoSession<'static> {
        &mut self.session
    }
}

#[derive(Clone)]
pub struct WasmRuntime {
    engine: Arc<Engine>,
    code_cache: Arc<RwLock<LruCache<Id, Module>>>,
    linker: Arc<Linker<WasmContext>>,
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
        //config.consume_fuel(true);

        let engine = Engine::new(&config)?;
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
            engine: Arc::new(engine),
            code_cache: Arc::new(RwLock::new(LruCache::new(NonZeroUsize::new(1024).unwrap()))),
            linker: Arc::new(linker),
        })
    }

    #[must_use]
    fn add_host_function<Params, Args>(
        linker: &mut Linker<WasmContext>,
        module: &str,
        name: &str,
        func: impl IntoFunc<WasmContext, Params, Args>,
    ) -> Result<(), ChainError> {
        linker.func_wrap(module, name, func)?;
        Ok(())
    }

    pub fn run(
        &mut self,
        receiver: Name,
        action: &Action,
        pending_block_time: BlockTimestamp,
        context: ApplyContext,
        undo_session: UndoSession<'_>,
        code_hash: Id,
    ) -> Result<(), ChainError> {
        // Different scope so session is released before running the wasm code.
        let module = {
            let mut code_cache = self.code_cache.write()?;

            if !code_cache.contains(&code_hash) {
                let code_object = undo_session.get::<CodeObject>(code_hash)?;
                let module = Module::new(&self.engine, code_object.code.as_ref())?;
                code_cache.put(code_hash, module);
            }

            code_cache
                .get(&code_hash)
                .ok_or_else(|| {
                    ChainError::WasmRuntimeError(format!(
                        "wasm module not found in cache: {}",
                        code_hash
                    ))
                })?
                .clone()
        };

        // Create the Wasm context containing the apply context and undo session
        // for use by host functions. The undo session reference is transmuted to
        // 'static because wasmtime requires that all data in the Store is 'static.
        let wasm_context: WasmContext = WasmContext::new(
            receiver,
            action.clone(),
            pending_block_time,
            context,
            unsafe { std::mem::transmute::<UndoSession<'_>, UndoSession<'static>>(undo_session) },
        );
        let mut store = Store::new(&self.engine, wasm_context);
        let instance = self.linker.instantiate(&mut store, &module)?;
        let apply_func = instance.get_typed_func::<(u64, u64, u64), ()>(&mut store, "apply")?;

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
                ChainError::WasmRuntimeError(format!("apply error: {}", e.root_cause()))
            })?;

        Ok(())
    }
}
