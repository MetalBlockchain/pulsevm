use std::{cell::RefCell, num::NonZeroUsize, rc::Rc};

use lru::LruCache;
use pulsevm_chainbase::UndoSession;
use wasmtime::{
    Config, Engine, InstanceAllocationStrategy, Linker, Module, PoolingAllocationConfig, Store,
    Strategy,
};

use super::{
    CodeObject, Id,
    error::ChainError,
    webassembly::{
        action_data_size, current_receiver, has_auth, is_account, memcmp, memcpy, memmove, memset,
        require_auth, send_inline,
    },
};

pub struct WasmContext<'a> {
    session: Rc<RefCell<UndoSession<'a>>>,
}

impl<'a> WasmContext<'a> {
    pub fn new(session: Rc<RefCell<UndoSession<'a>>>) -> Self {
        WasmContext { session }
    }
}

pub struct WasmRuntime<'a> {
    config: Config,
    engine: Engine,
    linker: Linker<WasmContext<'a>>,
    code_cache: LruCache<Id, Module>,
}

impl<'a> WasmRuntime<'a> {
    pub fn new() -> Self {
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

        let mut pool = PoolingAllocationConfig::new();
        pool.total_memories(50);
        pool.max_memory_size(1 << 31); // 2 GiB
        pool.total_tables(50);
        pool.table_elements(1000);
        pool.total_core_instances(10);
        config.allocation_strategy(InstanceAllocationStrategy::Pooling(pool));

        // Enable copy-on-write heap images.
        config.memory_init_cow(true);

        // Enable parallel compilation.
        config.parallel_compilation(true);

        let engine = Engine::new(&config)
            .map_err(|e| ChainError::WasmRuntimeError(e.to_string()))
            .unwrap();

        // Add host functions to the linker.
        let mut linker = Linker::<WasmContext<'a>>::new(&engine);
        // Action functions
        linker.func_wrap("env", "action_data_size", action_data_size());
        linker.func_wrap("env", "current_receiver", current_receiver());
        // Authorization functions
        linker.func_wrap("env", "require_auth", require_auth());
        linker.func_wrap("env", "has_auth", has_auth());
        linker.func_wrap("env", "require_auth2", require_auth());
        linker.func_wrap("env", "require_recipient", require_auth());
        linker.func_wrap("env", "is_account", is_account());
        // Memory functions
        linker.func_wrap("env", "memcpy", memcpy());
        linker.func_wrap("env", "memmove", memmove());
        linker.func_wrap("env", "memcmp", memcmp());
        linker.func_wrap("env", "memset", memset());
        // Transaction functions
        linker.func_wrap("env", "send_inline", send_inline());

        Self {
            config: config.to_owned(),
            engine: engine,
            linker,
            code_cache: LruCache::new(NonZeroUsize::new(1024).unwrap()),
        }
    }

    pub fn run(&mut self, context: WasmContext<'a>, code_hash: Id) -> Result<(), ChainError> {
        if !self.code_cache.contains(&code_hash) {
            let code_object = context
                .session
                .borrow()
                .get::<CodeObject>(code_hash)
                .map_err(|e| {
                    ChainError::WasmRuntimeError(format!("failed to get wasm code: {}", e))
                })?;
            let module = Module::new(&self.engine, code_object.code)
                .map_err(|e| ChainError::WasmRuntimeError(e.to_string()))?;
            self.code_cache.put(code_hash, module);
        }

        let mut store = Store::new(&self.engine, context);
        let module = self.code_cache.get(&code_hash).ok_or_else(|| {
            ChainError::WasmRuntimeError(format!("wasm module not found in cache: {}", code_hash))
        })?;
        let instance = self
            .linker
            .instantiate(&mut store, &module)
            .map_err(|e| ChainError::WasmRuntimeError(e.to_string()))?;
        let apply_func = instance
            .get_typed_func::<(), ()>(&mut store, "run")
            .map_err(|e| ChainError::WasmRuntimeError(e.to_string()))?;
        apply_func
            .call(store, ())
            .map_err(|e| ChainError::WasmRuntimeError(format!("apply error: {}", e.to_string())))?;
        Ok(())
    }
}
