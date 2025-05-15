use pulsevm_chainbase::UndoSession;
use wasmtime::{
    Config, Engine, InstanceAllocationStrategy, Linker, Module, PoolingAllocationConfig, Store,
    Strategy,
};

use super::{
    apply_context::ApplyContext,
    error::ChainError,
    webassembly::{has_auth, is_account, require_auth},
};

pub struct WasmContext<'a, 'b> {
    pub context: &'a mut ApplyContext<'a, 'b>,
    pub session: &'a UndoSession<'b>,
}

pub struct WasmRuntime<'a, 'b> {
    config: Config,
    engine: Engine,
    linker: Linker<WasmContext<'a, 'b>>,
}

impl<'a, 'b> WasmRuntime<'a, 'b> {
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

        let engine =
            Engine::new(&config).map_err(|e| ChainError::WasmRuntimeError(e.to_string()))?;

        // Add host functions to the linker.
        let mut linker = Linker::<WasmContext>::new(&engine);
        linker.func_wrap("env", "require_auth", require_auth());
        linker.func_wrap("env", "has_auth", has_auth());
        linker.func_wrap("env", "require_auth2", require_auth());
        linker.func_wrap("env", "require_recipient", require_auth());
        linker.func_wrap("env", "is_account", is_account());

        Ok(Self {
            config: config.to_owned(),
            engine: engine,
            linker,
        })
    }

    pub fn run(
        &self,
        session: &'a UndoSession<'b>,
        context: &'a mut ApplyContext<'a, 'b>,
        bytes: Vec<u8>,
    ) -> Result<(), ChainError> {
        let wasm_context = WasmContext { context, session };
        let mut store = Store::new(&self.engine, wasm_context);
        let module = Module::new(&self.engine, bytes)
            .map_err(|e| ChainError::WasmRuntimeError(e.to_string()))?;
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
