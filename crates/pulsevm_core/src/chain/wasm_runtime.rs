use std::{
    num::NonZeroUsize,
    sync::{Arc, RwLock},
};

use lru::LruCache;
use pulsevm_crypto::Bytes;
use pulsevm_error::ChainError;
use pulsevm_ffi::{CxxDigest, Database};
use wasmer::{
    Engine, Function, FunctionEnv, Instance, Memory, Module, Store, imports, sys::CompilerConfig,
    wasmparser::Operator,
};
use wasmer_compiler_llvm::{LLVM, LLVMOptLevel};
use wasmer_middlewares::{
    Metering,
    metering::{MeteringPoints, get_remaining_points, set_remaining_points},
};

use crate::{
    block::BlockTimestamp,
    chain::{
        apply_context::ApplyContext,
        id::Id,
        name::Name,
        transaction::Action,
        webassembly::{
            __addtf3, __ashlti3, __ashrti3, __cmptf2, __divtf3, __divti3, __eqtf2, __extenddftf2, __extendsftf2, __fixdfti, __fixsfti, __fixtfdi, __fixtfsi, __fixtfti, __fixunsdfti, __fixunssfti, __fixunstfsi, __fixunstfti, __floatditf, __floatsidf, __floatsitf, __floattidf, __floatunditf, __floatunsitf, __floatuntidf, __getf2, __gttf2, __letf2, __lshlti3, __lshrti3, __lttf2, __modti3, __multf3, __multi3, __negtf2, __netf2, __subtf3, __trunctfdf2, __trunctfsf2, __udivti3, __umodti3, __unordtf2, abort, assert_sha224, assert_sha256, assert_sha512, check_transaction_authorization, current_time, db_end_i64, db_find_i64, db_get_i64, db_idx64_end, db_idx64_find_primary, db_idx64_find_secondary, db_idx64_lowerbound, db_idx64_next, db_idx64_previous, db_idx64_remove, db_idx64_store, db_idx64_update, db_idx64_upperbound, db_idx128_end, db_idx128_find_primary, db_idx128_find_secondary, db_idx128_lowerbound, db_idx128_next, db_idx128_previous, db_idx128_remove, db_idx128_store, db_idx128_update, db_idx128_upperbound, db_lowerbound_i64, db_next_i64, db_previous_i64, db_remove_i64, db_store_i64, db_update_i64, db_upperbound_i64, eosio_assert, expiration, get_action, get_resource_limits, is_privileged, memcmp, memcpy, memmove, memset, printdf, printhex, printi, printi128, printn, prints, prints_l, printsf, printui, printui128, pulse_assert, pulse_assert_code, pulse_assert_message, pulse_exit, read_action_data, read_transaction, require_auth2, require_recipient, set_action_return_value, set_privileged, set_resource_limits, sha224, sha256, sha512, tapos_block_num, tapos_block_prefix, transaction_size
        },
    }, transaction::PackedTransaction,
};

use super::webassembly::{
    action_data_size, current_receiver, has_auth, is_account, require_auth, send_inline,
};

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
    pub fn new(
        receiver: Name,
        action: Action,
        pending_block_timestamp: BlockTimestamp,
        context: ApplyContext,
        db: Database,
    ) -> Self {
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

#[derive(Clone)]
struct CachedModule {
    module: Module,
    engine: Engine,
}

struct InnerWasmRuntime {
    code_cache: LruCache<Id, CachedModule>,
}

#[derive(Clone)]
pub struct WasmRuntime {
    inner: Arc<RwLock<InnerWasmRuntime>>,
}

const COST_FUNCTION: fn(&Operator) -> u64 = |operator: &Operator| -> u64 {
    match operator {
        Operator::Drop => 2,
        Operator::Select => 3,
        Operator::Br { .. }
        | Operator::BrTable { .. }
        | Operator::Call { .. }
        | Operator::CallIndirect { .. }
        | Operator::Return { .. } => 2,
        Operator::BrIf { .. } => 3,
        Operator::GlobalGet { .. }
        | Operator::GlobalSet { .. }
        | Operator::LocalGet { .. }
        | Operator::LocalSet { .. } => 3,
        Operator::I32Mul { .. }
        | Operator::I64Mul { .. }
        | Operator::F32Mul { .. }
        | Operator::F64Mul { .. } => 3,
        Operator::I32DivS { .. }
        | Operator::I32DivU { .. }
        | Operator::I32RemS { .. }
        | Operator::I32RemU { .. }
        | Operator::I64DivS { .. }
        | Operator::I64DivU { .. }
        | Operator::I64RemS { .. }
        | Operator::I64RemU { .. } => 80,
        Operator::I32Clz { .. } | Operator::I64Clz { .. } => 105,
        Operator::MemoryCopy { .. } | Operator::MemoryFill { .. } => 500,
        Operator::MemoryGrow { .. } => 1000, // Higher cost for memory growth
        _ => 1,                              // Default cost
    }
};

impl WasmRuntime {
    pub fn new() -> Result<Self, ChainError> {
        let mut compiler = LLVM::default();

        // Deterministic floating point operations
        LLVM::canonicalize_nans(&mut compiler, true);
        LLVM::opt_level(&mut compiler, LLVMOptLevel::Aggressive);

        Ok(Self {
            inner: Arc::new(RwLock::new(InnerWasmRuntime {
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
        cpu_limit: i64,
    ) -> Result<u64, ChainError> {
        // Pause timer
        apply_context.pause_billing_timer()?;

        let id = Id::from(code_hash);
        let module = {
            let mut inner = self.inner.write()?;

            if !inner.code_cache.contains(&id) {
                let code_object = db.get_code_object_by_hash(code_hash, 0, 0)?;
                let code_object = unsafe { &*code_object };

                // Create a temporary store just for module compilation
                let mut compiler = LLVM::default();

                // Add initial limit of 1,000 so start function can run if present
                let metering = Arc::new(Metering::new(1_000, COST_FUNCTION));
                compiler.push_middleware(metering);
                LLVM::canonicalize_nans(&mut compiler, true);
                LLVM::opt_level(&mut compiler, LLVMOptLevel::Aggressive);

                let temp_engine: Engine = compiler.into();
                let temp_store = Store::new(temp_engine.clone());

                let module = Module::new(temp_store.engine(), code_object.get_code().as_slice())
                    .map_err(|e| ChainError::WasmRuntimeError(e.to_string()))?;
                inner.code_cache.put(
                    id,
                    CachedModule {
                        module,
                        engine: temp_engine.clone(),
                    },
                );
            }

            inner.code_cache.get(&id).unwrap().clone()
        };

        let mut store = Store::new(module.engine.clone());
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
                // Memory functions
                "memcpy" => Function::new_typed_with_env(&mut store, &env, memcpy),
                "memset" => Function::new_typed_with_env(&mut store, &env, memset),
                "memcmp" => Function::new_typed_with_env(&mut store, &env, memcmp),
                "memmove" => Function::new_typed_with_env(&mut store, &env, memmove),
                // Builtins
                "__ashlti3" => Function::new_typed_with_env(&mut store, &env, __ashlti3),
                "__ashrti3" => Function::new_typed_with_env(&mut store, &env, __ashrti3),
                "__lshlti3" => Function::new_typed_with_env(&mut store, &env, __lshlti3),
                "__lshrti3" => Function::new_typed_with_env(&mut store, &env, __lshrti3),
                "__divti3" => Function::new_typed_with_env(&mut store, &env, __divti3),
                "__udivti3" => Function::new_typed_with_env(&mut store, &env, __udivti3),
                "__multi3" => Function::new_typed_with_env(&mut store, &env, __multi3),
                "__modti3" => Function::new_typed_with_env(&mut store, &env, __modti3),
                "__umodti3" => Function::new_typed_with_env(&mut store, &env, __umodti3),
                "__addtf3" => Function::new_typed_with_env(&mut store, &env, __addtf3),
                "__subtf3" => Function::new_typed_with_env(&mut store, &env, __subtf3),
                "__multf3" => Function::new_typed_with_env(&mut store, &env, __multf3),
                "__divtf3" => Function::new_typed_with_env(&mut store, &env, __divtf3),
                "__negtf2" => Function::new_typed_with_env(&mut store, &env, __negtf2),
                "__extendsftf2" => Function::new_typed_with_env(&mut store, &env, __extendsftf2),
                "__extenddftf2" => Function::new_typed_with_env(&mut store, &env, __extenddftf2),
                "__trunctfdf2" => Function::new_typed_with_env(&mut store, &env, __trunctfdf2),
                "__trunctfsf2" => Function::new_typed_with_env(&mut store, &env, __trunctfsf2),
                "__fixtfsi" => Function::new_typed_with_env(&mut store, &env, __fixtfsi),
                "__fixtfdi" => Function::new_typed_with_env(&mut store, &env, __fixtfdi),
                "__fixtfti" => Function::new_typed_with_env(&mut store, &env, __fixtfti),
                "__fixunstfsi" => Function::new_typed_with_env(&mut store, &env, __fixunstfsi),
                "__fixunstfti" => Function::new_typed_with_env(&mut store, &env, __fixunstfti),
                "__fixsfti" => Function::new_typed_with_env(&mut store, &env, __fixsfti),
                "__fixdfti" => Function::new_typed_with_env(&mut store, &env, __fixdfti),
                "__fixunssfti" => Function::new_typed_with_env(&mut store, &env, __fixunssfti),
                "__fixunsdfti" => Function::new_typed_with_env(&mut store, &env, __fixunsdfti),
                "__floatsidf" => Function::new_typed_with_env(&mut store, &env, __floatsidf),
                "__floatsitf" => Function::new_typed_with_env(&mut store, &env, __floatsitf),
                "__floatditf" => Function::new_typed_with_env(&mut store, &env, __floatditf),
                "__floatunsitf" => Function::new_typed_with_env(&mut store, &env, __floatunsitf),
                "__floatunditf" => Function::new_typed_with_env(&mut store, &env, __floatunditf),
                "__floattidf" => Function::new_typed_with_env(&mut store, &env, __floattidf),
                "__floatuntidf" => Function::new_typed_with_env(&mut store, &env, __floatuntidf),
                "__eqtf2" => Function::new_typed_with_env(&mut store, &env, __eqtf2),
                "__netf2" => Function::new_typed_with_env(&mut store, &env, __netf2),
                "__getf2" => Function::new_typed_with_env(&mut store, &env, __getf2),
                "__gttf2" => Function::new_typed_with_env(&mut store, &env, __gttf2),
                "__letf2" => Function::new_typed_with_env(&mut store, &env, __letf2),
                "__lttf2" => Function::new_typed_with_env(&mut store, &env, __lttf2),
                "__cmptf2" => Function::new_typed_with_env(&mut store, &env, __cmptf2),
                "__unordtf2" => Function::new_typed_with_env(&mut store, &env, __unordtf2),
                "action_data_size" => Function::new_typed_with_env(&mut store, &env, action_data_size),
                "read_action_data" => Function::new_typed_with_env(&mut store, &env, read_action_data),
                "current_receiver" => Function::new_typed_with_env(&mut store, &env, current_receiver),
                "set_action_return_value" => Function::new_typed_with_env(&mut store, &env, set_action_return_value),
                "require_auth" => Function::new_typed_with_env(&mut store, &env, require_auth),
                "has_auth" => Function::new_typed_with_env(&mut store, &env, has_auth),
                "require_auth2" => Function::new_typed_with_env(&mut store, &env, require_auth2),
                "require_recipient" => Function::new_typed_with_env(&mut store, &env, require_recipient),
                "is_account" => Function::new_typed_with_env(&mut store, &env, is_account),
                // Database functions for i64 tables
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
                // Secondary index functions for i64 tables
                "db_idx64_store" => Function::new_typed_with_env(&mut store, &env, db_idx64_store),
                "db_idx64_update" => Function::new_typed_with_env(&mut store, &env, db_idx64_update),
                "db_idx64_remove" => Function::new_typed_with_env(&mut store, &env, db_idx64_remove),
                "db_idx64_find_secondary" => Function::new_typed_with_env(&mut store, &env, db_idx64_find_secondary),
                "db_idx64_find_primary" => Function::new_typed_with_env(&mut store, &env, db_idx64_find_primary),
                "db_idx64_lowerbound" => Function::new_typed_with_env(&mut store, &env, db_idx64_lowerbound),
                "db_idx64_upperbound" => Function::new_typed_with_env(&mut store, &env, db_idx64_upperbound),
                "db_idx64_end" => Function::new_typed_with_env(&mut store, &env, db_idx64_end),
                "db_idx64_next" => Function::new_typed_with_env(&mut store, &env, db_idx64_next),
                "db_idx64_previous" => Function::new_typed_with_env(&mut store, &env, db_idx64_previous),
                // Index 128 functions
                "db_idx128_store" => Function::new_typed_with_env(&mut store, &env, db_idx128_store),
                "db_idx128_update" => Function::new_typed_with_env(&mut store, &env, db_idx128_update),
                "db_idx128_remove" => Function::new_typed_with_env(&mut store, &env, db_idx128_remove),
                "db_idx128_find_secondary" => Function::new_typed_with_env(&mut store, &env, db_idx128_find_secondary),
                "db_idx128_find_primary" => Function::new_typed_with_env(&mut store, &env, db_idx128_find_primary),
                "db_idx128_lowerbound" => Function::new_typed_with_env(&mut store, &env, db_idx128_lowerbound),
                "db_idx128_upperbound" => Function::new_typed_with_env(&mut store, &env, db_idx128_upperbound),
                "db_idx128_end" => Function::new_typed_with_env(&mut store, &env, db_idx128_end),
                "db_idx128_next" => Function::new_typed_with_env(&mut store, &env, db_idx128_next),
                "db_idx128_previous" => Function::new_typed_with_env(&mut store, &env, db_idx128_previous),
                // System functions
                "pulse_assert" => Function::new_typed_with_env(&mut store, &env, pulse_assert),
                "eosio_assert" => Function::new_typed_with_env(&mut store, &env, eosio_assert),
                "pulse_assert_message" => Function::new_typed_with_env(&mut store, &env, pulse_assert_message),
                "eosio_assert_message" => Function::new_typed_with_env(&mut store, &env, pulse_assert_message),
                "pulse_assert_code" => Function::new_typed_with_env(&mut store, &env, pulse_assert_code),
                "eosio_assert_code" => Function::new_typed_with_env(&mut store, &env, pulse_assert_code),
                "pulse_exit" => Function::new_typed_with_env(&mut store, &env, pulse_exit),
                "eosio_exit" => Function::new_typed_with_env(&mut store, &env, pulse_exit),
                "abort" => Function::new_typed_with_env(&mut store, &env, abort),
                "current_time" => Function::new_typed_with_env(&mut store, &env, current_time),
                // Crypto functions
                "sha224" => Function::new_typed_with_env(&mut store, &env, sha224),
                "sha256" => Function::new_typed_with_env(&mut store, &env, sha256),
                "sha512" => Function::new_typed_with_env(&mut store, &env, sha512),
                "assert_sha224" => Function::new_typed_with_env(&mut store, &env, assert_sha224),
                "assert_sha256" => Function::new_typed_with_env(&mut store, &env, assert_sha256),
                "assert_sha512" => Function::new_typed_with_env(&mut store, &env, assert_sha512),
                "is_privileged" => Function::new_typed_with_env(&mut store, &env, is_privileged),
                "set_privileged" => Function::new_typed_with_env(&mut store, &env, set_privileged),
                "set_resource_limits" => Function::new_typed_with_env(&mut store, &env, set_resource_limits),
                "get_resource_limits" => Function::new_typed_with_env(&mut store, &env, get_resource_limits),
                // Transaction functions
                "send_inline" => Function::new_typed_with_env(&mut store, &env, send_inline),
                "check_transaction_authorization" => Function::new_typed_with_env(&mut store, &env, check_transaction_authorization),
                "read_transaction" => Function::new_typed_with_env(&mut store, &env, read_transaction),
                "transaction_size" => Function::new_typed_with_env(&mut store, &env, transaction_size),
                "expiration" => Function::new_typed_with_env(&mut store, &env, expiration),
                "tapos_block_num" => Function::new_typed_with_env(&mut store, &env, tapos_block_num),
                "tapos_block_prefix" => Function::new_typed_with_env(&mut store, &env, tapos_block_prefix),
                "get_action" => Function::new_typed_with_env(&mut store, &env, get_action),
                // Console functions
                "prints" => Function::new_typed_with_env(&mut store, &env, prints),
                "prints_l" => Function::new_typed_with_env(&mut store, &env, prints_l),
                "printi" => Function::new_typed_with_env(&mut store, &env, printi),
                "printui" => Function::new_typed_with_env(&mut store, &env, printui),
                "printi128" => Function::new_typed_with_env(&mut store, &env, printi128),
                "printui128" => Function::new_typed_with_env(&mut store, &env, printui128),
                "printsf" => Function::new_typed_with_env(&mut store, &env, printsf),
                "printdf" => Function::new_typed_with_env(&mut store, &env, printdf),
                "printn" => Function::new_typed_with_env(&mut store, &env, printn),
                "printhex" => Function::new_typed_with_env(&mut store, &env, printhex),
            }
        };
        let instance = Instance::new(&mut store, &module.module, &import_object).map_err(|e| {
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

        // If CPU limit is -1, it means no limit, so we can set it to a very high value. Otherwise, use the provided limit.
        let cpu_limit = if cpu_limit >= 0 {
            cpu_limit as u64
        } else {
            300_000_000
        };

        // Set initial metering points based on resource limits
        set_remaining_points(&mut store, &instance, cpu_limit);

        let apply_func = instance
            .exports
            .get_typed_function::<(i64, i64, i64), ()>(&store, "apply")
            .map_err(|_| ChainError::WasmRuntimeError(format!("failed to find apply function")))?;

        // Resume timer
        apply_context.resume_billing_timer()?;

        let result = apply_func
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
                ChainError::WasmRuntimeError(format!("apply error: {}", e.message()))
            });
        let remaining_points: MeteringPoints = get_remaining_points(&mut store, &instance);

        match remaining_points {
            MeteringPoints::Remaining(points) => {
                // If the apply function returned an error, return it now that we've captured the remaining points
                if let Err(e) = result {
                    return Err(e);
                }

                Ok(cpu_limit.saturating_sub(points) as u64)
            }
            MeteringPoints::Exhausted => Err(ChainError::WasmRuntimeError(format!(
                "CPU limit of {} exhausted during apply",
                cpu_limit
            ))),
        }
    }
}
