//! Length-aware metering for the bulk-memory instructions.
//!
//! `memory.fill` and `memory.copy` are single wasm instructions that perform an
//! unbounded amount of native work: wasmer's LLVM backend lowers them to a bulk
//! `memset`/`memmove` over a length the contract chooses at runtime. wasmer's
//! [`Metering`] middleware cannot price that, because its cost function is a
//! pure `Operator -> u64` and the length lives on the operand stack, not in the
//! instruction's immediates. Pricing them flat -- 500 points for anything from
//! one byte to the whole linear memory -- undercharged by about five orders of
//! magnitude, and the metering budget is the only bound on in-wasm execution.
//!
//! This middleware injects the charge the flat cost could not express. It runs
//! *after* [`Metering`], reusing the very globals that middleware installs, so
//! exhaustion behaves identically however the budget is spent.
//!
//! The price is [`cost::memory`] -- `300 + 10 * len`, the same measured cost the
//! host `memcpy`/`memmove`/`memset`/`memcmp` intrinsics already charge for the
//! same work. That is the point: identical work now costs the same whether a
//! contract reaches it through a host intrinsic or a wasm instruction.
//!
//! **This changes gas accounting**, so it is consensus-visible: a contract using
//! bulk memory is billed differently than before. Rolling it out needs the usual
//! protocol-feature treatment and a golden-replay run.

use std::sync::Mutex;

use wasmer::{
    ExportIndex,
    GlobalInit,
    GlobalType,
    LocalFunctionIndex,
    ModuleInfo,
    Mutability,
    Type,
    sys::{
        FunctionMiddleware,
        MiddlewareError,
        MiddlewareReaderState,
        ModuleMiddleware,
        wasmparser::Operator,
    },
};

/// Fixed overhead of a bulk-memory operation, mirroring `cost::memory`.
const BULK_BASE_COST: i64 = 300;
/// Per-byte slope, mirroring `cost::memory`.
const BULK_PER_BYTE_COST: i64 = 10;

/// The globals this middleware needs: the two `Metering` installs, plus one
/// scratch slot of our own.
#[derive(Debug, Clone, Copy)]
struct Globals {
    remaining_points: u32,
    points_exhausted: u32,
    /// Holds the length operand while the charge is computed. wasm has no
    /// stack-duplicate instruction and a middleware cannot declare new locals,
    /// so the value is parked in a global and pushed back afterwards. An
    /// instance is single-threaded, so a shared slot is safe.
    scratch_len: u32,
}

#[derive(Debug)]
pub struct BulkMemoryMetering {
    globals: Mutex<Option<Globals>>,
}

impl BulkMemoryMetering {
    pub fn new() -> Self {
        Self {
            globals: Mutex::new(None),
        }
    }
}

impl Default for BulkMemoryMetering {
    fn default() -> Self {
        Self::new()
    }
}

/// Look up a global that another middleware exported by name.
fn exported_global(module_info: &ModuleInfo, name: &str) -> Option<u32> {
    match module_info.exports.get(name) {
        Some(ExportIndex::Global(index)) => Some(index.as_u32()),
        _ => None,
    }
}

impl ModuleMiddleware for BulkMemoryMetering {
    fn transform_module_info(&self, module_info: &mut ModuleInfo) -> Result<(), MiddlewareError> {
        let mut slot = self.globals.lock().unwrap();
        if slot.is_some() {
            return Err(MiddlewareError::new(
                "BulkMemoryMetering",
                "middleware instance reused across modules",
            ));
        }

        // Metering must already have run its module transform, which is what
        // publishes these. If they are missing the engine was built wrong, and
        // failing closed is the only safe answer -- silently skipping would
        // leave bulk memory unpriced.
        let remaining_points = exported_global(module_info, "wasmer_metering_remaining_points")
            .ok_or_else(|| {
                MiddlewareError::new(
                    "BulkMemoryMetering",
                    "wasmer_metering_remaining_points not found; push this middleware after Metering",
                )
            })?;
        let points_exhausted = exported_global(module_info, "wasmer_metering_points_exhausted")
            .ok_or_else(|| {
                MiddlewareError::new(
                    "BulkMemoryMetering",
                    "wasmer_metering_points_exhausted not found; push this middleware after Metering",
                )
            })?;

        let scratch_len = module_info
            .globals
            .push(GlobalType::new(Type::I32, Mutability::Var))
            .as_u32();
        module_info
            .global_initializers
            .push(GlobalInit::I32Const(0));

        *slot = Some(Globals {
            remaining_points,
            points_exhausted,
            scratch_len,
        });
        Ok(())
    }

    fn generate_function_middleware<'a>(
        &self,
        _local_function_index: LocalFunctionIndex,
    ) -> Box<dyn FunctionMiddleware<'a> + 'a> {
        Box::new(FunctionBulkMemoryMetering {
            globals: self.globals.lock().unwrap().expect(
                "BulkMemoryMetering::transform_module_info must run before function translation",
            ),
        })
    }
}

#[derive(Debug)]
struct FunctionBulkMemoryMetering {
    globals: Globals,
}

impl FunctionBulkMemoryMetering {
    /// Emit `300 + 10 * scratch_len` as an i64 on the operand stack.
    fn push_charge(&self, state: &mut MiddlewareReaderState<'_>) {
        state.extend(&[
            Operator::GlobalGet {
                global_index: self.globals.scratch_len,
            },
            // The length is an unsigned i32; extending it unsigned keeps a
            // length above 2 GiB from becoming a negative charge.
            Operator::I64ExtendI32U,
            Operator::I64Const {
                value: BULK_PER_BYTE_COST,
            },
            Operator::I64Mul,
            Operator::I64Const {
                value: BULK_BASE_COST,
            },
            Operator::I64Add,
        ]);
    }
}

impl<'a> FunctionMiddleware<'a> for FunctionBulkMemoryMetering {
    fn feed(
        &mut self,
        operator: Operator<'a>,
        state: &mut MiddlewareReaderState<'a>,
    ) -> Result<(), MiddlewareError> {
        if !matches!(
            operator,
            Operator::MemoryFill { .. } | Operator::MemoryCopy { .. }
        ) {
            state.push_operator(operator);
            return Ok(());
        }

        // Both ops take the byte count as the topmost operand:
        //   memory.fill (dest, value, len)
        //   memory.copy (dest, src,   len)
        // Park it, charge for it, put it back, then run the original op.
        state.extend(&[Operator::GlobalSet {
            global_index: self.globals.scratch_len,
        }]);

        // if remaining < charge { exhausted = 1; unreachable }
        state.extend(&[Operator::GlobalGet {
            global_index: self.globals.remaining_points,
        }]);
        self.push_charge(state);
        state.extend(&[
            Operator::I64LtU,
            Operator::If {
                blockty: wasmer::sys::wasmparser::BlockType::Empty,
            },
            Operator::I32Const { value: 1 },
            Operator::GlobalSet {
                global_index: self.globals.points_exhausted,
            },
            Operator::Unreachable,
            Operator::End,
        ]);

        // remaining -= charge
        state.extend(&[Operator::GlobalGet {
            global_index: self.globals.remaining_points,
        }]);
        self.push_charge(state);
        state.extend(&[
            Operator::I64Sub,
            Operator::GlobalSet {
                global_index: self.globals.remaining_points,
            },
        ]);

        // Restore the length and run the instruction we intercepted.
        state.extend(&[Operator::GlobalGet {
            global_index: self.globals.scratch_len,
        }]);
        state.push_operator(operator);
        Ok(())
    }
}
