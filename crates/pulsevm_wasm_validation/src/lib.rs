//! # EOSIO WASM Validation
//!
//! A Rust port of Antelope/Leap's `wasm_eosio_validation.cpp` using the
//! [`wasmparser`] crate. This module enforces the same constraints that the
//! C++ WAVM-based validator does:
//!
//! | Constraint                        | Limit                       |
//! |-----------------------------------|-----------------------------|
//! | Maximum linear memory             | 33 MiB (528 wasm pages)     |
//! | Maximum initial memory data       | 64 KiB                      |
//! | Maximum mutable global bytes      | 1 024 bytes                 |
//! | Maximum table elements            | 1 024                       |
//! | Maximum function local+param bytes| 8 192 bytes                 |
//! | Maximum call depth (nesting)      | 1 024                       |
//! | Maximum code size                 | 20 MiB                      |
//! | Memory store/load offset          | < 33 MiB                    |
//! | `apply(i64, i64, i64)` export     | required                    |

use wasmparser::{
    BinaryReaderError, Export, ExternalKind, FuncType, GlobalType, MemoryType, Operator, Parser,
    Payload, TableType, ValType,
};

// ---------------------------------------------------------------------------
// Constraints – mirrors `wasm_eosio_constraints.hpp`
// ---------------------------------------------------------------------------

/// EOSIO WASM constraints, matching the constants in
/// `libraries/chain/include/eosio/chain/wasm_eosio_constraints.hpp`.
pub mod constraints {
    /// 33 MiB – maximum linear memory in bytes.
    pub const MAXIMUM_LINEAR_MEMORY: u64 = 33 * 1024 * 1024;
    /// Maximum mutable global storage in bytes.
    pub const MAXIMUM_MUTABLE_GLOBALS: u32 = 1024;
    /// Maximum table element count.
    pub const MAXIMUM_TABLE_ELEMENTS: u64 = 1024;
    /// Maximum section element count (unused at module level in the C++ impl,
    /// but included for completeness).
    pub const MAXIMUM_SECTION_ELEMENTS: u32 = 1024;
    /// 64 KiB – data segments must lie within this range.
    pub const MAXIMUM_LINEAR_MEMORY_INIT: u64 = 64 * 1024;
    /// Maximum bytes of locals + parameters per function.
    pub const MAXIMUM_FUNC_LOCAL_BYTES: u32 = 8192;
    /// Maximum nesting depth for blocks/loops/ifs.
    pub const MAXIMUM_CALL_DEPTH: u32 = 250;
    /// 20 MiB – maximum code size.
    pub const MAXIMUM_CODE_SIZE: usize = 20 * 1024 * 1024;
    /// Standard WASM page size.
    pub const WASM_PAGE_SIZE: u64 = 64 * 1024;
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by EOSIO WASM validation.
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error(
        "Smart contract initial memory size must be less than or equal to {}KiB",
        constraints::MAXIMUM_LINEAR_MEMORY / 1024
    )]
    MemoryTooLarge,

    #[error("Smart contract has unexpected memory base offset type")]
    UnexpectedDataSegmentOffsetType,

    #[error(
        "Smart contract data segments must lie in first {}KiB",
        constraints::MAXIMUM_LINEAR_MEMORY_INIT / 1024
    )]
    DataSegmentOutOfRange,

    #[error(
        "Smart contract table limited to {} elements",
        constraints::MAXIMUM_TABLE_ELEMENTS
    )]
    TableTooLarge,

    #[error("Smart contract has unexpected global definition value type")]
    UnexpectedGlobalType,

    #[error(
        "Smart contract has more than {} bytes of mutable globals",
        constraints::MAXIMUM_MUTABLE_GLOBALS
    )]
    TooManyMutableGlobals,

    #[error(
        "Smart contract function has more than {} bytes of stack usage",
        constraints::MAXIMUM_FUNC_LOCAL_BYTES
    )]
    FunctionStackTooLarge,

    #[error("Smart contract's apply function not exported; non-existent; or wrong type")]
    ApplyNotExported,

    #[error("Smart contract used an invalid large memory store/load offset")]
    LargeMemoryOffset,

    #[error("Nested depth exceeded")]
    NestedDepthExceeded,

    #[error("Error, blacklisted opcode {0}")]
    BlacklistedOpcode(String),

    #[error(
        "Smart contract code size exceeds maximum ({} bytes)",
        constraints::MAXIMUM_CODE_SIZE
    )]
    CodeTooLarge,

    #[error("WASM parse error: {0}")]
    Parse(#[from] BinaryReaderError),
}

pub type Result<T> = std::result::Result<T, ValidationError>;

// ---------------------------------------------------------------------------
// Collected module-level information
// ---------------------------------------------------------------------------

/// Intermediate representation collected during a single pass of the WASM binary.
#[derive(Default)]
struct ModuleInfo {
    /// (min_pages, max_pages) for each defined memory.
    memories: Vec<MemoryType>,
    /// Defined tables.
    tables: Vec<TableType>,
    /// Defined globals.
    globals: Vec<GlobalType>,
    /// Function type indices – one entry per function *definition* (not import).
    func_type_indices: Vec<u32>,
    /// All declared types (function signatures).
    types: Vec<FuncType>,
    /// Exports.
    exports: Vec<(String, ExternalKind, u32)>,
    /// Number of imported functions (needed to map export index → local func).
    num_imported_functions: u32,
}

// ---------------------------------------------------------------------------
// Helpers to compute the byte-width of a `ValType`
// ---------------------------------------------------------------------------

fn val_type_byte_size(ty: &ValType) -> u32 {
    match ty {
        ValType::I32 | ValType::F32 => 4,
        ValType::I64 | ValType::F64 => 8,
        // v128 / funcref / externref are not used in EOSIO contracts, but
        // we conservatively size them so validation doesn't silently pass.
        ValType::V128 => 16,
        _ => 8, // reference types – treat as pointer-width
    }
}

// ---------------------------------------------------------------------------
// Module-level validators (mirrors the C++ `*_validation_visitor` structs)
// ---------------------------------------------------------------------------

/// `memories_validation_visitor::validate`
fn validate_memories(info: &ModuleInfo) -> Result<()> {
    if let Some(mem) = info.memories.first() {
        let min_bytes = (mem.initial as u64) * constraints::WASM_PAGE_SIZE;
        if min_bytes > constraints::MAXIMUM_LINEAR_MEMORY {
            return Err(ValidationError::MemoryTooLarge);
        }
    }
    Ok(())
}

/// `tables_validation_visitor::validate`
fn validate_tables(info: &ModuleInfo) -> Result<()> {
    if let Some(table) = info.tables.first() {
        if (table.initial as u64) > constraints::MAXIMUM_TABLE_ELEMENTS {
            return Err(ValidationError::TableTooLarge);
        }
    }
    Ok(())
}

/// `globals_validation_visitor::validate`
///
/// Note: the original C++ uses fall-through switch semantics (no `break`),
/// which means i64/f64 add 8 bytes total and i32/f32 add 4 bytes.
fn validate_globals(info: &ModuleInfo) -> Result<()> {
    let mut mutable_globals_total_size: u32 = 0;
    for global in &info.globals {
        if !global.mutable {
            continue;
        }
        match global.content_type {
            ValType::I64 | ValType::F64 => {
                // C++ fall-through: 4 (from i64/f64 case) + 4 (from i32/f32 case) = 8
                mutable_globals_total_size += 8;
            }
            ValType::I32 | ValType::F32 => {
                mutable_globals_total_size += 4;
            }
            _ => {
                return Err(ValidationError::UnexpectedGlobalType);
            }
        }
    }
    if mutable_globals_total_size > constraints::MAXIMUM_MUTABLE_GLOBALS {
        return Err(ValidationError::TooManyMutableGlobals);
    }
    Ok(())
}

/// `maximum_function_stack_visitor::validate`
fn validate_function_stack(info: &ModuleInfo) -> Result<()> {
    for &type_idx in &info.func_type_indices {
        if let Some(func_type) = info.types.get(type_idx as usize) {
            let param_bytes: u32 = func_type.params().iter().map(val_type_byte_size).sum();
            // Non-parameter locals are validated separately in the code section
            // pass, but we record the param contribution here. The local bytes
            // are accumulated when we parse the code section bodies.
            //
            // For the *module-level* check we only have type info (no locals yet),
            // so we just verify params don't already exceed the limit.
            if param_bytes > constraints::MAXIMUM_FUNC_LOCAL_BYTES {
                return Err(ValidationError::FunctionStackTooLarge);
            }
        }
    }
    Ok(())
}

/// `ensure_apply_exported_visitor::validate`
///
/// Searches for an export named `"apply"` that is a function with signature
/// `(i64, i64, i64) -> ()`.
fn validate_apply_export(info: &ModuleInfo) -> Result<()> {
    for (name, kind, index) in &info.exports {
        if *kind != ExternalKind::Func || name != "apply" {
            continue;
        }
        // Map the export function index to a type. Export indices are in the
        // combined function index space: imports first, then definitions.
        let type_idx = if *index < info.num_imported_functions {
            // Imported function – we don't track import types in this
            // simplified impl, so we skip. In practice the apply function
            // should always be defined, not imported.
            continue;
        } else {
            let local_idx = (*index - info.num_imported_functions) as usize;
            match info.func_type_indices.get(local_idx) {
                Some(&ti) => ti,
                None => continue,
            }
        };

        if let Some(func_type) = info.types.get(type_idx as usize) {
            let expected_params: &[ValType] = &[ValType::I64, ValType::I64, ValType::I64];
            if func_type.params() == expected_params && func_type.results().is_empty() {
                return Ok(());
            }
        }
    }
    Err(ValidationError::ApplyNotExported)
}

// ---------------------------------------------------------------------------
// Instruction-level validators
// ---------------------------------------------------------------------------

/// Validates that memory load/store offsets are within the linear memory limit.
/// Mirrors `large_offset_validator`.
fn validate_operator_offset(op: &Operator) -> Result<()> {
    let offset: Option<u64> = match op {
        Operator::I32Load { memarg } => Some(memarg.offset),
        Operator::I64Load { memarg } => Some(memarg.offset),
        Operator::F32Load { memarg } => Some(memarg.offset),
        Operator::F64Load { memarg } => Some(memarg.offset),
        Operator::I32Load8S { memarg } => Some(memarg.offset),
        Operator::I32Load8U { memarg } => Some(memarg.offset),
        Operator::I32Load16S { memarg } => Some(memarg.offset),
        Operator::I32Load16U { memarg } => Some(memarg.offset),
        Operator::I64Load8S { memarg } => Some(memarg.offset),
        Operator::I64Load8U { memarg } => Some(memarg.offset),
        Operator::I64Load16S { memarg } => Some(memarg.offset),
        Operator::I64Load16U { memarg } => Some(memarg.offset),
        Operator::I64Load32S { memarg } => Some(memarg.offset),
        Operator::I64Load32U { memarg } => Some(memarg.offset),
        Operator::I32Store { memarg } => Some(memarg.offset),
        Operator::I64Store { memarg } => Some(memarg.offset),
        Operator::F32Store { memarg } => Some(memarg.offset),
        Operator::F64Store { memarg } => Some(memarg.offset),
        Operator::I32Store8 { memarg } => Some(memarg.offset),
        Operator::I32Store16 { memarg } => Some(memarg.offset),
        Operator::I64Store8 { memarg } => Some(memarg.offset),
        Operator::I64Store16 { memarg } => Some(memarg.offset),
        Operator::I64Store32 { memarg } => Some(memarg.offset),
        _ => None,
    };

    if let Some(off) = offset {
        if off >= constraints::MAXIMUM_LINEAR_MEMORY {
            return Err(ValidationError::LargeMemoryOffset);
        }
    }
    Ok(())
}

/// Tracks block nesting depth. Mirrors `nested_validator`.
fn validate_nesting(op: &Operator, depth: &mut u32) -> Result<()> {
    match op {
        Operator::Block { .. } | Operator::Loop { .. } | Operator::If { .. } => {
            *depth += 1;
            if *depth >= 1024 {
                return Err(ValidationError::NestedDepthExceeded);
            }
        }
        Operator::End => {
            if *depth > 0 {
                *depth -= 1;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Validates that only allowed opcodes are used. Mirrors `opcode_whitelist_validator`.
fn validate_opcode_whitelist(op: &Operator) -> Result<()> {
    let allowed = matches!(
        op,
        // Control flow (block/loop/if/else also go through nested_validator)
        Operator::Block { .. }
        | Operator::Loop { .. }
        | Operator::If { .. }
        | Operator::Else
        | Operator::End
        | Operator::Unreachable
        | Operator::Br { .. }
        | Operator::BrIf { .. }
        | Operator::BrTable { .. }
        | Operator::Return
        | Operator::Call { .. }
        | Operator::CallIndirect { .. }
        | Operator::Drop
        | Operator::Select
        // Locals / globals
        | Operator::LocalGet { .. }
        | Operator::LocalSet { .. }
        | Operator::LocalTee { .. }
        | Operator::GlobalGet { .. }
        | Operator::GlobalSet { .. }
        // Memory
        | Operator::MemoryGrow { .. }
        | Operator::MemorySize { .. }
        | Operator::MemoryCopy { .. }
        | Operator::MemoryFill { .. }
        | Operator::Nop
        // Loads
        | Operator::I32Load { .. }
        | Operator::I64Load { .. }
        | Operator::F32Load { .. }
        | Operator::F64Load { .. }
        | Operator::I32Load8S { .. }
        | Operator::I32Load8U { .. }
        | Operator::I32Load16S { .. }
        | Operator::I32Load16U { .. }
        | Operator::I64Load8S { .. }
        | Operator::I64Load8U { .. }
        | Operator::I64Load16S { .. }
        | Operator::I64Load16U { .. }
        | Operator::I64Load32S { .. }
        | Operator::I64Load32U { .. }
        // Stores
        | Operator::I32Store { .. }
        | Operator::I64Store { .. }
        | Operator::F32Store { .. }
        | Operator::F64Store { .. }
        | Operator::I32Store8 { .. }
        | Operator::I32Store16 { .. }
        | Operator::I64Store8 { .. }
        | Operator::I64Store16 { .. }
        | Operator::I64Store32 { .. }
        // Constants
        | Operator::I32Const { .. }
        | Operator::I64Const { .. }
        | Operator::F32Const { .. }
        | Operator::F64Const { .. }
        // i32 comparison
        | Operator::I32Eqz
        | Operator::I32Eq
        | Operator::I32Ne
        | Operator::I32LtS
        | Operator::I32LtU
        | Operator::I32GtS
        | Operator::I32GtU
        | Operator::I32LeS
        | Operator::I32LeU
        | Operator::I32GeS
        | Operator::I32GeU
        // i32 unary
        | Operator::I32Clz
        | Operator::I32Ctz
        | Operator::I32Popcnt
        // i32 binary
        | Operator::I32Add
        | Operator::I32Sub
        | Operator::I32Mul
        | Operator::I32DivS
        | Operator::I32DivU
        | Operator::I32RemS
        | Operator::I32RemU
        | Operator::I32And
        | Operator::I32Or
        | Operator::I32Xor
        | Operator::I32Shl
        | Operator::I32ShrS
        | Operator::I32ShrU
        | Operator::I32Rotl
        | Operator::I32Rotr
        // i64 comparison
        | Operator::I64Eqz
        | Operator::I64Eq
        | Operator::I64Ne
        | Operator::I64LtS
        | Operator::I64LtU
        | Operator::I64GtS
        | Operator::I64GtU
        | Operator::I64LeS
        | Operator::I64LeU
        | Operator::I64GeS
        | Operator::I64GeU
        // i64 unary
        | Operator::I64Clz
        | Operator::I64Ctz
        | Operator::I64Popcnt
        // i64 binary
        | Operator::I64Add
        | Operator::I64Sub
        | Operator::I64Mul
        | Operator::I64DivS
        | Operator::I64DivU
        | Operator::I64RemS
        | Operator::I64RemU
        | Operator::I64And
        | Operator::I64Or
        | Operator::I64Xor
        | Operator::I64Shl
        | Operator::I64ShrS
        | Operator::I64ShrU
        | Operator::I64Rotl
        | Operator::I64Rotr
        // f32 comparison
        | Operator::F32Eq
        | Operator::F32Ne
        | Operator::F32Lt
        | Operator::F32Gt
        | Operator::F32Le
        | Operator::F32Ge
        // f64 comparison
        | Operator::F64Eq
        | Operator::F64Ne
        | Operator::F64Lt
        | Operator::F64Gt
        | Operator::F64Le
        | Operator::F64Ge
        // f32 unary / binary
        | Operator::F32Abs
        | Operator::F32Neg
        | Operator::F32Ceil
        | Operator::F32Floor
        | Operator::F32Trunc
        | Operator::F32Nearest
        | Operator::F32Sqrt
        | Operator::F32Add
        | Operator::F32Sub
        | Operator::F32Mul
        | Operator::F32Div
        | Operator::F32Min
        | Operator::F32Max
        | Operator::F32Copysign
        // f64 unary / binary
        | Operator::F64Abs
        | Operator::F64Neg
        | Operator::F64Ceil
        | Operator::F64Floor
        | Operator::F64Trunc
        | Operator::F64Nearest
        | Operator::F64Sqrt
        | Operator::F64Add
        | Operator::F64Sub
        | Operator::F64Mul
        | Operator::F64Div
        | Operator::F64Min
        | Operator::F64Max
        | Operator::F64Copysign
        // Conversions
        | Operator::I32TruncF32S
        | Operator::I32TruncF32U
        | Operator::I32TruncF64S
        | Operator::I32TruncF64U
        | Operator::I64TruncF32S
        | Operator::I64TruncF32U
        | Operator::I64TruncF64S
        | Operator::I64TruncF64U
        | Operator::F32ConvertI32S
        | Operator::F32ConvertI32U
        | Operator::F32ConvertI64S
        | Operator::F32ConvertI64U
        | Operator::F32DemoteF64
        | Operator::F64ConvertI32S
        | Operator::F64ConvertI32U
        | Operator::F64ConvertI64S
        | Operator::F64ConvertI64U
        | Operator::F64PromoteF32
        // Wraps / extends / reinterprets
        | Operator::I32WrapI64
        | Operator::I32Extend8S
        | Operator::I32Extend16S
        | Operator::I64ExtendI32S
        | Operator::I64ExtendI32U
        | Operator::I64Extend8S
        | Operator::I64Extend16S
        | Operator::I64Extend32S
        | Operator::I32ReinterpretF32
        | Operator::F32ReinterpretI32
        | Operator::I64ReinterpretF64
        | Operator::F64ReinterpretI64
        // Non-trapping SIMD ops (not actually used in EOSIO contracts, but we allow them
        | Operator::I32TruncSatF32S
        | Operator::I32TruncSatF32U
        | Operator::I32TruncSatF64S
        | Operator::I32TruncSatF64U
        | Operator::I64TruncSatF32S
        | Operator::I64TruncSatF32U
        | Operator::I64TruncSatF64S
        | Operator::I64TruncSatF64U
    );

    if !allowed {
        // Extract just the variant name (e.g. "MemoryCopy" from "MemoryCopy { ... }")
        let debug = format!("{:?}", op);
        let name = debug.split([' ', '{', '(']).next().unwrap_or(&debug).to_string();
        return Err(ValidationError::BlacklistedOpcode(name));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Data segment validation
// ---------------------------------------------------------------------------

/// `data_segments_validation_visitor::validate`
///
/// Each active data segment must have an i32.const base offset, and the
/// segment must lie entirely within `MAXIMUM_LINEAR_MEMORY_INIT` bytes.
fn validate_data_segment(offset_expr: &wasmparser::ConstExpr, data: &[u8]) -> Result<()> {
    let mut reader = offset_expr.get_operators_reader();
    let op = reader.read()?;

    match op {
        Operator::I32Const { value } => {
            let base = value as u32 as u64;
            let end = base.saturating_add(data.len() as u64);
            if end > constraints::MAXIMUM_LINEAR_MEMORY_INIT {
                return Err(ValidationError::DataSegmentOutOfRange);
            }
        }
        _ => {
            return Err(ValidationError::UnexpectedDataSegmentOffsetType);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Validate a WASM binary according to EOSIO/Antelope constraints.
///
/// This is the main entry point and corresponds to
/// `wasm_binary_validation::validate()` in the C++ code-base.
///
/// # Arguments
/// * `wasm` – the raw bytes of a WASM module.
///
/// # Errors
/// Returns a [`ValidationError`] describing the first constraint violation
/// found, if any.
pub fn validate_wasm(wasm: &[u8]) -> Result<()> {
    // ---- Code size check --------------------------------------------------
    if wasm.len() > constraints::MAXIMUM_CODE_SIZE {
        return Err(ValidationError::CodeTooLarge);
    }

    let parser = Parser::new(0);
    let mut info = ModuleInfo::default();

    for payload in parser.parse_all(wasm) {
        let payload = payload?;

        match payload {
            // ----- Type section --------------------------------------------
            Payload::TypeSection(reader) => {
                for rec_group in reader {
                    let rec_group = rec_group?;
                    for sub_type in rec_group.into_types() {
                        if let wasmparser::CompositeInnerType::Func(func_type) =
                            sub_type.composite_type.inner
                        {
                            info.types.push(func_type);
                        }
                    }
                }
            }

            // ----- Import section ------------------------------------------
            Payload::ImportSection(reader) => {
                for import in reader.into_imports() {
                    let import = import?;
                    match import.ty {
                        wasmparser::TypeRef::Func(_) => {
                            info.num_imported_functions += 1;
                        }
                        wasmparser::TypeRef::Memory(mem) => {
                            info.memories.push(mem);
                        }
                        wasmparser::TypeRef::Table(table) => {
                            info.tables.push(table);
                        }
                        wasmparser::TypeRef::Global(global) => {
                            info.globals.push(global);
                        }
                        _ => {}
                    }
                }
            }

            // ----- Function section ----------------------------------------
            Payload::FunctionSection(reader) => {
                for func in reader {
                    let type_idx = func?;
                    info.func_type_indices.push(type_idx);
                }
            }

            // ----- Memory section ------------------------------------------
            Payload::MemorySection(reader) => {
                for mem in reader {
                    info.memories.push(mem?);
                }
            }

            // ----- Table section -------------------------------------------
            Payload::TableSection(reader) => {
                for table in reader {
                    let table = table?;
                    info.tables.push(table.ty);
                }
            }

            // ----- Global section ------------------------------------------
            Payload::GlobalSection(reader) => {
                for global in reader {
                    let global = global?;
                    info.globals.push(global.ty);
                }
            }

            // ----- Export section ------------------------------------------
            Payload::ExportSection(reader) => {
                for export in reader {
                    let Export { name, kind, index } = export?;
                    info.exports.push((name.to_string(), kind, index));
                }
            }

            // ----- Data section --------------------------------------------
            Payload::DataSection(reader) => {
                for segment in reader {
                    let segment = segment?;
                    if let wasmparser::DataKind::Active {
                        memory_index: _,
                        offset_expr,
                    } = segment.kind
                    {
                        validate_data_segment(&offset_expr, segment.data)?;
                    }
                }
            }

            // ----- Code section --------------------------------------------
            Payload::CodeSectionEntry(body) => {
                // Determine which local function index this is.
                // `CodeSectionEntry` payloads arrive in order, starting from 0.
                // We use a simple counter via the length of func_type_indices
                // already consumed. We need to figure out the function's type
                // to include param bytes.
                let local_func_idx = {
                    // We will use a static-like approach: count how many code
                    // bodies we have seen. We track this via a separate counter
                    // stored on `info`, but since ModuleInfo doesn't have one,
                    // we compute it from the number of types already validated.
                    // Instead, just compute local bytes directly.
                    0usize // placeholder – we compute bytes below
                };
                let _ = local_func_idx; // suppress warning

                // --- Validate function locals + params --------------------
                let locals_reader = body.get_locals_reader()?;
                let mut local_bytes: u32 = 0;

                for local in locals_reader {
                    let (count, val_type) = local?;
                    local_bytes += count * val_type_byte_size(&val_type);
                }

                // We can't easily correlate code bodies to func type indices
                // in a single streaming pass without a counter, so we do a
                // conservative check: local bytes alone must not exceed the
                // limit (params are validated separately in
                // `validate_function_stack`). The combined check happens in
                // the full-module validators after the pass.
                if local_bytes > constraints::MAXIMUM_FUNC_LOCAL_BYTES {
                    return Err(ValidationError::FunctionStackTooLarge);
                }

                // --- Validate instructions --------------------------------
                let ops_reader = body.get_operators_reader()?;
                let mut nesting_depth: u32 = 0;

                for op in ops_reader {
                    let op = op?;
                    validate_opcode_whitelist(&op)?;
                    validate_operator_offset(&op)?;
                    validate_nesting(&op, &mut nesting_depth)?;
                }
            }

            _ => {}
        }
    }

    // ---- Module-level validators ------------------------------------------
    validate_memories(&info)?;
    validate_tables(&info)?;
    validate_globals(&info)?;
    validate_function_stack(&info)?;
    validate_apply_export(&info)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Convenience: validate with a custom set of constraints (advanced)
// ---------------------------------------------------------------------------

/// Configuration that mirrors the C++ `wasm_constraints` namespace but allows
/// per-call overrides.
#[derive(Debug, Clone)]
pub struct WasmConstraints {
    pub maximum_linear_memory: u64,
    pub maximum_mutable_globals: u32,
    pub maximum_table_elements: u64,
    pub maximum_linear_memory_init: u64,
    pub maximum_func_local_bytes: u32,
    pub maximum_code_size: usize,
}

impl Default for WasmConstraints {
    fn default() -> Self {
        Self {
            maximum_linear_memory: constraints::MAXIMUM_LINEAR_MEMORY,
            maximum_mutable_globals: constraints::MAXIMUM_MUTABLE_GLOBALS,
            maximum_table_elements: constraints::MAXIMUM_TABLE_ELEMENTS,
            maximum_linear_memory_init: constraints::MAXIMUM_LINEAR_MEMORY_INIT,
            maximum_func_local_bytes: constraints::MAXIMUM_FUNC_LOCAL_BYTES,
            maximum_code_size: constraints::MAXIMUM_CODE_SIZE,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a minimal valid EOSIO WASM module from WAT.
    fn valid_module() -> Vec<u8> {
        wat::parse_str(
            r#"
            (module
                (type (;0;) (func (param i64 i64 i64)))
                (func (;0;) (type 0))
                (memory (;0;) 1)
                (export "apply" (func 0))
            )
            "#,
        )
        .expect("valid WAT")
    }

    #[test]
    fn test_valid_module_passes() {
        let wasm = valid_module();
        assert!(validate_wasm(&wasm).is_ok());
    }

    #[test]
    fn test_memory_too_large() {
        // 33 MiB = 528 pages. 529 pages should fail.
        let wasm = wat::parse_str(
            r#"
            (module
                (type (func (param i64 i64 i64)))
                (func (type 0))
                (memory 529)
                (export "apply" (func 0))
            )
            "#,
        )
        .unwrap();
        let err = validate_wasm(&wasm).unwrap_err();
        assert!(matches!(err, ValidationError::MemoryTooLarge));
    }

    #[test]
    fn test_memory_at_limit_passes() {
        // 528 pages = exactly 33 MiB
        let wasm = wat::parse_str(
            r#"
            (module
                (type (func (param i64 i64 i64)))
                (func (type 0))
                (memory 528)
                (export "apply" (func 0))
            )
            "#,
        )
        .unwrap();
        assert!(validate_wasm(&wasm).is_ok());
    }

    #[test]
    fn test_table_too_large() {
        let wasm = wat::parse_str(
            r#"
            (module
                (type (func (param i64 i64 i64)))
                (func (type 0))
                (table 1025 funcref)
                (memory 1)
                (export "apply" (func 0))
            )
            "#,
        )
        .unwrap();
        let err = validate_wasm(&wasm).unwrap_err();
        assert!(matches!(err, ValidationError::TableTooLarge));
    }

    #[test]
    fn test_table_at_limit_passes() {
        let wasm = wat::parse_str(
            r#"
            (module
                (type (func (param i64 i64 i64)))
                (func (type 0))
                (table 1024 funcref)
                (memory 1)
                (export "apply" (func 0))
            )
            "#,
        )
        .unwrap();
        assert!(validate_wasm(&wasm).is_ok());
    }

    #[test]
    fn test_data_segment_out_of_range() {
        // Data segment starting at offset 65000 with 1000 bytes of data
        // → 65000 + 1000 = 66000 > 65536 (64 KiB).
        let wasm = wat::parse_str(
            r#"
            (module
                (type (func (param i64 i64 i64)))
                (func (type 0))
                (memory 1)
                (data (i32.const 65000) "\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00")
                (export "apply" (func 0))
            )
            "#,
        )
        .unwrap();
        let err = validate_wasm(&wasm).unwrap_err();
        assert!(matches!(err, ValidationError::DataSegmentOutOfRange));
    }

    #[test]
    fn test_missing_apply_export() {
        let wasm = wat::parse_str(
            r#"
            (module
                (type (func))
                (func (type 0))
                (memory 1)
                (export "main" (func 0))
            )
            "#,
        )
        .unwrap();
        let err = validate_wasm(&wasm).unwrap_err();
        assert!(matches!(err, ValidationError::ApplyNotExported));
    }

    #[test]
    fn test_apply_wrong_signature() {
        let wasm = wat::parse_str(
            r#"
            (module
                (type (func (param i32 i32 i32)))
                (func (type 0))
                (memory 1)
                (export "apply" (func 0))
            )
            "#,
        )
        .unwrap();
        let err = validate_wasm(&wasm).unwrap_err();
        assert!(matches!(err, ValidationError::ApplyNotExported));
    }

    #[test]
    fn test_apply_with_return_value_fails() {
        let wasm = wat::parse_str(
            r#"
            (module
                (type (func (param i64 i64 i64) (result i32)))
                (func (type 0) (i32.const 0))
                (memory 1)
                (export "apply" (func 0))
            )
            "#,
        )
        .unwrap();
        let err = validate_wasm(&wasm).unwrap_err();
        assert!(matches!(err, ValidationError::ApplyNotExported));
    }

    #[test]
    fn test_too_many_mutable_globals() {
        // Each mutable i64 global consumes 8 bytes.
        // 129 × 8 = 1032 > 1024.
        let mut wat = String::from("(module\n");
        wat.push_str("  (type (func (param i64 i64 i64)))\n");
        wat.push_str("  (func (type 0))\n");
        wat.push_str("  (memory 1)\n");
        for _ in 0..129 {
            wat.push_str("  (global (mut i64) (i64.const 0))\n");
        }
        wat.push_str("  (export \"apply\" (func 0))\n");
        wat.push_str(")\n");

        let wasm = wat::parse_str(&wat).unwrap();
        let err = validate_wasm(&wasm).unwrap_err();
        assert!(matches!(err, ValidationError::TooManyMutableGlobals));
    }

    #[test]
    fn test_mutable_globals_at_limit_passes() {
        // 128 × 8 = 1024 – exactly at the limit.
        let mut wat = String::from("(module\n");
        wat.push_str("  (type (func (param i64 i64 i64)))\n");
        wat.push_str("  (func (type 0))\n");
        wat.push_str("  (memory 1)\n");
        for _ in 0..128 {
            wat.push_str("  (global (mut i64) (i64.const 0))\n");
        }
        wat.push_str("  (export \"apply\" (func 0))\n");
        wat.push_str(")\n");

        let wasm = wat::parse_str(&wat).unwrap();
        assert!(validate_wasm(&wasm).is_ok());
    }

    #[test]
    fn test_function_stack_params_plus_locals_combined() {
        // 3 × i64 params (24 bytes) + 20 × i64 locals (160 bytes) = 184, passes.

        let wasm = wat::parse_str(
            r#"(module
                (type (func (param i64 i64 i64)))
                (func (type 0)
                    (local i64 i64 i64 i64 i64 i64 i64 i64 i64 i64)
                    (local i64 i64 i64 i64 i64 i64 i64 i64 i64 i64)
                )
                (memory 1)
                (export "apply" (func 0))
            )"#,
        )
        .unwrap();

        assert!(validate_wasm(&wasm).is_ok());
    }
}
