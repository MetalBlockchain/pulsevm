use std::{
    borrow::Cow,
    cell::RefCell,
    collections::BTreeSet,
    num::NonZeroUsize,
    sync::{
        Arc,
        RwLock,
    },
};

use lru::LruCache;
use pulsevm_crypto::Bytes;
use pulsevm_database::{
    BlockTimestamp,
    Database,
};
use pulsevm_error::ChainError;
use wasmer::{
    AsStoreMut,
    Engine,
    Extern,
    Function,
    FunctionEnv,
    Global,
    Imports,
    Instance,
    Memory,
    Module,
    RuntimeError,
    Store,
    Table,
    TypedFunction,
    Value,
    imports,
    sys::{
        CompilerConfig,
        EngineBuilder,
        Features,
    },
    wasmparser::Operator,
};
use wasmer_compiler_llvm::{
    LLVM,
    LLVMOptLevel,
};
use wasmer_middlewares::{
    Metering,
    metering::MeteringPoints,
};

use crate::chain::{
    apply_context::ApplyContext,
    id::Id,
    name::Name,
    protocol_features::{
        ProtocolExecutionContext,
        ProtocolFeature,
        ProtocolVersion,
    },
    transaction::Action,
    webassembly::{
        __addtf3,
        __ashlti3,
        __ashrti3,
        __cmptf2,
        __divtf3,
        __divti3,
        __eqtf2,
        __extenddftf2,
        __extendsftf2,
        __fixdfti,
        __fixsfti,
        __fixtfdi,
        __fixtfsi,
        __fixtfti,
        __fixunsdfti,
        __fixunssfti,
        __fixunstfdi,
        __fixunstfsi,
        __fixunstfti,
        __floatditf,
        __floatsidf,
        __floatsitf,
        __floattidf,
        __floatunditf,
        __floatunsitf,
        __floatuntidf,
        __getf2,
        __gttf2,
        __letf2,
        __lshlti3,
        __lshrti3,
        __lttf2,
        __modti3,
        __multf3,
        __multi3,
        __negtf2,
        __netf2,
        __subtf3,
        __trunctfdf2,
        __trunctfsf2,
        __udivti3,
        __umodti3,
        __unordtf2,
        abort,
        assert_recover_key,
        assert_ripemd160,
        assert_sha1,
        assert_sha224,
        assert_sha256,
        assert_sha512,
        check_permission_authorization,
        check_transaction_authorization,
        current_time,
        db_end_i64,
        db_find_i64,
        db_get_i64,
        db_idx_double_end,
        db_idx_double_find_primary,
        db_idx_double_find_secondary,
        db_idx_double_lowerbound,
        db_idx_double_next,
        db_idx_double_previous,
        db_idx_double_remove,
        db_idx_double_store,
        db_idx_double_update,
        db_idx_double_upperbound,
        db_idx_long_double_end,
        db_idx_long_double_find_primary,
        db_idx_long_double_find_secondary,
        db_idx_long_double_lowerbound,
        db_idx_long_double_next,
        db_idx_long_double_previous,
        db_idx_long_double_remove,
        db_idx_long_double_store,
        db_idx_long_double_update,
        db_idx_long_double_upperbound,
        db_idx64_end,
        db_idx64_find_primary,
        db_idx64_find_secondary,
        db_idx64_lowerbound,
        db_idx64_next,
        db_idx64_previous,
        db_idx64_remove,
        db_idx64_store,
        db_idx64_update,
        db_idx64_upperbound,
        db_idx128_end,
        db_idx128_find_primary,
        db_idx128_find_secondary,
        db_idx128_lowerbound,
        db_idx128_next,
        db_idx128_previous,
        db_idx128_remove,
        db_idx128_store,
        db_idx128_update,
        db_idx128_upperbound,
        db_idx256_end,
        db_idx256_find_primary,
        db_idx256_find_secondary,
        db_idx256_lowerbound,
        db_idx256_next,
        db_idx256_previous,
        db_idx256_remove,
        db_idx256_store,
        db_idx256_update,
        db_idx256_upperbound,
        db_lowerbound_i64,
        db_next_i64,
        db_previous_i64,
        db_remove_i64,
        db_store_i64,
        db_update_i64,
        db_upperbound_i64,
        eosio_assert,
        expiration,
        get_account_creation_time,
        get_action,
        get_active_producers,
        get_block_num,
        get_blockchain_parameters_packed,
        get_code_hash,
        get_context_free_data,
        get_permission_last_used,
        get_resource_limits,
        get_sender,
        is_feature_activated,
        is_privileged,
        memcmp,
        memcpy,
        memmove,
        memset,
        preactivate_feature,
        printdf,
        printhex,
        printi,
        printi128,
        printn,
        printqf,
        prints,
        prints_l,
        printsf,
        printui,
        printui128,
        publication_time,
        pulse_assert,
        pulse_assert_code,
        pulse_assert_message,
        pulse_exit,
        read_action_data,
        read_transaction,
        recover_key,
        require_auth2,
        require_recipient,
        ripemd160,
        send_context_free_inline,
        set_action_return_value,
        set_blockchain_parameters_packed,
        set_privileged,
        set_proposed_producers,
        set_proposed_producers_ex,
        set_resource_limits,
        sha1,
        sha224,
        sha256,
        sha512,
        tapos_block_num,
        tapos_block_prefix,
        transaction_size,
    },
};

fn exported_memory(instance: &Instance) -> Option<Memory> {
    instance
        .exports
        .get_memory("memory")
        .ok()
        .cloned()
        .or_else(|| {
            instance
                .exports
                .iter()
                .find_map(|(_, export)| match export {
                    Extern::Memory(memory) => Some(memory.clone()),
                    _ => None,
                })
        })
}

fn read_var_u32(bytes: &[u8], offset: &mut usize) -> Result<u32, ChainError> {
    let mut value = 0_u32;
    for shift in (0..35).step_by(7) {
        let byte = *bytes
            .get(*offset)
            .ok_or_else(|| ChainError::WasmRuntimeError("truncated wasm section".to_string()))?;
        *offset += 1;
        if shift == 28 && byte & 0xf0 != 0 {
            return Err(ChainError::WasmRuntimeError(
                "invalid wasm varuint32".to_string(),
            ));
        }
        value |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(ChainError::WasmRuntimeError(
        "invalid wasm varuint32".to_string(),
    ))
}

fn write_var_u32(mut value: u32, bytes: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        bytes.push(byte);
        if value == 0 {
            return;
        }
    }
}

#[derive(Clone, Debug, Default)]
struct ResetStateExports {
    globals: Vec<String>,
    tables: Vec<String>,
}

fn private_export_name(existing: &mut BTreeSet<Vec<u8>>, prefix: &[u8], index: u32) -> Vec<u8> {
    let mut name = format!("{}{}", String::from_utf8_lossy(prefix), index).into_bytes();
    while existing.contains(&name) {
        name.push(b'_');
    }
    existing.insert(name.clone());
    name
}

/// Exposes local globals and tables in the private compilation copy so a warm
/// instance can restore every mutable piece of VM state before it is reused.
///
/// Imported state is deliberately not handled here. The reuse audit rejects
/// modules that import memories, globals, or tables, leaving them on the fresh
/// instance path. Exporting an entity under an additional private name does not
/// alter the instruction stream or the on-chain code hash.
fn expose_reset_state(code: &[u8]) -> Result<(Cow<'_, [u8]>, ResetStateExports), ChainError> {
    const WASM_HEADER: &[u8; 8] = b"\0asm\x01\0\0\0";
    if code.get(..WASM_HEADER.len()) != Some(WASM_HEADER) {
        return Err(ChainError::WasmRuntimeError(
            "invalid wasm header".to_string(),
        ));
    }

    let mut offset = WASM_HEADER.len();
    let mut defined_tables = 0_u32;
    let mut defined_globals = 0_u32;
    let mut export_section = None;
    let mut export_names = BTreeSet::new();
    let mut export_insertion = code.len();

    while offset < code.len() {
        let section_start = offset;
        let section_id = code[offset];
        offset += 1;
        let section_size = read_var_u32(code, &mut offset)? as usize;
        let payload_start = offset;
        let payload_end = payload_start.checked_add(section_size).ok_or_else(|| {
            ChainError::WasmRuntimeError("wasm section size overflow".to_string())
        })?;
        if payload_end > code.len() {
            return Err(ChainError::WasmRuntimeError(
                "truncated wasm section".to_string(),
            ));
        }

        if section_id != 0 && section_id > 7 && export_insertion == code.len() {
            export_insertion = section_start;
        }
        match section_id {
            4 => {
                let mut cursor = payload_start;
                defined_tables = read_var_u32(code, &mut cursor)?;
            }
            6 => {
                let mut cursor = payload_start;
                defined_globals = read_var_u32(code, &mut cursor)?;
            }
            7 => {
                export_section = Some((section_start, payload_start, payload_end));
                let mut cursor = payload_start;
                let count = read_var_u32(code, &mut cursor)?;
                for _ in 0..count {
                    let name_len = read_var_u32(code, &mut cursor)? as usize;
                    let name_end = cursor.checked_add(name_len).ok_or_else(|| {
                        ChainError::WasmRuntimeError("wasm export name overflow".to_string())
                    })?;
                    let name = code.get(cursor..name_end).ok_or_else(|| {
                        ChainError::WasmRuntimeError("truncated wasm export".to_string())
                    })?;
                    export_names.insert(name.to_vec());
                    cursor = name_end;
                    cursor = cursor.checked_add(1).ok_or_else(|| {
                        ChainError::WasmRuntimeError("wasm export overflow".to_string())
                    })?;
                    let _index = read_var_u32(code, &mut cursor)?;
                }
            }
            _ => {}
        }
        offset = payload_end;
    }

    if defined_tables == 0 && defined_globals == 0 {
        return Ok((Cow::Borrowed(code), ResetStateExports::default()));
    }

    let mut reset_exports = ResetStateExports::default();
    let mut entries = Vec::new();
    for index in 0..defined_tables {
        let name = private_export_name(&mut export_names, b"__pulsevm_reset_table_", index);
        write_var_u32(name.len() as u32, &mut entries);
        entries.extend_from_slice(&name);
        entries.push(1); // external_kind::table
        write_var_u32(index, &mut entries);
        reset_exports
            .tables
            .push(String::from_utf8(name).expect("private export name is ASCII"));
    }
    for index in 0..defined_globals {
        let name = private_export_name(&mut export_names, b"__pulsevm_reset_global_", index);
        write_var_u32(name.len() as u32, &mut entries);
        entries.extend_from_slice(&name);
        entries.push(3); // external_kind::global
        write_var_u32(index, &mut entries);
        reset_exports
            .globals
            .push(String::from_utf8(name).expect("private export name is ASCII"));
    }

    let mut output = Vec::with_capacity(code.len() + entries.len() + 8);
    if let Some((section_start, payload_start, payload_end)) = export_section {
        let mut entries_start = payload_start;
        let export_count = read_var_u32(code, &mut entries_start)?;
        let added = defined_tables.checked_add(defined_globals).ok_or_else(|| {
            ChainError::WasmRuntimeError("too many private wasm exports".to_string())
        })?;
        let mut payload = Vec::with_capacity(payload_end - payload_start + entries.len());
        write_var_u32(
            export_count
                .checked_add(added)
                .ok_or_else(|| ChainError::WasmRuntimeError("too many wasm exports".to_string()))?,
            &mut payload,
        );
        payload.extend_from_slice(&code[entries_start..payload_end]);
        payload.extend_from_slice(&entries);

        output.extend_from_slice(&code[..section_start]);
        output.push(7);
        write_var_u32(payload.len() as u32, &mut output);
        output.extend_from_slice(&payload);
        output.extend_from_slice(&code[payload_end..]);
    } else {
        let mut payload = Vec::with_capacity(entries.len() + 5);
        write_var_u32(defined_tables + defined_globals, &mut payload);
        payload.extend_from_slice(&entries);

        output.extend_from_slice(&code[..export_insertion]);
        output.push(7);
        write_var_u32(payload.len() as u32, &mut output);
        output.extend_from_slice(&payload);
        output.extend_from_slice(&code[export_insertion..]);
    }

    Ok((Cow::Owned(output), reset_exports))
}

/// Makes an internal EOSIO linear memory visible to Wasmer host functions.
///
/// Legacy EOSIO contracts intentionally export only `apply`; nodeos runtimes
/// can still access their internal memory directly. Wasmer's public API cannot,
/// so add a private export to the compilation copy. The bytes stored on chain,
/// their code hash, and the WebAssembly instruction stream remain unchanged.
fn expose_internal_memory(code: &[u8]) -> Result<Cow<'_, [u8]>, ChainError> {
    const WASM_HEADER: &[u8; 8] = b"\0asm\x01\0\0\0";
    if code.get(..WASM_HEADER.len()) != Some(WASM_HEADER) {
        return Err(ChainError::WasmRuntimeError(
            "invalid wasm header".to_string(),
        ));
    }

    let mut offset = WASM_HEADER.len();
    let mut defined_memories = 0_u32;
    let mut export_section = None;
    let mut export_names = BTreeSet::new();
    let mut has_memory_export = false;
    let mut export_insertion = code.len();

    while offset < code.len() {
        let section_start = offset;
        let section_id = code[offset];
        offset += 1;
        let section_size = read_var_u32(code, &mut offset)? as usize;
        let payload_start = offset;
        let payload_end = payload_start.checked_add(section_size).ok_or_else(|| {
            ChainError::WasmRuntimeError("wasm section size overflow".to_string())
        })?;
        if payload_end > code.len() {
            return Err(ChainError::WasmRuntimeError(
                "truncated wasm section".to_string(),
            ));
        }

        if section_id != 0 && section_id > 7 && export_insertion == code.len() {
            export_insertion = section_start;
        }
        match section_id {
            5 => {
                let mut cursor = payload_start;
                defined_memories = read_var_u32(code, &mut cursor)?;
            }
            7 => {
                export_section = Some((section_start, payload_start, payload_end));
                let mut cursor = payload_start;
                let count = read_var_u32(code, &mut cursor)?;
                for _ in 0..count {
                    let name_len = read_var_u32(code, &mut cursor)? as usize;
                    let name_end = cursor.checked_add(name_len).ok_or_else(|| {
                        ChainError::WasmRuntimeError("wasm export name overflow".to_string())
                    })?;
                    let name = code.get(cursor..name_end).ok_or_else(|| {
                        ChainError::WasmRuntimeError("truncated wasm export".to_string())
                    })?;
                    export_names.insert(name.to_vec());
                    cursor = name_end;
                    let kind = *code.get(cursor).ok_or_else(|| {
                        ChainError::WasmRuntimeError("truncated wasm export".to_string())
                    })?;
                    cursor += 1;
                    let _index = read_var_u32(code, &mut cursor)?;
                    has_memory_export |= kind == 2;
                }
            }
            _ => {}
        }
        offset = payload_end;
    }

    if has_memory_export || defined_memories == 0 {
        return Ok(Cow::Borrowed(code));
    }
    if defined_memories != 1 {
        return Err(ChainError::WasmRuntimeError(format!(
            "expected one wasm memory, found {defined_memories}"
        )));
    }

    let mut export_name = b"__pulsevm_memory".to_vec();
    while export_names.contains(&export_name) {
        export_name.push(b'_');
    }
    let mut entry = Vec::with_capacity(export_name.len() + 8);
    write_var_u32(export_name.len() as u32, &mut entry);
    entry.extend_from_slice(&export_name);
    entry.push(2); // external_kind::memory
    write_var_u32(0, &mut entry); // the sole memory index

    let mut output = Vec::with_capacity(code.len() + entry.len() + 8);
    if let Some((section_start, payload_start, payload_end)) = export_section {
        let mut entries_start = payload_start;
        let export_count = read_var_u32(code, &mut entries_start)?;
        let mut payload = Vec::with_capacity(payload_end - payload_start + entry.len());
        write_var_u32(
            export_count
                .checked_add(1)
                .ok_or_else(|| ChainError::WasmRuntimeError("too many wasm exports".to_string()))?,
            &mut payload,
        );
        payload.extend_from_slice(&code[entries_start..payload_end]);
        payload.extend_from_slice(&entry);

        output.extend_from_slice(&code[..section_start]);
        output.push(7);
        write_var_u32(payload.len() as u32, &mut output);
        output.extend_from_slice(&payload);
        output.extend_from_slice(&code[payload_end..]);
    } else {
        let mut payload = Vec::with_capacity(entry.len() + 1);
        write_var_u32(1, &mut payload);
        payload.extend_from_slice(&entry);

        output.extend_from_slice(&code[..export_insertion]);
        output.push(7);
        write_var_u32(payload.len() as u32, &mut output);
        output.extend_from_slice(&payload);
        output.extend_from_slice(&code[export_insertion..]);
    }
    Ok(Cow::Owned(output))
}

use super::webassembly::{
    action_data_size,
    cancel_deferred,
    current_receiver,
    has_auth,
    is_account,
    require_auth,
    send_deferred,
    send_inline,
};

/// Sentinel raised by eosio_exit/pulse_exit. Wasmer transports it as a trap,
/// but Antelope semantics treat it as successful termination of this action.
#[derive(Debug)]
pub struct WasmExit {
    pub code: i32,
}

impl std::fmt::Display for WasmExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "wasm exit with code {}", self.code)
    }
}

impl std::error::Error for WasmExit {}

pub struct WasmContext {
    receiver: u64,
    action: Action,
    pending_block_timestamp: BlockTimestamp,
    context: ApplyContext,
    db: Database,
    memory: Option<Memory>,
    // Direct handles to the middleware globals avoid an export-name lookup for
    // every host intrinsic. They are installed only after instantiation.
    metering: Option<MeteringGlobals>,
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
            metering: None,
            return_value: None,
        }
    }

    /// Deduct `amount` metering points for a host intrinsic's own work, so an
    /// intrinsic's cost lands in the same budget (and the same billed CPU) as the
    /// wasm operators around it. Traps like the metering middleware would if the
    /// budget can't cover it, rather than letting the work run for free.
    ///
    /// The point unit is the one COST_FUNCTION uses for wasm operators; the
    /// per-intrinsic amounts live in the webassembly::cost module. Changing any
    /// amount changes billed CPU, which is committed to the block, so it is a
    /// consensus rule — every node must run the identical table.
    pub fn charge(&self, store: &mut impl AsStoreMut, amount: u64) -> Result<(), RuntimeError> {
        // The globals are captured only after `Instance::new`, so an intrinsic
        // reached from a module's start/initializer during instantiation has no
        // budget handle yet. That phase isn't billed anyway -- `run` reseeds the
        // metering points after instantiation and measures only the `apply`
        // call -- so skip the charge rather than fail instantiation. During
        // `apply`, where billing happens, the instance is always set.
        let Some(metering) = self.metering.as_ref() else {
            return Ok(());
        };
        charge_metering_globals(store, metering, amount)
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

    /// Validated consensus context for the currently executing WASM action.
    pub fn protocol_context(&self) -> ProtocolExecutionContext {
        self.context.protocol_context()
    }

    pub fn protocol_version(&self) -> ProtocolVersion {
        self.context.protocol_version()
    }

    pub fn protocol_feature_enabled(&self, feature: ProtocolFeature) -> bool {
        self.context.protocol_feature_enabled(feature)
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

/// Deduct `amount` metering points from a running instance, or trap if the
/// budget can't cover it. Shared by [`WasmContext::charge`] and its test; kept
/// free of `WasmContext` so it can be exercised against a bare metered instance.
#[cfg(test)]
fn charge_metering_points(
    store: &mut impl AsStoreMut,
    instance: &Instance,
    amount: u64,
) -> Result<(), RuntimeError> {
    let metering = MeteringGlobals::from_instance(instance)?;
    charge_metering_globals(store, &metering, amount)
}

const METERING_REMAINING_EXPORT: &str = "wasmer_metering_remaining_points";
const METERING_EXHAUSTED_EXPORT: &str = "wasmer_metering_points_exhausted";

#[derive(Clone)]
struct MeteringGlobals {
    remaining: Global,
    exhausted: Global,
}

impl MeteringGlobals {
    fn from_instance(instance: &Instance) -> Result<Self, RuntimeError> {
        let remaining = instance
            .exports
            .get_global(METERING_REMAINING_EXPORT)
            .map_err(|error| RuntimeError::new(error.to_string()))?
            .clone();
        let exhausted = instance
            .exports
            .get_global(METERING_EXHAUSTED_EXPORT)
            .map_err(|error| RuntimeError::new(error.to_string()))?
            .clone();
        Ok(Self {
            remaining,
            exhausted,
        })
    }

    fn set(&self, store: &mut impl AsStoreMut, points: u64) -> Result<(), RuntimeError> {
        self.remaining.set(store, Value::I64(points as i64))?;
        self.exhausted.set(store, Value::I32(0))?;
        Ok(())
    }

    fn get(&self, store: &mut impl AsStoreMut) -> Result<MeteringPoints, RuntimeError> {
        let exhausted = match self.exhausted.get(store) {
            Value::I32(value) => value,
            _ => {
                return Err(RuntimeError::new(
                    "metering exhausted global has the wrong type",
                ));
            }
        };
        if exhausted > 0 {
            return Ok(MeteringPoints::Exhausted);
        }
        match self.remaining.get(store) {
            Value::I64(value) => Ok(MeteringPoints::Remaining(value as u64)),
            _ => Err(RuntimeError::new(
                "metering remaining global has the wrong type",
            )),
        }
    }
}

fn charge_metering_globals(
    store: &mut impl AsStoreMut,
    metering: &MeteringGlobals,
    amount: u64,
) -> Result<(), RuntimeError> {
    match metering.get(store)? {
        MeteringPoints::Remaining(remaining) if remaining >= amount => {
            metering.set(store, remaining - amount)?;
            Ok(())
        }
        _ => {
            metering.set(store, 0)?;
            Err(RuntimeError::new(
                "cpu usage limit exceeded while charging a host intrinsic",
            ))
        }
    }
}

// Reset work runs outside deterministic WASM metering, just like fresh instance
// construction. Bound it so a contract with a very large memory cannot turn the
// optimization into unmetered copying; larger instances use the fresh path.
const MAX_RESETTABLE_MEMORY_BYTES: u64 = 8 * 1024 * 1024;
static ZERO_PAGE: [u8; 64 * 1024] = [0; 64 * 1024];

struct ResettableInstance {
    instance: Instance,
    apply: TypedFunction<(i64, i64, i64), ()>,
    memory: Memory,
    initial_memory: Vec<u8>,
    mutable_globals: Vec<(Global, Value)>,
    tables: Vec<(Table, Vec<Value>)>,
    metering: MeteringGlobals,
}

impl ResettableInstance {
    fn capture(
        store: &mut Store,
        instance: Instance,
        exports: &ResetStateExports,
    ) -> Result<Self, ChainError> {
        let memory = exported_memory(&instance).ok_or_else(|| {
            ChainError::WasmRuntimeError(
                "audited instance does not export its linear memory".to_string(),
            )
        })?;
        let memory_size = memory.view(store).data_size();
        if memory_size > MAX_RESETTABLE_MEMORY_BYTES {
            return Err(ChainError::WasmRuntimeError(format!(
                "audited instance memory is {memory_size} bytes, above the reset limit"
            )));
        }
        let mut initial_memory = vec![0; memory_size as usize];
        memory
            .view(store)
            .read(0, &mut initial_memory)
            .map_err(|error| ChainError::WasmRuntimeError(error.to_string()))?;

        let mut mutable_globals = Vec::new();
        for name in &exports.globals {
            let global = instance
                .exports
                .get_global(name)
                .map_err(|error| ChainError::WasmRuntimeError(error.to_string()))?
                .clone();
            if global.ty(store).mutability.is_mutable() {
                let initial = global.get(store);
                mutable_globals.push((global, initial));
            }
        }

        let mut tables = Vec::new();
        for name in &exports.tables {
            let table = instance
                .exports
                .get_table(name)
                .map_err(|error| ChainError::WasmRuntimeError(error.to_string()))?
                .clone();
            let initial = (0..table.size(store))
                .map(|index| {
                    table.get(store, index).ok_or_else(|| {
                        ChainError::WasmRuntimeError(format!(
                            "cannot snapshot table {name} entry {index}"
                        ))
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            tables.push((table, initial));
        }

        let metering = MeteringGlobals::from_instance(&instance)
            .map_err(|error| ChainError::WasmRuntimeError(error.to_string()))?;
        let apply = instance
            .exports
            .get_typed_function::<(i64, i64, i64), ()>(store, "apply")
            .map_err(|error| ChainError::WasmRuntimeError(error.to_string()))?;

        Ok(Self {
            instance,
            apply,
            memory,
            initial_memory,
            mutable_globals,
            tables,
            metering,
        })
    }

    /// Restore the exact post-instantiation state. Returning `false` discards
    /// the instance and lets the caller create a fresh one; it never runs a
    /// partially reset instance.
    fn reset(&self, store: &mut Store) -> Result<bool, ChainError> {
        let initial_size = self.initial_memory.len() as u64;
        let current_size = self.memory.view(store).data_size();
        if current_size < initial_size || current_size > MAX_RESETTABLE_MEMORY_BYTES {
            return Ok(false);
        }

        for (table, initial) in &self.tables {
            if table.size(store) != initial.len() as u32 {
                return Ok(false);
            }
        }

        if current_size > initial_size {
            let mut offset = initial_size;
            while offset < current_size {
                let length = (current_size - offset).min(ZERO_PAGE.len() as u64) as usize;
                self.memory
                    .view(store)
                    .write(offset, &ZERO_PAGE[..length])
                    .map_err(|error| ChainError::WasmRuntimeError(error.to_string()))?;
                offset += length as u64;
            }
            self.memory
                .reset(store)
                .map_err(|error| ChainError::WasmRuntimeError(error.to_string()))?;
            self.memory
                .grow_at_least(store, initial_size)
                .map_err(|error| ChainError::WasmRuntimeError(error.to_string()))?;
        }
        self.memory
            .view(store)
            .write(0, &self.initial_memory)
            .map_err(|error| ChainError::WasmRuntimeError(error.to_string()))?;

        for (global, initial) in &self.mutable_globals {
            global
                .set(store, initial.clone())
                .map_err(|error| ChainError::WasmRuntimeError(error.to_string()))?;
        }
        for (table, initial) in &self.tables {
            for (index, value) in initial.iter().enumerate() {
                table
                    .set(store, index as u32, value.clone())
                    .map_err(|error| ChainError::WasmRuntimeError(error.to_string()))?;
            }
        }
        Ok(true)
    }
}

#[derive(Clone)]
struct CachedModule {
    module: Module,
    engine: Engine,
    reset_exports: ResetStateExports,
    resettable: bool,
}

fn module_is_resettable(module: &Module) -> bool {
    let info = module.info();
    info.start_function.is_none()
        && info.num_imported_memories == 0
        && info.num_imported_globals == 0
        && info.num_imported_tables == 0
        && info.memories.len() == 1
        && info.passive_data.is_empty()
        && info.passive_elements.is_empty()
}

fn instance_reuse_enabled() -> bool {
    // Emergency/benchmark escape hatch. Both paths execute the same compiled
    // module and metering rules; this changes only whether post-instantiation
    // VM state is restored or rebuilt before the next invocation.
    std::env::var_os("PULSEVM_DISABLE_WASM_INSTANCE_REUSE").is_none()
}

/// A store with its host-import table already wired up, kept warm so it can be
/// reused across many contract invocations. Structurally audited modules also
/// keep one fully resettable instance in the bundle.
///
/// Building the ~150 host functions costs roughly two thirds of the per-action
/// setup time, and that work is identical for every call, so we pay it once.
/// The env is swapped in place before each call. An audited instance is restored
/// byte-for-byte to its post-instantiation memory/global/table state; every
/// module outside that strict audit continues to create a fresh instance.
///
/// A store's object slab only grows, so each new instance leaks a linear memory
/// into it. `uses` tracks how many instances we've spun up; once it hits
/// `MAX_INSTANCES_PER_STORE` the bundle is dropped instead of returned to the
/// pool, reclaiming the slab.
struct WarmStore {
    store: Store,
    env: FunctionEnv<WasmContext>,
    imports: Imports,
    instances_created: u32,
    resettable_instance: Option<ResettableInstance>,
}

/// How many instances to spin up on a warm store before recycling it. Larger
/// amortizes the import build further; the ceiling is there only to reclaim the
/// store's ever-growing object slab. Contract memories declare no maximum, so
/// wasmer allocates them dynamically (a small guard plus committed pages rather
/// than a 4 GiB reservation), which keeps an idle store cheap even at this count.
const MAX_INSTANCES_PER_STORE: u32 = 64;

// A warm store owns raw VM pointers and so is neither `Send` nor `Sync`; it
// cannot live in the shared runtime state. Keep the pool thread-local instead —
// block application is sequential on a given thread, so a warm store is only
// ever touched by the thread that built it, and no synchronization is needed.
thread_local! {
    static STORE_POOL: RefCell<LruCache<Id, WarmStore>> =
        RefCell::new(LruCache::new(NonZeroUsize::new(1024).unwrap()));
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
        Operator::I32Mul { .. } | Operator::I64Mul { .. } => 3,
        Operator::I32DivS { .. }
        | Operator::I32DivU { .. }
        | Operator::I32RemS { .. }
        | Operator::I32RemU { .. }
        | Operator::I64DivS { .. }
        | Operator::I64DivU { .. }
        | Operator::I64RemS { .. }
        | Operator::I64RemU { .. } => 80,
        Operator::I32Clz { .. } | Operator::I64Clz { .. } => 105,
        // Floating point priced from measurement (estimate_operator_costs): unlike
        // the integer arithmetic above, IEEE ops aren't reorderable so LLVM can't
        // fold a dependent chain, and the shipped defaults (1-3) under-charged them
        // by 8-100x -- a division or sqrt costs as much as an integer divide, not a
        // single cheap op. f32 shares the f64 price (an upper bound for it).
        Operator::F32Add { .. }
        | Operator::F64Add { .. }
        | Operator::F32Sub { .. }
        | Operator::F64Sub { .. } => 20,
        Operator::F32Mul { .. } | Operator::F64Mul { .. } => 26,
        Operator::F32Div { .. } | Operator::F64Div { .. } => 80,
        Operator::F32Sqrt { .. } | Operator::F64Sqrt { .. } => 110,
        Operator::MemoryCopy { .. } | Operator::MemoryFill { .. } => 500,
        Operator::MemoryGrow { .. } => 1000, // Higher cost for memory growth
        _ => 1,                              // Default cost
    }
};

impl WasmRuntime {
    pub fn new() -> Result<Self, ChainError> {
        Ok(Self {
            inner: Arc::new(RwLock::new(InnerWasmRuntime {
                code_cache: LruCache::new(NonZeroUsize::new(1024).unwrap()),
            })),
        })
    }

    // The wasm feature set we pin contract execution to. Left implicit,
    // Features::default() turns threads and simd on and could gain more on a
    // wasmer bump — a silent consensus change. threads and relaxed_simd are
    // nondeterministic by spec; simd isn't in the contract ABI. reference_types,
    // bulk_memory, multi_value and extended_const are deterministic and the
    // toolchain emits them (clang uses reference-types call_indirect and
    // memory.copy), so turning them off rejects real contracts. Changing this is
    // a consensus change.
    fn deterministic_features() -> Features {
        Features {
            threads: false,
            simd: false,
            relaxed_simd: false,
            tail_call: false,
            module_linking: false,
            multi_memory: false,
            memory64: false,
            exceptions: false,
            wide_arithmetic: false,
            reference_types: true,
            bulk_memory: true,
            multi_value: true,
            extended_const: true,
        }
    }

    // The one LLVM engine every contract compiles and runs on, so build, verify
    // and replay share the same config: NaN canonicalization, aggressive opt, the
    // metering middleware (seeded so a start fn can run) and the pinned features.
    fn deterministic_engine() -> Engine {
        let mut compiler = LLVM::default();
        compiler.push_middleware(Arc::new(Metering::new(1_000, COST_FUNCTION)));
        LLVM::canonicalize_nans(&mut compiler, true);
        LLVM::opt_level(&mut compiler, LLVMOptLevel::Aggressive);
        EngineBuilder::new(compiler)
            .set_features(Some(Self::deterministic_features()))
            .into()
    }

    pub fn run(
        &mut self,
        receiver: Name,
        action: Action,
        apply_context: ApplyContext,
        db: Database,
        code_hash: &[u8; 32],
        cpu_limit: i64,
    ) -> Result<u64, ChainError> {
        // Pause timer
        apply_context.pause_billing_timer()?;

        let id = Id::new(*code_hash);
        let module = {
            let mut inner = self.inner.write()?;

            if !inner.code_cache.contains(&id) {
                let code_bytes = db.get_code_bytes_by_hash(code_hash, 0, 0)?;
                let runtime_code = expose_internal_memory(code_bytes.as_slice())?;
                let (runtime_code, reset_exports) = expose_reset_state(runtime_code.as_ref())?;

                // Compile on a fresh engine carrying the pinned deterministic
                // config (NaN canonicalization, metering, feature set).
                let temp_engine = Self::deterministic_engine();
                let temp_store = Store::new(temp_engine.clone());

                let module = Module::new(temp_store.engine(), runtime_code.as_ref())
                    .map_err(|e| ChainError::WasmRuntimeError(e.to_string()))?;
                let resettable = instance_reuse_enabled() && module_is_resettable(&module);
                inner.code_cache.put(
                    id,
                    CachedModule {
                        module,
                        engine: temp_engine.clone(),
                        reset_exports,
                        resettable,
                    },
                );
            }

            inner.code_cache.get(&id).unwrap().clone()
        };
        let pooled = STORE_POOL.with(|pool| pool.borrow_mut().pop(&id));

        // Reuse a warm store if one is idle in the pool, otherwise build one.
        // Reuse only swaps the env's context; a fresh build pays for the whole
        // import table. The pool is keyed by code hash but shared across every
        // runtime on the thread, and a module can be recompiled onto a new
        // engine after a cache eviction, so only reuse a store whose engine
        // still matches this module — otherwise instantiation would mismatch.
        let pooled = pooled.filter(|warm| warm.store.engine().id() == module.engine.id());
        let mut warm = if let Some(mut warm) = pooled {
            *warm.env.as_mut(&mut warm.store) = WasmContext::new(
                receiver.clone(),
                action.clone(),
                apply_context.pending_block_timestamp().clone(),
                apply_context.clone(),
                db.clone(),
            );
            warm
        } else {
            let mut store = Store::new(module.engine.clone());
            let env = FunctionEnv::new(
                &mut store,
                WasmContext::new(
                    receiver.clone(),
                    action.clone(),
                    apply_context.pending_block_timestamp().clone(),
                    apply_context.clone(),
                    db.clone(),
                ),
            );
            let imports = imports! {
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
                "__fixunstfdi" => Function::new_typed_with_env(&mut store, &env, __fixunstfdi),
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
                // Index 256 functions
                "db_idx256_store" => Function::new_typed_with_env(&mut store, &env, db_idx256_store),
                "db_idx256_update" => Function::new_typed_with_env(&mut store, &env, db_idx256_update),
                "db_idx256_remove" => Function::new_typed_with_env(&mut store, &env, db_idx256_remove),
                "db_idx256_find_secondary" => Function::new_typed_with_env(&mut store, &env, db_idx256_find_secondary),
                "db_idx256_find_primary" => Function::new_typed_with_env(&mut store, &env, db_idx256_find_primary),
                "db_idx256_lowerbound" => Function::new_typed_with_env(&mut store, &env, db_idx256_lowerbound),
                "db_idx256_upperbound" => Function::new_typed_with_env(&mut store, &env, db_idx256_upperbound),
                "db_idx256_end" => Function::new_typed_with_env(&mut store, &env, db_idx256_end),
                "db_idx256_next" => Function::new_typed_with_env(&mut store, &env, db_idx256_next),
                "db_idx256_previous" => Function::new_typed_with_env(&mut store, &env, db_idx256_previous),
                // Index double functions
                "db_idx_double_store" => Function::new_typed_with_env(&mut store, &env, db_idx_double_store),
                "db_idx_double_update" => Function::new_typed_with_env(&mut store, &env, db_idx_double_update),
                "db_idx_double_remove" => Function::new_typed_with_env(&mut store, &env, db_idx_double_remove),
                "db_idx_double_find_secondary" => Function::new_typed_with_env(&mut store, &env, db_idx_double_find_secondary),
                "db_idx_double_find_primary" => Function::new_typed_with_env(&mut store, &env, db_idx_double_find_primary),
                "db_idx_double_lowerbound" => Function::new_typed_with_env(&mut store, &env, db_idx_double_lowerbound),
                "db_idx_double_upperbound" => Function::new_typed_with_env(&mut store, &env, db_idx_double_upperbound),
                "db_idx_double_end" => Function::new_typed_with_env(&mut store, &env, db_idx_double_end),
                "db_idx_double_next" => Function::new_typed_with_env(&mut store, &env, db_idx_double_next),
                "db_idx_double_previous" => Function::new_typed_with_env(&mut store, &env, db_idx_double_previous),
                // Index long double functions
                "db_idx_long_double_store" => Function::new_typed_with_env(&mut store, &env, db_idx_long_double_store),
                "db_idx_long_double_update" => Function::new_typed_with_env(&mut store, &env, db_idx_long_double_update),
                "db_idx_long_double_remove" => Function::new_typed_with_env(&mut store, &env, db_idx_long_double_remove),
                "db_idx_long_double_find_secondary" => Function::new_typed_with_env(&mut store, &env, db_idx_long_double_find_secondary),
                "db_idx_long_double_find_primary" => Function::new_typed_with_env(&mut store, &env, db_idx_long_double_find_primary),
                "db_idx_long_double_lowerbound" => Function::new_typed_with_env(&mut store, &env, db_idx_long_double_lowerbound),
                "db_idx_long_double_upperbound" => Function::new_typed_with_env(&mut store, &env, db_idx_long_double_upperbound),
                "db_idx_long_double_end" => Function::new_typed_with_env(&mut store, &env, db_idx_long_double_end),
                "db_idx_long_double_next" => Function::new_typed_with_env(&mut store, &env, db_idx_long_double_next),
                "db_idx_long_double_previous" => Function::new_typed_with_env(&mut store, &env, db_idx_long_double_previous),
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
                "publication_time" => Function::new_typed_with_env(&mut store, &env, publication_time),
                "is_feature_activated" => Function::new_typed_with_env(&mut store, &env, is_feature_activated),
                "get_block_num" => Function::new_typed_with_env(&mut store, &env, get_block_num),
                "get_code_hash" => Function::new_typed_with_env(&mut store, &env, get_code_hash),
                "get_sender" => Function::new_typed_with_env(&mut store, &env, get_sender),
                // Crypto functions
                "assert_recover_key" => Function::new_typed_with_env(&mut store, &env, assert_recover_key),
                "recover_key" => Function::new_typed_with_env(&mut store, &env, recover_key),
                "sha1" => Function::new_typed_with_env(&mut store, &env, sha1),
                "sha224" => Function::new_typed_with_env(&mut store, &env, sha224),
                "sha256" => Function::new_typed_with_env(&mut store, &env, sha256),
                "sha512" => Function::new_typed_with_env(&mut store, &env, sha512),
                "ripemd160" => Function::new_typed_with_env(&mut store, &env, ripemd160),
                "assert_sha1" => Function::new_typed_with_env(&mut store, &env, assert_sha1),
                "assert_sha224" => Function::new_typed_with_env(&mut store, &env, assert_sha224),
                "assert_sha256" => Function::new_typed_with_env(&mut store, &env, assert_sha256),
                "assert_sha512" => Function::new_typed_with_env(&mut store, &env, assert_sha512),
                "assert_ripemd160" => Function::new_typed_with_env(&mut store, &env, assert_ripemd160),
                // Privilege and resource limit functions
                "is_privileged" => Function::new_typed_with_env(&mut store, &env, is_privileged),
                "set_privileged" => Function::new_typed_with_env(&mut store, &env, set_privileged),
                "preactivate_feature" => Function::new_typed_with_env(&mut store, &env, preactivate_feature),
                "set_proposed_producers" => Function::new_typed_with_env(&mut store, &env, set_proposed_producers),
                "set_proposed_producers_ex" => Function::new_typed_with_env(&mut store, &env, set_proposed_producers_ex),
                "get_blockchain_parameters_packed" => Function::new_typed_with_env(&mut store, &env, get_blockchain_parameters_packed),
                "set_blockchain_parameters_packed" => Function::new_typed_with_env(&mut store, &env, set_blockchain_parameters_packed),
                "set_resource_limits" => Function::new_typed_with_env(&mut store, &env, set_resource_limits),
                "get_resource_limits" => Function::new_typed_with_env(&mut store, &env, get_resource_limits),
                // Transaction functions
                "send_inline" => Function::new_typed_with_env(&mut store, &env, send_inline),
                "send_context_free_inline" => Function::new_typed_with_env(&mut store, &env, send_context_free_inline),
                "send_deferred" => Function::new_typed_with_env(&mut store, &env, send_deferred),
                "cancel_deferred" => Function::new_typed_with_env(&mut store, &env, cancel_deferred),
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
                "printqf" => Function::new_typed_with_env(&mut store, &env, printqf),
                "printn" => Function::new_typed_with_env(&mut store, &env, printn),
                "printhex" => Function::new_typed_with_env(&mut store, &env, printhex),
                // Permission functions
                "check_transaction_authorization" => Function::new_typed_with_env(&mut store, &env, check_transaction_authorization),
                "check_permission_authorization" => Function::new_typed_with_env(&mut store, &env, check_permission_authorization),
                "get_permission_last_used" => Function::new_typed_with_env(&mut store, &env, get_permission_last_used),
                "get_account_creation_time" => Function::new_typed_with_env(&mut store, &env, get_account_creation_time),
                // Context free functions
                "get_context_free_data" => Function::new_typed_with_env(&mut store, &env, get_context_free_data),
                // Producer functions
                "get_active_producers" => Function::new_typed_with_env(&mut store, &env, get_active_producers),
            }
            };
            WarmStore {
                store,
                env,
                imports,
                instances_created: 0,
                resettable_instance: None,
            }
        };

        let mut resettable = warm.resettable_instance.take();
        if let Some(candidate) = resettable.as_ref() {
            match candidate.reset(&mut warm.store) {
                Ok(true) => {}
                Ok(false) | Err(_) => resettable = None,
            }
        }

        let (instance, apply_func, metering) = if let Some(candidate) = resettable.as_ref() {
            (
                candidate.instance.clone(),
                candidate.apply.clone(),
                candidate.metering.clone(),
            )
        } else {
            let instance =
                Instance::new(&mut warm.store, &module.module, &warm.imports).map_err(|e| {
                    ChainError::WasmRuntimeError(format!("failed to create wasm instance: {e}"))
                })?;
            warm.instances_created += 1;

            if module.resettable {
                if let Ok(candidate) = ResettableInstance::capture(
                    &mut warm.store,
                    instance.clone(),
                    &module.reset_exports,
                ) {
                    let apply = candidate.apply.clone();
                    let metering = candidate.metering.clone();
                    resettable = Some(candidate);
                    (instance, apply, metering)
                } else {
                    let apply = instance
                        .exports
                        .get_typed_function::<(i64, i64, i64), ()>(&warm.store, "apply")
                        .map_err(|_| {
                            ChainError::WasmRuntimeError("failed to find apply function".into())
                        })?;
                    let metering = MeteringGlobals::from_instance(&instance)
                        .map_err(|error| ChainError::WasmRuntimeError(error.to_string()))?;
                    (instance, apply, metering)
                }
            } else {
                let apply = instance
                    .exports
                    .get_typed_function::<(i64, i64, i64), ()>(&warm.store, "apply")
                    .map_err(|_| {
                        ChainError::WasmRuntimeError("failed to find apply function".into())
                    })?;
                let metering = MeteringGlobals::from_instance(&instance)
                    .map_err(|error| ChainError::WasmRuntimeError(error.to_string()))?;
                (instance, apply, metering)
            }
        };

        warm.env.as_mut(&mut warm.store).memory = exported_memory(&instance);
        warm.env.as_mut(&mut warm.store).metering = Some(metering.clone());

        // cpu_limit == -1 means execution is exempt from the local objective
        // account/block allowance (implicit actions and explicitly billed block
        // replay). Seed a large finite deterministic budget so malformed code
        // still cannot spin forever. See config::IMPLICIT_TX_CPU_BUDGET.
        let cpu_limit = if cpu_limit >= 0 {
            cpu_limit as u64
        } else {
            crate::config::IMPLICIT_TX_CPU_BUDGET
        };

        // Seed through cached handles. Wasmer's public helper performs two
        // string-indexed export lookups per call, which is especially costly for
        // host-heavy contracts such as eosio::onblock.
        metering
            .set(&mut warm.store, cpu_limit)
            .map_err(|error| ChainError::WasmRuntimeError(error.to_string()))?;

        // Resume timer
        apply_context.resume_billing_timer()?;

        // Compilation happens while billing is paused, but the subjective
        // watchdog deliberately includes that native wall-clock window.
        apply_context.checktime()?;

        let result = apply_func.call(
            &mut warm.store,
            receiver.as_u64() as i64,
            action.account().as_u64() as i64,
            action.name().as_u64() as i64,
        );
        let return_value = warm.env.as_ref(&warm.store).return_value.clone();
        let remaining_points = metering
            .get(&mut warm.store)
            .map_err(|error| ChainError::WasmRuntimeError(error.to_string()))?;

        // Return the warm store to the pool for reuse, unless it has spun up
        // enough instances that its object slab is worth reclaiming. The reset
        // happens before the next invocation, including after a trap; no dirty
        // instance can execute if restoration fails.
        warm.resettable_instance = resettable;
        if warm.instances_created < MAX_INSTANCES_PER_STORE {
            STORE_POOL.with(|pool| pool.borrow_mut().put(id, warm));
        }

        match remaining_points {
            MeteringPoints::Remaining(points) => {
                if let Err(e) = result {
                    if e.downcast_ref::<WasmExit>().is_none() {
                        if let Some(chain_err) = e.downcast_ref::<ChainError>() {
                            return Err(chain_err.clone());
                        }
                        return Err(ChainError::ApplyError(format!("{}", e.message())));
                    }
                }

                if let Some(value) = return_value {
                    apply_context.set_trace_return_value(value.0)?;
                }

                Ok(cpu_limit.saturating_sub(points) as u64)
            }
            MeteringPoints::Exhausted => Err(ChainError::ApplyError(format!(
                "CPU limit of {} exhausted during apply",
                cpu_limit
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use wasmer::{
        Instance,
        Module,
        Store,
        TypedFunction,
        Value,
        imports,
    };
    use wasmer_middlewares::metering::{
        MeteringPoints,
        get_remaining_points,
        set_remaining_points,
    };

    use super::{
        ResettableInstance,
        WasmRuntime,
        charge_metering_points,
        exported_memory,
        expose_internal_memory,
        expose_reset_state,
        module_is_resettable,
    };

    #[test]
    fn finds_legacy_nonstandard_memory_export() {
        let wasm = wat::parse_str(
            r#"
            (module
              (memory (export "linear_memory") 1))
            "#,
        )
        .unwrap();
        let mut store = Store::new(WasmRuntime::deterministic_engine());
        let module = Module::new(&store, &wasm).unwrap();
        let instance = Instance::new(&mut store, &module, &imports! {}).unwrap();

        assert!(exported_memory(&instance).is_some());
    }

    #[test]
    fn exposes_legacy_internal_memory_to_host_functions() {
        let wasm = wat::parse_str(
            r#"
            (module
              (memory 1)
              (func (export "apply") (param i64 i64 i64)))
            "#,
        )
        .unwrap();
        let runtime_wasm = expose_internal_memory(&wasm).unwrap();
        assert!(matches!(runtime_wasm, std::borrow::Cow::Owned(_)));

        let mut store = Store::new(WasmRuntime::deterministic_engine());
        let module = Module::new(&store, runtime_wasm.as_ref()).unwrap();
        let instance = Instance::new(&mut store, &module, &imports! {}).unwrap();

        assert!(exported_memory(&instance).is_some());
    }

    #[test]
    fn audited_instance_reset_restores_memory_growth_globals_and_tables() {
        let wasm = wat::parse_str(
            r#"
            (module
              (func $slot)
              (table 1 funcref)
              (elem (i32.const 0) $slot)
              (memory 1)
              (data (i32.const 0) "\05")
              (global $counter (mut i32) (i32.const 7))
              (func (export "apply") (param i64 i64 i64)
                (i32.store8 (i32.const 0) (i32.const 99))
                (drop (memory.grow (i32.const 1)))
                (i32.store8 (i32.const 65536) (i32.const 77))
                (global.set $counter (i32.const 42))
                (table.set (i32.const 0) (ref.null func)))
              (func (export "probe") (result i32)
                (i32.add (i32.load8_u (i32.const 0)) (global.get $counter)))
              (func (export "grow_probe") (result i32)
                (drop (memory.grow (i32.const 1)))
                (i32.load8_u (i32.const 65536))))
            "#,
        )
        .unwrap();
        let memory_wasm = expose_internal_memory(&wasm).unwrap();
        let (runtime_wasm, reset_exports) = expose_reset_state(memory_wasm.as_ref()).unwrap();
        let mut store = Store::new(WasmRuntime::deterministic_engine());
        let module = Module::new(&store, runtime_wasm.as_ref()).unwrap();
        assert!(module_is_resettable(&module));
        let instance = Instance::new(&mut store, &module, &imports! {}).unwrap();
        let resettable =
            ResettableInstance::capture(&mut store, instance.clone(), &reset_exports).unwrap();
        let probe: TypedFunction<(), i32> = instance
            .exports
            .get_typed_function(&store, "probe")
            .unwrap();
        let grow_probe: TypedFunction<(), i32> = instance
            .exports
            .get_typed_function(&store, "grow_probe")
            .unwrap();
        let table = instance
            .exports
            .get_table(&reset_exports.tables[0])
            .unwrap()
            .clone();

        resettable.metering.set(&mut store, 1_000_000).unwrap();
        resettable.apply.call(&mut store, 0, 0, 0).unwrap();
        assert_eq!(probe.call(&mut store).unwrap(), 141);
        assert_eq!(resettable.memory.size(&store).0, 2);
        assert!(matches!(
            table.get(&mut store, 0),
            Some(Value::FuncRef(None))
        ));

        assert!(resettable.reset(&mut store).unwrap());
        assert_eq!(probe.call(&mut store).unwrap(), 12);
        assert_eq!(resettable.memory.size(&store).0, 1);
        assert!(matches!(
            table.get(&mut store, 0),
            Some(Value::FuncRef(Some(_)))
        ));
        assert_eq!(grow_probe.call(&mut store).unwrap(), 0);
    }

    #[test]
    fn audited_instance_with_a_grown_table_falls_back_to_fresh() {
        let wasm = wat::parse_str(
            r#"
            (module
              (table 1 funcref)
              (memory 1)
              (func (export "apply") (param i64 i64 i64)
                (drop (table.grow (ref.null func) (i32.const 1)))))
            "#,
        )
        .unwrap();
        let memory_wasm = expose_internal_memory(&wasm).unwrap();
        let (runtime_wasm, reset_exports) = expose_reset_state(memory_wasm.as_ref()).unwrap();
        let mut store = Store::new(WasmRuntime::deterministic_engine());
        let module = Module::new(&store, runtime_wasm.as_ref()).unwrap();
        let instance = Instance::new(&mut store, &module, &imports! {}).unwrap();
        let resettable = ResettableInstance::capture(&mut store, instance, &reset_exports).unwrap();

        resettable.metering.set(&mut store, 1_000_000).unwrap();
        resettable.apply.call(&mut store, 0, 0, 0).unwrap();
        assert!(!resettable.reset(&mut store).unwrap());
    }

    #[test]
    fn audited_instance_with_large_memory_stays_on_fresh_path() {
        // 129 wasm pages is just over the 8 MiB reset-work ceiling.
        let wasm = wat::parse_str(
            r#"(module
                  (memory 129)
                  (func (export "apply") (param i64 i64 i64)))"#,
        )
        .unwrap();
        let memory_wasm = expose_internal_memory(&wasm).unwrap();
        let (runtime_wasm, reset_exports) = expose_reset_state(memory_wasm.as_ref()).unwrap();
        let mut store = Store::new(WasmRuntime::deterministic_engine());
        let module = Module::new(&store, runtime_wasm.as_ref()).unwrap();
        let instance = Instance::new(&mut store, &module, &imports! {}).unwrap();

        assert!(ResettableInstance::capture(&mut store, instance, &reset_exports).is_err());
    }

    #[test]
    fn audited_instance_reset_is_safe_after_a_trap() {
        let wasm = wat::parse_str(
            r#"
            (module
              (memory 1)
              (data (i32.const 0) "\0b")
              (global $counter (mut i32) (i32.const 13))
              (func (export "apply") (param i64 i64 i64)
                (i32.store8 (i32.const 0) (i32.const 99))
                (global.set $counter (i32.const 42))
                unreachable)
              (func (export "probe") (result i32)
                (i32.add (i32.load8_u (i32.const 0)) (global.get $counter))))
            "#,
        )
        .unwrap();
        let memory_wasm = expose_internal_memory(&wasm).unwrap();
        let (runtime_wasm, reset_exports) = expose_reset_state(memory_wasm.as_ref()).unwrap();
        let mut store = Store::new(WasmRuntime::deterministic_engine());
        let module = Module::new(&store, runtime_wasm.as_ref()).unwrap();
        let instance = Instance::new(&mut store, &module, &imports! {}).unwrap();
        let resettable =
            ResettableInstance::capture(&mut store, instance.clone(), &reset_exports).unwrap();
        let probe: TypedFunction<(), i32> = instance
            .exports
            .get_typed_function(&store, "probe")
            .unwrap();

        resettable.metering.set(&mut store, 1_000_000).unwrap();
        assert!(resettable.apply.call(&mut store, 0, 0, 0).is_err());
        assert!(resettable.reset(&mut store).unwrap());
        assert_eq!(probe.call(&mut store).unwrap(), 24);
    }

    #[test]
    fn reset_audit_rejects_start_passive_segments_and_imported_state() {
        for wat in [
            r#"(module
                  (memory 1)
                  (func $start)
                  (start $start)
                  (func (export "apply") (param i64 i64 i64)))"#,
            r#"(module
                  (memory 1)
                  (data "passive")
                  (func (export "apply") (param i64 i64 i64)))"#,
            r#"(module
                  (import "env" "memory" (memory 1))
                  (func (export "apply") (param i64 i64 i64)))"#,
        ] {
            let wasm = wat::parse_str(wat).unwrap();
            let memory_wasm = expose_internal_memory(&wasm).unwrap();
            let (runtime_wasm, _) = expose_reset_state(memory_wasm.as_ref()).unwrap();
            let store = Store::new(WasmRuntime::deterministic_engine());
            let module = Module::new(&store, runtime_wasm.as_ref()).unwrap();
            assert!(!module_is_resettable(&module));
        }
    }

    // A host intrinsic bills its own work out of the same metering budget the
    // wasm body spends: each charge lowers the remaining points by exactly the
    // amount, and a charge the budget can't cover traps (and zeroes the budget)
    // instead of running for free. This is what makes the per-intrinsic cost
    // table in `webassembly::cost` actually reach billed CPU.
    #[test]
    fn charging_a_host_intrinsic_spends_metering_points() {
        // Any module compiled on the metered engine carries the remaining-points
        // global; the body is irrelevant, we only move the budget.
        let wasm = wat::parse_str("(module)").unwrap();
        let mut store = Store::new(WasmRuntime::deterministic_engine());
        let module = Module::new(&store, &wasm).unwrap();
        let instance = Instance::new(&mut store, &module, &imports! {}).unwrap();

        set_remaining_points(&mut store, &instance, 1_000);

        // Two successive charges (as an intrinsic's base + per-byte would) each
        // subtract exactly their amount.
        charge_metering_points(&mut store, &instance, 100).unwrap();
        charge_metering_points(&mut store, &instance, 250).unwrap();
        match get_remaining_points(&mut store, &instance) {
            MeteringPoints::Remaining(p) => assert_eq!(p, 650),
            MeteringPoints::Exhausted => panic!("budget should not be exhausted yet"),
        }

        // A charge larger than what's left traps (Err) and zeroes the budget, so
        // a subsequent wasm op also runs out rather than resuming for free.
        assert!(charge_metering_points(&mut store, &instance, 10_000).is_err());
        match get_remaining_points(&mut store, &instance) {
            MeteringPoints::Remaining(p) => assert_eq!(p, 0),
            MeteringPoints::Exhausted => {}
        }
    }

    // Operator prices are consensus values (they become billed CPU committed to the
    // block), so pin the ones the estimator corrected. If you change COST_FUNCTION
    // deliberately, update this in the same commit; an unexpected failure means an
    // operator cost was edited by accident. See docs/intrinsic-cost-model.md.
    #[test]
    fn operator_costs_are_pinned() {
        use wasmer::wasmparser::Operator;

        use super::COST_FUNCTION;

        // Floating point: the estimator's headline fix (shipped 1-3, measured 80/110/26/20).
        assert_eq!(COST_FUNCTION(&Operator::F64Div), 80);
        assert_eq!(COST_FUNCTION(&Operator::F64Sqrt), 110);
        assert_eq!(COST_FUNCTION(&Operator::F64Mul), 26);
        assert_eq!(COST_FUNCTION(&Operator::F64Add), 20);
        assert_eq!(COST_FUNCTION(&Operator::F32Div), 80);
        // Integer arithmetic kept its structural weights (folds under LLVM).
        assert_eq!(COST_FUNCTION(&Operator::I64DivU), 80);
        assert_eq!(COST_FUNCTION(&Operator::I64Mul), 3);
        assert_eq!(COST_FUNCTION(&Operator::I64Add), 1); // default
    }

    // Run a float op on the real deterministic_engine and feed it non-canonical
    // NaNs; each must come back as the one wasm canonical NaN. Off, the input
    // payload leaks through — a platform-dependent, consensus-visible value.
    // Verified: fails with canonicalize_nans off.
    #[test]
    fn canonicalize_nans_masks_nan_payloads() {
        // Reinterpret the i64 arg as f64, run x + 0.0 (kept with no fast-math,
        // NaN-preserving) and return the bits.
        let wasm = wat::parse_str(
            r#"
            (module
              (func (export "canon") (param i64) (result i64)
                (i64.reinterpret_f64
                  (f64.add (f64.reinterpret_i64 (local.get 0)) (f64.const 0)))))
            "#,
        )
        .unwrap();

        let mut store = Store::new(WasmRuntime::deterministic_engine());
        let module = Module::new(&store, &wasm).unwrap();
        let instance = Instance::new(&mut store, &module, &imports! {}).unwrap();
        set_remaining_points(&mut store, &instance, 1_000_000);
        let canon: TypedFunction<i64, i64> = instance
            .exports
            .get_typed_function(&store, "canon")
            .unwrap();

        // Assorted non-canonical NaNs: quiet-with-payload, signaling, negative.
        for input in [
            0x7ff8_0000_dead_beef_u64,
            0x7ff0_0000_0000_0001,
            0xfff4_0000_0000_0000,
        ] {
            let out = canon.call(&mut store, input as i64).unwrap() as u64;
            // Canonical NaN, ignoring the sign bit: exponent all ones, only the
            // mantissa MSB set. The input payload must be gone.
            assert_eq!(
                out & 0x7fff_ffff_ffff_ffff,
                0x7ff8_0000_0000_0000,
                "NaN input {input:#018x} was not canonicalized (got {out:#018x})"
            );
        }

        // A finite value is untouched: 1.0 + 0.0 == 1.0.
        let one = 1.0_f64.to_bits() as i64;
        assert_eq!(canon.call(&mut store, one).unwrap(), one);
    }

    // Locks the feature set. Flipping any of these is a consensus change, so it
    // should be deliberate, not a silent default a wasmer bump drags in.
    #[test]
    fn pinned_features_stay_deterministic() {
        let f = WasmRuntime::deterministic_features();

        // Nondeterministic by spec, or unused by the contract toolchain: off.
        assert!(
            !f.threads,
            "threads (shared memory + atomics) is nondeterministic"
        );
        assert!(!f.relaxed_simd, "relaxed-simd is nondeterministic by spec");
        assert!(!f.simd, "simd is not part of the contract ABI");
        assert!(!f.exceptions);
        assert!(!f.tail_call);
        assert!(!f.memory64);
        assert!(!f.multi_memory);
        assert!(!f.module_linking);
        assert!(!f.wide_arithmetic);

        // Deterministic, and emitted by compiled contracts: on.
        assert!(f.reference_types);
        assert!(f.bulk_memory);
        assert!(f.multi_value);
        assert!(f.extended_const);
    }

    // Parameter estimator for the host-intrinsic cost table (webassembly::cost).
    // Ignored: it's a calibration tool, not an assertion, and it takes a few
    // seconds. Run it to (re)derive the table:
    //
    //   cargo test -p pulsevm_core --lib estimate_intrinsic_costs \
    //     -- --ignored --nocapture
    //
    // Method (a stripped-down NEAR runtime-params-estimator):
    //   1. Anchor. Run a compute-bound wasm loop on the real metered LLVM engine and read BOTH wall
    //      time and points consumed from the metering middleware. Their ratio is ns-per-point on
    //      this machine -- it ties the intrinsic prices to the same scale the operator table
    //      already bills in, without hand-computing any operator cost.
    //   2. Measure. Time each intrinsic's native work across input sizes and least-squares fit ns =
    //      base + slope*bytes.
    //   3. Convert. points = ns / ns_per_point, times a conservative SAFETY multiplier so a point
    //      is an UPPER bound on real time (an under-charge is a DoS hole; an over-charge only costs
    //      fairness).
    //
    // The absolute numbers are hardware-specific; the ratios and the resulting
    // table are what get pinned. Anchoring to the current operator table means
    // the table inherits that table's own lack of ns-calibration -- documented
    // limitation, absorbed by SAFETY; a full recalibration of operators too is
    // the deeper follow-up.
    #[test]
    #[ignore = "calibration tool; run manually with --ignored --nocapture"]
    fn estimate_intrinsic_costs() {
        use std::{
            hint::black_box,
            str::FromStr,
            time::Instant,
        };

        use sha2::Digest as _;

        use crate::crypto::PrivateKey;

        // Points are an upper bound on real time; bias high. NEAR historically
        // used ~3x. Under-charging is the only unsafe direction.
        const SAFETY: f64 = 3.0;

        fn time_ns(iters: u32, mut f: impl FnMut()) -> f64 {
            for _ in 0..(iters / 8).max(2) {
                f();
            }
            let t = Instant::now();
            for _ in 0..iters {
                f();
            }
            (t.elapsed().as_nanos() as f64) / (iters as f64)
        }

        // Least-squares fit of ns = base + slope*bytes; clamp both non-negative.
        fn fit(pts: &[(f64, f64)]) -> (f64, f64) {
            let n = pts.len() as f64;
            let sx: f64 = pts.iter().map(|p| p.0).sum();
            let sy: f64 = pts.iter().map(|p| p.1).sum();
            let sxx: f64 = pts.iter().map(|p| p.0 * p.0).sum();
            let sxy: f64 = pts.iter().map(|p| p.0 * p.1).sum();
            let slope = (n * sxy - sx * sy) / (n * sxx - sx * sx);
            let base = (sy - slope * sx) / n;
            (base.max(0.0), slope.max(0.0))
        }

        // --- 1. anchor: ns per metering point on the real engine ---
        let wasm = wat::parse_str(
            r#"
            (module
              (func (export "work") (param $n i64) (result i64)
                (local $i i64) (local $acc i64)
                (local.set $acc (i64.const 2))
                (block $done
                  (loop $l
                    (br_if $done (i64.ge_u (local.get $i) (local.get $n)))
                    (local.set $acc
                      (i64.xor
                        (i64.mul (local.get $acc) (i64.const 6364136223846793005))
                        (i64.add (local.get $i) (i64.const 1442695040888963407))))
                    (local.set $i (i64.add (local.get $i) (i64.const 1)))
                    (br $l)))
                (local.get $acc)))
            "#,
        )
        .unwrap();
        let mut store = Store::new(WasmRuntime::deterministic_engine());
        let module = Module::new(&store, &wasm).unwrap();
        let instance = Instance::new(&mut store, &module, &imports! {}).unwrap();
        let work: TypedFunction<i64, i64> =
            instance.exports.get_typed_function(&store, "work").unwrap();

        const SEED: u64 = 1_000_000_000_000;
        let n = 2_000_000i64;
        for _ in 0..3 {
            set_remaining_points(&mut store, &instance, SEED);
            black_box(work.call(&mut store, n).unwrap());
        }
        let (mut total_ns, mut total_pts) = (0.0f64, 0u64);
        for _ in 0..20 {
            set_remaining_points(&mut store, &instance, SEED);
            let t = Instant::now();
            black_box(work.call(&mut store, n).unwrap());
            total_ns += t.elapsed().as_nanos() as f64;
            total_pts += match get_remaining_points(&mut store, &instance) {
                MeteringPoints::Remaining(p) => SEED - p,
                MeteringPoints::Exhausted => panic!("anchor loop exhausted the budget"),
            };
        }
        let ns_per_point = total_ns / total_pts as f64;

        let sizes = [0usize, 64, 256, 1024, 4096, 16384, 65536, 262144];
        let iters_for = |s: usize| -> u32 {
            if s >= 65536 {
                400
            } else if s >= 4096 {
                3000
            } else {
                20000
            }
        };

        println!("\n==== intrinsic cost estimate (hardware-specific) ====");
        println!("anchor: {ns_per_point:.4} ns/point  ({total_pts} pts over {total_ns:.0} ns)");
        println!("safety multiplier: {SAFETY}x\n");
        println!(
            "{:<14} {:>10} {:>12} {:>12} {:>14}",
            "intrinsic", "base_pts", "per_byte", "bytes/pt", "shipped(base/pB)"
        );

        // sweep a sized intrinsic, fit, and print its candidate constants.
        let report_sized = |name: &str, shipped_base: u64, mut work: Box<dyn FnMut(&[u8])>| {
            let data: Vec<(f64, f64)> = sizes
                .iter()
                .map(|&s| {
                    let buf = vec![0xa5u8; s];
                    (s as f64, time_ns(iters_for(s), || work(black_box(&buf))))
                })
                .collect();
            // Base is the fixed overhead measured at size 0; slope is fit over the
            // linear region (>= 1 KiB) so small-size noise doesn't distort the
            // intercept.
            let base_ns = data[0].1;
            let linear: Vec<(f64, f64)> = data.iter().copied().filter(|p| p.0 >= 1024.0).collect();
            let (_, slope_ns) = fit(&linear);
            let base_pts = (base_ns / ns_per_point * SAFETY).ceil();
            let per_byte = slope_ns / ns_per_point * SAFETY;
            let bytes_per_pt = if per_byte > 0.0 {
                1.0 / per_byte
            } else {
                f64::INFINITY
            };
            println!(
                "{name:<14} {base_pts:>10.0} {per_byte:>12.4} {bytes_per_pt:>12.1} {:>14}",
                format!("{shipped_base}/1")
            );
        };

        report_sized(
            "sha256",
            30,
            Box::new(|b| {
                black_box(sha2::Sha256::digest(b));
            }),
        );
        report_sized(
            "sha512",
            30,
            Box::new(|b| {
                black_box(sha2::Sha512::digest(b));
            }),
        );
        report_sized(
            "sha1",
            30,
            Box::new(|b| {
                black_box(sha1::Sha1::digest(b));
            }),
        );
        report_sized(
            "ripemd160",
            30,
            Box::new(|b| {
                black_box(ripemd::Ripemd160::digest(b));
            }),
        );
        // memcpy intrinsic ~ one alloc + read guest->buf + write buf->guest.
        report_sized(
            "memcpy",
            10,
            Box::new(|b| {
                let mut buf = vec![0u8; b.len()];
                buf.copy_from_slice(b);
                let mut out = vec![0u8; b.len()];
                out.copy_from_slice(&buf);
                black_box((buf, out));
            }),
        );

        // --- recover_key: fixed, no size sweep ---
        let key = PrivateKey::from_str("PVT_K1_5G7JEG7CWZkGfnaQePCcJSNgocGFoeCxG1pU7r1B6rY2gueez")
            .unwrap();
        let digest = pulsevm_crypto::Digest::hash(b"pulsevm-intrinsic-cost-benchmark");
        let sig = key.sign(&digest).unwrap();
        let recover_ns = time_ns(300, || {
            black_box(sig.recover_public_key(black_box(&digest)).unwrap());
        });
        let recover_pts = (recover_ns / ns_per_point * SAFETY).ceil();
        println!("\nrecover_key: {recover_ns:.0} ns -> {recover_pts:.0} pts (shipped 2000)");
        println!("=====================================================\n");
    }

    // ns per metering point on this machine, from a mixed integer compute loop run
    // on the real metered engine (reading wall time and points consumed). Shared
    // anchor for the calibration tools below and for estimate_intrinsic_costs'
    // method; ties native measurements to the point unit the chain already bills.
    #[cfg(test)]
    fn anchor_ns_per_point() -> f64 {
        use std::{
            hint::black_box,
            time::Instant,
        };
        const SEED: u64 = 200_000_000_000;
        let src = "(module (func (export \"run\") (param $n i64) (result i64)\n\
             (local $i i64) (local $acc i64)\n\
             (local.set $acc (i64.const 2))\n\
             (block $done (loop $l\n\
             (br_if $done (i64.ge_u (local.get $i) (local.get $n)))\n\
             (local.set $acc (i64.xor (i64.mul (local.get $acc) (i64.const 6364136223846793005))\
             (i64.add (local.get $i) (i64.const 1442695040888963407))))\n\
             (local.set $i (i64.add (local.get $i) (i64.const 1)))\n\
             (br $l)))\n\
             (local.get $acc)))";
        let mut store = Store::new(WasmRuntime::deterministic_engine());
        let module = Module::new(&store, src).unwrap();
        let instance = Instance::new(&mut store, &module, &imports! {}).unwrap();
        let f: TypedFunction<i64, i64> =
            instance.exports.get_typed_function(&store, "run").unwrap();
        for _ in 0..3 {
            set_remaining_points(&mut store, &instance, SEED);
            black_box(f.call(&mut store, 2_000_000).unwrap());
        }
        let (mut ns, mut pts) = (0.0f64, 0u64);
        for _ in 0..20 {
            set_remaining_points(&mut store, &instance, SEED);
            let t = Instant::now();
            black_box(f.call(&mut store, 2_000_000).unwrap());
            ns += t.elapsed().as_nanos() as f64;
            pts += match get_remaining_points(&mut store, &instance) {
                MeteringPoints::Remaining(p) => SEED - p,
                MeteringPoints::Exhausted => panic!("anchor exhausted"),
            };
        }
        ns / pts as f64
    }

    // Recalibrate the *relative* weights in COST_FUNCTION against measurement,
    // keeping the anchor fixed. Ignored: a calibration tool, run manually.
    //
    //   cargo test -p pulsevm_core --lib estimate_operator_costs \
    //     -- --ignored --nocapture
    //
    // The point unit is pinned by integer metering: the cheapest operator has to
    // cost >= 1 point, so we normalize everything to i64.add = 1 and read the rest
    // off as multiples of it. That keeps POINTS_PER_US and the intrinsic table
    // (which is denominated in this same unit) untouched, and only corrects
    // operators whose hand-picked weight is wrong relative to add.
    //
    // Only the arithmetic and bulk-memory operators are re-measured. Control flow,
    // calls, selects, and local/global access are left at their structural
    // hand-values: at Aggressive opt LLVM inlines callees and folds branches, so a
    // single operator's isolated wall-clock is dominated by pipelining and doesn't
    // mean much -- measuring it would be false precision. The arithmetic ops are
    // where the shipped table is actually wrong (clz at 105 is ~100x too high; a
    // native lzcnt is a couple of cycles).
    //
    // Method: run a metered loop whose body is M copies of one dependent update to
    // an accumulator, minus the empty loop, over N trips -> ns per operator. The
    // operand comes from a runtime parameter (not a constant) so LLVM can't fold or
    // strength-reduce the division; the accumulator feeds the next op so nothing is
    // dead-code eliminated. Timing is on the real deterministic_engine, so the
    // metering decrement each op pays is included, as it is on-chain.
    #[test]
    #[ignore = "calibration tool; run manually with --ignored --nocapture"]
    fn estimate_operator_costs() {
        use std::{
            hint::black_box,
            time::Instant,
        };

        const N: i64 = 300_000; // loop trips
        const M: usize = 48; // op copies per trip
        const SEED: u64 = 200_000_000_000; // metering budget; never exhausted here
        const D: i64 = 0x9E3779B97F4A7C15u128 as i64; // runtime operand, defeats folding

        // Build an i64-accumulator loop whose body is `unit` repeated `m` times.
        let int_src = |unit: &str, m: usize| -> String {
            let body = unit.repeat(m);
            format!(
                "(module (func (export \"run\") (param $n i64) (param $d i64) (result i64)\n\
                 (local $i i64) (local $acc i64)\n\
                 (local.set $acc (local.get $d))\n\
                 (block $done (loop $l\n\
                 (br_if $done (i64.ge_u (local.get $i) (local.get $n)))\n\
                 {body}\n\
                 (local.set $i (i64.add (local.get $i) (i64.const 1)))\n\
                 (br $l)))\n\
                 (local.get $acc)))"
            )
        };
        let float_src = |unit: &str, m: usize| -> String {
            let body = unit.repeat(m);
            format!(
                "(module (func (export \"run\") (param $n i64) (param $d f64) (result f64)\n\
                 (local $i i64) (local $acc f64)\n\
                 (local.set $acc (local.get $d))\n\
                 (block $done (loop $l\n\
                 (br_if $done (i64.ge_u (local.get $i) (local.get $n)))\n\
                 {body}\n\
                 (local.set $i (i64.add (local.get $i) (i64.const 1)))\n\
                 (br $l)))\n\
                 (local.get $acc)))"
            )
        };
        let mem_src = |m: usize| -> String {
            // Each unit copies 64 bytes; measured as a base per invocation (the
            // length is a runtime operand on-chain, so the operator is flat-priced).
            let body = "(memory.copy (i32.const 0) (i32.const 4096) (i32.const 64))\n".repeat(m);
            format!(
                "(module (memory 1)\n\
                 (func (export \"run\") (param $n i64) (param $d i64) (result i64)\n\
                 (local $i i64)\n\
                 (block $done (loop $l\n\
                 (br_if $done (i64.ge_u (local.get $i) (local.get $n)))\n\
                 {body}\n\
                 (local.set $i (i64.add (local.get $i) (i64.const 1)))\n\
                 (br $l)))\n\
                 (local.get $i)))"
            )
        };

        // Best-of wall time (ns) for one compiled i64->i64 "run" module.
        let best_i64 = |src: &str| -> f64 {
            let mut store = Store::new(WasmRuntime::deterministic_engine());
            let module = Module::new(&store, src).unwrap();
            let instance = Instance::new(&mut store, &module, &imports! {}).unwrap();
            let f: TypedFunction<(i64, i64), i64> =
                instance.exports.get_typed_function(&store, "run").unwrap();
            for _ in 0..3 {
                set_remaining_points(&mut store, &instance, SEED);
                black_box(f.call(&mut store, N, D).unwrap());
            }
            let mut best = f64::MAX;
            for _ in 0..7 {
                set_remaining_points(&mut store, &instance, SEED);
                let t = Instant::now();
                black_box(f.call(&mut store, N, D).unwrap());
                best = best.min(t.elapsed().as_nanos() as f64);
            }
            best
        };

        // Anchor: ns per metering point on this machine. Operators are directly
        // metered, so no safety multiplier -- a point already is the billed unit.
        let ns_per_point = anchor_ns_per_point();

        // Per-operator ns for an int-accumulator unit: (loop with M) - (empty loop),
        // amortized over N*M.
        let int_base = best_i64(&int_src("", 0));
        let per_op_int = |unit: &str| -> f64 {
            (best_i64(&int_src(unit, M)) - int_base) / (N as f64 * M as f64)
        };

        // Float uses its own empty-loop baseline (f64 local, same shape).
        let f_src_base = {
            let mut store = Store::new(WasmRuntime::deterministic_engine());
            let module = Module::new(&store, &float_src("", 0)).unwrap();
            let instance = Instance::new(&mut store, &module, &imports! {}).unwrap();
            let f: TypedFunction<(i64, f64), f64> =
                instance.exports.get_typed_function(&store, "run").unwrap();
            for _ in 0..3 {
                set_remaining_points(&mut store, &instance, SEED);
                black_box(f.call(&mut store, N, 1.0000001f64).unwrap());
            }
            let mut best = f64::MAX;
            for _ in 0..7 {
                set_remaining_points(&mut store, &instance, SEED);
                let t = Instant::now();
                black_box(f.call(&mut store, N, 1.0000001f64).unwrap());
                best = best.min(t.elapsed().as_nanos() as f64);
            }
            best
        };
        let per_op_float = |unit: &str| -> f64 {
            let mut store = Store::new(WasmRuntime::deterministic_engine());
            let module = Module::new(&store, &float_src(unit, M)).unwrap();
            let instance = Instance::new(&mut store, &module, &imports! {}).unwrap();
            let f: TypedFunction<(i64, f64), f64> =
                instance.exports.get_typed_function(&store, "run").unwrap();
            for _ in 0..3 {
                set_remaining_points(&mut store, &instance, SEED);
                black_box(f.call(&mut store, N, 1.0000001f64).unwrap());
            }
            let mut best = f64::MAX;
            for _ in 0..7 {
                set_remaining_points(&mut store, &instance, SEED);
                let t = Instant::now();
                black_box(f.call(&mut store, N, 1.0000001f64).unwrap());
                best = best.min(t.elapsed().as_nanos() as f64);
            }
            (best - f_src_base) / (N as f64 * M as f64)
        };

        let mem_base = best_i64(&mem_src(0));
        let per_op_mem = (best_i64(&mem_src(M)) - mem_base) / (N as f64 * M as f64);

        // points = round(ns / ns_per_point). A measurement at or below the anchor
        // floor (~ns_per_point) is flagged: LLVM folded the repeated op (scalar
        // evolution solves linear recurrences over the accumulator), so its
        // isolated cost is not observable and its structural weight is kept.
        let floor = ns_per_point * 1.5;
        let pts = |ns: f64| (ns / ns_per_point).round().max(1.0);

        println!("\n==== operator cost estimate ====");
        println!(
            "anchor: {ns_per_point:.5} ns/point  (=> ~{:.0} points/us)",
            1000.0 / ns_per_point
        );
        println!(
            "{:<16} {:>10} {:>10} {:>8}  note",
            "operator", "ns/op", "points", "shipped"
        );

        let row = |name: &str, ns: f64, shipped: u64| {
            let note = if ns < floor {
                "folded (kept)"
            } else {
                "measured"
            };
            println!(
                "{name:<16} {ns:>10.4} {:>10.0} {shipped:>8}  {note}",
                pts(ns)
            );
        };
        row(
            "i64.mul",
            per_op_int("(local.set $acc (i64.mul (local.get $acc) (local.get $d)))"),
            3,
        );
        row(
            "i64.div_u",
            per_op_int(
                "(local.set $acc (i64.div_u (local.get $acc) (i64.or (local.get $d) (i64.const 1))))",
            ),
            80,
        );
        row(
            "i64.rem_u",
            per_op_int(
                "(local.set $acc (i64.rem_u (local.get $acc) (i64.or (local.get $d) (i64.const 3))))",
            ),
            80,
        );
        row(
            "i64.clz",
            per_op_int("(local.set $acc (i64.add (i64.clz (local.get $acc)) (local.get $d)))"),
            105,
        );
        row(
            "i64.ctz",
            per_op_int("(local.set $acc (i64.add (i64.ctz (local.get $acc)) (local.get $d)))"),
            1,
        );
        row(
            "i64.popcnt",
            per_op_int("(local.set $acc (i64.add (i64.popcnt (local.get $acc)) (local.get $d)))"),
            1,
        );
        row(
            "i64.shl",
            per_op_int("(local.set $acc (i64.shl (local.get $acc) (local.get $d)))"),
            1,
        );
        row(
            "f64.add",
            per_op_float("(local.set $acc (f64.add (local.get $acc) (local.get $d)))"),
            1,
        );
        row(
            "f64.sub",
            per_op_float("(local.set $acc (f64.sub (local.get $acc) (local.get $d)))"),
            1,
        );
        row(
            "f64.mul",
            per_op_float("(local.set $acc (f64.mul (local.get $acc) (local.get $d)))"),
            3,
        );
        row(
            "f64.div",
            per_op_float("(local.set $acc (f64.div (local.get $acc) (local.get $d)))"),
            1,
        );
        row(
            "f64.sqrt",
            per_op_float("(local.set $acc (f64.sqrt (f64.abs (local.get $acc))))"),
            1,
        );
        row("memory.copy/64", per_op_mem, 500);
        println!("================================\n");
    }

    // Stateful estimator for the database intrinsics (cost::DB_OP and the value
    // per-byte). Ignored: a calibration tool needing a real chainbase, run manually.
    //
    //   cargo test -p pulsevm_core --lib estimate_db_intrinsic_costs \
    //     -- --ignored --nocapture
    //
    // The db intrinsics do native database work invisible to wasm metering, so
    // like the crypto intrinsics they bill themselves and get the same 3x safety
    // multiplier. We time the real work directly on a populated table (Database +
    // KeyValueIteratorCache, the same path db_find_i64/db_next_i64/db_store_i64
    // reach through ApplyContext, minus the RwLock hop) and convert ns -> points via
    // the shared anchor. This is the PROVISIONAL tier the intrinsic doc called out.
}
