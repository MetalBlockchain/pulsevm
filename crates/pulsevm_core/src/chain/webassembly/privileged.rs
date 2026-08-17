use std::collections::BTreeSet;

use pulsevm_database::ChainConfigV0;
use pulsevm_error::ChainError;
use pulsevm_serialization::{
    Read,
    VarUint32,
    Write,
};
use wasmer::{
    FunctionEnvMut,
    RuntimeError,
    WasmPtr,
};

use super::cost;
use crate::chain::{
    Name,
    apply_context::ApplyContext,
    producer_schedule::{
        MAX_PRODUCERS,
        MAX_SCHEDULE_BYTES,
        ProducerKey,
    },
    resource_limits::ResourceLimitsManager,
    utils::pulse_assert,
    wasm_runtime::WasmContext,
    webassembly::context_aware_check,
};

fn privileged_check(context: &ApplyContext) -> Result<(), RuntimeError> {
    if !context.is_privileged()? {
        return Err(RuntimeError::new(
            "attempt to call privileged instruction without proper authorization",
        ));
    }
    Ok(())
}

pub fn set_proposed_producers(
    mut env: FunctionEnvMut<WasmContext>,
    data_ptr: WasmPtr<u8>,
    data_len: u32,
) -> Result<i64, RuntimeError> {
    {
        context_aware_check(&env)?;
        let context = env.data_mut().apply_context_mut();
        privileged_check(context)?;
    }

    // Reject an oversized buffer before copying it out of wasm.
    pulse_assert(
        data_len <= MAX_SCHEDULE_BYTES,
        ChainError::TransactionError(format!(
            "proposed producer schedule is too large ({} bytes, max {})",
            data_len, MAX_SCHEDULE_BYTES
        )),
    )?;

    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(
        &mut store,
        cost::PRIVILEGED + cost::per_byte(data_len as u64),
    )?;
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let slice = data_ptr.slice(&view, data_len)?;
    let mut src_bytes = vec![0u8; data_len as usize];
    slice.read_slice(&mut src_bytes)?;

    // Validate the declared element count against the cap *before* the full
    // decode. `Vec::read` reserves the declared count up front, so a bogus length
    // prefix (a VarUint32, up to ~4.3 billion) would otherwise drive a huge
    // pre-allocation regardless of how few bytes actually follow.
    let declared = VarUint32::read(&src_bytes, &mut 0)
        .map_err(|e| RuntimeError::new(format!("failed to read producer count: {}", e)))?
        .0 as usize;
    pulse_assert(
        declared >= 1 && declared <= MAX_PRODUCERS,
        ChainError::TransactionError(format!(
            "proposed producer count {} out of range [1, {}]",
            declared, MAX_PRODUCERS
        )),
    )?;

    let producers = <Vec<ProducerKey>>::read(&src_bytes, &mut 0)
        .map_err(|e| RuntimeError::new(format!("failed to read proposed producers: {}", e)))?;

    // Every producer must be a real account, and no producer may appear twice —
    // the schedule is a name->key map, so a duplicate would silently shadow, and
    // the check must be deterministic across nodes.
    let db = env_data.db().clone();
    let mut seen = BTreeSet::new();
    for producer in &producers {
        pulse_assert(
            seen.insert(producer.producer_name.as_u64()),
            ChainError::TransactionError(format!(
                "duplicate producer {} in proposed schedule",
                producer.producer_name
            )),
        )?;
        pulse_assert(
            db.is_account(producer.producer_name.as_u64())?,
            ChainError::TransactionError(format!(
                "proposed producer {} is not an account",
                producer.producer_name
            )),
        )?;
    }

    let context = env_data.apply_context();
    if producers == context.active_producers()? {
        return Ok(-1);
    }
    let new_version = context.active_schedule_version()? as i64 + 1;
    let context = env_data.apply_context_mut();
    context.set_proposed_producers(producers)?;
    Ok(new_version)
}

pub fn get_blockchain_parameters_packed(
    mut env: FunctionEnvMut<WasmContext>,
    data_ptr: WasmPtr<u8>,
    data_len: u32,
) -> Result<u32, RuntimeError> {
    // Gate on privilege before charging, so a non-privileged caller isn't metered
    // for work that is rejected anyway — matching set_blockchain_parameters_packed.
    {
        context_aware_check(&env)?;
        let context = env.data_mut().apply_context_mut();
        privileged_check(context)?;
    }

    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(
        &mut store,
        cost::PRIVILEGED + cost::per_byte(data_len as u64),
    )?;

    // Read the active chain configuration and pack it in the same ChainConfigV0
    // wire format `set_blockchain_parameters_packed` consumes, so a contract can
    // round-trip the parameters it sets. Served as owned values (from the arena
    // in the Rust database).
    let cfg = env_data.db().chain_config()?;
    let packed = cfg
        .pack()
        .map_err(|e| RuntimeError::new(format!("packing blockchain parameters: {e}")))?;
    let size = packed.len() as u32;

    // EOSIO semantics: a zero-length buffer is a size query; otherwise write only
    // if the whole packed blob fits, and return 0 when it doesn't (a partial
    // packed record is useless).
    if data_len == 0 {
        return Ok(size);
    }
    if size > data_len {
        return Ok(0);
    }
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let slice = data_ptr.slice(&view, size)?;
    slice.write_slice(&packed)?;
    Ok(size)
}

pub fn set_blockchain_parameters_packed(
    mut env: FunctionEnvMut<WasmContext>,
    data_ptr: WasmPtr<u8>,
    data_len: u32,
) -> Result<(), RuntimeError> {
    {
        context_aware_check(&env)?;
        let context = env.data_mut().apply_context_mut();
        privileged_check(context)?;
    }

    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(
        &mut store,
        cost::PRIVILEGED + cost::per_byte(data_len as u64),
    )?;
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let slice = data_ptr.slice(&view, data_len)?;
    let mut src_bytes = vec![0u8; data_len as usize];
    slice.read_slice(&mut src_bytes)?;
    let cfg = ChainConfigV0::read(&src_bytes, &mut 0)
        .map_err(|e| RuntimeError::new(format!("failed to read blockchain parameters: {}", e)))?;
    cfg.validate()?;
    let context = env_data.apply_context_mut();
    context.set_global_properties(&cfg)?;
    Ok(())
}

pub fn is_privileged(
    mut env: FunctionEnvMut<WasmContext>,
    account: u64,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::PRIVILEGED)?;
    let context = env_data.apply_context_mut();
    privileged_check(context)?;
    let db = env_data.db();

    Ok(db.is_account_privileged(account)? as i32)
}

pub fn set_privileged(
    mut env: FunctionEnvMut<WasmContext>,
    account: u64,
    is_priv: i32,
) -> Result<(), RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::PRIVILEGED)?;
    let context = env_data.apply_context_mut();
    privileged_check(context)?;
    context.set_privileged(account, is_priv == 1)?;
    Ok(())
}

pub fn set_resource_limits(
    mut env: FunctionEnvMut<WasmContext>,
    account: u64,
    ram_bytes: i64,
    net_weight: i64,
    cpu_weight: i64,
) -> Result<(), RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::PRIVILEGED)?;
    pulse_assert(
        ram_bytes >= -1,
        ChainError::WasmRuntimeError(format!(
            "invalid value for ram resource limit expected [-1,INT64_MAX]"
        )),
    )?;
    pulse_assert(
        net_weight >= -1,
        ChainError::WasmRuntimeError(format!(
            "invalid value for net resource limit expected [-1,INT64_MAX]"
        )),
    )?;
    pulse_assert(
        cpu_weight >= -1,
        ChainError::WasmRuntimeError(format!(
            "invalid value for cpu resource limit expected [-1,INT64_MAX]"
        )),
    )?;
    let account: Name = account.into();
    let context = env_data.apply_context_mut();
    privileged_check(context)?;
    let mut db = env_data.db_mut();
    let decreased = ResourceLimitsManager::set_account_limits(
        &mut db, &account, net_weight, cpu_weight, ram_bytes,
    )?;
    // Lowering a limit doesn't touch usage, so if the account's allowance shrank
    // it may now be over quota; schedule a RAM check before the transaction
    // commits (an increase is checked via add_ram_usage instead).
    if decreased {
        env_data.apply_context_mut().validate_ram_usage(&account)?;
    }
    Ok(())
}

pub fn get_resource_limits(
    mut env: FunctionEnvMut<WasmContext>,
    account: u64,
    ram_bytes_ptr: WasmPtr<u8>,
    net_weight_ptr: WasmPtr<u8>,
    cpu_weight_ptr: WasmPtr<u8>,
) -> Result<(), RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::PRIVILEGED)?;
    let context = env_data.apply_context_mut();
    privileged_check(context)?;
    let mut db = env_data.db_mut();
    let mut ram_bytes = 0;
    let mut net_weight = 0;
    let mut cpu_weight = 0;
    ResourceLimitsManager::get_account_limits(
        &mut db,
        &account.into(),
        &mut ram_bytes,
        &mut net_weight,
        &mut cpu_weight,
    )?;
    let memory = env_data
        .memory()
        .as_ref()
        .expect("Wasm memory not initialized");
    let view = memory.view(&store);
    let ram_bytes_slice = ram_bytes_ptr.slice(&view, 8)?;
    let net_weight_slice = net_weight_ptr.slice(&view, 8)?;
    let cpu_weight_slice = cpu_weight_ptr.slice(&view, 8)?;
    ram_bytes_slice.write_slice(&ram_bytes.to_le_bytes())?;
    net_weight_slice.write_slice(&net_weight.to_le_bytes())?;
    cpu_weight_slice.write_slice(&cpu_weight.to_le_bytes())?;
    Ok(())
}
