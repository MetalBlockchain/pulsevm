use wasmer::{
    FunctionEnvMut,
    RuntimeError,
    WasmPtr,
};

use crate::chain::{
    wasm_runtime::WasmContext,
    webassembly::context_aware_check,
};

use super::cost;

const GET_CODE_HASH_FEATURE_DIGEST: [u8; 32] = [
    0xd2, 0x59, 0x66, 0x97, 0xfe, 0xd1, 0x4a, 0x08, 0x40, 0x01, 0x36, 0x47, 0xb9, 0x90, 0x45,
    0x02, 0x2a, 0xe6, 0xa8, 0x85, 0x08, 0x9f, 0x35, 0xa7, 0xe7, 0x8d, 0x7a, 0x43, 0xad, 0x76,
    0xed, 0x04,
];

pub fn require_auth(
    mut env: FunctionEnvMut<WasmContext>,
    account: u64,
) -> Result<(), RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::AUTH)?;
    let context = env_data.apply_context();

    if let Err(err) = context.require_authorization(&account.into(), None) {
        return Err(err.into());
    } else {
        Ok(())
    }
}

pub fn has_auth(mut env: FunctionEnvMut<WasmContext>, account: u64) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::AUTH)?;
    let context = env_data.apply_context();
    let result = context.has_authorization(&account.into())?;

    if result { Ok(1) } else { Ok(0) }
}

pub fn require_auth2(
    mut env: FunctionEnvMut<WasmContext>,
    account: u64,
    permission: u64,
) -> Result<(), RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::AUTH)?;
    let context = env_data.apply_context_mut();

    if let Err(err) = context.require_authorization(&account.into(), Some(permission.into())) {
        return Err(err.into());
    } else {
        Ok(())
    }
}

pub fn require_recipient(
    mut env: FunctionEnvMut<WasmContext>,
    recipient: u64,
) -> Result<(), RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::AUTH)?;
    let context = env_data.apply_context_mut();

    if let Err(err) = context.require_recipient(&recipient.into()) {
        return Err(err.into());
    } else {
        Ok(())
    }
}

pub fn is_account(
    mut env: FunctionEnvMut<WasmContext>,
    recipient: u64,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    // is_account hits the database, unlike the auth scans above, so it is priced as a lookup.
    env_data.charge(&mut store, cost::DB_FIND)?;
    let context = env_data.apply_context();
    let result = context.is_account(&recipient.into())?;

    if result { Ok(1) } else { Ok(0) }
}

/// Return Leap's packed `get_code_hash_result` structure. The struct is:
/// `varuint32 version, uint64 code_sequence, checksum256 code_hash,
/// uint8 vm_type, uint8 vm_version`.
pub fn get_code_hash(
    mut env: FunctionEnvMut<WasmContext>,
    account: u64,
    _struct_version: u32,
    packed_ptr: WasmPtr<u8>,
    packed_len: u32,
) -> Result<u32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    if !env_data
        .db()
        .protocol_feature_activated(GET_CODE_HASH_FEATURE_DIGEST)
    {
        return Err(RuntimeError::new(
            "get_code_hash is unavailable before the GET_CODE_HASH protocol feature is activated",
        ));
    }

    let (code_sequence, code_hash, vm_type, vm_version) = env_data
        .db()
        .account_code_info(account)
        .map_err(|error| RuntimeError::new(error.to_string()))?;
    let mut packed = Vec::with_capacity(43);
    packed.push(0); // struct_version, encoded as unsigned varuint32(0)
    packed.extend_from_slice(&code_sequence.to_le_bytes());
    packed.extend_from_slice(&code_hash);
    packed.push(vm_type);
    packed.push(vm_version);

    let copy_size = packed_len.min(packed.len() as u32);
    env_data.charge(
        &mut store,
        cost::DB_FIND + cost::per_byte(copy_size as u64),
    )?;
    if copy_size == 0 {
        return Ok(packed.len() as u32);
    }

    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);
    packed_ptr
        .slice(&view, copy_size)?
        .write_slice(&packed[..copy_size as usize])?;
    Ok(packed.len() as u32)
}
