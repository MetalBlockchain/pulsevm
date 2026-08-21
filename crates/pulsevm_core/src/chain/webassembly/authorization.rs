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
    0xbc, 0xd2, 0xa2, 0x63, 0x94, 0xb3, 0x66, 0x14, 0xfd, 0x48, 0x94, 0x24, 0x1d, 0x3c, 0x45,
    0x1a, 0xb0, 0xf6, 0xfd, 0x11, 0x09, 0x58, 0xc3, 0x42, 0x30, 0x73, 0x62, 0x1a, 0x70, 0x82,
    0x6e, 0x99,
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
