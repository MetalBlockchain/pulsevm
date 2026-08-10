use pulsevm_name::Name;
use wasmer::{
    FunctionEnvMut,
    RuntimeError,
    WasmPtr,
};

use super::cost;
use crate::{
    chain::webassembly::context_aware_check,
    wasm_runtime::WasmContext,
};

/// Pack producer account names the way EOSIO's `get_active_producers` expects
/// them: a raw, contiguous array of little-endian `u64` name values with **no**
/// length prefix. The count is implied by `bytes.len() / 8`. This deliberately
/// does not use the serialization `Write`/`pack` path, which would prepend a
/// `VarUint32` length and shift every offset.
fn pack_active_producer_names(names: &[Name]) -> Vec<u8> {
    let mut out = Vec::with_capacity(names.len() * 8);
    for name in names {
        out.extend_from_slice(&name.as_u64().to_le_bytes());
    }
    out
}

pub fn get_active_producers(
    mut env: FunctionEnvMut<WasmContext>,
    data_ptr: WasmPtr<u8>,
    data_len: u32,
) -> Result<i32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();

    let producers = env_data
        .apply_context()
        .active_producers()
        .map_err(|e| RuntimeError::new(format!("failed to read active producers: {e}")))?;
    let names: Vec<Name> = producers.iter().map(|p| p.producer_name).collect();
    let packed = pack_active_producer_names(&names);
    let total = packed.len() as u32;
    let copy_size = data_len.min(total);

    // Charge for the bytes actually written (a zero-length buffer is a pure size
    // query), consistent with read_action_data.
    env_data.charge(
        &mut store,
        cost::PRODUCER + cost::per_byte(copy_size as u64),
    )?;

    // EOSIO buffer protocol: a zero-length buffer asks for the required size.
    if data_len == 0 {
        return Ok(total as i32);
    }
    if copy_size == 0 {
        return Ok(0);
    }

    let memory = env_data
        .memory()
        .as_ref()
        .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
    let view = memory.view(&store);
    let slice = data_ptr.slice(&view, copy_size).map_err(|e| {
        RuntimeError::new(format!("get_active_producers: invalid buffer range: {e}"))
    })?;
    slice
        .write_slice(&packed[..copy_size as usize])
        .map_err(|e| RuntimeError::new(format!("failed to write active producers: {e}")))?;
    Ok(copy_size as i32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn packs_names_as_raw_little_endian_u64_no_prefix() {
        let names = vec![
            Name::from_str("pulse").unwrap(),
            Name::from_str("alice").unwrap(),
            Name::from_str("bob").unwrap(),
        ];
        let packed = pack_active_producer_names(&names);
        // Exactly 8 bytes per name, no length prefix.
        assert_eq!(packed.len(), names.len() * 8);
        // Each 8-byte little-endian chunk decodes back to the name.
        for (i, name) in names.iter().enumerate() {
            let chunk: [u8; 8] = packed[i * 8..i * 8 + 8].try_into().unwrap();
            assert_eq!(u64::from_le_bytes(chunk), name.as_u64());
        }
    }

    #[test]
    fn empty_schedule_packs_to_nothing() {
        assert!(pack_active_producer_names(&[]).is_empty());
    }
}
