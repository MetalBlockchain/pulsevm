use wasmer::{
    FunctionEnvMut,
    RuntimeError,
    WasmPtr,
};

use super::cost;
use crate::chain::{
    wasm_runtime::{
        WasmContext,
        WasmExit,
    },
    webassembly::context_aware_check,
};

const MAX_ASSERT_MESSAGE: usize = 1024;

const GET_SENDER_FEATURE_DIGEST: [u8; 32] = [
    0xf0, 0xaf, 0x56, 0xd2, 0xc5, 0xa4, 0x8d, 0x60, 0xa4, 0xa5, 0xb5, 0xc9, 0x03, 0xed, 0xfb,
    0x7d, 0xb3, 0xa7, 0x36, 0xa9, 0x4e, 0xd5, 0x89, 0xd0, 0xb7, 0x97, 0xdf, 0x33, 0xff, 0x9d,
    0x3e, 0x1d,
];
const GET_BLOCK_NUM_FEATURE_DIGEST: [u8; 32] = [
    0x35, 0xc2, 0x18, 0x6c, 0xc3, 0x6f, 0x7b, 0xb4, 0xae, 0xaf, 0x44, 0x87, 0xb3, 0x6e, 0x57,
    0x0, 0x39, 0xcc, 0xf4, 0x5a, 0x91, 0x3, 0x6a, 0x85, 0x6a, 0x5d, 0x56, 0x9e, 0xca, 0xa5,
    0x5e, 0xf2,
];

pub fn eosio_assert(
    mut env: FunctionEnvMut<WasmContext>,
    condition: u32,
    msg_ptr: WasmPtr<u8>,
) -> Result<(), RuntimeError> {
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::SYSTEM)?;
    if condition == 0 {
        if msg_ptr.is_null() {
            return Err(RuntimeError::new(
                "pulse assertion is false with no message",
            ));
        }

        let memory = env_data
            .memory()
            .as_ref()
            .expect("Wasm memory not initialized");
        let view = memory.view(&store);

        // Clamp the read window to what memory can actually provide, so a short
        // message near the end of memory doesn't trap as an out-of-bounds slice.
        let mem_len = view.data_size(); // u64, total linear-memory bytes
        let start = msg_ptr.offset() as u64;
        if start >= mem_len {
            return Err(RuntimeError::new("eosio assert failed"));
        }
        let max = MAX_ASSERT_MESSAGE.min((mem_len - start) as usize);

        let mut buf = vec![0u8; max];
        view.read(start, &mut buf)?;

        // EOSIO treats msg as a NUL-terminated C string: stop at the first NUL.
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        let msg = String::from_utf8_lossy(&buf[..end]);

        return Err(RuntimeError::new(format!("eosio assert failed: {}", msg)));
    }

    Ok(())
}

pub fn pulse_assert(
    mut env: FunctionEnvMut<WasmContext>,
    condition: u32,
    msg_ptr: WasmPtr<u8>,
    msg_len: u32,
) -> Result<(), RuntimeError> {
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::SYSTEM)?;
    if condition == 0 {
        if msg_len == 0 {
            return Err(RuntimeError::new(
                "pulse assertion is false with no message",
            ));
        }

        let memory = env_data
            .memory()
            .as_ref()
            .expect("Wasm memory not initialized");
        let view = memory.view(&store);
        let slice = msg_ptr.slice(&view, msg_len)?;
        let mut src_bytes = vec![0u8; msg_len as usize];
        slice.read_slice(&mut src_bytes)?;
        let c_str = String::from_utf8(src_bytes);

        match c_str {
            Ok(msg_str) => {
                return Err(RuntimeError::new(format!(
                    "pulse assert failed: {}",
                    msg_str
                )));
            }
            Err(_) => {
                return Err(RuntimeError::new("pulse assert failed"));
            }
        }
    }

    Ok(())
}

pub fn pulse_assert_message(
    mut env: FunctionEnvMut<WasmContext>,
    condition: u32,
    msg_ptr: WasmPtr<u8>,
    msg_len: u32,
) -> Result<(), RuntimeError> {
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::SYSTEM + cost::per_byte(msg_len as u64))?;
    if condition == 0 {
        let memory = env_data
            .memory()
            .as_ref()
            .ok_or_else(|| RuntimeError::new("Wasm memory not initialized"))?;
        let view = memory.view(&store);

        // The legacy_span is bounds-checked for the FULL msg_len before
        // truncation — an oversized len must trap as OOB, not silently clamp.
        let slice = msg_ptr.slice(&view, msg_len)?;

        // Truncation to max_assert_message happens after validation
        let sz = (msg_len as usize).min(MAX_ASSERT_MESSAGE);
        let mut src_bytes = vec![0u8; sz];
        slice.subslice(0..sz as u64).read_slice(&mut src_bytes)?;

        let msg = String::from_utf8_lossy(&src_bytes);
        return Err(RuntimeError::new(format!(
            "assertion failure with message: {}",
            msg
        )));
    }

    Ok(())
}

pub fn pulse_assert_code(
    mut env: FunctionEnvMut<WasmContext>,
    condition: u32,
    error_code: u64,
) -> Result<(), RuntimeError> {
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::SYSTEM)?;
    if condition == 0 {
        return Err(RuntimeError::new(format!(
            "assertion failure with error code: {}",
            error_code
        )));
    }

    Ok(())
}

pub fn pulse_exit(mut env: FunctionEnvMut<WasmContext>, code: i32) -> Result<(), RuntimeError> {
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::SYSTEM)?;
    // Not a failure: eosio_exit/pulse_exit ends the current action successfully.
    // WasmExit rides back as a trap that `run` recognizes and turns into Ok, so
    // the state this action already produced is kept.
    Err(RuntimeError::user(Box::new(WasmExit { code })))
}

pub fn abort(mut env: FunctionEnvMut<WasmContext>) -> Result<(), RuntimeError> {
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::SYSTEM)?;
    return Err(RuntimeError::new("abort called"));
}

pub fn current_time(mut env: FunctionEnvMut<WasmContext>) -> Result<u64, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::BASE)?;
    let result = env_data
        .pending_block_timestamp()
        .to_time_point()
        .time_since_epoch()
        .count();

    Ok(result as u64)
}

pub fn get_sender(mut env: FunctionEnvMut<WasmContext>) -> Result<u64, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::BASE)?;
    if !env_data
        .db()
        .protocol_feature_activated(GET_SENDER_FEATURE_DIGEST)
    {
        return Err(RuntimeError::new(
            "get_sender is unavailable before the GET_SENDER protocol feature is activated",
        ));
    }

    env_data
        .apply_context()
        .get_sender()
        .map_err(|error| RuntimeError::new(error.to_string()))
}

pub fn get_block_num(mut env: FunctionEnvMut<WasmContext>) -> Result<u32, RuntimeError> {
    context_aware_check(&env)?;
    let (env_data, mut store) = env.data_and_store_mut();
    env_data.charge(&mut store, cost::BASE)?;
    if !env_data
        .db()
        .protocol_feature_activated(GET_BLOCK_NUM_FEATURE_DIGEST)
    {
        return Err(RuntimeError::new(
            "get_block_num is unavailable before the GET_BLOCK_NUM protocol feature is activated",
        ));
    }

    Ok(env_data.apply_context().get_block_num())
}
