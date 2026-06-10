use wasmer::{FunctionEnvMut, RuntimeError, WasmPtr};

use crate::chain::wasm_runtime::WasmContext;

const MAX_ASSERT_MESSAGE: usize = 1024;

pub fn pulse_assert(
    mut env: FunctionEnvMut<WasmContext>,
    condition: u32,
    msg_ptr: WasmPtr<u8>,
    msg_len: u32,
) -> Result<(), RuntimeError> {
    if condition != 1 {
        if msg_len == 0 {
            return Err(RuntimeError::new(
                "pulse assertion is false with no message",
            ));
        }

        let (env_data, store) = env.data_and_store_mut();
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
    if condition == 0 {
        let (env_data, store) = env.data_and_store_mut();
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
        slice
            .subslice(0..sz as u64)
            .read_slice(&mut src_bytes)?;

        let msg = String::from_utf8_lossy(&src_bytes);
        return Err(RuntimeError::new(format!(
            "assertion failure with message: {}",
            msg
        )));
    }

    Ok(())
}

pub fn pulse_assert_code(
    _env: FunctionEnvMut<WasmContext>,
    condition: u32,
    error_code: u64,
) -> Result<(), RuntimeError> {
    if condition == 0 {
        return Err(RuntimeError::new(format!(
            "assertion failure with error code: {}",
            error_code
        )));
    }

    Ok(())
}

pub fn pulse_exit(
    _env: FunctionEnvMut<WasmContext>,
    code: u32,
) -> Result<(), RuntimeError> {
    return Err(RuntimeError::new(format!(
        "exit called with code: {}",
        code
    )));
}

pub fn abort(
    _env: FunctionEnvMut<WasmContext>,
) -> Result<(), RuntimeError> {
    return Err(RuntimeError::new("abort called"));
}

pub fn current_time(env: FunctionEnvMut<WasmContext>) -> Result<u64, RuntimeError> {
    let result = env
        .data()
        .pending_block_timestamp()
        .to_time_point()
        .time_since_epoch()
        .count();

    Ok(result as u64)
}
