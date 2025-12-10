use wasmer::{FunctionEnvMut, RuntimeError, WasmPtr};

use crate::chain::wasm_runtime::WasmContext;

pub fn pulse_assert(
    mut env: FunctionEnvMut<WasmContext>,
    condition: u32,
    msg_ptr: WasmPtr<u8>,
    msg_len: u32,
) -> Result<(), RuntimeError> {
    if condition != 1 {
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

pub fn current_time(env: FunctionEnvMut<WasmContext>) -> Result<u64, RuntimeError> {
    let result = env
        .data()
        .pending_block_timestamp()
        .to_time_point()
        .time_since_epoch()
        .count();

    Ok(result as u64)
}
