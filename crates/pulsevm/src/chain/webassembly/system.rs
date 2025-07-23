use anyhow::bail;
use wasmtime::Caller;

use crate::chain::wasm_runtime::WasmContext;

pub fn pulse_assert() -> impl Fn(Caller<'_, WasmContext>, u32, u32, u32) -> Result<(), wasmtime::Error> {
    |mut caller, condition, msg, msg_len| {
        if condition != 1 {
            let memory = caller
                .get_export("memory")
                .and_then(|ext| ext.into_memory())
                .ok_or_else(|| anyhow::anyhow!("memory export not found"))?;

            let mut src_bytes = vec![0u8; msg_len as usize];
            memory.read(&caller, msg as usize, &mut src_bytes)?;
            let c_str = String::from_utf8(src_bytes);

            if c_str.is_ok() {
                let msg_str = c_str.unwrap();
                bail!("pulse assert failed: {}", msg_str);
            } else {
                bail!("pulse assert failed: condition is not zero");
            }
        }

        Ok(())
    }
}