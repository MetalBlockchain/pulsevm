use anyhow::bail;
use pulsevm_serialization::Deserialize;
use wasmtime::Caller;

use crate::chain::{Action, wasm_runtime::WasmContext};

pub fn send_inline() -> impl Fn(Caller<'_, WasmContext>, u32, u32) -> Result<(), wasmtime::Error> {
    |mut caller, ptr, length| {
        // TODO: Check max inline action size
        let memory = caller
            .get_export("memory")
            .and_then(|ext| ext.into_memory())
            .ok_or_else(|| anyhow::anyhow!("memory export not found"))?;

        let mut src_bytes = vec![0u8; length as usize];
        memory.read(&caller, ptr as usize, &mut src_bytes)?;

        let action = Action::deserialize(&src_bytes, &mut 0);
        if action.is_err() {
            bail!("failed to deserialize action: {:?}", action.err());
        }

        Ok(())
    }
}
