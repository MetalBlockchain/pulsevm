use anyhow::bail;
use wasmtime::Caller;

use crate::chain::wasm_runtime::WasmContext;

pub fn pulse_assert() -> impl Fn(Caller<'_, WasmContext>, u32, u32) -> Result<(), wasmtime::Error> {
    |caller, condition, msg| {
        if condition != 0 {
            bail!("pulse assert failed: condition is not zero");
        }

        Ok(())
    }
}
