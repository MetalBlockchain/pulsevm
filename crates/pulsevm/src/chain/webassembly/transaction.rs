use pulsevm_serialization::Deserialize;
use wasmtime::Caller;

use crate::chain::{
    Action, Controller, error::ChainError, pulse_assert, wasm_runtime::WasmContext,
};

pub fn send_inline() -> impl Fn(Caller<'_, WasmContext>, u32, u32) -> Result<(), wasmtime::Error> {
    |mut caller, ptr, length| {
        {
            let context = caller.data_mut().apply_context_mut();
            let session = context.undo_session();
            let mut session = session.borrow_mut();
            let gpo = Controller::get_global_properties(&mut session)?;
            pulse_assert(
                length < gpo.configuration.max_inline_action_size,
                ChainError::WasmRuntimeError(format!("inline action too big")),
            )?;
        }

        let memory = caller
            .get_export("memory")
            .and_then(|ext| ext.into_memory())
            .ok_or_else(|| anyhow::anyhow!("memory export not found"))?;
        let mut src_bytes = vec![0u8; length as usize];
        memory.read(&caller, ptr as usize, &mut src_bytes)?;
        let action = Action::deserialize(&src_bytes, &mut 0)?;

        caller
            .data_mut()
            .apply_context_mut()
            .execute_inline(&action)?;

        Ok(())
    }
}
