use wasmtime::Caller;

use crate::chain::{Name, wasm_runtime::WasmContext};

pub fn db_find_i64()
-> impl Fn(Caller<'_, WasmContext>, u64, u64, u64, u64) -> Result<i32, wasmtime::Error> {
    |mut caller, code, scope, table, id| {
        let context = caller.data_mut().apply_context_mut();
        let result = context.db_find_i64(code.into(), scope.into(), table.into(), id.into())?;
        Ok(result)
    }
}

pub fn db_store_i64()
-> impl Fn(Caller<'_, WasmContext>, u64, u64, u64, u64, u32, u32) -> Result<i32, wasmtime::Error> {
    |mut caller, scope, table, payer, id, buffer, buffer_size| {
        let memory = caller
            .get_export("memory")
            .and_then(|ext| ext.into_memory())
            .ok_or_else(|| anyhow::anyhow!("memory export not found"))?;

        // Read source bytes safely
        let mut src_bytes = vec![0u8; buffer_size as usize];
        memory.read(&caller, buffer as usize, &mut src_bytes)?;

        let context = caller.data_mut().apply_context_mut();
        let result = context.db_store_i64(
            scope.into(),
            table.into(),
            payer.into(),
            id.into(),
            &src_bytes,
        )?;
        Ok(result)
    }
}

pub fn db_get_i64()
-> impl Fn(Caller<'_, WasmContext>, i32, u32, u32) -> Result<i32, wasmtime::Error> {
    |mut caller, itr, buffer, buffer_size| {
        let memory = caller
            .get_export("memory")
            .and_then(|ext| ext.into_memory())
            .ok_or_else(|| anyhow::anyhow!("memory export not found"))?;
        let mut dest_bytes = vec![0u8; buffer_size as usize];
        let context = caller.data_mut().apply_context_mut();
        let result = context.db_get_i64(itr, &mut dest_bytes, buffer_size as usize)?;
        memory.write(&mut caller, buffer as usize, &dest_bytes)?;
        Ok(result)
    }
}

pub fn db_update_i64()
-> impl Fn(Caller<'_, WasmContext>, i32, u64, u32, u32) -> Result<(), wasmtime::Error> {
    |mut caller, itr, payer, buffer, buffer_size| {
        let memory = caller
            .get_export("memory")
            .and_then(|ext| ext.into_memory())
            .ok_or_else(|| anyhow::anyhow!("memory export not found"))?;

        // Read source bytes safely
        let mut src_bytes = vec![0u8; buffer_size as usize];
        memory.read(&caller, buffer as usize, &mut src_bytes)?;

        let context = caller.data_mut().apply_context_mut();
        context.db_update_i64(itr, payer.into(), &src_bytes)?;

        Ok(())
    }
}

pub fn db_remove_i64() -> impl Fn(Caller<'_, WasmContext>, i32) -> Result<(), wasmtime::Error> {
    |mut caller, itr| {
        let context = caller.data_mut().apply_context_mut();
        context.db_remove_i64(itr)?;

        Ok(())
    }
}
