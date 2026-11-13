#[cfg(test)]
mod auth_tests {
    use std::{
        fs,
        path::Path,
        sync::Arc,
    };

    use anyhow::Result;
    use pulsevm_core::{
        authority::PermissionLevel,
        transaction::{
            Action,
            Transaction,
        },
        wat2wasm,
    };
    use pulsevm_name_macro::name;

    use crate::{
        tests::{
            DEFAULT_EXPIRATION_DELTA,
            Testing,
            get_private_key,
        },
        unittests::contracts::{
            ALIGNED_CONST_REF_WAST,
            ALIGNED_REF_WAST,
            ENTRY_WAST,
            ENTRY_WAST_2,
            MISALIGNED_CONST_REF_WAST,
            MISALIGNED_REF_WAST,
        },
    };

    #[tokio::test]
    async fn test_misaligned() -> Result<()> {
        let mut chain = Testing::new().await;
        chain.create_accounts(vec![name!("aligncheck").into()], false, true)?;

        let check_aligned = |chain: &mut Testing, wast: &str| -> Result<()> {
            chain.set_code(name!("aligncheck").into(), wat2wasm(wast)?.into())?;
            let mut trx = Transaction::default();
            chain.set_transaction_headers(&mut trx, DEFAULT_EXPIRATION_DELTA, 0);
            trx.actions.push(Action {
                account: name!("aligncheck").into(),
                name: name!("").into(),
                authorization: vec![PermissionLevel {
                    actor: name!("aligncheck").into(),
                    permission: name!("active").into(),
                }],
                data: Arc::from(vec![]),
            });
            let trx = trx.sign(
                &get_private_key(name!("aligncheck").into(), "active"),
                chain.controller.chain_id(),
            )?;
            chain.push_transaction(trx)?;
            Ok(())
        };

        check_aligned(&mut chain, ALIGNED_REF_WAST)?;
        check_aligned(&mut chain, MISALIGNED_REF_WAST)?;
        check_aligned(&mut chain, ALIGNED_CONST_REF_WAST)?;
        check_aligned(&mut chain, MISALIGNED_CONST_REF_WAST)?;

        Ok(())
    }

    /// A contract with no linear memory has nothing to pass pointers in, but it
    /// can still call an intrinsic that takes one (here with a null pointer and
    /// zero length). That must fail the transaction cleanly, never panic inside
    /// the host function, which would take the executing thread with it.
    #[tokio::test]
    async fn a_contract_without_memory_calling_an_intrinsic_fails_cleanly() -> Result<()> {
        const NO_MEMORY_WAST: &str = r#"(module
            (import "env" "db_store_i64"
              (func $store (param i64 i64 i64 i64 i32 i32) (result i32)))
            (func (export "apply") (param i64 i64 i64)
              (drop (call $store
                (local.get 0) (i64.const 1) (local.get 0) (i64.const 1)
                (i32.const 0) (i32.const 0)))))"#;

        let mut chain = Testing::new().await;
        chain.create_accounts(vec![name!("nomem").into()], false, true)?;
        chain.set_code(name!("nomem").into(), wat2wasm(NO_MEMORY_WAST)?.into())?;
        let mut trx = Transaction::default();
        chain.set_transaction_headers(&mut trx, DEFAULT_EXPIRATION_DELTA, 0);
        trx.actions.push(Action {
            account: name!("nomem").into(),
            name: name!("go").into(),
            authorization: vec![PermissionLevel {
                actor: name!("nomem").into(),
                permission: name!("active").into(),
            }],
            data: Arc::from(vec![]),
        });
        let trx = trx.sign(
            &get_private_key(name!("nomem").into(), "active"),
            chain.controller.chain_id(),
        )?;
        let result = chain.push_transaction(trx);
        assert!(
            result.is_err(),
            "a memory-less contract cannot store a row; the action must fail, not succeed"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_entry_behavior() -> Result<()> {
        // A start section runs during instantiation, before apply is called and
        // before the metering budget is seeded, so any host intrinsic it reaches
        // (here `current_time`) would run unbilled. set_code must reject such a
        // contract outright.
        let mut chain = Testing::new().await;
        chain.create_accounts(vec![name!("entrycheck").into()], false, true)?;
        let result = chain.set_code(name!("entrycheck").into(), wat2wasm(ENTRY_WAST)?.into());
        assert!(result.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn test_entry_behavior_2() -> Result<()> {
        // Same rule regardless of where the start section sits relative to the
        // function bodies: a declared start section is rejected.
        let mut chain = Testing::new().await;
        chain.create_accounts(vec![name!("entrycheck").into()], false, true)?;
        let result = chain.set_code(name!("entrycheck").into(), wat2wasm(ENTRY_WAST_2)?.into());
        assert!(result.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn test_endless_loop() -> Result<()> {
        let mut chain = Testing::new().await;
        chain.create_accounts(vec![name!("loop").into()], false, true)?;
        let wasm_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("reference_contracts")
            .join("endless_loop.wasm");
        let wasm = fs::read(wasm_path).expect("Failed to read endless loop wasm file");
        chain.set_code(name!("loop").into(), wasm.into())?;

        let mut trx = Transaction::default();
        chain.set_transaction_headers(&mut trx, DEFAULT_EXPIRATION_DELTA, 0);
        trx.actions.push(Action {
            account: name!("loop").into(),
            name: name!("el").into(),
            authorization: vec![PermissionLevel {
                actor: name!("loop").into(),
                permission: name!("active").into(),
            }],
            data: Arc::from(vec![]),
        });
        let trx = trx.sign(
            &get_private_key(name!("loop").into(), "active"),
            chain.controller.chain_id(),
        )?;
        assert!(chain.push_transaction(trx).is_err());

        Ok(())
    }
}
