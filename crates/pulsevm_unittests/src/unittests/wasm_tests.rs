#[cfg(test)]
mod auth_tests {
    use std::sync::Arc;

    use anyhow::Result;
    use pulsevm_core::{authority::PermissionLevel, transaction::{Action, SignedTransaction, Transaction}, wat2wasm};
    use pulsevm_name_macro::name;

    use crate::{tests::{Testing, get_private_key}, unittests::contracts::{ALIGNED_CONST_REF_WAST, ALIGNED_REF_WAST, ENTRY_WAST, ENTRY_WAST_2, MISALIGNED_CONST_REF_WAST, MISALIGNED_REF_WAST}};

    #[test]
    fn test_misaligned() -> Result<()> {
        let mut chain = Testing::new();
        chain.create_accounts(vec![name!("aligncheck").into()], false, true)?;

        let check_aligned = |chain: &mut Testing, wast: &str| -> Result<()> {
            chain.set_code(name!("aligncheck").into(), wat2wasm(wast)?.into())?;
            let mut trx = Transaction::default();
            chain.set_transaction_headers(&mut trx, u32::MAX, 0);
            trx.actions.push(Action {
                account: name!("aligncheck").into(),
                name: name!("").into(),
                authorization: vec![PermissionLevel {
                    actor: name!("aligncheck").into(),
                    permission: name!("active").into(),
                }],
                data: Arc::from(vec![]),
            });
            let trx = trx.sign(&get_private_key(name!("aligncheck").into(), "active"), chain.controller.chain_id())?;
            chain.push_transaction(trx)?;
            Ok(())
        };

        check_aligned(&mut chain, ALIGNED_REF_WAST)?;
        check_aligned(&mut chain, MISALIGNED_REF_WAST)?;
        check_aligned(&mut chain, ALIGNED_CONST_REF_WAST)?;
        check_aligned(&mut chain, MISALIGNED_CONST_REF_WAST)?;
        
        Ok(())
    }

    #[test]
    fn test_entry_behavior() -> Result<()> {
        let mut chain = Testing::new();
        chain.create_accounts(vec![name!("entrycheck").into()], false, true)?;
        chain.set_code(name!("entrycheck").into(), wat2wasm(ENTRY_WAST)?.into())?;

        let mut trx = Transaction::default();
        chain.set_transaction_headers(&mut trx, u32::MAX, 0);
        trx.actions.push(Action {
            account: name!("entrycheck").into(),
            name: name!("").into(),
            authorization: vec![PermissionLevel {
                actor: name!("entrycheck").into(),
                permission: name!("active").into(),
            }],
            data: Arc::from(vec![]),
        });
        let trx = trx.sign(&get_private_key(name!("entrycheck").into(), "active"), chain.controller.chain_id())?;
        chain.push_transaction(trx)?;
        
        Ok(())
    }

    #[test]
    fn test_entry_behavior_2() -> Result<()> {
        let mut chain = Testing::new();
        chain.create_accounts(vec![name!("entrycheck").into()], false, true)?;
        chain.set_code(name!("entrycheck").into(), wat2wasm(ENTRY_WAST_2)?.into())?;

        let mut trx = Transaction::default();
        chain.set_transaction_headers(&mut trx, u32::MAX, 0);
        trx.actions.push(Action {
            account: name!("entrycheck").into(),
            name: name!("").into(),
            authorization: vec![PermissionLevel {
                actor: name!("entrycheck").into(),
                permission: name!("active").into(),
            }],
            data: Arc::from(vec![]),
        });
        let trx = trx.sign(&get_private_key(name!("entrycheck").into(), "active"), chain.controller.chain_id())?;
        chain.push_transaction(trx)?;
        
        Ok(())
    }
}
