#[cfg(test)]
mod auth_tests {
    use anyhow::Result;
    use pulsevm_core::{ACTIVE_NAME, authority::PermissionLevel, error::ChainError};
    use pulsevm_proc_macros::name;

    use crate::tests::Testing;

    #[test]
    fn test_missing_sigs() -> Result<()> {
        let mut chain = Testing::new();
        chain.create_accounts(vec![name!("alice").into()], false, true)?;
        assert_eq!(
            chain
                .push_reqauth2(
                    name!("alice").into(),
                    vec![PermissionLevel::new(name!("alice").into(), ACTIVE_NAME)],
                    vec![],
                )
                .err(),
            Some(ChainError::AuthorizationError(
                "transaction declares authority 'alice@active' but does not have signatures for it"
                    .into()
            ))
        );
        chain.push_reqauth(name!("alice").into(), "owner", false)?;
        Ok(())
    }
}
