#[cfg(test)]
mod net_tests {
    use anyhow::Result;
    use pulsevm_core::{
        ACTIVE_NAME,
        ChainError,
        PULSE_NAME,
        authority::PermissionLevel,
        name::Name,
        resource_limits::ResourceLimitsManager,
        transaction::{
            Action,
            SignedTransaction,
            Transaction,
            TransactionTrace,
        },
    };
    use pulsevm_name_macro::name;
    use pulsevm_serialization::{
        VarUint32,
        Write,
    };

    use crate::tests::{
        DEFAULT_EXPIRATION_DELTA,
        Testing,
        get_private_key,
    };

    /// Pushes a `reqauth` from `from` with the given `max_net_usage_words`
    /// header value (0 = no transaction-specified limit).
    fn push_reqauth_with_net_words(
        chain: &mut Testing,
        from: Name,
        max_net_usage_words: u32,
    ) -> Result<TransactionTrace, ChainError> {
        let mut trx = Transaction::default();
        trx.actions.push(Action::new(
            PULSE_NAME.into(),
            name!("reqauth").into(),
            from.pack().unwrap(),
            vec![PermissionLevel::new(from.as_u64(), ACTIVE_NAME.as_u64())],
        ));
        chain.set_transaction_headers(&mut trx, DEFAULT_EXPIRATION_DELTA, 0);
        trx.header.max_net_usage_words = VarUint32(max_net_usage_words);

        let signed = SignedTransaction::new(trx, Vec::new(), vec![]).sign(
            &get_private_key(from, "active"),
            &chain.controller.chain_id(),
        )?;
        chain.push_transaction(signed)
    }

    fn assert_net_usage_too_high(result: Result<TransactionTrace, ChainError>) {
        match result {
            Ok(_) => panic!("expected net usage error, got success"),
            Err(ChainError::TransactionError(msg)) => assert!(
                msg.contains("transaction net usage is too high"),
                "unexpected error message: {msg}"
            ),
            Err(other) => panic!("expected net usage error, got: {other:?}"),
        }
    }

    fn assert_block_net_exceeded(result: Result<TransactionTrace, ChainError>) {
        match result {
            Ok(_) => panic!("expected block net limit error, got success"),
            Err(ChainError::TransactionError(msg)) => assert!(
                msg.contains("not enough space left in block"),
                "unexpected error message: {msg}"
            ),
            Err(other) => panic!("expected block net limit error, got: {other:?}"),
        }
    }

    /// Shrinks `net_limit_parameters.max` so that the block's remaining net
    /// capacity (`max - pending_net_usage`) becomes exactly `remaining`.
    fn set_block_net_remaining(chain: &mut Testing, remaining: u64) -> Result<(), ChainError> {
        let mut db = chain.get_pending_block_state().db;
        let cpu = db.get_cpu_limit_parameters()?;
        let mut net = db.get_net_limit_parameters()?;
        let pending = net.max - db.get_block_net_limit()?;
        net.max = pending + remaining;
        ResourceLimitsManager::set_block_parameters(&mut db, &cpu, &net)?;
        assert_eq!(db.get_block_net_limit()?, remaining);
        Ok(())
    }

    /// Billed net usage lands in the trace, matches the receipt's word count,
    /// is word-aligned, and is deterministic for same-sized transactions.
    #[tokio::test]
    async fn test_net_usage_billed_and_recorded() -> Result<()> {
        let mut chain = Testing::new().await;
        let alice: Name = name!("alice").into();
        chain.create_account(alice, PULSE_NAME.into(), false, true)?;

        let trace = push_reqauth_with_net_words(&mut chain, alice, 0)?;
        assert!(trace.net_usage > 0, "input transaction must bill net usage");
        assert_eq!(
            trace.net_usage % 8,
            0,
            "net usage must be rounded to word size"
        );
        assert_eq!(
            trace.receipt.net_usage_words.0 as u64 * 8,
            trace.net_usage,
            "receipt words must match billed bytes"
        );

        // A second reqauth packs to the same size (only expiration and
        // signature bytes differ, both fixed-width), so it bills identically.
        let trace2 = push_reqauth_with_net_words(&mut chain, alice, 0)?;
        assert_eq!(trace2.net_usage, trace.net_usage);
        Ok(())
    }

    /// A transaction-specified net limit far below the actual usage fails the
    /// eager check in `TransactionContext::init` before execution.
    #[tokio::test]
    async fn test_trx_net_limit_exceeded() -> Result<()> {
        let mut chain = Testing::new().await;
        let alice: Name = name!("alice").into();
        chain.create_account(alice, PULSE_NAME.into(), false, true)?;

        assert_net_usage_too_high(push_reqauth_with_net_words(&mut chain, alice, 1));
        Ok(())
    }

    /// The transaction-specified net limit is exact: a limit equal to the
    /// billed usage passes, one word less fails.
    #[tokio::test]
    async fn test_trx_net_limit_boundary() -> Result<()> {
        let mut chain = Testing::new().await;
        let alice: Name = name!("alice").into();
        chain.create_account(alice, PULSE_NAME.into(), false, true)?;

        // Measure the actual usage of an unrestricted reqauth.
        let usage = push_reqauth_with_net_words(&mut chain, alice, 0)?.net_usage;
        let usage_words = (usage / 8) as u32;
        assert!(usage_words >= 2, "usage too small to test the boundary");

        // Exactly enough words: accepted, and billed the same amount.
        let trace = push_reqauth_with_net_words(&mut chain, alice, usage_words)?;
        assert_eq!(trace.net_usage, usage);

        // One word short: rejected.
        assert_net_usage_too_high(push_reqauth_with_net_words(
            &mut chain,
            alice,
            usage_words - 1,
        ));
        Ok(())
    }

    /// Accounts without explicit resource limits are unlimited (-1) and can
    /// transact freely.
    #[tokio::test]
    async fn test_account_net_limit_unlimited_by_default() -> Result<()> {
        let mut chain = Testing::new().await;
        let alice: Name = name!("alice").into();
        chain.create_account(alice, PULSE_NAME.into(), false, true)?;

        let db = chain.get_pending_block_state().db;
        let (limit, greylisted) = ResourceLimitsManager::get_account_net_limit(&db, &alice, None)?;
        assert_eq!(limit, -1, "default account net limit must be unlimited");
        assert!(!greylisted);

        push_reqauth_with_net_words(&mut chain, alice, 0)?;
        Ok(())
    }

    /// An account whose net weight is a sliver of the total gets a tiny byte
    /// allowance. Its usage stays within `account_limit + net_usage_leeway`, so
    /// the eager check in `init` passes, and the transaction is rejected by the
    /// hard per-account check in `finalize` instead.
    #[tokio::test]
    async fn test_account_net_limit_enforced_at_finalize() -> Result<()> {
        let mut chain = Testing::new().await;
        let alice: Name = name!("alice").into();
        let bob: Name = name!("bob").into();
        chain.create_accounts(vec![alice, bob], false, true)?;

        // Measure what a reqauth actually bills while both accounts are still
        // unlimited.
        let usage = push_reqauth_with_net_words(&mut chain, bob, 0)?.net_usage as i64;

        // bob holds virtually all net weight, squeezing alice's share of the
        // block's capacity down to a few bytes even at full elastic expansion.
        let mut db = chain.get_pending_block_state().db;
        ResourceLimitsManager::set_account_limits(&mut db, &alice, 1, -1, -1)?;
        ResourceLimitsManager::set_account_limits(&mut db, &bob, 10_000_000_000, -1, -1)?;
        ResourceLimitsManager::process_account_limit_updates(&mut db)?;

        let (limit, greylisted) = ResourceLimitsManager::get_account_net_limit(&db, &alice, None)?;
        assert!(!greylisted);
        assert!(
            limit >= 0 && limit < usage,
            "alice's allowance ({limit}) must be below the tx usage ({usage})"
        );
        // Within leeway (500 in the test genesis) of the allowance, so the
        // eager check passes and rejection comes from finalize.
        assert!(
            usage <= limit + 500,
            "usage ({usage}) must be within leeway of the allowance ({limit})"
        );

        assert_net_usage_too_high(push_reqauth_with_net_words(&mut chain, alice, 0));

        // bob owns nearly all of the weight and is unaffected.
        push_reqauth_with_net_words(&mut chain, bob, 0)?;
        Ok(())
    }

    /// Every executed transaction's billed net usage is charged against the
    /// block: the remaining block net capacity drops by exactly that amount.
    #[tokio::test]
    async fn test_block_net_limit_decreases_with_usage() -> Result<()> {
        let mut chain = Testing::new().await;
        let alice: Name = name!("alice").into();
        chain.create_account(alice, PULSE_NAME.into(), false, true)?;

        let db = chain.get_pending_block_state().db;
        let before = db.get_block_net_limit()?;
        let trace = push_reqauth_with_net_words(&mut chain, alice, 0)?;
        assert_eq!(
            db.get_block_net_limit()?,
            before - trace.net_usage,
            "block net capacity must drop by the billed usage"
        );
        Ok(())
    }

    /// When the block's remaining net capacity is below the transaction's
    /// usage, the eager check in `init` rejects it with the block variant of
    /// the error (retryable in a later block), not the transaction variant.
    #[tokio::test]
    async fn test_block_net_limit_exceeded() -> Result<()> {
        let mut chain = Testing::new().await;
        let alice: Name = name!("alice").into();
        chain.create_account(alice, PULSE_NAME.into(), false, true)?;

        let usage = push_reqauth_with_net_words(&mut chain, alice, 0)?.net_usage;

        set_block_net_remaining(&mut chain, usage - 8)?;
        assert_block_net_exceeded(push_reqauth_with_net_words(&mut chain, alice, 0));
        Ok(())
    }

    /// Transactions fit while block space lasts and are rejected once it runs
    /// out, with the remaining capacity ticking down in between.
    #[tokio::test]
    async fn test_block_net_limit_fills_up() -> Result<()> {
        let mut chain = Testing::new().await;
        let alice: Name = name!("alice").into();
        chain.create_account(alice, PULSE_NAME.into(), false, true)?;

        let usage = push_reqauth_with_net_words(&mut chain, alice, 0)?.net_usage;

        // Room for exactly two more reqauths (plus one spare word).
        set_block_net_remaining(&mut chain, 2 * usage + 8)?;
        let db = chain.get_pending_block_state().db;

        push_reqauth_with_net_words(&mut chain, alice, 0)?;
        assert_eq!(db.get_block_net_limit()?, usage + 8);
        push_reqauth_with_net_words(&mut chain, alice, 0)?;
        assert_eq!(db.get_block_net_limit()?, 8);

        // The block is effectively full: one word left, a reqauth needs more.
        assert_block_net_exceeded(push_reqauth_with_net_words(&mut chain, alice, 0));

        // Nothing was billed for the rejected transaction.
        assert_eq!(db.get_block_net_limit()?, 8);
        Ok(())
    }
}
