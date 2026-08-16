#[cfg(test)]
mod ram_tests {
    use std::collections::BTreeSet;

    use anyhow::Result;
    use pulsevm_core::{
        ACTIVE_NAME,
        authority::PermissionLevel,
        name::Name,
        resource_limits::ResourceLimitsManager,
        transaction::{
            Action,
            SignedTransaction,
            Transaction,
        },
        wat2wasm,
    };
    use pulsevm_name_macro::name;

    use crate::tests::{
        DEFAULT_EXPIRATION_DELTA,
        Testing,
        get_private_key,
    };

    // These tests guard two contract-table RAM-accounting bugs that had zero
    // coverage (the block-replay oracle never deletes a row):
    //   1. db_remove_i64 charged value + key_value_object overhead on delete instead of refunding
    //      it, and credited self.receiver instead of the row's stored payer.
    //   2. the db_idxN_remove paths refunded self.receiver instead of the secondary row's stored
    //      payer.
    //
    // A tiny contract stores / removes one primary (db_*_i64) or one secondary
    // (db_idx64_*) row, driven entirely by action data so a single wasm covers
    // every case. Action-data layout: payer(u64 LE) | id(u64 LE) | op(u8), with
    // op = 0 store row, 1 remove row, 2 store idx64, 3 remove idx64.
    //
    // The per-row payer tests measure against a baseline that first plants a
    // "keeper" row, so the contract table already exists and the measured
    // store/remove carries no one-time table_id_object overhead — isolating
    // exactly the per-row cost (value + key_value_object / index64_object) that a
    // store bills and a remove must refund. The table overhead itself (billed on
    // table creation, refunded when the last row leaves) is covered separately by
    // removing_last_row_refunds_table_overhead.
    static RAM_WAST: &str = r#"(module
 (import "env" "read_action_data" (func $read_action_data (param i32 i32) (result i32)))
 (import "env" "db_store_i64" (func $db_store_i64 (param i64 i64 i64 i64 i32 i32) (result i32)))
 (import "env" "db_find_i64" (func $db_find_i64 (param i64 i64 i64 i64) (result i32)))
 (import "env" "db_remove_i64" (func $db_remove_i64 (param i32)))
 (import "env" "db_idx64_store" (func $db_idx64_store (param i64 i64 i64 i64 i32) (result i32)))
 (import "env" "db_idx64_find_primary" (func $db_idx64_find_primary (param i64 i64 i64 i32 i64) (result i32)))
 (import "env" "db_idx64_remove" (func $db_idx64_remove (param i32)))
 (memory $0 1)
 (export "memory" (memory $0))
 (export "apply" (func $apply))
 (func $apply (param $receiver i64) (param $code i64) (param $action i64)
  (local $itr i32)
  (local $payer i64)
  (local $id i64)
  (drop (call $read_action_data (i32.const 0) (i32.const 24)))
  (local.set $payer (i64.load (i32.const 0)))
  (local.set $id (i64.load (i32.const 8)))
  (block $done
   (block $b3
    (block $b2
     (block $b1
      (block $b0
       (br_table $b0 $b1 $b2 $b3 $done (i32.load8_u (i32.const 16)))
      )
      ;; op 0: store one primary row (8-byte value) into table 1111.
      (i64.store (i32.const 24) (i64.const 81985529216486895))
      (drop (call $db_store_i64
        (local.get $receiver) (i64.const 1111) (local.get $payer)
        (local.get $id) (i32.const 24) (i32.const 8)))
      (br $done)
     )
     ;; op 1: find then remove the primary row.
     (local.set $itr (call $db_find_i64
       (local.get $receiver) (local.get $receiver) (i64.const 1111) (local.get $id)))
     (call $db_remove_i64 (local.get $itr))
     (br $done)
    )
    ;; op 2: store one idx64 secondary row into table 2222.
    (i64.store (i32.const 32) (i64.const 42))
    (drop (call $db_idx64_store
      (local.get $receiver) (i64.const 2222) (local.get $payer)
      (local.get $id) (i32.const 32)))
    (br $done)
   )
   ;; op 3: find-by-primary then remove the idx64 row.
   (i64.store (i32.const 32) (i64.const 0))
   (local.set $itr (call $db_idx64_find_primary
     (local.get $receiver) (local.get $receiver) (i64.const 2222) (i32.const 32) (local.get $id)))
   (call $db_idx64_remove (local.get $itr))
   (br $done)
  )
 )
)"#;

    const OP_STORE: u8 = 0;
    const OP_REMOVE: u8 = 1;
    const OP_IDX_STORE: u8 = 2;
    const OP_IDX_REMOVE: u8 = 3;

    fn action_data(payer: Name, id: u64, op: u8) -> Vec<u8> {
        let mut d = Vec::with_capacity(17);
        d.extend_from_slice(&payer.as_u64().to_le_bytes());
        d.extend_from_slice(&id.to_le_bytes());
        d.push(op);
        d
    }

    /// Push a single `op` action to `contract`, authorized by (and signed with the
    /// active keys of) every actor in `authorizers`. A distinct `payer` must be
    /// among the authorizers, otherwise the store's RAM charge to it is rejected
    /// ("cannot charge RAM to other accounts"). `payer`/`id` reach the wasm as
    /// action data.
    fn push_op(
        chain: &mut Testing,
        contract: Name,
        payer: Name,
        id: u64,
        op: u8,
        authorizers: &[Name],
    ) -> Result<()> {
        let mut trx = Transaction::default();
        chain.set_transaction_headers(&mut trx, DEFAULT_EXPIRATION_DELTA, 0);
        trx.actions.push(Action::new(
            contract,
            name!("act").into(),
            action_data(payer, id, op),
            authorizers
                .iter()
                .map(|a| PermissionLevel::new(a.as_u64(), ACTIVE_NAME.as_u64()))
                .collect(),
        ));
        let mut signed = SignedTransaction::new(trx, BTreeSet::new(), vec![]);
        for a in authorizers {
            signed = signed.sign(&get_private_key(*a, "active"), &chain.controller.chain_id())?;
        }
        chain.push_transaction(signed)?;
        Ok(())
    }

    fn ram(chain: &mut Testing, account: Name) -> i64 {
        let db = chain.controller.database();
        ResourceLimitsManager::get_account_ram_usage(&db, &account).unwrap()
    }

    /// Bug 1, refund magnitude: a primary store bills `value + key_value_object`
    /// RAM to the payer; the matching remove must refund exactly that, netting the
    /// payer back to where it started. The old code charged the payer a second
    /// time on remove, leaving `baseline + 2 * row_cost`.
    #[tokio::test]
    async fn store_remove_primary_nets_to_baseline() -> Result<()> {
        let mut chain = Testing::new().await;
        let c: Name = name!("ramtest").into();
        chain.create_accounts(vec![c], false, true)?;
        chain.set_code(c, wat2wasm(RAM_WAST)?.into())?;

        // Keeper row keeps table 1111 alive so the measured row carries no
        // one-time table overhead.
        push_op(&mut chain, c, c, 1, OP_STORE, &[c])?;
        let baseline = ram(&mut chain, c);

        push_op(&mut chain, c, c, 2, OP_STORE, &[c])?;
        let after_store = ram(&mut chain, c);
        let row_cost = after_store - baseline;
        assert!(row_cost > 0, "store must bill the payer for the row");

        push_op(&mut chain, c, c, 2, OP_REMOVE, &[c])?;
        let after_remove = ram(&mut chain, c);
        assert_eq!(
            after_remove,
            baseline,
            "remove must refund the row (got {after_remove}, baseline {baseline}, \
             the doubling bug would give {})",
            baseline + 2 * row_cost
        );
        Ok(())
    }

    /// Bug 1, refund target: a row whose stored payer differs from the contract
    /// receiver must, on remove, refund the *payer* — not the receiver. Here the
    /// contract `ramtest` stores rows paid for by `alice`; removing one credits
    /// alice back to baseline and never touches the receiver's usage. The old code
    /// refunded self.receiver, so alice would stay high and the receiver would
    /// drift.
    #[tokio::test]
    async fn primary_remove_refunds_stored_payer_not_receiver() -> Result<()> {
        let mut chain = Testing::new().await;
        let c: Name = name!("ramtest").into();
        let alice: Name = name!("alice").into();
        chain.create_accounts(vec![c, alice], false, true)?;
        chain.set_code(c, wat2wasm(RAM_WAST)?.into())?;

        // Keeper row (paid by alice) creates table 1111 up front.
        push_op(&mut chain, c, alice, 1, OP_STORE, &[c, alice])?;
        let base_alice = ram(&mut chain, alice);
        let base_recv = ram(&mut chain, c);

        push_op(&mut chain, c, alice, 2, OP_STORE, &[c, alice])?;
        let row_cost = ram(&mut chain, alice) - base_alice;
        assert!(row_cost > 0, "store must bill the row's payer (alice)");
        assert_eq!(
            ram(&mut chain, c),
            base_recv,
            "storing a row paid by alice must not bill the receiver"
        );

        push_op(&mut chain, c, alice, 2, OP_REMOVE, &[c])?;
        assert_eq!(
            ram(&mut chain, alice),
            base_alice,
            "remove must refund the stored payer (alice)"
        );
        assert_eq!(
            ram(&mut chain, c),
            base_recv,
            "remove must not credit the receiver's RAM"
        );
        Ok(())
    }

    /// Bug 2: db_idx64_remove must refund the secondary row's stored payer, not
    /// self.receiver. Same shape as the primary payer test, over db_idx64_*: alice
    /// pays for the index rows, removing one nets alice back to baseline and leaves
    /// the receiver untouched. This also confirms the idx refund magnitude
    /// (index64_object overhead) nets to zero.
    #[tokio::test]
    async fn idx64_remove_refunds_stored_payer_not_receiver() -> Result<()> {
        let mut chain = Testing::new().await;
        let c: Name = name!("ramtest").into();
        let alice: Name = name!("alice").into();
        chain.create_accounts(vec![c, alice], false, true)?;
        chain.set_code(c, wat2wasm(RAM_WAST)?.into())?;

        // Keeper index row (paid by alice) creates table 2222 up front.
        push_op(&mut chain, c, alice, 1, OP_IDX_STORE, &[c, alice])?;
        let base_alice = ram(&mut chain, alice);
        let base_recv = ram(&mut chain, c);

        push_op(&mut chain, c, alice, 2, OP_IDX_STORE, &[c, alice])?;
        let row_cost = ram(&mut chain, alice) - base_alice;
        assert!(row_cost > 0, "idx store must bill the row's payer (alice)");
        assert_eq!(
            ram(&mut chain, c),
            base_recv,
            "storing an index row paid by alice must not bill the receiver"
        );

        push_op(&mut chain, c, alice, 2, OP_IDX_REMOVE, &[c])?;
        assert_eq!(
            ram(&mut chain, alice),
            base_alice,
            "idx remove must refund the stored payer (alice)"
        );
        assert_eq!(
            ram(&mut chain, c),
            base_recv,
            "idx remove must not credit the receiver's RAM"
        );
        Ok(())
    }

    /// Table overhead: creating a table bills the table_id_object overhead, and
    /// removing the table's last row must refund it — what chainbase does in
    /// remove_table. Store the only row into a fresh table, then remove it: RAM
    /// returns fully to baseline, table overhead included. Before the fix the
    /// table overhead was stranded, leaving `baseline + table_id_object overhead`.
    #[tokio::test]
    async fn removing_last_row_refunds_table_overhead() -> Result<()> {
        let mut chain = Testing::new().await;
        let c: Name = name!("ramtest").into();
        chain.create_accounts(vec![c], false, true)?;
        chain.set_code(c, wat2wasm(RAM_WAST)?.into())?;

        let baseline = ram(&mut chain, c);

        // Store the sole row (id 7): creates table 1111, billing the row plus the
        // one-time table overhead.
        push_op(&mut chain, c, c, 7, OP_STORE, &[c])?;
        assert!(
            ram(&mut chain, c) > baseline,
            "store must bill the row and the new table's overhead"
        );

        // Remove it: this empties the table, so both the row and the table
        // overhead come back.
        push_op(&mut chain, c, c, 7, OP_REMOVE, &[c])?;
        assert_eq!(
            ram(&mut chain, c),
            baseline,
            "removing a table's last row must refund the table_id overhead too"
        );
        Ok(())
    }
}
