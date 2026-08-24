//! Regression test against a real Antelope portable snapshot: the XPR testnet
//! `create_snapshot` output at head block 390401414 (2026-06-16, nodeos 5.0.3,
//! chain snapshot version 6, 176 MB).
//!
//! The fixture is too large to commit, so the test is `#[ignore]`d and takes
//! the file from `PULSEVM_SNAPSHOT_BIN`:
//!
//! ```sh
//! PULSEVM_SNAPSHOT_BIN=~/snapshots/xpr-testnet-snapshot-2026-06-16.bin \
//! cargo test -p pulsevm_snapshot -- --ignored --nocapture
//! ```
//!
//! Every row iterator verifies its section was consumed byte-exactly, so this
//! test pins the row schemas against ~2.6 million real rows, not synthetic
//! fixtures. The expected values below were cross-checked against the source
//! chain (chain id, head block, producer schedule) and are exact.

use pulsevm_crypto::Digest;
use pulsevm_name::Name;
use pulsevm_snapshot::{
    SnapshotPublicKey,
    SnapshotReader,
    section_names,
};

const XPR_TESTNET_CHAIN_ID: &str =
    "71ee83bcf52142d61019d95f9cc5427ba6a0d7ff8accd9e2088ae2abeaf3d3dd";
const HEAD_BLOCK_NUM: u32 = 390401414;
const HEAD_BLOCK_ID: &str = "17450d8654eff3bda4f4946f463bb2c6ca441679a4882bb4d1b5e96983186941";

fn load() -> Vec<u8> {
    let path = std::env::var("PULSEVM_SNAPSHOT_BIN")
        .expect("set PULSEVM_SNAPSHOT_BIN to the XPR testnet snapshot .bin");
    std::fs::read(&path).expect("read snapshot file")
}

fn name(s: &str) -> Name {
    s.parse().expect("valid name")
}

#[test]
#[ignore = "needs the 176MB XPR testnet snapshot fixture (PULSEVM_SNAPSHOT_BIN)"]
fn reads_the_xpr_testnet_snapshot() {
    let bytes = load();
    let snapshot = SnapshotReader::new(&bytes).expect("parse container");

    assert_eq!(snapshot.chain_version(), 6);

    // The full v6 section list, in file order.
    let names: Vec<&str> = snapshot
        .sections()
        .iter()
        .map(|s| s.name.as_str())
        .collect();
    assert_eq!(
        names,
        vec![
            section_names::CHAIN_SNAPSHOT_HEADER,
            section_names::BLOCK_STATE,
            section_names::ACCOUNT,
            section_names::ACCOUNT_METADATA,
            section_names::ACCOUNT_RAM_CORRECTION,
            section_names::GLOBAL_PROPERTY,
            section_names::PROTOCOL_STATE,
            section_names::DYNAMIC_GLOBAL_PROPERTY,
            section_names::BLOCK_SUMMARY,
            section_names::TRANSACTION,
            section_names::GENERATED_TRANSACTION,
            section_names::CODE,
            section_names::CONTRACT_TABLES,
            section_names::PERMISSION,
            section_names::PERMISSION_LINK,
            section_names::RESOURCE_LIMITS,
            section_names::RESOURCE_USAGE,
            section_names::RESOURCE_LIMITS_STATE,
            section_names::RESOURCE_LIMITS_CONFIG,
        ]
    );

    // Head block: this is what height continuity resumes from.
    let head = snapshot.block_header_state().expect("block_state");
    assert_eq!(head.block_num, HEAD_BLOCK_NUM);
    assert_eq!(
        head.block_num_from_id(),
        HEAD_BLOCK_NUM,
        "decode drifted before the block id"
    );
    assert_eq!(head.id.to_string(), HEAD_BLOCK_ID);
    assert_eq!(head.header.producer, name("testalvosec"));
    assert_eq!(head.active_schedule.version, 806);
    assert_eq!(head.active_schedule.producers.len(), 21);
    assert!(head.activated_protocol_features.is_some());

    // Chain identity and configuration.
    let gpo = snapshot.global_property().expect("global_property");
    assert_eq!(gpo.chain_id.to_string(), XPR_TESTNET_CHAIN_ID);
    assert_eq!(gpo.configuration.base.max_block_cpu_usage, 200000);
    assert_eq!(gpo.configuration.base.max_transaction_cpu_usage, 150000);

    let protocol = snapshot.protocol_state().expect("protocol_state");
    assert!(!protocol.activated_protocol_features.is_empty());

    // Accounts.
    let mut accounts = 0u64;
    let mut with_abi = 0u64;
    let mut saw_protonnz = false;
    for account in snapshot.accounts().expect("accounts") {
        let account = account.expect("account row");
        accounts += 1;
        if !account.abi.0.is_empty() {
            with_abi += 1;
        }
        if account.name == name("protonnz") {
            saw_protonnz = true;
        }
    }
    assert_eq!(accounts, 32333);
    assert_eq!(with_abi, 812);
    assert!(saw_protonnz, "protonnz account missing");

    // Account metadata: privileged set and code linkage.
    let mut privileged = Vec::new();
    let mut eosio_code_hash = Digest::default();
    let mut with_code = 0u64;
    for meta in snapshot.account_metadata().expect("account_metadata") {
        let meta = meta.expect("metadata row");
        if meta.is_privileged() {
            privileged.push(meta.name.to_string());
        }
        if meta.has_code() {
            with_code += 1;
        }
        if meta.name == name("eosio") {
            eosio_code_hash = meta.code_hash;
        }
    }
    assert_eq!(
        privileged,
        vec!["eosio", "eosio.msig", "eosio.wrap", "eosio.rex"]
    );
    assert_eq!(with_code, 792);
    assert_ne!(
        eosio_code_hash,
        Digest::default(),
        "eosio must have the system contract"
    );

    // Code objects: every row's wasm must hash to its declared code hash —
    // 599 independent sha256 proofs that the byte decode is exact.
    let mut code_rows = 0u64;
    let mut saw_eosio_code = false;
    for code in snapshot.code().expect("code") {
        let code = code.expect("code row");
        assert_eq!(
            Digest::hash(&code.code.0),
            code.code_hash,
            "wasm bytes corrupt"
        );
        assert!(code.code_ref_count > 0);
        code_rows += 1;
        if code.code_hash == eosio_code_hash {
            saw_eosio_code = true;
        }
    }
    assert_eq!(code_rows, 599);
    assert!(saw_eosio_code, "eosio's code hash has no code object");

    // Permissions, including the non-K1 key material a real chain carries.
    let mut permissions = 0u64;
    let mut k1 = 0u64;
    let mut r1 = 0u64;
    let mut webauthn = 0u64;
    let mut protonnz_perms = Vec::new();
    for permission in snapshot.permissions().expect("permissions") {
        let permission = permission.expect("permission row");
        permissions += 1;
        for kw in &permission.auth.keys {
            match &kw.key {
                SnapshotPublicKey::K1(_) => k1 += 1,
                SnapshotPublicKey::R1(_) => r1 += 1,
                SnapshotPublicKey::WebAuthn(wa) => {
                    webauthn += 1;
                    assert!(
                        !wa.rpid.is_empty(),
                        "WebAuthn key without a relying party id"
                    );
                }
            }
        }
        if permission.owner == name("protonnz") {
            protonnz_perms.push(permission);
        }
    }
    assert_eq!(permissions, 65420);
    assert_eq!((k1, r1, webauthn), (63755, 6, 998));
    let owner = protonnz_perms
        .iter()
        .find(|p| p.name == name("owner"))
        .expect("protonnz owner permission");
    assert_eq!(
        owner.parent,
        Name::default(),
        "owner permission has no parent"
    );
    assert!(owner.auth.threshold >= 1);
    assert!(!owner.auth.keys.is_empty() || !owner.auth.accounts.is_empty());
    let active = protonnz_perms
        .iter()
        .find(|p| p.name == name("active"))
        .expect("protonnz active permission");
    assert_eq!(active.parent, name("owner"));

    assert_eq!(snapshot.permission_links().expect("links").count(), 818);

    // Contract tables: full sweep of the interleaved section (~2.4M rows).
    let mut tables = 0u64;
    let mut kv_rows = 0u64;
    let mut idx = [0u64; 5];
    let mut protonnz_token_rows = 0usize;
    for table in snapshot.contract_tables().expect("contract_tables") {
        let table = table.expect("table");
        let declared: usize = table.key_values.len()
            + table.idx64.len()
            + table.idx128.len()
            + table.idx256.len()
            + table.idx_double.len()
            + table.idx_long_double.len();
        assert_eq!(
            table.table.count as usize, declared,
            "table_id count mismatch"
        );
        tables += 1;
        kv_rows += table.key_values.len() as u64;
        idx[0] += table.idx64.len() as u64;
        idx[1] += table.idx128.len() as u64;
        idx[2] += table.idx256.len() as u64;
        idx[3] += table.idx_double.len() as u64;
        idx[4] += table.idx_long_double.len() as u64;
        if table.table.code == name("eosio.token")
            && table.table.scope == name("protonnz")
            && table.table.table == name("accounts")
        {
            protonnz_token_rows = table.key_values.len();
        }
    }
    assert_eq!(tables, 74588);
    assert_eq!(kv_rows, 801374);
    assert_eq!(idx, [483579, 154605, 457480, 132, 0]);
    assert!(
        protonnz_token_rows >= 1,
        "protonnz must hold a token balance row"
    );

    // Resources.
    let mut limits = 0u64;
    let mut saw_protonnz_limits = false;
    for row in snapshot.resource_limits().expect("resource_limits") {
        let row = row.expect("limits row");
        limits += 1;
        if row.owner == name("protonnz") {
            saw_protonnz_limits = true;
            assert!(row.ram_bytes > 0);
        }
    }
    assert_eq!(limits, 32333);
    assert!(saw_protonnz_limits);

    let mut usage = 0u64;
    let mut saw_protonnz_usage = false;
    for row in snapshot.resource_usage().expect("resource_usage") {
        let row = row.expect("usage row");
        usage += 1;
        if row.owner == name("protonnz") {
            saw_protonnz_usage = true;
            assert!(row.ram_usage > 0, "protonnz uses RAM on the source chain");
        }
    }
    assert_eq!(usage, 32333);
    assert!(saw_protonnz_usage);

    let state = snapshot
        .resource_limits_state()
        .expect("resource_limits_state");
    assert_eq!(state.virtual_cpu_limit, 200000000);
    assert_eq!(state.virtual_net_limit, 1048576000);

    let config = snapshot
        .resource_limits_config()
        .expect("resource_limits_config");
    assert_eq!(config.cpu_limit_parameters.max, 200000);

    // The small fixed-shape sections.
    assert_eq!(
        snapshot.block_summaries().expect("summaries").count(),
        65536
    );
    assert_eq!(snapshot.transactions().expect("transactions").count(), 424);
    assert_eq!(
        snapshot
            .generated_transactions()
            .expect("generated")
            .count(),
        1
    );
    assert_eq!(
        snapshot
            .account_ram_corrections()
            .expect("ram corrections")
            .count(),
        0
    );
    assert!(snapshot.dynamic_global_property().is_ok());
}
