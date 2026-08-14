//! Cross-validate the pure-Rust `GenesisState::compute_chain_id` against the C++
//! `genesis_state::compute_chain_id` reached through the bridge. Both are the
//! sha256 of the fc-packed genesis, so they must agree byte-for-byte over any
//! genesis. This proves the Rust fc-pack (timestamp, key, the 19 config fields)
//! is laid out exactly like fc before the bridge is removed.
//!
//! Run with the C++ toolchain env and the arena-shadow feature:
//!   cargo test -p pulsevm_ffi --features arena-shadow \
//!     --test genesis_chain_id_cross_validation -- --nocapture

use pulsevm_chain_types::GenesisState;

fn cxx_chain_id(json: &str) -> Vec<u8> {
    let g = pulsevm_ffi::CxxGenesisState::new(json).expect("cxx parse genesis");
    g.compute_chain_id()
}

fn check(json: &str) {
    let rust = GenesisState::from_json(json).expect("rust parse genesis");
    let rust_id = rust.compute_chain_id();
    let cxx_id = cxx_chain_id(json);
    assert_eq!(
        rust_id.as_slice(),
        cxx_id.as_slice(),
        "chain id mismatch for genesis {json}\n rust={}\n cxx ={}",
        hex(&rust_id),
        hex(&cxx_id)
    );
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn genesis_json(ts: &str, key: &str, cfg_extra: &str) -> String {
    format!(
        r#"{{
            "initial_timestamp": "{ts}",
            "initial_key": "{key}",
            "initial_configuration": {{
                "max_block_net_usage": 1048576,
                "target_block_net_usage_pct": 1000,
                "max_transaction_net_usage": 524288,
                "base_per_transaction_net_usage": 12,
                "net_usage_leeway": 500,
                "context_free_discount_net_usage_num": 20,
                "context_free_discount_net_usage_den": 100,
                "max_block_cpu_usage": 3000000000,
                "target_block_cpu_usage_pct": 2500,
                "max_transaction_cpu_usage": 1000000000,
                "min_transaction_cpu_usage": 100000,
                "max_transaction_lifetime": 3600,
                {cfg_extra}
                "max_inline_action_size": 4096,
                "max_inline_action_depth": 6,
                "max_authority_depth": 6,
                "max_action_return_value_size": 256
            }}
        }}"#
    )
}

#[test]
fn rust_chain_id_matches_cxx() {
    let k1 = "PUB_K1_8fsJkG5ka4o1G1wBhySUavHuGqstcjtXMrquxiRWVcYw8ZvZLX";
    let k2 = "PUB_K1_5bbkxaLdB5bfVZW6DJY8M74vwT2m61PqwywNUa5azfkJTvYa5H";

    // The committed genesis.json shape (delay fields present).
    check(&genesis_json(
        "2023-01-01T00:00:00",
        k1,
        r#""deferred_trx_expiration_window": 600, "max_transaction_delay": 3888000,"#,
    ));
    // A different key and a fractional-second timestamp.
    check(&genesis_json(
        "2023-06-15T12:34:56.500",
        k2,
        r#""deferred_trx_expiration_window": 600, "max_transaction_delay": 3888000,"#,
    ));
    // Delay fields omitted (both default to 0 in fc and in the Rust parse).
    check(&genesis_json("2024-02-29T23:59:59", k1, ""));
    // Different timestamps to exercise the i64 micro packing.
    check(&genesis_json("1970-01-01T00:00:00", k2, ""));
    check(&genesis_json("2038-01-19T03:14:07", k1, ""));

    // Also validate the actual committed genesis.json if present.
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    if let Ok(bytes) = std::fs::read(repo_root.join("genesis.json")) {
        let json = String::from_utf8(bytes).unwrap();
        check(&json);
        let id = GenesisState::from_json(&json).unwrap().compute_chain_id();
        eprintln!("committed genesis.json chain id = {}", hex(&id));
    }

    eprintln!("genesis chain id: rust == cxx across all cases");
}
