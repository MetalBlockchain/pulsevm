//! Contracts the stress fixture deploys next to the reference token.
//!
//! They are written in WAT and assembled at runtime so the fixture needs no CDT
//! toolchain (the same approach `main.rs` takes for its `setprods` forwarder).
//! Each one is deliberately small but exercises a different part of the
//! execution path than a plain token transfer:
//!
//! * `oracle`: keyed upserts, a commutative last-writer-wins rule, a single hot counter row every
//!   call touches, and a table scan loop (`aggregate`).
//! * `amm`: a constant-product pool whose state is order-dependent, with assertion failures
//!   (slippage, balance) on purpose.
//! * `router`: builds an inline `transfer` on the token contract, so the load includes
//!   cross-contract inline dispatch.
//!
//! Every action carries a trailing nonce the contract ignores. Antelope-style
//! transaction ids hash only the transaction body, so without it two identical
//! calls in the same expiration second would collide as duplicates.

use std::str::FromStr;

use anyhow::{
    Context,
    Result,
};
use pulsevm_core::name::Name;

pub const ORACLE: &str = "oracle";
pub const AMM: &str = "amm";
pub const ROUTER: &str = "router";

fn n(name: &str) -> Result<i64> {
    Ok(Name::from_str(name)
        .map_err(|e| anyhow::anyhow!("encoding name {name}: {e}"))?
        .as_u64() as i64)
}

const PRELUDE: &str = r#"
  (import "env" "action_data_size" (func $ads (result i32)))
  (import "env" "read_action_data" (func $read (param i32 i32) (result i32)))
  (import "env" "require_auth" (func $auth (param i64)))
  (import "env" "eosio_assert" (func $assert (param i32 i32)))
  (import "env" "db_store_i64" (func $store (param i64 i64 i64 i64 i32 i32) (result i32)))
  (import "env" "db_find_i64" (func $find (param i64 i64 i64 i64) (result i32)))
  (import "env" "db_get_i64" (func $get (param i32 i32 i32) (result i32)))
  (import "env" "db_update_i64" (func $upd (param i32 i64 i32 i32)))
  (import "env" "db_lowerbound_i64" (func $lb (param i64 i64 i64 i64) (result i32)))
  (import "env" "db_next_i64" (func $next (param i32 i32) (result i32)))
  (memory 1)
  (export "memory" (memory 0))
  (data (i32.const 1024) "bad action data\00")
  (data (i32.const 1056) "unknown action\00")
  (data (i32.const 1088) "no feeds\00")
  (data (i32.const 1120) "pool already initialised\00")
  (data (i32.const 1152) "no pool\00")
  (data (i32.const 1184) "no balance row\00")
  (data (i32.const 1216) "amount too large\00")
  (data (i32.const 1248) "insufficient balance\00")
  (data (i32.const 1280) "zero output\00")
  (data (i32.const 1312) "slippage exceeded\00")
"#;

/// Price oracle.
///
/// `setprice(feeder, pair, price, seq, nonce)` upserts `feeds[pair][feeder]`
/// only when `seq` is newer than the stored one. Concurrent submissions are
/// accepted in whatever order they reach a block, yet the end state is the same
/// (highest `seq` wins), which is what lets the harness predict it exactly.
/// Every call, accepted or stale, also bumps `stats[0].updates`: one row that
/// every transaction writes.
///
/// `aggregate(caller, pair, nonce)` scans every feeder row for `pair` and
/// stores `agg[pair] = {sum, count, avg}`.
pub fn oracle_wasm() -> Result<Vec<u8>> {
    let setprice = n("setprice")?;
    let aggregate = n("aggregate")?;
    let feeds = n("feeds")?;
    let stats = n("stats")?;
    let agg = n("agg")?;
    let wat = format!(
        r#"(module {PRELUDE}
  (func (export "apply") (param $recv i64) (param $code i64) (param $act i64)
    (local $itr i32) (local $feeder i64) (local $pair i64) (local $price i64) (local $seq i64)
    (local $sum i64) (local $cnt i64)
    (if (i64.ne (local.get $recv) (local.get $code)) (then (return)))
    (call $assert (i32.le_u (call $ads) (i32.const 128)) (i32.const 1024))
    (drop (call $read (i32.const 0) (call $ads)))

    (if (i64.eq (local.get $act) (i64.const {setprice}))
      (then
        (call $assert (i32.ge_u (call $ads) (i32.const 32)) (i32.const 1024))
        (local.set $feeder (i64.load (i32.const 0)))
        (local.set $pair (i64.load (i32.const 8)))
        (local.set $price (i64.load (i32.const 16)))
        (local.set $seq (i64.load (i32.const 24)))
        (call $auth (local.get $feeder))
        (local.set $itr (call $find (local.get $recv) (local.get $pair) (i64.const {feeds}) (local.get $feeder)))
        (if (i32.lt_s (local.get $itr) (i32.const 0))
          (then
            (i64.store (i32.const 64) (local.get $price))
            (i64.store (i32.const 72) (local.get $seq))
            (drop (call $store (local.get $pair) (i64.const {feeds}) (local.get $feeder) (local.get $feeder) (i32.const 64) (i32.const 16))))
          (else
            (drop (call $get (local.get $itr) (i32.const 64) (i32.const 16)))
            (if (i64.gt_u (local.get $seq) (i64.load (i32.const 72)))
              (then
                (i64.store (i32.const 64) (local.get $price))
                (i64.store (i32.const 72) (local.get $seq))
                (call $upd (local.get $itr) (i64.const 0) (i32.const 64) (i32.const 16))))))
        (local.set $itr (call $find (local.get $recv) (local.get $recv) (i64.const {stats}) (i64.const 0)))
        (if (i32.lt_s (local.get $itr) (i32.const 0))
          (then
            (i64.store (i32.const 96) (i64.const 1))
            (drop (call $store (local.get $recv) (i64.const {stats}) (local.get $recv) (i64.const 0) (i32.const 96) (i32.const 8))))
          (else
            (drop (call $get (local.get $itr) (i32.const 96) (i32.const 8)))
            (i64.store (i32.const 96) (i64.add (i64.load (i32.const 96)) (i64.const 1)))
            (call $upd (local.get $itr) (i64.const 0) (i32.const 96) (i32.const 8))))
        (return)))

    (if (i64.eq (local.get $act) (i64.const {aggregate}))
      (then
        (call $assert (i32.ge_u (call $ads) (i32.const 16)) (i32.const 1024))
        (call $auth (i64.load (i32.const 0)))
        (local.set $pair (i64.load (i32.const 8)))
        (local.set $itr (call $lb (local.get $recv) (local.get $pair) (i64.const {feeds}) (i64.const 0)))
        (block $done
          (loop $scan
            (br_if $done (i32.lt_s (local.get $itr) (i32.const 0)))
            (drop (call $get (local.get $itr) (i32.const 64) (i32.const 16)))
            (local.set $sum (i64.add (local.get $sum) (i64.load (i32.const 64))))
            (local.set $cnt (i64.add (local.get $cnt) (i64.const 1)))
            (local.set $itr (call $next (local.get $itr) (i32.const 80)))
            (br $scan)))
        (call $assert (i64.ne (local.get $cnt) (i64.const 0)) (i32.const 1088))
        (i64.store (i32.const 96) (local.get $sum))
        (i64.store (i32.const 104) (local.get $cnt))
        (i64.store (i32.const 112) (i64.div_u (local.get $sum) (local.get $cnt)))
        (local.set $itr (call $find (local.get $recv) (local.get $pair) (i64.const {agg}) (i64.const 0)))
        (if (i32.lt_s (local.get $itr) (i32.const 0))
          (then (drop (call $store (local.get $pair) (i64.const {agg}) (i64.load (i32.const 0)) (i64.const 0) (i32.const 96) (i32.const 24))))
          (else (call $upd (local.get $itr) (i64.const 0) (i32.const 96) (i32.const 24))))
        (return)))

    (call $assert (i32.const 0) (i32.const 1056))))"#
    );
    wat::parse_str(&wat).context("assembling oracle contract")
}

/// Constant-product pool with an internal ledger.
///
/// `init(a, b)` seeds reserves (contract account only). `faucet(trader, a, b,
/// nonce)` credits play-money balances. `swap(trader, dir, amount_in, min_out,
/// nonce)` trades `a -> b` when `dir == 0`, else `b -> a`, with
/// `out = floor(y * in / (x + in))`. Reserves and amounts are bounded below 2^32
/// so the product cannot overflow a u64.
///
/// The pool row is written by every swap, and final reserves depend on swap
/// order, so the harness checks invariants (value conservation, `k` never
/// shrinking, the swap count) rather than an exact value.
pub fn amm_wasm() -> Result<Vec<u8>> {
    let init = n("init")?;
    let faucet = n("faucet")?;
    let swap = n("swap")?;
    let pool = n("pool")?;
    let bal = n("bal")?;
    let wat = format!(
        r#"(module {PRELUDE}
  (func (export "apply") (param $recv i64) (param $code i64) (param $act i64)
    (local $pit i32) (local $bit i32) (local $trader i64) (local $dir i64)
    (local $in i64) (local $min i64) (local $out i64)
    (local $x i64) (local $y i64) (local $ba i64) (local $bb i64)
    (if (i64.ne (local.get $recv) (local.get $code)) (then (return)))
    (call $assert (i32.le_u (call $ads) (i32.const 128)) (i32.const 1024))
    (drop (call $read (i32.const 0) (call $ads)))

    (if (i64.eq (local.get $act) (i64.const {init}))
      (then
        (call $assert (i32.ge_u (call $ads) (i32.const 16)) (i32.const 1024))
        (call $auth (local.get $recv))
        (call $assert
          (i32.lt_s (call $find (local.get $recv) (local.get $recv) (i64.const {pool}) (i64.const 0)) (i32.const 0))
          (i32.const 1120))
        (i64.store (i32.const 128) (i64.load (i32.const 0)))
        (i64.store (i32.const 136) (i64.load (i32.const 8)))
        (i64.store (i32.const 144) (i64.const 0))
        (drop (call $store (local.get $recv) (i64.const {pool}) (local.get $recv) (i64.const 0) (i32.const 128) (i32.const 24)))
        (return)))

    (if (i64.eq (local.get $act) (i64.const {faucet}))
      (then
        (call $assert (i32.ge_u (call $ads) (i32.const 32)) (i32.const 1024))
        (local.set $trader (i64.load (i32.const 0)))
        (call $auth (local.get $trader))
        (local.set $bit (call $find (local.get $recv) (local.get $recv) (i64.const {bal}) (local.get $trader)))
        (if (i32.lt_s (local.get $bit) (i32.const 0))
          (then
            (i64.store (i32.const 160) (i64.load (i32.const 8)))
            (i64.store (i32.const 168) (i64.load (i32.const 16)))
            (drop (call $store (local.get $recv) (i64.const {bal}) (local.get $trader) (local.get $trader) (i32.const 160) (i32.const 16))))
          (else
            (drop (call $get (local.get $bit) (i32.const 160) (i32.const 16)))
            (i64.store (i32.const 160) (i64.add (i64.load (i32.const 160)) (i64.load (i32.const 8))))
            (i64.store (i32.const 168) (i64.add (i64.load (i32.const 168)) (i64.load (i32.const 16))))
            (call $upd (local.get $bit) (i64.const 0) (i32.const 160) (i32.const 16))))
        (return)))

    (if (i64.eq (local.get $act) (i64.const {swap}))
      (then
        (call $assert (i32.ge_u (call $ads) (i32.const 40)) (i32.const 1024))
        (local.set $trader (i64.load (i32.const 0)))
        (local.set $dir (i64.load (i32.const 8)))
        (local.set $in (i64.load (i32.const 16)))
        (local.set $min (i64.load (i32.const 24)))
        (call $auth (local.get $trader))
        (call $assert (i64.lt_u (local.get $in) (i64.const 4294967296)) (i32.const 1216))
        (local.set $pit (call $find (local.get $recv) (local.get $recv) (i64.const {pool}) (i64.const 0)))
        (call $assert (i32.ge_s (local.get $pit) (i32.const 0)) (i32.const 1152))
        (drop (call $get (local.get $pit) (i32.const 128) (i32.const 24)))
        (local.set $bit (call $find (local.get $recv) (local.get $recv) (i64.const {bal}) (local.get $trader)))
        (call $assert (i32.ge_s (local.get $bit) (i32.const 0)) (i32.const 1184))
        (drop (call $get (local.get $bit) (i32.const 160) (i32.const 16)))
        (if (i64.eqz (local.get $dir))
          (then
            (local.set $x (i64.load (i32.const 128))) (local.set $y (i64.load (i32.const 136)))
            (local.set $ba (i64.load (i32.const 160))) (local.set $bb (i64.load (i32.const 168))))
          (else
            (local.set $x (i64.load (i32.const 136))) (local.set $y (i64.load (i32.const 128)))
            (local.set $ba (i64.load (i32.const 168))) (local.set $bb (i64.load (i32.const 160)))))
        (call $assert
          (i32.and (i64.lt_u (local.get $x) (i64.const 4294967296)) (i64.lt_u (local.get $y) (i64.const 4294967296)))
          (i32.const 1216))
        (call $assert (i64.ge_u (local.get $ba) (local.get $in)) (i32.const 1248))
        (local.set $out (i64.div_u (i64.mul (local.get $y) (local.get $in)) (i64.add (local.get $x) (local.get $in))))
        (call $assert (i64.ne (local.get $out) (i64.const 0)) (i32.const 1280))
        (call $assert (i64.ge_u (local.get $out) (local.get $min)) (i32.const 1312))
        (local.set $ba (i64.sub (local.get $ba) (local.get $in)))
        (local.set $bb (i64.add (local.get $bb) (local.get $out)))
        (local.set $x (i64.add (local.get $x) (local.get $in)))
        (local.set $y (i64.sub (local.get $y) (local.get $out)))
        (if (i64.eqz (local.get $dir))
          (then
            (i64.store (i32.const 128) (local.get $x)) (i64.store (i32.const 136) (local.get $y))
            (i64.store (i32.const 160) (local.get $ba)) (i64.store (i32.const 168) (local.get $bb)))
          (else
            (i64.store (i32.const 136) (local.get $x)) (i64.store (i32.const 128) (local.get $y))
            (i64.store (i32.const 168) (local.get $ba)) (i64.store (i32.const 160) (local.get $bb))))
        (i64.store (i32.const 144) (i64.add (i64.load (i32.const 144)) (i64.const 1)))
        (call $upd (local.get $pit) (i64.const 0) (i32.const 128) (i32.const 24))
        (call $upd (local.get $bit) (i64.const 0) (i32.const 160) (i32.const 16))
        (return)))

    (call $assert (i32.const 0) (i32.const 1056))))"#
    );
    wat::parse_str(&wat).context("assembling amm contract")
}

/// Pays out of its own token balance on a caller's say-so.
///
/// `pay` takes a packed token `transfer` whose `from` is the *caller*; the caller
/// must authorise the call. The router rewrites `from` to itself and sends the
/// transfer to the token contract as an inline action under its own `active`
/// permission, which therefore has to include `router@pulse.code`. (A contract
/// cannot hand a user's authority on to another contract; only itself.)
///
/// The memo is capped so the packed action stays under 128 bytes and its length
/// fits a one byte varint.
pub fn router_wasm(token: &str) -> Result<Vec<u8>> {
    let token = n(token)?;
    let transfer = n("transfer")?;
    let pay = n("pay")?;
    let active = n("active")?;
    let wat = format!(
        r#"(module
  (import "env" "action_data_size" (func $ads (result i32)))
  (import "env" "read_action_data" (func $read (param i32 i32) (result i32)))
  (import "env" "require_auth" (func $auth (param i64)))
  (import "env" "eosio_assert" (func $assert (param i32 i32)))
  (import "env" "send_inline" (func $inline (param i32 i32)))
  (memory 1)
  (export "memory" (memory 0))
  (data (i32.const 2048) "bad pay data\00")
  (data (i32.const 2080) "unknown action\00")
  (func (export "apply") (param $recv i64) (param $code i64) (param $act i64)
    (local $len i32) (local $i i32) (local $from i64)
    (if (i64.ne (local.get $recv) (local.get $code)) (then (return)))
    (call $assert (i64.eq (local.get $act) (i64.const {pay})) (i32.const 2080))
    (local.set $len (call $ads))
    (call $assert (i32.and (i32.ge_u (local.get $len) (i32.const 33)) (i32.le_u (local.get $len) (i32.const 127))) (i32.const 2048))
    (drop (call $read (i32.const 1024) (local.get $len)))
    (local.set $from (i64.load (i32.const 1024)))
    (call $auth (local.get $from))
    ;; The payment is made by this contract from its own balance, so the inline
    ;; action's sender and authority are the router itself.
    (i64.store (i32.const 1024) (local.get $recv))
    (i64.store (i32.const 0) (i64.const {token}))
    (i64.store (i32.const 8) (i64.const {transfer}))
    (i32.store8 (i32.const 16) (i32.const 1))
    (i64.store (i32.const 17) (local.get $recv))
    (i64.store (i32.const 25) (i64.const {active}))
    (i32.store8 (i32.const 33) (local.get $len))
    (loop $copy
      (i32.store8
        (i32.add (i32.const 34) (local.get $i))
        (i32.load8_u (i32.add (i32.const 1024) (local.get $i))))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br_if $copy (i32.lt_u (local.get $i) (local.get $len))))
    (call $inline (i32.const 0) (i32.add (i32.const 34) (local.get $len)))))"#
    );
    wat::parse_str(&wat).context("assembling router contract")
}

/// ABI for the oracle. `getTableRows` refuses to read a contract whose ABI does
/// not declare the table, even in raw mode.
pub fn oracle_abi() -> &'static str {
    r#"{
  "version": "eosio::abi/1.1",
  "types": [],
  "structs": [
    {"name": "feed", "base": "", "fields": [{"name": "price", "type": "uint64"}, {"name": "seq", "type": "uint64"}]},
    {"name": "counter", "base": "", "fields": [{"name": "updates", "type": "uint64"}]},
    {"name": "aggregate_row", "base": "", "fields": [{"name": "sum", "type": "uint64"}, {"name": "count", "type": "uint64"}, {"name": "avg", "type": "uint64"}]},
    {"name": "setprice", "base": "", "fields": [{"name": "feeder", "type": "name"}, {"name": "pair", "type": "name"}, {"name": "price", "type": "uint64"}, {"name": "seq", "type": "uint64"}, {"name": "nonce", "type": "uint64"}]},
    {"name": "aggregate", "base": "", "fields": [{"name": "caller", "type": "name"}, {"name": "pair", "type": "name"}, {"name": "nonce", "type": "uint64"}]}
  ],
  "actions": [
    {"name": "setprice", "type": "setprice", "ricardian_contract": ""},
    {"name": "aggregate", "type": "aggregate", "ricardian_contract": ""}
  ],
  "tables": [
    {"name": "feeds", "type": "feed", "index_type": "i64", "key_names": [], "key_types": []},
    {"name": "stats", "type": "counter", "index_type": "i64", "key_names": [], "key_types": []},
    {"name": "agg", "type": "aggregate_row", "index_type": "i64", "key_names": [], "key_types": []}
  ],
  "ricardian_clauses": [],
  "variants": []
}"#
}

/// ABI for the AMM; see [`oracle_abi`].
pub fn amm_abi() -> &'static str {
    r#"{
  "version": "eosio::abi/1.1",
  "types": [],
  "structs": [
    {"name": "pool_row", "base": "", "fields": [{"name": "reserve_a", "type": "uint64"}, {"name": "reserve_b", "type": "uint64"}, {"name": "swaps", "type": "uint64"}]},
    {"name": "balance_row", "base": "", "fields": [{"name": "a", "type": "uint64"}, {"name": "b", "type": "uint64"}]},
    {"name": "init", "base": "", "fields": [{"name": "a", "type": "uint64"}, {"name": "b", "type": "uint64"}]},
    {"name": "faucet", "base": "", "fields": [{"name": "trader", "type": "name"}, {"name": "a", "type": "uint64"}, {"name": "b", "type": "uint64"}, {"name": "nonce", "type": "uint64"}]},
    {"name": "swap", "base": "", "fields": [{"name": "trader", "type": "name"}, {"name": "dir", "type": "uint64"}, {"name": "amount_in", "type": "uint64"}, {"name": "min_out", "type": "uint64"}, {"name": "nonce", "type": "uint64"}]}
  ],
  "actions": [
    {"name": "init", "type": "init", "ricardian_contract": ""},
    {"name": "faucet", "type": "faucet", "ricardian_contract": ""},
    {"name": "swap", "type": "swap", "ricardian_contract": ""}
  ],
  "tables": [
    {"name": "pool", "type": "pool_row", "index_type": "i64", "key_names": [], "key_types": []},
    {"name": "bal", "type": "balance_row", "index_type": "i64", "key_names": [], "key_types": []}
  ],
  "ricardian_clauses": [],
  "variants": []
}"#
}

/// Little-endian packing of u64 action fields, the layout the WAT contracts read.
pub fn pack_u64s(values: &[u64]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_le_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A WAT typo or a stack-type mistake would otherwise only show up as an
    /// opaque setcode failure minutes into a network run, so assemble and run
    /// each contract through the chain's own validator here.
    #[test]
    fn contracts_assemble_and_pass_chain_validation() {
        for (name, wasm) in [
            ("oracle", oracle_wasm()),
            ("amm", amm_wasm()),
            ("router", router_wasm("pulse.token")),
        ] {
            let wasm = wasm.unwrap_or_else(|e| panic!("{name} does not assemble: {e:#}"));
            pulsevm_wasm_validation::validate_wasm(&wasm)
                .unwrap_or_else(|e| panic!("{name} fails chain validation: {e}"));
        }
    }

    #[test]
    fn abis_declare_every_table_the_harness_reads() {
        for (abi, tables) in [
            (oracle_abi(), vec!["feeds", "stats", "agg"]),
            (amm_abi(), vec!["pool", "bal"]),
        ] {
            let parsed: serde_json::Value = serde_json::from_str(abi).expect("ABI is JSON");
            let declared: Vec<_> = parsed["tables"]
                .as_array()
                .expect("tables array")
                .iter()
                .filter_map(|t| t["name"].as_str())
                .collect();
            for table in tables {
                assert!(declared.contains(&table), "ABI is missing table {table}");
            }
        }
    }

    #[test]
    fn pack_u64s_is_little_endian_in_field_order() {
        assert_eq!(
            pack_u64s(&[1, 0x0102]),
            vec![1, 0, 0, 0, 0, 0, 0, 0, 2, 1, 0, 0, 0, 0, 0, 0]
        );
    }
}
