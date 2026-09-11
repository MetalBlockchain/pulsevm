//! An ABI and its row bytes are both fully attacker-controlled: `setabi` accepts
//! any ABI that merely *parses* (it never checks that declared types exist), and
//! rows come from `db_store_i64`. Both are then fed to `bin_to_json` by
//! `getTableRows`, which is served over the unauthenticated `/rpc` handler.
//!
//! So decoding must fail cleanly on hostile input rather than aborting the
//! process or looping.

use pulsevm_abi::Abi;

/// Minimal `fc::raw`-packed `abi_def` declaring one struct with a single field
/// of `field_type`, and one table whose row type is that struct.
fn packed_abi(field_type: &str) -> Vec<u8> {
    fn string(out: &mut Vec<u8>, s: &str) {
        varuint(out, s.len() as u32);
        out.extend_from_slice(s.as_bytes());
    }
    fn varuint(out: &mut Vec<u8>, mut v: u32) {
        loop {
            let mut byte = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if v == 0 {
                break;
            }
        }
    }

    let mut a = Vec::new();
    string(&mut a, "eosio::abi/1.1"); // version
    varuint(&mut a, 0); // types
    varuint(&mut a, 1); // structs
    string(&mut a, "row");
    string(&mut a, ""); // base
    varuint(&mut a, 1); // fields
    string(&mut a, "f");
    string(&mut a, field_type);
    varuint(&mut a, 0); // actions
    varuint(&mut a, 1); // tables
    a.extend_from_slice(&1u64.to_le_bytes()); // table name
    string(&mut a, "i64"); // index_type
    varuint(&mut a, 0); // key_names
    varuint(&mut a, 0); // key_types
    string(&mut a, "row"); // row type
    varuint(&mut a, 0); // ricardian_clauses
    varuint(&mut a, 0); // error_messages
    varuint(&mut a, 0); // abi_extensions
    a
}

#[test]
fn huge_array_count_is_rejected_not_allocated() {
    // Five bytes of row data claiming u32::MAX elements. Reserving for that
    // asks the allocator for ~137 GB (serde_json::Value is 32 bytes); the
    // allocation fails and `handle_alloc_error` aborts the whole node.
    let abi = Abi::from_bytes(&packed_abi("uint64[]")).expect("abi should parse");
    let row = [0xFF, 0xFF, 0xFF, 0xFF, 0x0F];
    let err = abi
        .bin_to_json("row", &mut &row[..])
        .expect_err("an array count beyond the input must be rejected");
    assert!(
        err.to_string().contains("unexpected end of input"),
        "expected a clean length error, got: {err}"
    );
}

#[test]
fn array_of_zero_width_elements_terminates() {
    // A struct with no fields consumes no bytes, so a large count would spin
    // without ever running out of input. `empty[]` with a big count must stop.
    // Same shape as `packed_abi`, but with a second, field-less struct, so it
    // is built inline rather than through that helper.
    let mut abi_bytes = Vec::new();
    {
        fn string(out: &mut Vec<u8>, s: &str) {
            varuint(out, s.len() as u32);
            out.extend_from_slice(s.as_bytes());
        }
        fn varuint(out: &mut Vec<u8>, mut v: u32) {
            loop {
                let mut byte = (v & 0x7f) as u8;
                v >>= 7;
                if v != 0 {
                    byte |= 0x80;
                }
                out.push(byte);
                if v == 0 {
                    break;
                }
            }
        }
        let a = &mut abi_bytes;
        string(a, "eosio::abi/1.1");
        varuint(a, 0); // types
        varuint(a, 2); // structs
        string(a, "empty");
        string(a, "");
        varuint(a, 0); // no fields -> consumes nothing
        string(a, "row");
        string(a, "");
        varuint(a, 1);
        string(a, "f");
        string(a, "empty[]");
        varuint(a, 0); // actions
        varuint(a, 1); // tables
        a.extend_from_slice(&1u64.to_le_bytes());
        string(a, "i64");
        varuint(a, 0);
        varuint(a, 0);
        string(a, "row");
        varuint(a, 0);
        varuint(a, 0);
        varuint(a, 0);
    }

    let abi = Abi::from_bytes(&abi_bytes).expect("abi should parse");
    // A count that fits within the remaining bytes, so the length guard alone
    // does not save us -- only the forward-progress check does.
    let row = [0x04, 0x00, 0x00, 0x00, 0x00];
    let err = abi
        .bin_to_json("row", &mut &row[..])
        .expect_err("a zero-width element type must be rejected");
    assert!(
        err.to_string().contains("consumes no input"),
        "expected a zero-width element error, got: {err}"
    );
}
