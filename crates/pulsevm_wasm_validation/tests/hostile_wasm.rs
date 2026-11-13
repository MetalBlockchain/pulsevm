//! Contract bytecode is attacker-supplied: `setcode` accepts any module that
//! passes this validator. It must always return, `Ok` or `Err`, quickly and
//! without allocating by a declared (not actual) size.

use proptest::{
    collection::vec,
    prelude::*,
};
use pulsevm_wasm_validation::validate_wasm;

/// A module exercising memory, a table, globals, an exported function with a
/// loop, and a data segment, so mutations land in many different sections.
fn seed_module() -> Vec<u8> {
    wat::parse_str(
        r#"(module
            (import "env" "prints" (func $prints (param i32)))
            (memory 1 4)
            (table 4 funcref)
            (global $g (mut i32) (i32.const 7))
            (data (i32.const 0) "hello")
            (func $apply (export "apply") (param i64 i64 i64)
              (local i32)
              (loop $l
                (local.set 3 (i32.add (local.get 3) (i32.const 1)))
                (br_if $l (i32.lt_u (local.get 3) (i32.const 10))))
              (call $prints (i32.const 0)))
          )"#,
    )
    .expect("the seed assembles")
}

fn mutate(seed: Vec<u8>) -> impl Strategy<Value = Vec<u8>> {
    let len = seed.len().max(1);
    (
        Just(seed),
        0usize..len,
        any::<u8>(),
        0usize..5,
        vec(any::<u8>(), 0..64),
    )
        .prop_map(|(mut bytes, at, value, op, extra)| {
            match op {
                0 => {
                    if let Some(byte) = bytes.get_mut(at) {
                        *byte = value;
                    }
                }
                1 => bytes.truncate(at),
                2 => bytes.extend_from_slice(&extra),
                // Overwrite a few bytes with a maximal LEB128 (a section or
                // element count of ~4 billion).
                3 => {
                    let end = (at + 5).min(bytes.len());
                    if at < end {
                        bytes.splice(
                            at..end,
                            [0xFFu8, 0xFF, 0xFF, 0xFF, 0x0F].into_iter().take(end - at),
                        );
                    }
                }
                // Drop a byte (shifts every later length).
                _ => {
                    if at < bytes.len() {
                        bytes.remove(at);
                    }
                }
            }
            bytes
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn arbitrary_bytes_never_panic(bytes in vec(any::<u8>(), 0..4096)) {
        let _ = validate_wasm(&bytes);
    }

    #[test]
    fn arbitrary_bytes_behind_a_valid_header_never_panic(body in vec(any::<u8>(), 0..4096)) {
        let mut bytes = b"\0asm\x01\0\0\0".to_vec();
        bytes.extend(body);
        let _ = validate_wasm(&bytes);
    }

    #[test]
    fn mutated_valid_modules_never_panic(bytes in mutate(seed_module())) {
        let _ = validate_wasm(&bytes);
    }
}

#[test]
fn the_seed_module_is_valid_so_mutations_start_from_something_accepted() {
    // The seed imports env.prints, which the validator may or may not allow;
    // what matters is that it parses, so mutation reaches the section logic.
    let seed = seed_module();
    assert!(seed.starts_with(b"\0asm"));
    let _ = validate_wasm(&seed);
}

#[test]
fn declared_sizes_far_beyond_the_input_are_rejected_cheaply() {
    // Hand-built sections whose declared counts/limits dwarf the bytes present.
    let header = b"\0asm\x01\0\0\0";
    let max_leb = [0xFFu8, 0xFF, 0xFF, 0xFF, 0x0F];

    // Function section claiming ~4 billion functions.
    let mut module = header.to_vec();
    module.extend([3u8, 6]);
    module.extend(max_leb);
    module.push(0);
    assert!(validate_wasm(&module).is_err());

    // Memory with a minimum of ~4 billion pages.
    let mut module = header.to_vec();
    module.extend([5u8, 6, 1, 0]);
    module.extend(max_leb);
    assert!(validate_wasm(&module).is_err());

    // Table with ~4 billion initial elements.
    let mut module = header.to_vec();
    module.extend([4u8, 8, 1, 0x70, 0]);
    module.extend(max_leb);
    assert!(validate_wasm(&module).is_err());

    // Type section claiming ~4 billion types.
    let mut module = header.to_vec();
    module.extend([1u8, 6]);
    module.extend(max_leb);
    module.push(0x60);
    assert!(validate_wasm(&module).is_err());
}
