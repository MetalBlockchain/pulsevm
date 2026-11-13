//! Every host intrinsic a contract can import, called with hostile arguments.
//!
//! Contract code is attacker-controlled: any account can deploy a module and
//! call any intrinsic with any values. An intrinsic that panics takes the
//! executing thread down mid-block. (One did: with no linear memory, every
//! `db_*` call hit an `.expect`.) This reads the intrinsic table the runtime
//! really links, builds one contract per intrinsic, with and without a memory,
//! and calls it with out-of-range pointers, huge lengths, negative iterators,
//! NaN and the integer extremes. A call may fail; it may not panic.

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        panic::{
            AssertUnwindSafe,
            catch_unwind,
        },
        str::FromStr,
        sync::Arc,
    };

    use anyhow::Result;
    use pulsevm_core::{
        Name,
        authority::PermissionLevel,
        transaction::{
            Action,
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

    // The linked table and the functions behind it, read from the same sources
    // the runtime compiles, so a new intrinsic is covered without editing this.
    const RUNTIME: &str = include_str!("../../../pulsevm_core/src/chain/wasm_runtime.rs");
    const SOURCES: [&str; 12] = [
        include_str!("../../../pulsevm_core/src/chain/webassembly/action.rs"),
        include_str!("../../../pulsevm_core/src/chain/webassembly/authorization.rs"),
        include_str!("../../../pulsevm_core/src/chain/webassembly/builtins.rs"),
        include_str!("../../../pulsevm_core/src/chain/webassembly/console.rs"),
        include_str!("../../../pulsevm_core/src/chain/webassembly/context_free.rs"),
        include_str!("../../../pulsevm_core/src/chain/webassembly/crypto.rs"),
        include_str!("../../../pulsevm_core/src/chain/webassembly/database.rs"),
        include_str!("../../../pulsevm_core/src/chain/webassembly/memory.rs"),
        include_str!("../../../pulsevm_core/src/chain/webassembly/permission.rs"),
        include_str!("../../../pulsevm_core/src/chain/webassembly/privileged.rs"),
        include_str!("../../../pulsevm_core/src/chain/webassembly/producer.rs"),
        include_str!("../../../pulsevm_core/src/chain/webassembly/system.rs"),
    ];
    const MORE_SOURCES: [&str; 1] = [include_str!(
        "../../../pulsevm_core/src/chain/webassembly/transaction.rs"
    )];

    #[derive(Clone, Copy, Debug)]
    enum Wt {
        I32,
        I64,
        F32,
        F64,
    }

    impl Wt {
        fn wat(self) -> &'static str {
            match self {
                Wt::I32 => "i32",
                Wt::I64 => "i64",
                Wt::F32 => "f32",
                Wt::F64 => "f64",
            }
        }

        /// Hostile constants of this type, indexed by pattern.
        fn constant(self, index: usize) -> String {
            const I32: [&str; 8] = [
                "0",
                "1",
                "4",
                "64",
                "65535",
                "2147483647",
                "-1",
                "-2147483648",
            ];
            const I64: [&str; 8] = [
                "0",
                "1",
                "5",
                "4294967295",
                "4294967296",
                "9223372036854775807",
                "-1",
                "-9223372036854775808",
            ];
            const F: [&str; 8] = ["0", "-0", "nan", "inf", "-inf", "1e38", "1e-45", "-1"];
            let i = index % 8;
            match self {
                Wt::I32 => format!("(i32.const {})", I32[i]),
                Wt::I64 => format!("(i64.const {})", I64[i]),
                Wt::F32 => format!("(f32.const {})", F[i]),
                Wt::F64 => format!("(f64.const {})", F[i]),
            }
        }
    }

    struct Intrinsic {
        name: String,
        params: Vec<Wt>,
        result: Option<Wt>,
    }

    fn map_type(text: &str) -> Option<Wt> {
        let t = text.trim();
        match t {
            "u64" | "i64" => Some(Wt::I64),
            "u32" | "i32" => Some(Wt::I32),
            "f32" => Some(Wt::F32),
            "f64" => Some(Wt::F64),
            _ if t.starts_with("WasmPtr<") => Some(Wt::I32),
            _ => None,
        }
    }

    fn linked_intrinsics() -> (Vec<Intrinsic>, Vec<String>) {
        let start = RUNTIME
            .find("let imports = imports! {")
            .expect("import table");
        let table = &RUNTIME[start..];
        let linked = regex::Regex::new(
            r#""(\w+)"\s*=>\s*Function::new_typed_with_env\(&mut store,\s*&env,\s*([\w:]+)\)"#,
        )
        .unwrap();
        let function = regex::Regex::new(
            r"pub fn (\w+)\s*\(\s*(?:mut\s+)?env:\s*FunctionEnvMut<WasmContext>\s*,?([^)]*)\)\s*(?:->\s*([^{]+?))?\s*\{",
        )
        .unwrap();
        let mut signatures: BTreeMap<String, (String, String)> = BTreeMap::new();
        for source in SOURCES.iter().chain(MORE_SOURCES.iter()) {
            for caps in function.captures_iter(source) {
                signatures.insert(
                    caps[1].to_string(),
                    (
                        caps[2].to_string(),
                        caps.get(3)
                            .map(|m| m.as_str().trim().to_string())
                            .unwrap_or_default(),
                    ),
                );
            }
        }
        let mut found = Vec::new();
        let mut unparsed = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for caps in linked.captures_iter(table) {
            let import = caps[1].to_string();
            if !seen.insert(import.clone()) {
                continue;
            }
            let function_name = caps[2].rsplit("::").next().unwrap().to_string();
            let Some((params, result)) = signatures.get(&function_name) else {
                unparsed.push(import);
                continue;
            };
            let mut types = Vec::new();
            let mut ok = true;
            for part in params.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                match part.split_once(':').and_then(|(_, t)| map_type(t)) {
                    Some(t) => types.push(t),
                    None => ok = false,
                }
            }
            let result_type = result
                .strip_prefix("Result<")
                .and_then(|r| r.rsplit_once(','))
                .map(|(t, _)| t.trim().to_string());
            let result = match result_type.as_deref() {
                Some("()") => Some(None),
                Some(t) => map_type(t).map(Some),
                None => None,
            };
            match (ok, result) {
                (true, Some(result)) => found.push(Intrinsic {
                    name: import,
                    params: types,
                    result,
                }),
                _ => unparsed.push(import),
            }
        }
        (found, unparsed)
    }

    const PATTERNS: usize = 10;

    fn pattern_name(p: usize) -> Name {
        Name::from_str(&format!("p{}", (b'a' + p as u8) as char)).unwrap()
    }

    /// One contract importing the intrinsic; action `pa`..`pj` selects the
    /// argument pattern, so a single deployment serves all patterns.
    fn contract(intrinsic: &Intrinsic, with_memory: bool) -> String {
        let params: String = intrinsic
            .params
            .iter()
            .map(|t| format!(" {}", t.wat()))
            .collect();
        let param_decl = if params.is_empty() {
            String::new()
        } else {
            format!("(param{params})")
        };
        let result_decl = intrinsic
            .result
            .map(|t| format!("(result {})", t.wat()))
            .unwrap_or_default();
        let mut body = String::new();
        for p in 0..PATTERNS {
            let args: String = intrinsic
                .params
                .iter()
                .enumerate()
                .map(|(j, t)| {
                    let index = match p {
                        8 => 0,
                        9 => 5,
                        _ => p * 3 + j * 5,
                    };
                    t.constant(index)
                })
                .collect::<Vec<_>>()
                .join(" ");
            let call = format!("(call $f {args})");
            let call = if intrinsic.result.is_some() {
                format!("(drop {call})")
            } else {
                call
            };
            body.push_str(&format!(
                "(if (i64.eq (local.get 2) (i64.const {})) (then {call}))\n",
                pattern_name(p).as_u64() as i64
            ));
        }
        let memory = if with_memory {
            r#"(memory (export "memory") 1 2) (data (i32.const 0) "0123456789abcdef")"#
        } else {
            ""
        };
        format!(
            r#"(module
                (import "env" "{}" (func $f {param_decl} {result_decl}))
                {memory}
                (func (export "apply") (param i64 i64 i64) {body}))"#,
            intrinsic.name
        )
    }

    fn call(chain: &mut Testing, account: Name, pattern: usize, tag: u32) -> Result<()> {
        let mut trx = Transaction::default();
        chain.set_transaction_headers(&mut trx, DEFAULT_EXPIRATION_DELTA, 0);
        trx.actions.push(Action {
            account: account.into(),
            name: pattern_name(pattern).into(),
            authorization: vec![PermissionLevel {
                actor: account.into(),
                permission: name!("active").into(),
            }],
            // Distinct data per call so no two transactions share an id.
            data: Arc::from(tag.to_le_bytes().to_vec()),
        });
        let trx = trx.sign(
            &get_private_key(account.into(), "active"),
            chain.controller.chain_id(),
        )?;
        chain.push_transaction(trx)?;
        Ok(())
    }

    #[test]
    fn the_intrinsic_table_is_read_in_full() {
        let (found, unparsed) = linked_intrinsics();
        // 185 imports are linked today. Falling well short means the parser
        // stopped understanding the source, and the hostile run below would
        // silently cover less than it claims.
        assert!(
            found.len() >= 175,
            "only {} intrinsics parsed, unparsed: {unparsed:?}",
            found.len()
        );
        assert!(unparsed.len() <= 10, "too many unparsed: {unparsed:?}");
    }

    #[tokio::test]
    async fn no_intrinsic_panics_on_hostile_arguments() -> Result<()> {
        let (intrinsics, _) = linked_intrinsics();
        let account = Name::from_str("hostile").unwrap();
        let mut chain = Testing::new().await;
        chain.create_accounts(vec![account.into()], false, true)?;

        let mut panicked = Vec::new();
        let mut deployed = 0usize;
        let mut not_deployable = Vec::new();
        let mut calls = 0usize;
        let mut tag = 0u32;
        for (number, intrinsic) in intrinsics.iter().enumerate() {
            // The test chain's clock advances with every transaction; after a
            // few thousand, new transactions fail "too long lifetime" and the
            // rest of the table would go untested. A fresh chain every 30
            // intrinsics keeps the whole table in range.
            if number > 0 && number % 30 == 0 {
                chain = Testing::new().await;
                chain.create_accounts(vec![account.into()], false, true)?;
            }
            for with_memory in [true, false] {
                let wat = contract(intrinsic, with_memory);
                let Ok(wasm) = wat2wasm(&wat) else {
                    not_deployable.push(format!("{} (assemble)", intrinsic.name));
                    continue;
                };
                if let Err(error) = chain.set_code(account.into(), wasm.into()) {
                    not_deployable.push(format!("{} ({error})", intrinsic.name));
                    continue;
                }
                deployed += 1;
                for p in 0..PATTERNS {
                    tag += 1;
                    calls += 1;
                    let outcome = catch_unwind(AssertUnwindSafe(|| {
                        let _ = call(&mut chain, account, p, tag);
                    }));
                    if outcome.is_err() {
                        panicked.push(format!(
                            "{} (memory={with_memory}, pattern {p})",
                            intrinsic.name
                        ));
                        break;
                    }
                }
            }
        }
        eprintln!(
            "hostile intrinsics: {} linked, {deployed} contracts deployed, {calls} calls, \
             {} not deployable: {not_deployable:?}",
            intrinsics.len(),
            not_deployable.len()
        );
        assert!(
            panicked.is_empty(),
            "intrinsics that panic on hostile arguments:\n{}",
            panicked.join("\n")
        );
        // Every intrinsic must be exercised in both memory modes. A contract
        // that cannot be deployed is untested ground, so this is exact.
        assert!(
            not_deployable.is_empty(),
            "contracts that could not be deployed (untested): {not_deployable:?}"
        );
        assert_eq!(deployed, intrinsics.len() * 2);
        Ok(())
    }
}
