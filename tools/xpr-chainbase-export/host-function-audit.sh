#!/usr/bin/env bash
# Compare the XPR/Leap intrinsic registry with PulseVM's Wasmer import map and
# verify that the code-object fields used by the migration sidecar still exist
# on both sides. The audit is source-based and independent of the Rust tests.

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: host-function-audit.sh --xpr-core PATH [--report PATH] [--strict]

--xpr-core PATH  XPR/Leap checkout at the revision used to build nodeos
--report PATH    Write the JSON audit report to PATH
--strict         Exit non-zero when a reference host function is not wired
EOF
}

xpr_core=""
report=""
strict=false
while (($#)); do
    case "$1" in
        --xpr-core) xpr_core="$2"; shift 2 ;;
        --report) report="$2"; shift 2 ;;
        --strict) strict=true; shift ;;
        --help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done
[[ -d "$xpr_core" ]] || { echo "XPR checkout does not exist: $xpr_core" >&2; exit 2; }

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
wasm_runtime="$repo_root/crates/pulsevm_core/src/chain/wasm_runtime.rs"
wasm_interface="$xpr_core/libraries/chain/wasm_interface.cpp"
state_history="$xpr_core/plugins/state_history_plugin/state_history_plugin.cpp"
[[ -f "$wasm_runtime" && -f "$wasm_interface" && -f "$state_history" ]] || {
    echo "checkout is missing the expected XPR or PulseVM source files" >&2
    exit 2
}

python3 - "$wasm_interface" "$state_history" "$wasm_runtime" "$report" "$strict" <<'PY'
import json
import re
import sys
from pathlib import Path

wasm_interface = Path(sys.argv[1])
state_history = Path(sys.argv[2])
wasm_runtime = Path(sys.argv[3])
report = Path(sys.argv[4]) if sys.argv[4] else None
strict = sys.argv[5] == "true"

ref_text = wasm_interface.read_text()
ref = set()
for block in re.finditer(r"REGISTER(?:_INJECTED)?_INTRINSICS\(\s*[^,]+,(.*?)\n\);", ref_text, re.S):
    ref.update(re.findall(r"^\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,", block.group(1), re.M))
for index in ("idx64", "idx128", "idx256", "idx_double", "idx_long_double"):
    for operation in ("store", "remove", "update", "find_primary", "find_secondary", "lowerbound", "upperbound", "end", "next", "previous"):
        ref.add(f"db_{index}_{operation}")

rust = set(re.findall(r'"([A-Za-z_][A-Za-z0-9_]*)"\s*=>\s*Function::', wasm_runtime.read_text()))
injected = sorted(name for name in ref if name.startswith("_eosio_") or name in {"call_depth_assert", "checktime"})
unsupported_by_reference = sorted({"activate_feature", "is_feature_active"} & ref)
missing = sorted(ref - rust - set(injected) - set(unsupported_by_reference))
extra = sorted(rust - ref)

tables = [
    "account", "account_metadata", "code", "contract_table", "contract_row",
    "contract_index64", "contract_index128", "contract_index256",
    "contract_index_double", "contract_index_long_double", "global_property",
    "generated_transaction", "protocol_state", "permission", "permission_link",
    "resource_limits", "resource_usage", "resource_limits_state", "resource_limits_config",
]
state_history_text = state_history.read_text()
table_presence = {name: bool(re.search(rf'process_table\("{re.escape(name)}"', state_history_text)) for name in tables}
code_source = (wasm_interface.parent / "include/eosio/chain/code_object.hpp").read_text()
code_rust = wasm_runtime.parents[3].joinpath("pulsevm_chaindb/src/lib.rs").read_text()
code_fields = ["code_ref_count", "code", "first_block_used", "vm_type", "vm_version", "code_hash"]
code_object = {
    "reference_fields": {field: field in code_source for field in code_fields},
    "arena_fields": {field: field in code_rust for field in code_fields},
}
code_object["complete"] = all(code_object["reference_fields"].values()) and all(code_object["arena_fields"].values())

result = {
    "reference_registered_count": len(ref),
    "rust_registered_count": len(rust),
    "injected_excluded": injected,
    "reference_unsupported": unsupported_by_reference,
    "missing_direct_imports": missing,
    "rust_extensions": extra,
    "state_history_19_tables": table_presence,
    "code_object": code_object,
}
print(json.dumps(result, indent=2, sort_keys=True))
if report:
    report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
if not all(table_presence.values()) or not code_object["complete"]:
    raise SystemExit("audit failed: source table or code-object coverage is incomplete")
if strict and missing:
    raise SystemExit("audit failed: missing direct host imports: " + ", ".join(missing))
PY
