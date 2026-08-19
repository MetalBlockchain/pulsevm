# SHiP chain-state delta (`pack_deltas`) pure-Rust port

The nodeos state-history per-block delta serializer is implemented in pure Rust
over the arena, and `store_chain_state` appends its output to the chain-state
log.
Everything below is reverse-engineered from the C++ (git `782d9a47`:
`crates/pulsevm_database/pulsevm/libraries/state_history/{create_deltas.cpp,include/.../serialization.hpp}`)
and **verified byte-for-byte against the frozen golden**
(`crates/pulsevm_database/tests/ship_golden.txt.gz`, `<block_num> <hex>`, blocks 2..1697).

## fc encodings used everywhere
- `uvar` = `fc::unsigned_int` LEB128 (7 bits/byte, high bit = continue).
- ints: fixed little-endian (u16/u32/u64/i64). `bool` = 1 byte. `name` = u64 LE.
- `block_timestamp_type` = u32 LE. `fc::time_point` = i64 LE (microseconds).
- `digest_type`/`chain_id_type` = 32 raw bytes.
- `shared_string`/`bytes` = `uvar(len)` + bytes.
- `public_key_type` (K1) = pulsevm_crypto K1 packed form (tag byte 0x00 + 33 compressed) — confirm against golden.
- container = `uvar(count)` + each element via its wrapper.

## Wire format (create_deltas.cpp) — verified: block 2 = 6346 bytes, 9 tables, exact
```
uvar num_tables                      // count of non-empty tables only
for each table in the fixed order below, emit ONLY if it has entries:
  uvar struct_version = 0
  string name                        // uvar len + utf8
  uvar row_count
  for each row: u8 present; uvar byte_len; <byte_len bytes of history-serialized row>
```
Table order (16): account, account_metadata, code, contract_table, contract_row,
contract_index64, contract_index128, contract_index256, global_property,
protocol_state, permission, permission_link, resource_limits, resource_usage,
resource_limits_state, resource_limits_config.

full_snapshot (first appended block = block 2): every row, present=true.
delta (later blocks): from the arena `UndoState` of the block's open undo session
(pack_deltas runs in store_chain_state BEFORE commit) —
  modified: `old_values` where include_delta → present=true, serialize the CURRENT row;
  removed:  `removed_values` → present=false, serialize the removed row;
  created:  ids new this session → present=true.
`include_delta` = "any change" for all tables except `protocol_state` (compares
`activated_protocol_features`; the arena has none yet, so it never emits a delta).

Within a delta, modified rows are emitted first, then removed rows, then new
rows. chainbase stores the first two groups in intrusive singly linked lists and
uses `push_front`, so they are in reverse first-touch order. New rows are read
from the primary index in ascending id order.

## Per-row history serializers — every one starts with `uvar(0)` version unless noted.
Sizes below are the golden's block-2 first-row lengths (all verified).

- account (2147 for system acct) = `00` + name:u64 + creation_date:u32 + abi:shared_string.
  arena: `AccountRow{ name, creation_date:u32, abi:blob }`.
- account_metadata (19, no code) = `00` + name:u64 + is_privileged:bool +
  last_code_update:time_point(i64) + has_code:bool + [if has_code: vm_type:u8 +
  vm_version:u8 + code_hash:32]. has_code = code_hash != 0.
  arena: `AccountMetaRow{ name, last_code_update:i64, code_hash:[u8;32], flags:u32 (bit0=priv), vm_type:u8, vm_version:u8 }`.
- code = `00` + vm_type:u8 + vm_version:u8 + code_hash:32 + code:shared_string. (empty at block 2)
- contract_table (table_id) = `00` + code:u64 + scope:u64 + table:u64 + payer:u64.
  arena: `ContractTableRow{ code, scope, table, payer, count }`.
- contract_row (key_value) — CONTEXT wrapper = `00` + code:u64 + scope:u64 + table:u64 +
  primary_key:u64 + payer:u64 + value via `history_pack_big_bytes` (check: likely uvar len + bytes).
  code/scope/table come from the row's table_id (ContractKeyValueRow.t_id → ContractTableRow).
- contract_index64/128/256 — context wrapper, same header + secondary_key (8/16/32 bytes). (empty at block 2)
- global_property (143) = `01`(version 1!) + chain_config + chain_id:32 + wasm_config.
  - chain_config (65) = `01`(version 1!) + max_block_net_usage:u64 +
    target_block_net_usage_pct:u32 + max_transaction_net_usage:u32 +
    base_per_transaction_net_usage:u32 + net_usage_leeway:u32 +
    context_free_discount_net_usage_num:u32 + context_free_discount_net_usage_den:u32 +
    max_block_cpu_usage:u32 + target_block_cpu_usage_pct:u32 + max_transaction_cpu_usage:u32 +
    min_transaction_cpu_usage:u32 + max_transaction_lifetime:u32 + max_inline_action_size:u32 +
    max_inline_action_depth:u16 + max_authority_depth:u16 + max_action_return_value_size:u32.
    (NOTE: history OMITS max_transaction_delay and deferred_trx_expiration_window.)
  - wasm_config (45) = `00` + 11×u32: max_mutable_global_bytes, max_table_elements,
    max_section_elements, max_linear_memory_init, max_func_local_bytes, max_nested_structures,
    max_symbol_bytes, max_module_bytes, max_code_bytes, max_pages, max_call_depth.
  ARENA GAPS to resolve: `GlobalPropertyRow` ends at max_authority_depth and does not
  obviously store max_inline_action_depth, max_action_return_value_size, chain_id, or
  wasm_config. Source them (chain_id is on the controller; wasm_config is the pinned
  constant used by the wasm validation; the two chain_config tail fields may need adding
  to GlobalPropertyRow or sourcing from genesis config). FLAG if truly absent.
- protocol_state (2) = `00` + container(activated_protocol_features)=uvar(0). Always empty.
- permission (40 for an empty-auth perm) = `00` + owner:u64 + perm_name:u64 +
  parent_perm_name:u64 (0 if root; else the PARENT ROW's perm_name — resolve
  PermissionRow.parent:i64 → that row's perm_name) + last_updated:time_point(i64) +
  authority. authority = threshold:u32 + container(key_weight) + container(perm_level_weight)
  + container(wait_weight), where
    key_weight = public_key + weight:u16 (NO version prefix),
    perm_level_weight = (actor:u64 + permission:u64) + weight:u16 (NO version prefix),
    wait_weight = wait_sec:u32 + weight:u16 (NO version prefix).
  arena: `PermissionRow{ parent:i64, owner, perm_name, last_updated:i64, auth:blob }`; the
  auth blob is `encode_authority` — decode to (threshold, keys, accounts, waits) and
  re-serialize in the above history order (chaindb already has decode helpers).
- permission_link = `00` + account:u64 + code:u64 + message_type:u64 + required_permission:u64. (empty at block 2)
- resource_limits (33) = `00` + owner:u64 + net_weight:i64 + cpu_weight:i64 + ram_bytes:i64.
  ONLY non-pending rows (`ResourceLimitsRow.pending == 0`). NOTE field ORDER differs from struct.
- usage_accumulator = `00` + last_ordinal:u32 + value_ex:u64 + consumed:u64.
  arena `UsageAccumulator{ value_ex, consumed, last_ordinal }` (reorder!).
- resource_usage (59) = `00` + owner:u64 + net_usage:accumulator + cpu_usage:accumulator + ram_usage:u64.
- resource_limits_state (83) = `00` + average_block_net_usage:accumulator +
  average_block_cpu_usage:accumulator + total_net_weight:u64 + total_cpu_weight:u64 +
  total_ram_bytes:u64 + virtual_net_limit:u64 + virtual_cpu_limit:u64. arena: `ResourceStateRow`.
- resource_limits_config (127) = `00` + cpu_limit_parameters:elastic + net_limit_parameters:elastic +
  account_cpu_usage_average_window:u32 + account_net_usage_average_window:u32.
  - elastic (59) = `00` + target:u64 + max:u64 + periods:u32 + max_multiplier:u32 +
    contract_rate:ratio + expand_rate:ratio.
  - ratio (17) = `00` + numerator:u64 + denominator:u64.
  arena: `ResourceConfigRow{ cpu_target, cpu_max, cpu_contract_num/den, cpu_expand_num/den,
    net_target, net_max, net_contract_num/den, net_expand_num/den, ... windows, periods, multiplier }`.
    (periods/max_multiplier may be constants — check ResourceConfigRow / genesis.)

## Verification

The replay harness compares every generated delta against the frozen C++ oracle.
The completed port matches all 1,696 post-genesis blocks byte-for-byte and keeps
all 1,697 per-block arena state roots unchanged. Focused arena tests pin
chainbase's reverse-first-touch undo ordering, including nested squashes; the
chaindb tests also pin the empty delta and protocol-state-only snapshot framing.

Run the full replay with:

```sh
PULSEVM_RPC_BLOCKS_DIR=target/replay/rpcblocks \
PULSEVM_GOLDEN_ROOTS=target/replay/golden_roots.txt \
PULSEVM_SHIP_VERIFY=target/replay/ship_golden.txt \
cargo test -p pulsevm_core --lib replay_testnet_blocks -- --ignored --nocapture --test-threads=1
```
