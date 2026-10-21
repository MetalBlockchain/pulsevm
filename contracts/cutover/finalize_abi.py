#!/usr/bin/env python3
"""Inject table definitions into the abigen ABI.

CDT 1.8 abigen emits actions but no tables, and `get_table_rows` needs the
table entries to decode rows (it resolves the table name through the ABI
even for hex row queries). This script adds exactly the tables whose binary
layout is fixed by the contracts; field order and types must stay in
lockstep with the C++ structs (the live single-key vote test fails loudly
on any drift, since the digest binds the key bytes).
"""

import json
import sys

ABI_PATH = sys.argv[1] if len(sys.argv) > 1 else "cutover.abi"

abi = json.load(open(ABI_PATH))

TABLES = [
    {
        "name": "ceremony",
        "index_type": "i64",
        "key_names": [],
        "key_types": [],
        "type": "ceremony",
    },
    {
        "name": "members",
        "index_type": "i64",
        "key_names": ["producer"],
        "key_types": ["name"],
        "type": "member",
    },
    # Fixture-only: the seeder's synthetic `eosio.producers` row. The head
    # mirrors the live system layout exactly (see schedule_view.hpp); the
    # flattened authority tail is opaque bytes here because no standard ABI
    # type consumes the exact 42 raw bytes. Row presence/count queries work;
    # full JSON decoding of the tail is not supported by this ABI (the
    # cutover contract parses the tail itself; the A-Chain verifier decodes
    # checkpoint state with its own layout).
    {
        "name": "producers",
        "index_type": "i64",
        "key_names": ["owner"],
        "key_types": ["name"],
        "type": "producer_row",
    },
]

STRUCTS = [
    {
        "name": "ceremony",
        "base": "",
        "fields": [
            {"name": "id", "type": "uint64"},
            {"name": "h", "type": "uint32"},
            {"name": "source_chain_id", "type": "checksum256"},
            {"name": "total_weight", "type": "uint128"},
            {"name": "voted_weight", "type": "uint128"},
            {"name": "finalized", "type": "bool"},
            {"name": "declaration_digest", "type": "checksum256"},
        ],
    },
    {
        "name": "member",
        "base": "",
        "fields": [
            {"name": "producer", "type": "name"},
            {"name": "key", "type": "public_key"},
            {"name": "weight", "type": "uint128"},
            {"name": "voted", "type": "bool"},
        ],
    },
    {
        "name": "producer_row",
        "base": "",
        "fields": [
            {"name": "head", "type": "producer_head"},
            {"name": "tail", "type": "bytes"},
        ],
    },
    {
        "name": "producer_head",
        "base": "",
        "fields": [
            {"name": "owner", "type": "name"},
            {"name": "total_votes", "type": "float64"},
            {"name": "producer_key", "type": "public_key"},
            {"name": "is_active", "type": "bool"},
            {"name": "url", "type": "string"},
            {"name": "unpaid_blocks", "type": "uint32"},
            {"name": "last_claim_time", "type": "int64"},
            {"name": "location", "type": "uint16"},
        ],
    },
]

# Table/struct ownership per ABI file: abigen emits actions only, so the
# injector is the sole source of table definitions. The cutover contract
# owns ceremony/members; the seeder owns the synthetic producers row.
OWNERS = {
    "ceremony": "cutover",
    "members": "cutover",
    "member": "cutover",
    "producers": "seed",
    "producer_row": "seed",
    "producer_head": "seed",
}
owner = "cutover" if ABI_PATH.startswith("cutover") else "seed"

have_tables = {entry["name"] for entry in abi.get("tables", [])}
for entry in TABLES:
    if OWNERS.get(entry["name"]) == owner and entry["name"] not in have_tables:
        abi.setdefault("tables", []).append(entry)

have_structs = {entry["name"] for entry in abi.get("structs", [])}
for entry in STRUCTS:
    if OWNERS.get(entry["name"], "cutover") == owner and entry["name"] not in have_structs:
        abi["structs"].append(entry)

json.dump(abi, open(ABI_PATH, "w"), indent=4)
print(f"finalized {ABI_PATH}: tables {[t['name'] for t in abi.get('tables', [])]}")
