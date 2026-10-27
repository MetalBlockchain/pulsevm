#!/usr/bin/env python3
"""Pre-ceremony readiness audit for the cutover contract.

The ceremony freezes the ACTIVE SCHEDULE (one member, one vote), so this
tool proves the freeze candidates before coordination spends one on them:
every scheduled producer must be active with a valid K1 key, and each
producers-table `producer_key` must equal the schedule's
`block_signing_key`. A mismatch would mint a freeze nobody can sign for.
Multisig or non-K1 schedules are loudly unsupported by design. Run it at
T-14, at freeze time, and from the rehearsal preflight.

Usage:
    check-schedule-readiness.py --api URL [--host-header HOST]
                                [--allow-pending]

Checks (hard failures, exit 1):
  - each active producer's schedule key is a valid K1 key (PUB_K1_ or
    legacy EOS with checksum);
  - where the row carries an `authority` field (non-XPR chains), it must
    be threshold 1, exactly one weight-1 key, no accounts, no waits, and
    equal to the schedule key. XPR mainnet rows carry NO authority
    (verified live: 8 fields, 90 bytes) — the schedule key is the only
    consensus-relevant key, so absence is the expected shape, not a
    failure;
  - every active-schedule member is active in the producers table with the
    same key (table key vs schedule key compared parsed, never as
    strings).
A staged pending/proposed schedule also fails unless --allow-pending: the
frozen schedule must name the set that will actually produce H.

Informational only: active count, schedule version and size, active
standbys outside the schedule (they simply are not in the quorum).
total_votes is not checked: with unit weights there is nothing to drift.
"""

import argparse
import hashlib
import json
import sys
import urllib.request

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode(text):
    value = 0
    for char in text:
        value = value * 58 + B58.index(char)
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big") if value else b""
    pad = len(text) - len(text.lstrip("1"))
    return b"\x00" * pad + raw


def parse_k1(key):
    """Return 33-byte compressed key or raise."""
    if key.startswith("PUB_K1_"):
        raw = b58decode(key[len("PUB_K1_"):])
        if len(raw) != 37:
            raise ValueError("bad PUB_K1_ length")
        body, checksum = raw[:-4], raw[-4:]
        if hashlib.new("ripemd160", body + b"K1").digest()[:4] != checksum:
            raise ValueError("bad PUB_K1_ checksum")
        return body
    if key.startswith("EOS"):
        raw = b58decode(key[len("EOS"):])
        if len(raw) != 37:
            raise ValueError("bad legacy key length")
        body, checksum = raw[:-4], raw[-4:]
        if hashlib.new("ripemd160", body).digest()[:4] != checksum:
            raise ValueError("bad legacy key checksum")
        return body
    raise ValueError("not a K1 key (need PUB_K1_ or legacy EOS)")


def post(api, path, payload, host_header):
    request = urllib.request.Request(
        api.rstrip("/") + path,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "Host": host_header},
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.load(response)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--api", required=True)
    parser.add_argument("--host-header", default="127.0.0.1:8888")
    parser.add_argument("--allow-pending", action="store_true")
    args = parser.parse_args()

    failures = []
    try:
        rows = post(
            args.api,
            "/v1/chain/get_table_rows",
            {
                "json": True,
                "code": "eosio",
                "scope": "eosio",
                "table": "producers",
                "limit": 200,
            },
            args.host_header,
        )["rows"]
    except Exception as error:  # noqa: BLE001 - report and fail closed
        print(f"readiness: FAIL: cannot read producers table: {error}")
        return 1
    active = [row for row in rows if row.get("is_active")]
    if not active:
        print("readiness: FAIL: no active producers found")
        return 1

    # Key validity per active row. total_votes is deliberately ignored: the
    # ceremony is a count quorum over the active schedule, so vote
    # magnitudes are informational only (printed below), never gating.
    for row in active:
        name = row.get("owner", "?")
        problems = []
        try:
            schedule_key = parse_k1(row.get("producer_key", ""))
        except ValueError as error:
            problems.append(f"bad schedule key: {error}")
            schedule_key = None
        if "authority" in row:
            # Non-XPR chain shape: the on-chain authority must be plain
            # 1-of-1 K1 and match the schedule key, exactly what the
            # contract used to enforce before XPR dropped the field.
            authority = row.get("authority") or {}
            if authority.get("threshold") != 1:
                problems.append(f"threshold={authority.get('threshold')}")
            keys = authority.get("keys") or []
            if len(keys) != 1 or keys[0].get("weight") != 1:
                problems.append("not exactly one weight-1 key")
            if authority.get("accounts"):
                problems.append("has account approvals")
            if authority.get("waits"):
                problems.append("has waits")
            try:
                auth_key = parse_k1(keys[0]["key"]) if keys else None
            except (ValueError, KeyError, IndexError) as error:
                problems.append(f"bad authority key: {error}")
                auth_key = None
            if (
                auth_key is not None
                and schedule_key is not None
                and auth_key != schedule_key
            ):
                problems.append("authority key differs from schedule key")
        if problems:
            failures.append(f"{name}: {'; '.join(problems)}")

    for failure in failures:
        print(f"readiness: FAIL: {failure}")

    try:
        schedule = post(args.api, "/v1/chain/get_producer_schedule", {}, args.host_header)
    except Exception as error:  # noqa: BLE001 - report and fail closed
        print(f"readiness: FAIL: cannot read producer schedule: {error}")
        return 1
    # Mirrors the voter's read_live_schedule: pending OR proposed counts
    # as staged. Null slots (Leap returns explicit nulls) mean unstaged.
    staged = {}
    for slot in ("pending", "proposed"):
        producers = (schedule.get(slot) or {}).get("producers", [])
        if producers:
            staged[slot] = [p.get("producer_name") for p in producers]
    if staged and not args.allow_pending:
        detail = ", ".join(f"{slot} ({len(names)})" for slot, names in staged.items())
        print(f"readiness: FAIL: schedule change staged ({detail}); freeze after it activates")
        return 1

    # The freeze must name the ACTIVE SCHEDULE, and the schedule keys must
    # match the producers table row-for-row: a producer_key that differs
    # from the schedule's block_signing_key would mint a freeze nobody can
    # sign for. Standbys (active but unscheduled) are informational only —
    # they simply are not in the quorum.
    active_slot = schedule.get("active") or {}
    scheduled = (active_slot.get("producers") or [])
    schedule_version = active_slot.get("version")
    table_keys = {}
    for row in rows:
        try:
            table_keys[row.get("owner")] = parse_k1(row.get("producer_key", ""))
        except ValueError:
            continue
    active_names = {row.get("owner") for row in active}
    if not scheduled:
        print("readiness: FAIL: producer schedule carries no active producers")
        return 1
    for producer in scheduled:
        name = producer.get("producer_name", "?")
        try:
            scheduled_key = parse_k1(producer.get("block_signing_key", ""))
        except ValueError as error:
            failures.append(f"{name}: bad schedule key: {error}")
            continue
        if name not in active_names:
            failures.append(f"{name}: scheduled but not active in the producers table")
        elif table_keys.get(name) != scheduled_key:
            failures.append(
                f"{name}: producers.producer_key differs from the schedule signing key"
            )
    scheduled_names = {p.get("producer_name") for p in scheduled}
    standbys = sorted(active_names - scheduled_names)
    print(
        f"readiness: {len(active)} active producers checked, {len(failures)} failures; "
        f"schedule version {schedule_version} with {len(scheduled)} members, "
        f"{len(standbys)} active standbys outside the schedule"
    )
    if staged:
        detail = ", ".join(f"{slot} ({len(names)})" for slot, names in staged.items())
        print(f"readiness: note: schedule change staged ({detail}), allowed by flag")
    if failures:
        return 1
    print(
        "readiness: PASS: frozen schedule candidates match live schedule keys, "
        "no change staged"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
