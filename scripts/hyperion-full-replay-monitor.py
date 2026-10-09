#!/usr/bin/env python3
"""Bounded-storage verifier for a full PulseVM -> SHiP -> Hyperion replay."""

from __future__ import annotations

import json
import os
import re
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ES_URL = os.environ.get("HYPERION_ES_URL", "http://127.0.0.1:9200").rstrip("/")
CHAIN = os.environ.get("HYPERION_CHAIN_NAME", "xpr-full-replay")
WATERMARK = Path(os.environ.get("XPR_REPLAY_INDEXED_HEIGHT_FILE", "/data/xpr-hyperion/indexed-height"))
REPORT = Path(os.environ.get("XPR_REPLAY_REPORT_PATH", "/data/xpr-hyperion/replay.json"))
REPLAY_LOG = Path(os.environ.get("XPR_REPLAY_LOG_FILE", "/data/xpr-hyperion/replay.log"))
START_BLOCK = int(os.environ.get("HYPERION_AUDIT_START_BLOCK", "2"))
SOURCE_HEAD = int(os.environ.get("XPR_REPLAY_SOURCE_HEAD", "0"))
FOLLOW_MODE = os.environ.get("XPR_REPLAY_FOLLOW") == "1"
VERIFY_CHUNK = int(os.environ.get("HYPERION_VERIFY_CHUNK_BLOCKS", "100000"))
RETAIN_BLOCKS = int(os.environ.get("HYPERION_RETAIN_BLOCKS", "200000"))
PRUNE_ENABLED = os.environ.get("HYPERION_PRUNE_ENABLED", "0") == "1"
POLL_SECONDS = float(os.environ.get("HYPERION_MONITOR_POLL_SECONDS", "2"))
REQUEST_TIMEOUT = float(os.environ.get("HYPERION_MONITOR_REQUEST_TIMEOUT", "120"))
RUN_ONCE = os.environ.get("HYPERION_MONITOR_ONCE") == "1"
ACCEPTED_RE = re.compile(r"accepted block (\d+)/(LIVE|\d+) \(([0-9]+) blocks/s")


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def atomic_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(value)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def request(method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    headers = {"content-type": "application/json"} if data is not None else {}
    req = urllib.request.Request(f"{ES_URL}{path}", data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as response:
        value = json.load(response)
    if not isinstance(value, dict):
        raise ValueError(f"Elasticsearch {path} returned a non-object")
    return value


def max_block() -> int:
    body = {"size": 0, "aggs": {"head": {"max": {"field": "block_num"}}}}
    value = request("POST", f"/{CHAIN}-block/_search", body)
    maximum = value.get("aggregations", {}).get("head", {}).get("value")
    return int(maximum) if isinstance(maximum, (int, float)) else 0


def range_count(kind: str, first: int, last: int) -> int:
    query = {"query": {"range": {"block_num": {"gte": first, "lte": last}}}}
    # Delta documents span a rollover alias. Querying the original concrete
    # index silently misses every delta written after its shard reached the
    # Lucene document ceiling.
    index = f"{CHAIN}-delta-rw" if kind == "delta" else f"{CHAIN}-{kind}"
    return int(request("POST", f"/{index}/_count", query)["count"])


def block_id(height: int) -> str | None:
    query = {
        "size": 1,
        "_source": ["block_id"],
        "query": {"term": {"block_num": height}},
    }
    hits = request("POST", f"/{CHAIN}-block/_search", query).get("hits", {}).get("hits", [])
    if not hits:
        return None
    value = hits[0].get("_source", {}).get("block_id")
    return value if isinstance(value, str) else None


def replay_progress(previous: dict[str, Any] | None = None) -> tuple[int, int, int]:
    try:
        with REPLAY_LOG.open("rb") as source:
            source.seek(0, os.SEEK_END)
            source.seek(max(0, source.tell() - 256_000))
            tail = source.read().decode("utf-8", errors="replace")
    except OSError:
        tail = ""
    matches = list(ACCEPTED_RE.finditer(tail))
    if not matches:
        if isinstance(previous, dict) and isinstance(previous.get("replay_head"), int):
            return (
                previous["replay_head"],
                int(previous.get("replay_target") or SOURCE_HEAD),
                int(previous.get("replay_blocks_per_second") or 0),
            )
        return 0, SOURCE_HEAD, 0
    match = matches[-1]
    head = int(match.group(1))
    target = int(match.group(2)) if match.group(2) != "LIVE" else 0
    if FOLLOW_MODE:
        target = 0
    rate = int(match.group(3))
    # The replay process can emit a burst of SHiP backpressure messages after
    # its last accepted-block line.  Never let a short log tail make the
    # published position move backwards while that happens.
    if isinstance(previous, dict) and isinstance(previous.get("replay_head"), int):
        previous_head = previous["replay_head"]
        if previous_head > head:
            return (
                previous_head,
                int(previous.get("replay_target") or target or SOURCE_HEAD),
                int(previous.get("replay_blocks_per_second") or rate),
            )
    return head, target, rate


def load_report() -> dict[str, Any]:
    try:
        value = json.loads(REPORT.read_text(encoding="utf-8"))
        if isinstance(value, dict):
            return value
    except (OSError, json.JSONDecodeError):
        pass
    return {
        "status": "running",
        "audit_start_block": START_BLOCK,
        "verified_through": START_BLOCK - 1,
        "retained_from": START_BLOCK,
        "cumulative": {"blocks": 0, "actions": 0, "deltas": 0},
        "checkpoints": [],
    }


def save_report(report: dict[str, Any], indexed: int) -> None:
    replay_head, replay_target, replay_rate = replay_progress(report)
    report.update(
        {
            "updated_at": now(),
            "replay_head": replay_head,
            "replay_target": replay_target or SOURCE_HEAD,
            "replay_blocks_per_second": replay_rate,
            "hyperion_indexed": indexed,
            "head_lag": max(0, replay_head - indexed),
        }
    )
    if replay_target and report.get("verified_through", 0) >= replay_target:
        report["status"] = "complete"
    atomic_text(REPORT, json.dumps(report, indent=2, sort_keys=True) + "\n")


def delete_before(kind: str, boundary: int) -> None:
    index = f"{CHAIN}-delta-rw" if kind == "delta" else f"{CHAIN}-{kind}"
    encoded = urllib.parse.quote(index, safe="-_")
    body = {"query": {"range": {"block_num": {"lt": boundary}}}}
    result = request(
        "POST",
        f"/{encoded}/_delete_by_query?conflicts=proceed&refresh=true&wait_for_completion=true",
        body,
    )
    if result.get("failures"):
        raise RuntimeError(f"delete failures for {kind}: {result['failures']}")


def verify_available_chunks(report: dict[str, Any], indexed: int) -> bool:
    changed = False
    verified = int(report.get("verified_through", START_BLOCK - 1))
    if indexed < verified:
        raise RuntimeError(
            f"Hyperion indexed height regressed below verified checkpoint: "
            f"{indexed} < {verified}"
        )
    while True:
        first = verified + 1
        full_chunk_end = verified + VERIFY_CHUNK
        if indexed >= full_chunk_end:
            last = full_chunk_end
        elif SOURCE_HEAD > 0 and indexed >= SOURCE_HEAD and verified < SOURCE_HEAD:
            last = SOURCE_HEAD
        else:
            break
        blocks = range_count("block", first, last)
        expected = last - first + 1
        if blocks != expected:
            raise RuntimeError(
                f"Hyperion block completeness failure for {first}..{last}: {blocks}/{expected}"
            )
        actions = range_count("action", first, last)
        deltas = range_count("delta", first, last)
        checkpoint = {
            "first_block": first,
            "last_block": last,
            "last_block_id": block_id(last),
            "blocks": blocks,
            "actions": actions,
            "deltas": deltas,
            "verified_at": now(),
        }
        report.setdefault("checkpoints", []).append(checkpoint)
        cumulative = report.setdefault("cumulative", {"blocks": 0, "actions": 0, "deltas": 0})
        cumulative["blocks"] = int(cumulative.get("blocks", 0)) + blocks
        cumulative["actions"] = int(cumulative.get("actions", 0)) + actions
        cumulative["deltas"] = int(cumulative.get("deltas", 0)) + deltas
        report["verified_through"] = last
        verified = last
        changed = True

    prune_before = max(START_BLOCK, verified - RETAIN_BLOCKS + 1)
    if PRUNE_ENABLED and prune_before > int(report.get("retained_from", START_BLOCK)):
        # The audit report is durable before deletion, so a crash can never
        # erase an unrecorded range. Publish the verified capacity before the
        # potentially slow delete-by-query calls so replay is not needlessly
        # stalled behind historical retention cleanup.
        save_report(report, indexed)
        atomic_text(WATERMARK, f"{indexed}\n")
        for kind in ("action", "delta", "block"):
            delete_before(kind, prune_before)
        report["retained_from"] = prune_before
        changed = True
    return changed


def main() -> None:
    if START_BLOCK < 1 or VERIFY_CHUNK < 1 or RETAIN_BLOCKS < VERIFY_CHUNK:
        raise SystemExit("invalid audit start/chunk/retention configuration")
    report = load_report()
    while True:
        try:
            indexed = max_block()
            verify_available_chunks(report, indexed)
            report["status"] = "running"
            report.pop("error", None)
            save_report(report, indexed)
            # Publish capacity only after all completed audit chunks pass. The
            # replay therefore stops within its bounded lag if completeness
            # verification or retention fails.
            atomic_text(WATERMARK, f"{indexed}\n")
        except (OSError, ValueError, KeyError, RuntimeError, urllib.error.URLError) as error:
            report["status"] = "error"
            report["error"] = str(error)
            save_report(report, int(report.get("hyperion_indexed", 0)))
        if RUN_ONCE:
            break
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
