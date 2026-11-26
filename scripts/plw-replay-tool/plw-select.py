#!/usr/bin/env python3
"""Choose the kept images to start-test. Every named-mark image; up to
MAX_SSI images with state_sync_installing (spread evenly over them), up to MAX_EXTRA with other temporary files; every image
with a .log zero tail > 64 B; up to 3 per class; then random kept images (seed 5) up to <total>.
Usage: plw-select.py <classify.jsonl>... <total> > selected.jsonl   (env MAX_SSI default 40, MAX_EXTRA default 15)"""
import json, os, random, sys
files, tot = sys.argv[1:-1], int(sys.argv[-1]); rows = [json.loads(l) for f in files for l in open(f) if '"kept"' in l]
MS, ME = int(os.environ.get("MAX_SSI", 40)), int(os.environ.get("MAX_EXTRA", 15)); sel = {}; per = {}
key = lambda r: str(r["entry"])
ex = lambda r: [e for e in (r["c"].get("extra_files") or []) if e != "synced_schedule.bin"]
ssi = [r for r in rows if "state_sync_installing" in ex(r)]; oth = [r for r in rows if ex(r) and r not in ssi]
for r in rows:
    lz = any(((r["c"].get(k) or {}).get("log_zero_tail") or 0) > 64 for k in ("block_log", "trace_log", "chain_state_log"))
    if r["why"].startswith("mark:") or lz: sel[key(r)] = r
for group, cap in ((ssi, MS), (oth, ME)):
    step = max(1, len(group) // cap) if group else 1
    for r in group[::step][:cap]: sel.setdefault(key(r), r)
for r in rows:
    if per.get(r["class"], 0) < int(os.environ.get("PER", 3)): per[r["class"]] = per.get(r["class"], 0) + 1; sel.setdefault(key(r), r)
rest = [r for r in rows if key(r) not in sel]; random.Random(5).shuffle(rest)
for r in rest[:max(0, tot - len(sel))]: sel[key(r)] = r
for r in sorted(sel.values(), key=lambda r: str(r["entry"])): print(json.dumps(r))
