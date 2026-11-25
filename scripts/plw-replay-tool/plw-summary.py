#!/usr/bin/env python3
"""Summarize plw-replay.py classify.jsonl (offline image states) and plw-start.py results.
Usage: plw-summary.py classify <classify.jsonl> | start <start.jsonl>"""
import collections, json, sys
def classify(p):
    rows = [json.loads(l) for l in open(p)]; C = collections.Counter
    why = C(r["why"].split(":")[0] for r in rows)
    print(f"cuts={len(rows)} by kind: {dict(why)}")
    fk = C(); wal = C(); tails = C(); f3 = 0; f6 = 0; zi = C(); zmax = collections.defaultdict(int); zl = C(); nc = C(); extra = C(); mf = 0
    rel = C(); real = []
    for r in rows:
        if "mount_error" in r: mf += 1
        fk[r["class"].split("|")[0]] += 1
        if r.get("fsck_real_msgs"): real.append((r["entry"], r["fsck_real_msgs"][:3]))
        c = r.get("c", {}); w = c.get("wal")
        if w is None: wal["no WAL file"] += 1
        else:
            wal[w["outcome"]] += 1
            if w.get("tail_bytes"): tails[f"{w['outcome']} tail={w['tail_bytes']}B allzero={w.get('tail_all_zero')}"] += 1
            if w.get("valid_records_after_stop"): f3 += 1
            if w["outcome"] == "REFUSE-altered" and w.get("tail_all_zero"): f6 += 1
        for k in ("block_log", "trace_log", "chain_state_log"):
            x = c.get(k) or {}
            if x.get("zero_tail_entries"): zi[k] += 1; zmax[k] = max(zmax[k], x["zero_tail_entries"])
            if (x.get("log_zero_tail") or 0) > 64: zl[k] += 1
            if x.get("contiguous_prefix") is False: nc[k] += 1
        for e in c.get("extra_files", []) or []: extra[e] += 1
        bl = (c.get("block_log") or {}).get("last_nonzero"); wl = w.get("rev_last") if w else None
        if bl is not None and wl is not None: rel[f"block-index-last-nonzero minus WAL-last = {bl - wl}"] += 1
    print(f"fsck: {dict(fk)}  mount failures: {mf}  real (non-counter) fsck repairs: {len(real)} {real[:5]}")
    print(f"WAL outcome (plugin's scan_wal rules): {dict(wal)}")
    print(f"WAL tails: {dict(tails)}")
    print(f"F3 hazard (a digest-valid record after the stop point): {f3}   F6 (all-zero tail refused as altered): {f6}")
    print(f"index zero tails: {dict(zi)} max zero entries {dict(zmax)}; .log zero tails >64B: {dict(zl)}; non-contiguous index prefix: {dict(nc)}")
    print(f"extra (temporary) files present: {dict(extra)}")
    print("block index vs WAL: " + ", ".join(f"{k.split('= ')[1]}:{v}" for k, v in sorted(rel.items(), key=lambda x: int(x[0].split('= ')[1]))))
def start(p):
    rows = [json.loads(l) for l in open(p)]; C = collections.Counter
    j = [r for r in rows if r["joined_s"] is not None]; f = [r for r in rows if r["joined_s"] is None]
    print(f"cases={len(rows)} joined={len(j)} not-joined={len(f)}")
    if j: js = sorted(r["joined_s"] for r in j); print(f"join s: min {js[0]} median {js[len(js) // 2]} max {js[-1]}")
    for r in f: print(f"  NOT JOINED entry {r['entry']} {r['class']}: {r['failed'] or (r['startup'][-3:] if r['startup'] else 'no lines')}")
    rec = C(); rew = C(); kinds = C()
    for r in rows:
        k = []
        if r["recovered"]: k.append("WAL-recovered" + ("+discarded-partial" if any("discarded" in x[1] for x in r["recovered"]) else ""))
        if r["rewinding"]:
            k.append("rewind"); [rew.__setitem__(f"{a}: {int(b) - int(c)} block(s)", rew[f"{a}: {int(b) - int(c)} block(s)"] + 1) for a, b, c in r["rewinding"]]
        if any("dropping the incomplete" in l for l in r["startup"]): k.append("dropped-accept-record")
        if any("rebuil" in l.lower() for l in r["startup"]): k.append("index-rebuild")
        if any("[error]" in l for l in r["startup"]): k.append("error-lines")
        if any("[warn]" in l and "chain id" not in l for l in r["startup"]): k.append("warn-lines")
        kinds["+".join(k) or "plain start"] += 1
    print(f"start-up kinds: {dict(kinds)}")
    # state sync / quarantine counters
    g = lambda k: sum(1 for r in rows if r.get(k)); t = lambda k: sum(r.get(k, 0) for r in rows)
    print(f"state sync: cases with state sync applied {g('n_sync_applied')} (finished {g('n_sync_finished')}), with 'unexpected message ... Pending Transactions' {g('n_unexpected_pending')} (total {t('n_unexpected_pending')}), "
          f"applied-but-never-finished {sum(1 for r in rows if r.get('n_sync_applied', 0) > r.get('n_sync_finished', 0))}, ALARM install_abandoned {g('n_alarm')}, skipping summary {g('n_skipping_summary')}, "
          f"proposervm-behind refusals {g('proposervm_behind')}")
    print(f"rewinds: {dict(rew)}")
    eq = sum(r["roots"]["equal"] for r in rows); cmp_ = sum(r["roots"]["compared"] for r in rows); d = [(r["entry"], r["roots"]["differ"]) for r in rows if r["roots"]["differ"]]
    print(f"roots: compared {cmp_} heights over all cases, equal {eq}, cases with a differing root: {len(d)} {d[:5]}")
    lines = C()
    for r in rows:
        for l in r["startup"]:
            if "[warn]" in l or "[error]" in l:
                import re; lines[re.sub(r"\d{3,}", "N", l.split("] ", 2)[-1])[:220]] += 1
    print("warn/error line shapes:"); [print(f"  {v:4d} {k}") for k, v in lines.most_common(25)]
if __name__ == "__main__":
    {"classify": classify, "start": start}[sys.argv[1]](sys.argv[2])
