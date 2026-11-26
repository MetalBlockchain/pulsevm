#!/usr/bin/env python3
"""Start-test kept power-loss images as a real node of a LIVE network: per case, stop the node, replace its chainData/ and
db/ with the image's copies (made by plw-replay.py run/subset), start it, and record whether it joins, how long it takes,
what it logged while starting (WAL recovery, rewinds, state sync, refusals), and - if reference roots are given - whether
every state root it logs after the start equals the reference at the same height.

Configuration (environment; every command runs through /bin/sh):
  PLW_NODE_DIR     the node's directory (holds chainData/, db/, logs/)
  PLW_STOP         stops the node and returns once its MetalGo and plugin processes are gone
  PLW_START        starts the node (returns at once)
  PLW_HEAD         prints the node's accepted head (prints nothing / fails while it is down)
  PLW_REF_HEAD     prints the highest accepted head among the OTHER nodes
  PLW_LOG_GLOB     glob of the node's chain log files (default <node dir>/logs/*.log; rotated files are read too)
  PLW_ROOTS_REF    optional: TSV "height<TAB>root" of the other nodes' "arena state root at block N: <hex>" lines
                   (chain config state_root_log_every = 1), refreshed by you while the test runs
  JOIN_LIMIT       seconds to wait for the join (default 120); a case is "joined" when its head is within 1 of PLW_REF_HEAD
Usage: plw-start.py <classify.jsonl or selected.jsonl> <out.jsonl> [max-cases]
Before the first case the node's own chainData/ and db/ are moved to *.plw-orig; after the last they are put back and the
node is started again. Keep load running on the network while this runs: several outcomes (e.g. a state sync with
transactions pending) only appear under load."""
import glob, json, os, re, shutil, subprocess, sys, time
CL, OUTF = sys.argv[1], sys.argv[2]; MAXC = int(sys.argv[3]) if len(sys.argv) > 3 else 10**9
ND = os.environ["PLW_NODE_DIR"]; LOGG = os.environ.get("PLW_LOG_GLOB", f"{ND}/logs/*.log"); REFR = os.environ.get("PLW_ROOTS_REF")
LIMIT = float(os.environ.get("JOIN_LIMIT", 120))
def sh(c, t=300): return subprocess.run(c, shell=True, capture_output=True, text=True, timeout=t)
def num(c):
    try: return int(sh(c, 10).stdout.strip())
    except Exception: return None
TS = re.compile(r"^\[(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d\.\d+)|^\[(\d\d)-(\d\d)\|(\d\d:\d\d:\d\d\.\d+)")
def lines_since(t0):
    lim = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t0)); yr = time.strftime("%Y", time.gmtime(t0)); out = []
    for f in sorted(glob.glob(LOGG), key=os.path.getmtime):
        if os.path.getmtime(f) < t0 - 5: continue
        for l in open(f, errors="replace"):
            m = TS.match(l)
            if not m: continue
            t = f"{m.group(1)}T{m.group(2)}" if m.group(1) else f"{yr}-{m.group(3)}-{m.group(4)}T{m.group(5)}"
            if t[:19] >= lim: out.append((t, l.rstrip()))
    out.sort(key=lambda x: x[0]); return [l for _, l in out]
ROOT = re.compile(r"arena state root at block (\d+): ([0-9a-f]{64})")
KEY = re.compile(r"did not shut down cleanly|dropping the incomplete|rewinding|database revision|block log contains|could not initialize|"
                 r"controller initialization|write-ahead|missed a block|repairing accepted|starting consensus|\[error\]|panic|fatal|"
                 r"does not match|refus|rebuil|corrupt|No space|state sync|state summary|unexpected message|ALARM|abandon|"
                 r"error creating chain|truncat|torn|discard|zero")
NOISE = re.compile(r"built block has no|arena state root at block|block_accept called|accepted successfully|could not verify block|refused \d+ more")
def stop(): sh(os.environ["PLW_STOP"], 120); time.sleep(0.5)
rows = [json.loads(l) for l in open(CL)]; cases = [r for r in rows if r.get("kept")][:MAXC]
done = {json.loads(l)["entry"] for l in open(OUTF)} if os.path.exists(OUTF) else set()
stop()
for d in ("chainData", "db"):
    if not os.path.exists(f"{ND}/{d}.plw-orig"): shutil.move(f"{ND}/{d}", f"{ND}/{d}.plw-orig")
for r in cases:
    if r["entry"] in done: continue
    stop()
    for d in ("chainData", "db"):
        shutil.rmtree(f"{ND}/{d}", ignore_errors=True); shutil.copytree(f"{r['kept']}/{d}", f"{ND}/{d}", symlinks=True)
    t0 = time.time(); sh(os.environ["PLW_START"])
    res = {"entry": r["entry"], "why": r["why"], "after_mark": r.get("after_mark"), "class": r["class"], "t": time.strftime("%FT%TZ", time.gmtime(t0))}
    joined = failed = None
    while time.time() - t0 < LIMIT:
        h = num(os.environ["PLW_HEAD"]); ref = num(os.environ["PLW_REF_HEAD"])
        if h is not None and ref is not None and h >= ref - 1: joined = round(time.time() - t0, 1); res["join_height"] = h; break
        if time.time() - t0 > 8 and int(time.time() - t0) % 4 == 0:
            f = [l for l in lines_since(t0) if re.search(r"controller initialization failed|could not initialize|panicked|error creating chain", l)]
            if f: failed = f[0][:500]; time.sleep(3); break
        time.sleep(0.5)
    res["joined_s"] = joined; res["failed"] = failed
    if joined: time.sleep(15)
    ls = lines_since(t0); j = "\n".join(ls)
    res["startup"] = [l[:420] for l in ls if KEY.search(l) and not NOISE.search(l)][:40]
    res["recovered"] = re.findall(r"recovered (\d+) accepted block\(s\) from the arena write-ahead log([^;]*); state is at revision (\d+)", j)
    res["rewinding"] = sorted(set(re.findall(r"rewinding ([\w ]+?) from (\d+) to durable Arena revision (\d+)", j)))
    for k, pat in (("n_sync_applied", r"state sync applied at height"), ("n_sync_finished", r"state sync finished, notifying engine"),
                   ("n_unexpected_pending", r"unexpected message from the VM.*Pending Transactions"), ("n_alarm", r"ALARM event=state_sync.install_abandoned"),
                   ("n_skipping_summary", r"skipping state summary")):
        res[k] = len(re.findall(pat, j))
    m = re.search(r"proposervm height index \((\d+)\) should never be lower than the inner height index \((\d+)\)", j)
    if m: res["proposervm_behind"] = {"proposervm": int(m.group(1)), "inner": int(m.group(2))}
    if REFR and os.path.exists(REFR):
        mine = {}
        for l in ls:
            x = ROOT.search(l)
            if x: mine.setdefault(int(x.group(1)), set()).add(x.group(2))
        ref = {}
        for l in open(REFR):
            p = l.rstrip("\n").split("\t")
            if len(p) >= 2: ref.setdefault(int(p[0]), set()).add(p[1])
        common = [h for h in mine if h in ref]
        res["roots"] = {"logged": len(mine), "compared": len(common), "equal": sum(1 for h in common if mine[h] == ref[h]),
                        "differ": [h for h in common if mine[h] != ref[h]][:10]}
    else:
        res["roots"] = {"logged": 0, "compared": 0, "equal": 0, "differ": []}
    open(OUTF, "a").write(json.dumps(res) + "\n")
    print(f"{time.strftime('%T')} entry {r['entry']} joined={joined} failed={bool(failed)} roots={res['roots']['equal']}/{res['roots']['compared']}", flush=True)
stop()
for d in ("chainData", "db"):
    shutil.rmtree(f"{ND}/{d}", ignore_errors=True); shutil.move(f"{ND}/{d}.plw-orig", f"{ND}/{d}")
sh(os.environ["PLW_START"]); print("START-DONE", flush=True)
