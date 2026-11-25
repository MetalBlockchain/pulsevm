#!/usr/bin/env python3
"""Replay a dm-log-writes log (recorded with plw-dev.sh) to many cut points and classify each resulting image of a
PulseVM node directory (MetalGo layout: chainData/<blockchain id>/ for the plugin's data, db/ for MetalGo's database).

Log format (kernel drivers/md/dm-log-writes.c; xfstests src/log-writes/log-writes.[ch]): sector 0 = super {u64 magic
0x6a736677736872, u64 version, u64 nr_entries, u32 sectorsize}; from offset sectorsize on, one entry per sector
{u64 sector, u64 nr_sectors, u64 flags, u64 data_len, mark text}, followed (unless DISCARD) by nr_sectors*sectorsize
data bytes. Flags: 1 FLUSH, 2 FUA, 4 DISCARD, 8 MARK, 16 METADATA. Replay = pwrite(data, sector*sectorsize) in log
order; DISCARD = punch hole. A cut "after entry k" = every logged write up to k applied, nothing after (the state a
crash leaves if the disk lost exactly the suffix of completed writes; NOT arbitrary reordering of unflushed writes).

Settings (environment): PLW_WORK (work dir, default ./plw-work; the replay base image is written to
$PLW_WORK/<name>/replay-base.img), PLW_DEVSIZE (bytes of the recorded device, default 2 GiB = plw-dev.sh's default),
PLW_CHAIN_SUBDIR (path of the PulseVM data dir inside the node dir, e.g. chainData/<blockchain id>; default: the first
directory under chainData/ that holds arena_state.bin, arena_wal.bin or block_log.log). Scratch images go to /dev/shm.
Requires root (mount), e2fsck, cp --sparse.

Usage:
  plw-replay.py index <log.img> <out.tsv>
  plw-replay.py run <log.img> <index.tsv> <name> <outdir> [--flush-max N] [--random N] [--keep-per-class K] [--keep-random P]
      cuts = every MARK, FLUSH/FUA points (all inside event windows, others subsampled to --flush-max), --random data-write
      entries. For each cut: copy the image (sparse) to /dev/shm, e2fsck -fy, mount ro, classify the node's files
      (WAL scanned with the plugin's own scan_wal rules, db.rs:195-254 at dbe5fcee, PVMWAL04 keyed), one JSON line to outdir/classify.jsonl.
      Keeps chainData/ + db/ of the first K cuts of each class and a fraction P of the rest under outdir/cases/<entry>/.
      --sync-writes N adds up to N data-write entries inside the state-sync windows (marks restarted-for-sync-* ..
      joined-after-sync-*) as cuts.
  plw-replay.py subset <log.img> <index.tsv> <name> <outdir> [--n N] [--keep-per-class K] [--keep-random P]
  plw-replay.py image <log.img> <index.tsv> <entry> <out.img>     image after entry (for spot checks / replay-log cross-check)
Marks the cut selection understands (write them with plw-dev.sh mark): "copied" (start) and "end" (required); pre-*  ..
restarted* = an event window (every FLUSH/FUA inside is a cut); restarted-for-sync-* .. joined-after-sync-* = a state-sync
window (--sync-writes N data writes inside become cuts); marks starting with "h" are progress marks (not cut points).
"""
import ctypes, hashlib, json, os, random, shutil, struct, subprocess, sys, time

FLUSH, FUA, DISCARD, MARK, META = 1, 2, 4, 8, 16
WORK = os.environ.get("PLW_WORK", os.path.join(os.getcwd(), "plw-work"))
DEVSIZE = int(os.environ.get("PLW_DEVSIZE", 2 << 30))
def chain_dir(mnt):
    sub = os.environ.get("PLW_CHAIN_SUBDIR")
    if sub: return f"{mnt}/{sub}"
    for d in sorted(os.listdir(f"{mnt}/chainData")) if os.path.isdir(f"{mnt}/chainData") else []:
        p = f"{mnt}/chainData/{d}"
        if any(os.path.exists(f"{p}/{f}") for f in ("arena_state.bin", "arena_wal.bin", "block_log.log")): return p
    return f"{mnt}/chainData/MISSING"
def punch(fd, off, ln):
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    if libc.fallocate(fd, 3, ctypes.c_long(off), ctypes.c_long(ln)) != 0:  # PUNCH_HOLE|KEEP_SIZE
        os.pwrite(fd, b"\0" * ln, off)

def super_(f):
    f.seek(0); b = f.read(32)
    magic, ver, n, ss = struct.unpack_from("<QQQI", b)
    assert magic == 0x6a736677736872, hex(magic)
    return n, ss

def index(logp, outp):
    f = open(logp, "rb"); n, ss = super_(f); pos = ss; out = open(outp, "w")
    out.write(f"# nr_entries={n} sectorsize={ss}\n")
    for i in range(n):
        f.seek(pos); h = f.read(ss)
        sec, nr, fl, dl = struct.unpack_from("<QQQQ", h)
        mark = h[32:32 + dl].decode(errors="replace") if fl & MARK else ""
        out.write(f"{i}\t{pos + ss}\t{sec}\t{nr}\t{fl}\t{mark}\n")
        pos += ss + (0 if fl & DISCARD else nr * ss)
    print(f"indexed {n} entries, sectorsize {ss}, log bytes used {pos}")

def load_index(p):
    ents = []; ss = None
    for l in open(p):
        if l.startswith("#"): ss = int(l.split("sectorsize=")[1]); continue
        a = l.rstrip("\n").split("\t"); ents.append((int(a[0]), int(a[1]), int(a[2]), int(a[3]), int(a[4]), a[5]))
    return ents, ss

class Replayer:
    def __init__(self, logp, ents, ss, img):
        self.f = open(logp, "rb"); self.ents = ents; self.ss = ss; self.next = 0
        with open(img, "wb") as o: o.truncate(DEVSIZE)
        self.fd = os.open(img, os.O_RDWR)
    def upto(self, k):  # apply entries next..k inclusive
        while self.next <= k:
            i, doff, sec, nr, fl, _ = self.ents[self.next]
            if fl & DISCARD: punch(self.fd, sec * self.ss, nr * self.ss)
            elif nr:
                self.f.seek(doff); os.pwrite(self.fd, self.f.read(nr * self.ss), sec * self.ss)
            self.next += 1

def _rec_at(d, pos, key):
    """PulseVM dbe5fcee db.rs wal_record_at: (payload start, payload end, record end) if a record that verifies starts at pos."""
    if pos + 8 > len(d): return None
    n = struct.unpack_from("<Q", d, pos)[0]; ps = pos + 8; pe = ps + n; re_ = pe + 32
    if re_ > len(d): return None
    if hashlib.sha256(key + d[pos:pos + 8] + d[ps:pe]).digest() != d[pe:re_]: return None
    return ps, pe, re_

BUDGET = 256 * 1024 * 1024   # PulseVM 25956263 db.rs WAL_DAMAGE_SCAN_BUDGET
WAL_MAX_REVISION_GAP = 1_000_000

def _could_follow(d, pos, expect):
    """Cheap FramePrefix check from pulsevm_arena::db before hashing a candidate."""
    if expect is None:
        return True
    if pos + 8 + 16 > len(d):
        return False
    revision, table_count = struct.unpack_from("<qQ", d, pos + 8)
    last_revision, last_table_count = expect
    return (table_count == last_table_count and revision > last_revision
            and revision <= last_revision + WAL_MAX_REVISION_GAP)

def _valid_follows(d, frm, key, expect=None):
    """Return a valid later frame offset, None, or "BUDGET".

    The 256 MiB budget counts only candidates with a plausible FramePrefix:
    revision greater than the last good frame and within 1,000,000, with the
    same table count. The scanner still hashes each plausible candidate, since
    hostile WAL bytes can forge that cheap prefix.
    """
    p = frm; hashed = 0
    while p + 8 + 16 + 32 <= len(d):
        n = struct.unpack_from("<Q", d, p)[0]
        if (16 <= n <= len(d) - p) and _could_follow(d, p, expect):
            hashed += n
            if hashed > BUDGET: return "BUDGET"
            if _rec_at(d, p, key): return p
        p += 1
    return None

def scan_wal(d):
    """The plugin's scan_wal (dbe5fcee crates/pulsevm_arena/src/db.rs:195-254, PVMWAL04: 8-byte magic + 32-byte random key,
    digest SHA-256(key || length || payload); an all-zero file is a torn (never-happened) append): a record that cannot be
    completed or does not verify ends the log as a torn tail unless an intact record follows it anywhere, in which case the
    node refuses ("altered, not cut short")."""
    r = {"size": len(d)}
    if not d: r["outcome"] = "empty"; return r
    if not any(d): r["outcome"] = "torn-all-zero"; r["records"] = 0; return r
    if len(d) < 8:
        r["outcome"] = "torn-header" if b"PVMWAL04".startswith(d) else "REFUSE-bad-header"; return r
    if d[:8] != b"PVMWAL04": r["outcome"] = "REFUSE-not-checksummed-format"; return r
    if len(d) < 40: r["outcome"] = "torn-key"; r["records"] = 0; return r
    key = d[8:40]
    pos = 40; revs = []; prefix = None
    while pos < len(d):
        rec = _rec_at(d, pos, key)
        if rec is None:
            nxt = _valid_follows(d, pos + 1, key, prefix)
            if nxt == "BUDGET": r["outcome"] = "REFUSE-scan-budget"; r["refuse_at"] = pos; break
            if nxt is not None: r["outcome"] = "REFUSE-altered"; r["refuse_at"] = pos; r["next_valid"] = nxt; break
            r["outcome"] = "torn"; break
        ps, pe, re_ = rec
        revision = struct.unpack_from("<q", d, ps)[0] if pe - ps >= 8 else None
        revs.append(revision)
        if pe - ps >= 16:
            prefix = struct.unpack_from("<qQ", d, ps)
        pos = re_
    else:
        r["outcome"] = "clean"
    r["records"] = len(revs); r["rev_first"] = revs[0] if revs else None; r["rev_last"] = revs[-1] if revs else None
    r["valid_len"] = pos; tail = d[pos:]; r["tail_bytes"] = len(tail)
    if tail:
        r["tail_all_zero"] = not any(tail)
        r["tail_trailing_zero_bytes"] = len(tail) - len(tail.rstrip(b"\0"))
        r["valid_records_after_stop"] = 1 if r["outcome"] == "REFUSE-altered" else 0
    return r

def metalgo_db(mnt):
    """What kind of MetalGo database the image holds (913b38b6 docs: pebbledb keeps OPTIONS-* in its directory)."""
    out = {"dirs": [], "pebble_options": 0, "pebble_wal_logs": 0, "pebble_sst": 0, "leveldb_ldb": 0, "manifest": 0}
    for d, ds, fs in os.walk(f"{mnt}/db"):
        rel = os.path.relpath(d, f"{mnt}/db")
        if rel.count(os.sep) <= 2: out["dirs"].append(rel)
        for f in fs:
            if f.startswith("OPTIONS-"): out["pebble_options"] += 1
            elif f.endswith(".log"): out["pebble_wal_logs"] += 1
            elif f.endswith(".sst"): out["pebble_sst"] += 1
            elif f.endswith(".ldb"): out["leveldb_ldb"] += 1
            elif f.startswith("MANIFEST-"): out["manifest"] += 1
    out["dirs"] = sorted(out["dirs"])[:12]
    return out

def idx_end(p):
    """A 12-byte index record = u32 block number + u64 log offset (state_history/log.rs). Reports the record count, the
    last record, how many records at the end are all zero, and the last non-zero block."""
    try:
        d = open(p, "rb").read()
    except FileNotFoundError:
        return None
    k = len(d) // 12; r = {"entries": k, "rem": len(d) % 12, "bytes": len(d)}
    if not k: return r
    recs = [struct.unpack_from("<IQ", d, i * 12) for i in range(k)]
    z = 0
    while z < k and recs[k - 1 - z] == (0, 0): z += 1
    r["last"] = recs[-1][0]; r["zero_tail_entries"] = z
    r["last_nonzero"] = recs[k - 1 - z][0] if z < k else None
    r["first"] = recs[0][0]
    good = all(recs[i][0] == recs[0][0] + i for i in range(k - z))
    r["contiguous_prefix"] = good
    return r

def log_tail(p):
    try:
        sz = os.path.getsize(p)
        with open(p, "rb") as f:
            f.seek(max(0, sz - 262144)); t = f.read()
        return sz, len(t) - len(t.rstrip(b"\0"))
    except FileNotFoundError:
        return None, None

def classify(mnt, node):
    c = chain_dir(mnt); r = {}
    try:
        files = sorted(os.listdir(c))
    except FileNotFoundError:
        return {"chaindir": "missing"}
    r["files"] = {f: os.path.getsize(f"{c}/{f}") for f in files if os.path.isfile(f"{c}/{f}")}
    r["extra_files"] = [f for f in files if f not in ("arena_metadata.json", "arena_state.bin", "arena_wal.bin", "block_log.index",
        "block_log.log", "chain_state_log.index", "chain_state_log.log", "trace_log.index", "trace_log.log", "lost+found",
        "migration-restore-verified", "protocol_records.json", "synced_schedule.bin")]
    r["wal"] = scan_wal(open(f"{c}/arena_wal.bin", "rb").read()) if "arena_wal.bin" in files else None
    for k in ("block_log", "trace_log", "chain_state_log"):
        r[k] = idx_end(f"{c}/{k}.index")
        if r[k] is not None: r[k]["log_size"], r[k]["log_zero_tail"] = log_tail(f"{c}/{k}.log")
    if "arena_state.bin" in files:
        b = open(f"{c}/arena_state.bin", "rb").read(); r["ckpt_sha8"] = hashlib.sha256(b).hexdigest()[:8]
        r["ckpt_zero_tail"] = len(b) - len(b.rstrip(b"\0"))
    for j in ("arena_metadata.json", "protocol_records.json"):
        if j in files:
            try: json.loads(open(f"{c}/{j}").read()); r[j] = "ok"
            except Exception as e: r[j] = f"BAD {type(e).__name__} size={r['files'][j]}"
    try: r["db_files"] = sum(len(fs) for _, _, fs in os.walk(f"{mnt}/db")); r["metalgo_db"] = metalgo_db(mnt)
    except Exception: r["db_files"] = None
    return r

BENIGN = ("recovering journal", "Free blocks count wrong", "Free inodes count wrong", "Fix? yes", "FILE SYSTEM WAS MODIFIED",
          "files (", "Clearing orphaned inode", "Truncating orphaned inode", "Directories count wrong", "Inode bitmap differences",
          "Block bitmap differences", "Padding at end of", "e2fsck")
def fsck_kind(r):
    if r.get("fsck_rc", 0) >= 4: return f"fsck-UNFIXED{r['fsck_rc']}"
    real = [m for m in r.get("fsck_msgs", []) if not any(b in m for b in BENIGN) and m.strip() and not m.strip().startswith(("-", "+"))]
    r["fsck_real_msgs"] = real
    orph = any("orphaned inode" in m for m in r.get("fsck_msgs", []))
    return ("fsck-REPAIR" if real else "fsck-ok") + ("+orphan" if orph else "")

def klass(r):
    if r.get("fsck_rc", 0) >= 4: return f"fsck{r['fsck_rc']}"
    c = r.get("c", {})
    if c.get("chaindir") == "missing": return "no-chaindir"
    w = c.get("wal"); bl = (c.get("block_log") or {}).get("last_nonzero"); tl = (c.get("trace_log") or {}).get("last_nonzero")
    cl = (c.get("chain_state_log") or {}).get("last_nonzero")
    ws = "nowal" if w is None else w["outcome"]
    if w and w.get("tail_bytes"): ws += f"+tail{'Z' if w.get('tail_all_zero') else ''}{'>40' if w['tail_bytes'] > 40 else '<=40'}"
    if w and w.get("valid_records_after_stop"): ws += "+VALID-AFTER"
    rel = lambda a, b: "na" if a is None or b is None else ("=" if a == b else ("+" if a > b else "-"))
    wl = w.get("rev_last") if w else None
    bad = [k for k in ("block_log", "trace_log", "chain_state_log") if (c.get(k) or {}).get("rem")]
    zi = [k.split("_")[0] for k in ("block_log", "trace_log", "chain_state_log") if (c.get(k) or {}).get("zero_tail_entries")]
    zl = [k.split("_")[0] for k in ("block_log", "trace_log", "chain_state_log") if ((c.get(k) or {}).get("log_zero_tail") or 0) > 64]
    nc = [k.split("_")[0] for k in ("block_log", "trace_log", "chain_state_log") if (c.get(k) or {}).get("contiguous_prefix") is False]
    js = [k for k in ("arena_metadata.json", "protocol_records.json") if str(c.get(k, "ok")).startswith("BAD")]
    return f"{fsck_kind(r)}|{ws}|blk-wal{rel(bl, wl)}|trace-blk{rel(tl, bl)}|cs-blk{rel(cl, bl)}" + \
        (f"|partial-idx:{','.join(bad)}" if bad else "") + (f"|idx-zero-tail:{','.join(zi)}" if zi else "") + \
        (f"|log-zero-tail:{','.join(zl)}" if zl else "") + (f"|idx-NONCONTIG:{','.join(nc)}" if nc else "") + \
        (f"|badjson:{','.join(js)}" if js else "") + \
        (f"|extra:{','.join(c.get('extra_files', []))}" if c.get("extra_files") else "")

def run(logp, idxp, node, outd, flush_max, nrand, keepk, keepp, nsync=0):
    ents, ss = load_index(idxp); os.makedirs(f"{outd}/cases", exist_ok=True)
    marks = [(e[0], e[5]) for e in ents if e[4] & MARK]
    names = [m for _, m in marks]
    start = next(i for i, m in marks if m == "copied"); end = next(i for i, m in marks if m == "end")
    # event windows: from each pre-* mark to the next restarted* mark
    wins = []; openm = None
    for i, m in marks:
        if m.startswith("pre-"): openm = i
        elif m.startswith("restarted") and openm is not None: wins.append((openm, i)); openm = None
    fl = [e[0] for e in ents if start < e[0] < end and e[4] & (FLUSH | FUA)]
    inwin = [k for k in fl if any(a <= k <= b for a, b in wins)]; outwin = [k for k in fl if k not in set(inwin)]
    step = 1 if flush_max <= 0 else (max(1, len(outwin) // max(1, flush_max - len(inwin))) if outwin else 1)  # --flush-max 0 = every flush
    data_w = [e[0] for e in ents if start < e[0] < end and not e[4] & (FLUSH | FUA | MARK | DISCARD) and e[3]]
    rnd = random.Random(11); rsamp = rnd.sample(data_w, min(nrand, len(data_w)))
    # state-sync windows (restarted-for-sync-* .. joined-after-sync-*): up to --sync-writes data-write entries inside them
    swins = []; openm = None
    for i, m in marks:
        if m.startswith("restarted-for-sync"): openm = i
        elif m.startswith("joined-after-sync") and openm is not None: swins.append((openm, i)); openm = None
    sw = [e[0] for e in ents if any(a < e[0] < b for a, b in swins) and not e[4] & (MARK | DISCARD) and e[3]]
    ssamp = sorted(random.Random(13).sample(sw, min(nsync, len(sw))))
    cuts = {}
    for i, m in marks:
        if start <= i <= end and not m.startswith("h"): cuts[i - 1] = f"mark:{m}"
    for k in inwin: cuts.setdefault(k, "flush-in-event-window")
    for k in outwin[::step]: cuts.setdefault(k, "flush")
    for k in rsamp: cuts.setdefault(k, "between-flushes")
    for k in ssamp: cuts.setdefault(k, "sync-window")
    order = sorted(cuts)
    meta = {"entries": len(ents), "marks": len(marks), "flush_fua_in_run": len(fl), "flush_in_windows": len(inwin), "windows": wins,
            "data_writes_in_run": len(data_w), "cuts": len(order), "start": start, "end": end, "sync_windows": swins, "sync_window_writes": len(sw), "sync_window_cuts": len(ssamp)}
    json.dump(meta, open(f"{outd}/cuts-meta.json", "w"), indent=1); print(json.dumps(meta)[:600], flush=True)
    base = f"{WORK}/{node}/replay-base.img"; rp = Replayer(logp, ents, ss, base)
    case = f"/dev/shm/plw-case-{node}.img"; mnt = f"/mnt/plw-case-{node}"; os.makedirs(mnt, exist_ok=True)
    out = open(f"{outd}/classify.jsonl", "a"); seen = {}; lastmark = "copied"; markat = dict(marks)
    mi = 0; t0 = time.time()
    for n, k in enumerate(order):
        rp.upto(k)
        while mi < len(marks) and marks[mi][0] <= k: lastmark = marks[mi][1]; mi += 1
        subprocess.run(["cp", "--sparse=always", base, case], check=True)
        fs = subprocess.run(["e2fsck", "-fy", case], capture_output=True, text=True)
        r = {"entry": k, "why": cuts[k], "after_mark": lastmark, "fsck_rc": fs.returncode,
             "fsck_msgs": [l for l in fs.stdout.splitlines() if l and not l.startswith(("Pass ", "e2fsck "))][:16]}
        mr = subprocess.run(["mount", "-o", "ro,loop", case, mnt], capture_output=True, text=True)
        if mr.returncode != 0:
            r["mount_error"] = mr.stderr.strip()[:200]
        else:
            try:
                r["c"] = classify(mnt, node)
                r["class"] = klass(r)
                cnt = seen.get(r["class"], 0); seen[r["class"]] = cnt + 1
                if cnt < keepk or rnd.random() < keepp or cuts[k].startswith("mark:"):
                    d = f"{outd}/cases/{k}"; os.makedirs(d, exist_ok=True)
                    subprocess.run(["cp", "-a", f"{mnt}/chainData", f"{mnt}/db", d], check=True); r["kept"] = d
            finally:
                subprocess.run(["umount", mnt])
        r.setdefault("class", f"mount-failed|fsck{r['fsck_rc']}")
        out.write(json.dumps(r) + "\n"); out.flush()
        if n % 50 == 0: print(f"{time.strftime('%T')} {n}/{len(order)} entry {k} {r['class']} ({time.time() - t0:.0f}s)", flush=True)
    os.unlink(case)
    print("CLASSES:"); [print(f"  {v:5d} {c}") for c, v in sorted(seen.items(), key=lambda x: -x[1])]
    print("RUN-DONE", flush=True)

def subset(logp, idxp, node, outd, nsamp, keepk, keepp):
    """Volatile-cache model: barriers = entries with the FLUSH (preflush) flag; everything completed before a barrier is
    durable. Pick a barrier b_i and a cut c uniformly in (b_i, b_{i+1}); of the writes completed in (b_i, c], each non-FUA
    write survives with p = 0.5, FUA writes always survive. Marks/discards in that span are applied/ignored as logged."""
    ents, ss = load_index(idxp); os.makedirs(f"{outd}/cases", exist_ok=True)
    marks = [(e[0], e[5]) for e in ents if e[4] & MARK]
    start = next(i for i, m in marks if m == "copied"); end = next(i for i, m in marks if m == "end")
    bars = [e[0] for e in ents if start <= e[0] < end and e[4] & FLUSH]
    rnd = random.Random(1111); samples = []
    for _ in range(nsamp):
        i = rnd.randrange(len(bars) - 1); b, nb = bars[i], bars[i + 1]
        if nb - b < 2: continue
        c = rnd.randint(b + 1, nb - 1)
        span = [k for k in range(b + 1, c + 1) if ents[k][3] and not ents[k][4] & (MARK | DISCARD)]
        keep = [k for k in span if ents[k][4] & FUA or rnd.random() < 0.5]
        samples.append((b, c, keep, len(span)))
    samples.sort()
    base = f"{WORK}/{node}/replay-base.img"; rp = Replayer(logp, ents, ss, base)
    case = f"/dev/shm/plw-case-{node}.img"; mnt = f"/mnt/plw-case-{node}"; os.makedirs(mnt, exist_ok=True)
    out = open(f"{outd}/classify.jsonl", "a"); seen = {}; t0 = time.time(); lf = open(logp, "rb")
    for n, (b, c, keep, nspan) in enumerate(samples):
        rp.upto(b)
        subprocess.run(["cp", "--sparse=always", base, case], check=True)
        fd = os.open(case, os.O_RDWR)
        for k in keep:
            _, doff, sec, nr, fl, _ = ents[k]; lf.seek(doff); os.pwrite(fd, lf.read(nr * ss), sec * ss)
        os.close(fd)
        fs = subprocess.run(["e2fsck", "-fy", case], capture_output=True, text=True)
        lastmark = max((m for m in marks if m[0] <= c), default=(0, "?"))[1]
        r = {"entry": f"{b}+{c}", "why": "subset", "barrier": b, "cut": c, "span_writes": nspan, "kept_writes": len(keep),
             "after_mark": lastmark, "fsck_rc": fs.returncode,
             "fsck_msgs": [l for l in fs.stdout.splitlines() if l and not l.startswith(("Pass ", "e2fsck "))][:16]}
        mr = subprocess.run(["mount", "-o", "ro,loop", case, mnt], capture_output=True, text=True)
        if mr.returncode != 0: r["mount_error"] = mr.stderr.strip()[:200]
        else:
            try:
                r["c"] = classify(mnt, node); r["class"] = klass(r)
                cnt = seen.get(r["class"], 0); seen[r["class"]] = cnt + 1
                if cnt < keepk or rnd.random() < keepp:
                    d = f"{outd}/cases/{b}+{c}"; os.makedirs(d, exist_ok=True)
                    subprocess.run(["cp", "-a", f"{mnt}/chainData", f"{mnt}/db", d], check=True); r["kept"] = d
            finally:
                subprocess.run(["umount", mnt])
        r.setdefault("class", f"mount-failed|fsck{r['fsck_rc']}")
        out.write(json.dumps(r) + "\n"); out.flush()
        if n % 100 == 0: print(f"{time.strftime('%T')} {n}/{len(samples)} {b}+{c} {r['class']} ({time.time() - t0:.0f}s)", flush=True)
    os.unlink(case)
    print("CLASSES:"); [print(f"  {v:5d} {c}") for c, v in sorted(seen.items(), key=lambda x: -x[1])]
    print("RUN-DONE", flush=True)

if __name__ == "__main__":
    a = sys.argv
    if a[1] == "subset":
        opt = {"--n": 3000, "--keep-per-class": 3, "--keep-random": 0.002}
        for i in range(6, len(a), 2): opt[a[i]] = float(a[i + 1])
        subset(a[2], a[3], a[4], a[5], int(opt["--n"]), int(opt["--keep-per-class"]), opt["--keep-random"]); sys.exit(0)
    if a[1] == "index": index(a[2], a[3])
    elif a[1] == "image":
        ents, ss = load_index(a[3]); Replayer(a[2], ents, ss, a[5]).upto(int(a[4])); print("ok")
    elif a[1] == "run":
        opt = {"--flush-max": 600, "--random": 200, "--keep-per-class": 2, "--keep-random": 0.03, "--sync-writes": 0}
        for i in range(6, len(a), 2): opt[a[i]] = float(a[i + 1])
        run(a[2], a[3], a[4], a[5], int(opt["--flush-max"]), int(opt["--random"]), int(opt["--keep-per-class"]), opt["--keep-random"], int(opt["--sync-writes"]))
