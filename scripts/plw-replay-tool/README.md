# plw-replay-tool: power-loss cut-point replay for a PulseVM node

These tools record every block-device write a PulseVM node makes (plugin data and MetalGo's database) while it runs under load
and through restarts. They then rebuild the node's directory as a power cut at many points of that recording would have left
it, check each rebuilt image offline, and start a sample of the images as a real node of a live network to see whether it
rejoins, how, and with what state.

This is the method behind the power-loss results we reported on PR #129. It needs a Linux host with root access
and the `dm-log-writes` device-mapper target. Most hosted CI runners have neither (see "Limits").

## Files

| file | what it does |
|---|---|
| `plw-dev.sh` | Moves a node directory onto ext4 over a `dm-log-writes` device (two sparse loop files). Writes named marks into the log. Tears down again. |
| `example-record.sh` | An example recording run: load plus clean restarts, SIGKILLs and a state-sync restart, with marks around each event. Adapt the commands at the top. |
| `plw-replay.py` | `index` reads the write log. `run` replays it to the prefix cut points. `subset` replays it to the volatile-cache states. `image` writes one replayed image. Each image is checked with `e2fsck -fy`, mounted read-only and classified, giving one JSON line per cut. A sample of the images is kept for start tests. |
| `plw-select.py` | Picks the kept images to start-test: every named mark, up to 3 per class, every image with temporary files or a zero log tail, then random images up to a total. |
| `plw-start.py` | Swaps each selected image in as the node of a live network and records join time, start-up lines and state-sync / ALARM / refusal counters. If reference roots are given, it also compares the state roots the node logs after the start against them. |
| `plw-summary.py` | Summaries of `classify.jsonl` (offline states) and of the start-test results. |

## Requirements

- Linux with `dm-log-writes` (`modprobe dm-log-writes`; `CONFIG_DM_LOG_WRITES`). We used Ubuntu 24.04 with kernel 6.8.
- Root (for `losetup`, `dmsetup`, `mount`), `e2fsprogs`, GNU `cp` (`--sparse`) and `tar`, Python 3.10 or newer. No Python packages are needed.
- Disk: the device file (default 2 GiB) plus the log file (sparse, default 24 GiB). Our 10-12 minute recordings used 280-360 MB of log per node. A replay keeps one base image and one scratch image in `/dev/shm`, each the size of the device.
- A node whose whole directory (`chainData/`, `db/`, configs, staking files) can be moved onto the device. Its `logs/` directory stays on the host through a bind mount, so log output is not part of the recording.
- For start tests: a running network that the node can rejoin, a way to stop, start and SIGKILL that node, and load (transactions) while the tests run.

## How to run

```
# 1. record (as root). Adapt NODE_DIR / STOP / START / KILL / LOAD, or write your own timeline with plw-dev.sh mark.
NAME=node5 NODE_DIR=/path/to/network/node5 STOP='...' START='...' KILL='...' LOAD='...' ./example-record.sh

# 2. offline: index, prefix cuts, volatile-cache subsets
export PLW_WORK=$PWD/plw-work PLW_CHAIN_SUBDIR=chainData/<blockchain id>
./plw-replay.py index  $PLW_WORK/node5/log.img $PLW_WORK/node5/index.tsv
./plw-replay.py run    $PLW_WORK/node5/log.img $PLW_WORK/node5/index.tsv node5 out/prefix --flush-max 0 --random 4000 --sync-writes 3000
./plw-replay.py subset $PLW_WORK/node5/log.img $PLW_WORK/node5/index.tsv node5 out/subset --n 3000
./plw-summary.py classify out/prefix/classify.jsonl

# 3. start tests on the live network (load running)
cat out/prefix/classify.jsonl out/subset/classify.jsonl > all.jsonl
./plw-select.py all.jsonl 150 > selected.jsonl
PLW_NODE_DIR=/path/to/network/node5 PLW_STOP='...' PLW_START='...' PLW_HEAD='...' PLW_REF_HEAD='...' \
  [PLW_ROOTS_REF=ref-roots.tsv] ./plw-start.py selected.jsonl start.jsonl
./plw-summary.py start start.jsonl
```

`PLW_HEAD` and `PLW_REF_HEAD` are shell commands that print one number. For example, curl `pulsevm.getInfo` on the node, and
the highest `head_block_num` of the other nodes. For the roots check, set `state_root_log_every: 1` in the chain config and keep
`ref-roots.tsv` (`height<TAB>root`) updated from the other nodes' `arena state root at block N: <hex>` lines.

## What each mode models

- **Prefix cuts (`run`).** The image holds every write the device completed up to entry *k* of the log and nothing after it.
  This is a disk that loses exactly the writes it had not completed yet. Cut points are:
  - every named mark;
  - every FLUSH/FUA entry (`--flush-max 0`), which are the points where the file system or the node asked for durability;
  - `--random` data-write entries between flushes;
  - with `--sync-writes N`, up to N data writes inside the state-sync windows (marks `restarted-for-sync*` to `joined-after-sync*`).
- **Volatile-cache subsets (`subset`).** Barriers are entries with the FLUSH (pre-flush) flag. Everything before a barrier is
  durable. Between a barrier and a random cut, each non-FUA write survives with probability 0.5 and FUA writes always survive.
  This models a disk cache that loses an arbitrary part of the unflushed writes, out of order.
- **Start tests (`plw-start.py`).** Each selected image becomes the node: its plugin data and its MetalGo database together,
  as a whole-node power cut would leave them. The node is then started while the rest of the network runs under load.

## What it reports

- Offline, per image: fsck outcome, mount result, the write-ahead log scanned with the plugin's own rules (`clean`, `torn`,
  `REFUSE-altered`, header/format refusals), and block/trace/chain-state log and index tails (zero records, zero bytes,
  non-contiguous index). It also reports temporary files left (`state_sync_installing`, `*.tmp`, `state_sync_abandoned`) and the
  kind of MetalGo database present.
- At start: joined or not, and in how many seconds; WAL blocks recovered; rewinds; state sync applied and finished; MetalGo's
  "unexpected message ... Pending Transactions"; `ALARM event=state_sync.install_abandoned`; "skipping state summary";
  proposervm-behind refusals; any `[error]` line; and roots equal or different from the reference.

## Limits

- One file system configuration (ext4, mkfs defaults, `data=ordered`) on loop devices over the host's disk. Other file systems,
  mount options and real disks with their own caches are not covered.
- No torn sectors: a sector is written fully or not at all. Only the two models above. Writes are never reordered across a
  FLUSH barrier.
- The whole node directory loses power together. Separate disks for MetalGo's database and the plugin data are not modelled.
- The scanner in `plw-replay.py` follows the current PulseVM WAL scanner: `PVMWAL04`, a 32-byte key, and a 256 MiB
  damage-scan budget charged only for candidate frames whose revision/table-count prefix could follow the last valid
  frame. Plausible candidates are still hashed and budgeted, so hostile bytes can force a refusal. State-history logs use
  48-byte headers and magic 0. The scripts classify images; they do not decide outcomes. The start test does.
- Start tests take 10-120 s each. Expect about 1 h per 50-60 images.
- `dm-log-writes` and the loop devices need privileges that hosted CI runners do not grant. A self-hosted runner, or a VM
  you control, works.
- These are the generic, path-free versions of the scripts we ran. `plw-replay.py`, `plw-select.py` and `plw-summary.py` in this form
  were smoke-tested on one of our recordings: index, 70 prefix cuts, 20 subsets, selection. `plw-start.py` here is a rewrite of our
  start-test harness: it takes its node, stop/start and head commands from the environment. It was not run in this exact form, so
  expect to adapt it to your network once.
