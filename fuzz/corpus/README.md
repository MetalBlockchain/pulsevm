# Fuzz seeds for PulseVM's `fuzz/` targets (prepared, NOT sent)

Real files from a five-node PulseVM test network running PR #129 at 25956263 (pebbledb, a migrated test chain,
mixed load: token transfers, secondary-index table writes, row remove-and-reuse, contract setcode churn). Nothing
here was planted except where a file says so. These are meant as a starting corpus: the upstream doc notes that random
bytes mostly fail a checksum early and that depth needs real files.

## Layout

- `wal_replay/` — whole `arena_wal.bin` files (`PVMWAL04`: 8-byte magic, the node's random 32-byte key, keyed records). For
  `fuzz/fuzz_targets/wal_replay.rs`. That target registers one dummy table, so records from a real chain fail at the
  first unknown table id after the framing and torn-tail logic has run; the framing, digest, torn-tail and damage-scan
  paths are what these seeds reach. The key in each header is a per-node random value from a disposable test network.
- `history_log/` — short state-history-format logs (48-byte entry headers, magic 0, no checksum): the last six entries
  of a node's block, trace and chain-state logs, cut from a copy, clean and in five damage shapes. For
  `fuzz/fuzz_targets/history_log.rs` (it writes the input as `block_log.log`; the entry format is the same for all three).
- `MANIFEST.tsv` — file, bytes, sha256, what it is and what 25956263 did with that shape.

## What was measured

The `[M live]` notes in MANIFEST.tsv describe what the node did with that damage shape on its full log, in a live start
on the network. The short `history/` files are cut from the same logs with the same shapes. They were not themselves
started. Two notes come from an offline open with upstream `Database::new` instead (marked `[M offline]`).

Highlights:
- `wal_replay/tornreal-262144.bin` — an honest torn record (header claims 262,144 bytes, 90% present, the payload made of this
  log's own row-data records). 25956263 refuses it: `write-ahead log record at byte 1010988 cannot be read and the
  file after it is too large to rule out damage within the scan budget: it is refused rather than discarded`.
  dbe5fcee recovers it in 0.2 s. A good regression seed for the damage-scan budget.
- `wal_replay/F-D6-quadtail131072.bin` — the hostile tail (one plausible length every 8 bytes), refused by the budget. The
  64 KiB variant is recovered.
- `history_log/*-zerolast581-inplace.log` — the last 581 bytes of the last entry zeroed in place. On the live node this
  entry is kept with no warning, and for the block log the node then served a block that differs from the network's
  over `getBlock`.

## Sizes

24 seed files, 3,645,480 bytes in total (largest: `wal_replay/tornreal-262144.bin`, 1,246,925 B). libFuzzer's default `-max_len` is
4096 unless the corpus holds larger files. Pass `-max_len` explicitly (for example 2000000) if the whole WAL seeds
should be used.

## Checks before sending

Scanned for private keys (`PVT_K1_`, `PVT_R1_`, WIF, PEM private keys), host names, IP addresses, file-system paths
and personal or organisation names: none found. The files hold public chain data only: account names, public keys,
signatures, action data of test transactions, and the WASM of public test contracts (Leap unittests, eosio.system).

`SHA256SUMS` covers every file.
