# PulseVM

A virtual machine built for Metal Blockchain based on the XPR Network protocol, aka EOS / Leap / Spring.

## Notable changes

### Objective CPU calculation

EOS calculates CPU subjectively by charging the actual time it took a producer to execute a certain transaction. This is far from ideal as producers on slower hardware would charge more CPU than producers with faster hardware.

PulseVM calculates CPU objectively by charging a baseline of `50 microseconds` per action. In addition, WebAssembly modules are instrumented with an instruction counter which allows it to calculate the exact amount of instructions a certain action performed.

### Instant finality

PulseVM blocks have near instant finality, improving on the average of 120 seconds seen in XPR Network. 

It does this by handling a mempool of transactions, every `500 milliseconds` the mempool is checked for transactions. 

If the mempool contains transactions then the producer will request `metalgo` to produce a block, the actual producer building the block might be different from the producer requesting it. This is determined by the production window `metalgo` enforces.

The producer that built the block will then submit the block to other producer for verification. If consensus is reached then all producers will be asked to accept the block.

This process takes around `200 milliseconds` depending on various factors.

## Requirements

- Supported OS
  - Ubuntu 22.04 or greater
  - Mac OSX: only for development
- zstd
  - For Mac: `brew install zstd`
- LLVM 18: used to compile and run WebAssembly contracts
  - For Mac: `brew install llvm@18`
- LibFFI
  - For Mac: `brew install libffi`

If you are getting a zstd error on Mac, try:

```bash
export LIBRARY_PATH="$(brew --prefix zstd)/lib:${LIBRARY_PATH:-}"
export CPATH="$(brew --prefix zstd)/include:${CPATH:-}"
```

## Run locally

### Spin up a local cluster using metal-network-runner

```bash
metal-network-runner server \
--log-level info \
--port=":8080" \
--grpc-gateway-port=":8081"
```
### Start a clean instance of the virtual machine

Make sure `METALGO_EXEC_PATH` points to a compiled `metalgo` binary. The `--plugin-dir` directive should point to a directory that has a compiled version of this virtual machine, the binary should be renamed to `rXcAFxZvio99epp6TzEwYfexCfPAbJuBTMsjUUoiT7PkVykNs` as that is what `metalgo` will be looking for.

```bash
metal-network-runner control start --log-level info \
--endpoint="0.0.0.0:8080" \
--number-of-nodes=5 \
--metalgo-path ${METALGO_EXEC_PATH} \
--plugin-dir $(pwd)/build \
--blockchain-specs '[{"vm_name": "pulsevm", "genesis": "/Users/glennmarien/Documents/MetalBlockchain/pulsevm/genesis.json"}]'
```

### Start five nodes from imported XPR state

First produce an Arena checkpoint using the local XPR fixture instructions in
[`tools/xpr-chainbase-export/localnet/README.md`](tools/xpr-chainbase-export/localnet/README.md).
Then run the normal five-node harness with that checkpoint supplied to every
PulseVM instance:

```bash
METALGO_EXEC_PATH=../metalgo/build/metalgo \
METAL_NETWORK_RUNNER_PATH=../metal-network-runner/bin/metal-network-runner \
PULSEVM_MIGRATION_CHECKPOINT=/tmp/pulsevm-xpr-migration.snapshot \
scripts/run-local.sh
```

For a large imported checkpoint, use the companion runner branch
`feat/pulsevm-checkpoint-startup` (commit `3d2e25d`), which allows up to two
minutes for MetalGo to write its dynamic process-info file. The stock runner's
three-second wait can report a healthy VM as failed while Arena is restoring.

The harness passes `migration_checkpoint` and its emitted manifest through the
runner's per-chain VM configuration. Every node verifies the manifest hash and
revision before restoring the Arena checkpoint. It also generates a distinct
target genesis committed to that checkpoint hash, so a different migration gets
a different target chain identity. This proves the local conversion and
five-node boot path; Mainnet migration still requires a validated Mainnet export
plus the remaining system-contract policy work.

### Exercise writes against imported state

An imported XPR checkpoint retains the real `pulse@active` authority, so its
production private key must never be used for local testing. Derive a disposable
copy that replaces only `pulse@owner` and `pulse@active` with a development key:

```bash
cargo run -p pulsevm_database --example xpr_test_authority -- \
  /tmp/xpr-migration.snapshot \
  /tmp/xpr-migration.snapshot.manifest.json \
  /tmp/xpr-migration-test-authority.snapshot \
  "$PULSEVM_TEST_PRIVATE_KEY"
```

The command writes a matching `.manifest.json` beside the derived checkpoint.
Use that copy with `PULSEVM_MIGRATION_CHECKPOINT` and pass the same development
key to `pulsevm-e2e-boot`; the canonical XPR checkpoint is not modified.
