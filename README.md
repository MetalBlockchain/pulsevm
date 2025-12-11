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
  - Mac OSX
- zstd
  - For Mac: `brew install zstd`
- LLVM >= 18: used to compile and run WebAssembly contracts
  - For Mac: `brew install llvm@18`

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