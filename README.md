# PulseVM

A virtual machine built for Metal Blockchain based on the XPR Network protocol, aka EOS / Leap / Spring.

## Run locally

metal-network-runner server \
--log-level info \
--port=":8080" \
--grpc-gateway-port=":8081"

metal-network-runner control start --log-level info \
--endpoint="0.0.0.0:8080" \
--number-of-nodes=5 \
--metalgo-path ${METALGO_EXEC_PATH} \
--plugin-dir $(pwd)/build \
--blockchain-specs '[{"vm_name": "pulsevm", "genesis": "/Users/glennmarien/Documents/MetalBlockchain/pulsevm/genesis.json"}]'