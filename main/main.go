package main

import (
	"context"

	"github.com/MetalBlockchain/metalgo/vms/rpcchainvm"
	"github.com/MetalBlockchain/pulsevm/vm"
)

func main() {
	rpcchainvm.Serve(context.Background(), &vm.VM{})
}
