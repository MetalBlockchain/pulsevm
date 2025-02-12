package main

import (
	"context"
	"fmt"
	"os"

	"github.com/MetalBlockchain/metalgo/utils/logging"
	"github.com/MetalBlockchain/metalgo/utils/ulimit"
	"github.com/MetalBlockchain/metalgo/vms/rpcchainvm"
	"github.com/MetalBlockchain/pulsevm/chain/constants"
	"github.com/MetalBlockchain/pulsevm/vm"
)

func main() {
	version, err := PrintVersion()
	if err != nil {
		fmt.Printf("couldn't get config: %s", err)
		os.Exit(1)
	}
	if version {
		fmt.Println(constants.Version)
		os.Exit(0)
	}
	if err := ulimit.Set(ulimit.DefaultFDLimit, logging.NoLog{}); err != nil {
		fmt.Printf("failed to set fd limit correctly due to: %s", err)
		os.Exit(1)
	}

	// Start gRPC server
	rpcchainvm.Serve(context.Background(), &vm.VM{})

}
