package client

import (
	"context"
	"fmt"
	"time"

	"github.com/MetalBlockchain/metalgo/utils/rpc"
	"github.com/MetalBlockchain/pulsevm/vm"
)

type Client interface {
	// Pings the VM.
	Ping(ctx context.Context) (bool, error)
}

// New creates a new client object.
func New(uri string, reqTimeout time.Duration) Client {
	req := rpc.NewEndpointRequester(
		fmt.Sprintf("%s%s", uri, vm.Endpoint),
	)
	return &client{req: req}
}

type client struct {
	req rpc.EndpointRequester
}

func (cli *client) Ping(ctx context.Context) (bool, error) {
	resp := new(vm.PingReply)
	err := cli.req.SendRequest(ctx,
		"pulsevm.ping",
		nil,
		resp,
	)
	if err != nil {
		return false, err
	}
	return resp.Success, nil
}

func (cli *client) Info(ctx context.Context) (bool, error) {
	resp := new(vm.PingReply)
	err := cli.req.SendRequest(ctx,
		"pulsevm.ping",
		nil,
		resp,
	)
	if err != nil {
		return false, err
	}
	return resp.Success, nil
}
