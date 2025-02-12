package vm

import (
	"context"
	"testing"

	"github.com/MetalBlockchain/metalgo/api/metrics"
	"github.com/MetalBlockchain/metalgo/database/memdb"
	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/snow"
	"github.com/MetalBlockchain/metalgo/snow/engine/common"
	"github.com/MetalBlockchain/metalgo/utils/logging"
	"github.com/stretchr/testify/assert"
)

func TestVMInit(t *testing.T) {
	genesisBytes := []byte(`{
		"timestamp": "2020-11-30T14:20:28.000Z"
	}`)
	chainCtx := &snow.Context{
		Metrics: metrics.NewPrefixGatherer(),
		Log:     logging.NewLogger("pulsevm"),
	}
	vm := &VM{}
	err := vm.Initialize(
		context.Background(),
		chainCtx,
		memdb.New(),
		genesisBytes,
		nil,
		nil,
		make(chan<- common.Message),
		nil,
		nil,
	)
	assert.NoError(t, err)
	lastAccepted, err := vm.LastAccepted(context.TODO())
	assert.NoError(t, err)
	assert.Equal(t, lastAccepted, ids.FromStringOrPanic("2czBM5bSGmQ3Pb5Zcv2z8x5jrjSNTmHXiNcmpjAX7dJT244Fon"))
}
