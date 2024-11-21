package vm

import (
	"context"
	"net/http"
	"time"

	"github.com/MetalBlockchain/metalgo/database"
	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/snow"
	"github.com/MetalBlockchain/metalgo/snow/consensus/snowman"
	"github.com/MetalBlockchain/metalgo/snow/engine/common"
	"github.com/MetalBlockchain/metalgo/snow/engine/snowman/block"
	"github.com/MetalBlockchain/metalgo/utils"
	"github.com/MetalBlockchain/metalgo/version"
	"github.com/MetalBlockchain/pulsevm/state"
)

var _ block.ChainVM = &VM{}
var _ block.BatchedChainVM = &VM{}

type VM struct {
	chainCtx     *snow.Context
	genesisBytes []byte
	toEngine     chan<- common.Message
	db           database.Database

	state state.State

	// Bootstrapped remembers if this chain has finished bootstrapping or not
	bootstrapped utils.Atomic[bool]
}

func (vm *VM) Initialize(
	ctx context.Context,
	chainCtx *snow.Context,
	db database.Database,
	genesisBytes []byte,
	upgradeBytes []byte,
	configBytes []byte,
	toEngine chan<- common.Message,
	fxs []*common.Fx,
	appSender common.AppSender,
) error {
	vm.chainCtx = chainCtx
	vm.genesisBytes = genesisBytes
	vm.toEngine = toEngine
	vm.db = db

	if state, err := state.New(
		vm.db,
	); err != nil {
		return err
	} else {
		vm.state = state
	}

	return nil
}

func (vm *VM) SetState(ctx context.Context, state snow.State) error {
	switch state {
	case snow.Bootstrapping:
		return vm.onBootstrapStarted()
	case snow.NormalOp:
		return vm.onNormalOperationsStarted()
	default:
		return snow.ErrUnknownState
	}
}

func (vm *VM) Shutdown(context.Context) error {
	return nil
}

func (vm *VM) Version(context.Context) (string, error) {
	return "v0.0.1", nil
}

func (vm *VM) CreateHandlers(context.Context) (map[string]http.Handler, error) {
	return nil, nil
}

func (vm *VM) HealthCheck(context.Context) (interface{}, error) {
	return nil, nil
}

func (vm *VM) BuildBlock(context.Context) (snowman.Block, error) {
	return nil, nil
}

func (vm *VM) SetPreference(ctx context.Context, blkID ids.ID) error {
	return nil
}

func (vm *VM) LastAccepted(context.Context) (ids.ID, error) {
	return ids.Empty, nil
}

func (vm *VM) GetBlockIDAtHeight(ctx context.Context, height uint64) (ids.ID, error) {
	return ids.Empty, nil
}

func (vm *VM) GetBlock(ctx context.Context, blkID ids.ID) (snowman.Block, error) {
	return nil, nil
}

func (vm *VM) ParseBlock(ctx context.Context, blockBytes []byte) (snowman.Block, error) {
	return nil, nil
}

func (vm *VM) GetAncestors(
	ctx context.Context,
	blkID ids.ID, // first requested block
	maxBlocksNum int, // max number of blocks to be retrieved
	maxBlocksSize int, // max cumulated byte size of retrieved blocks
	maxBlocksRetrivalTime time.Duration, // max duration of retrival operation
) ([][]byte, error) {
	return nil, nil
}

func (vm *VM) BatchedParseBlock(ctx context.Context, blks [][]byte) ([]snowman.Block, error) {
	return nil, nil
}

func (vm *VM) AppRequest(
	ctx context.Context,
	nodeID ids.NodeID,
	requestID uint32,
	deadline time.Time,
	request []byte,
) error {
	return nil
}

func (vm *VM) AppResponse(
	ctx context.Context,
	nodeID ids.NodeID,
	requestID uint32,
	response []byte,
) error {
	return nil
}

func (vm *VM) AppRequestFailed(
	ctx context.Context,
	nodeID ids.NodeID,
	requestID uint32,
	appErr *common.AppError,
) error {
	return nil
}

func (vm *VM) AppGossip(
	ctx context.Context,
	nodeID ids.NodeID,
	msg []byte,
) error {
	return nil
}

func (vm *VM) Connected(
	ctx context.Context,
	nodeID ids.NodeID,
	nodeVersion *version.Application,
) error {
	return nil
}

func (vm *VM) Disconnected(ctx context.Context, nodeID ids.NodeID) error {
	return nil
}

func (vm *VM) CrossChainAppRequest(
	ctx context.Context,
	chainID ids.ID,
	requestID uint32,
	deadline time.Time,
	request []byte,
) error {
	return nil
}

func (vm *VM) CrossChainAppResponse(
	ctx context.Context,
	chainID ids.ID,
	requestID uint32,
	response []byte,
) error {
	return nil
}

func (vm *VM) CrossChainAppRequestFailed(
	ctx context.Context,
	chainID ids.ID,
	requestID uint32,
	appErr *common.AppError,
) error {
	return nil
}

// onBootstrapStarted marks this VM as bootstrapping
func (vm *VM) onBootstrapStarted() error {
	vm.bootstrapped.Set(false)
	return nil
}

// onNormalOperationsStarted marks this VM as bootstrapped
func (vm *VM) onNormalOperationsStarted() error {
	if vm.bootstrapped.Get() {
		return nil
	}
	vm.bootstrapped.Set(true)

	if err := vm.state.Commit(); err != nil {
		return err
	}

	// Start the block builder
	vm.Builder.StartBlockTimer()
	return nil
}
