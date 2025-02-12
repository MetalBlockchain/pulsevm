package vm

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/MetalBlockchain/metalgo/api/metrics"
	"github.com/MetalBlockchain/metalgo/database"
	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/snow"
	"github.com/MetalBlockchain/metalgo/snow/consensus/snowman"
	"github.com/MetalBlockchain/metalgo/snow/engine/common"
	"github.com/MetalBlockchain/metalgo/utils"
	"github.com/MetalBlockchain/metalgo/utils/json"
	"github.com/MetalBlockchain/metalgo/utils/timer/mockable"
	"github.com/MetalBlockchain/metalgo/version"
	"github.com/MetalBlockchain/pulsevm/chain/block"
	"github.com/MetalBlockchain/pulsevm/chain/config"
	txexecutor "github.com/MetalBlockchain/pulsevm/chain/txs/executor"
	ourmetrics "github.com/MetalBlockchain/pulsevm/metrics"
	"github.com/MetalBlockchain/pulsevm/state"
	"go.uber.org/zap"

	blockbuilder "github.com/MetalBlockchain/pulsevm/chain/block/builder"
	blockexecutor "github.com/MetalBlockchain/pulsevm/chain/block/executor"
	"github.com/MetalBlockchain/pulsevm/chain/txs/mempool"

	snowmanblock "github.com/MetalBlockchain/metalgo/snow/engine/snowman/block"

	"github.com/gorilla/rpc/v2"
)

var _ snowmanblock.ChainVM = &VM{}

//var _ snowmanblock.BatchedChainVM = &VM{}

type VM struct {
	blockbuilder.Builder

	metrics ourmetrics.Metrics

	// Used to get time. Useful for faking time during tests.
	clock mockable.Clock

	ctx          *snow.Context
	genesisBytes []byte
	toEngine     chan<- common.Message
	db           database.Database

	state state.State

	// Bootstrapped remembers if this chain has finished bootstrapping or not
	bootstrapped utils.Atomic[bool]

	manager blockexecutor.Manager
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
	chainCtx.Log.Verbo("initializing pulsevm")

	execConfig, err := config.GetConfig(configBytes)
	if err != nil {
		return err
	}
	chainCtx.Log.Info("using VM execution config", zap.Reflect("config", execConfig))

	registerer, err := metrics.MakeAndRegister(chainCtx.Metrics, "")
	if err != nil {
		return err
	}

	// Initialize metrics as soon as possible
	vm.metrics, err = ourmetrics.New(registerer)
	if err != nil {
		return fmt.Errorf("failed to initialize metrics: %w", err)
	}

	vm.ctx = chainCtx
	vm.genesisBytes = genesisBytes
	vm.toEngine = toEngine
	vm.db = db

	if state, err := state.New(
		vm.db,
		genesisBytes,
		registerer,
		execConfig,
	); err != nil {
		return err
	} else {
		vm.state = state
	}

	txExecutorBackend := &txexecutor.Backend{
		Ctx:          vm.ctx,
		Clk:          &vm.clock,
		Bootstrapped: &vm.bootstrapped,
	}

	mempool, err := mempool.New("mempool", registerer, toEngine)
	if err != nil {
		return fmt.Errorf("failed to create mempool: %w", err)
	}

	vm.manager = blockexecutor.NewManager(
		mempool,
		vm.state,
		txExecutorBackend,
	)

	vm.Builder = blockbuilder.New(
		mempool,
		txExecutorBackend,
		vm.manager,
	)

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
	if vm.db == nil {
		return nil
	}

	vm.Builder.ShutdownBlockTimer()

	return errors.Join(
		vm.state.Close(),
		vm.db.Close(),
	)
}

func (vm *VM) Version(context.Context) (string, error) {
	return "v0.0.1", nil
}

func (vm *VM) CreateHandlers(context.Context) (map[string]http.Handler, error) {
	server := rpc.NewServer()
	server.RegisterCodec(json.NewCodec(), "application/json")
	server.RegisterCodec(json.NewCodec(), "application/json;charset=UTF-8")
	service := &Service{
		vm: vm,
	}

	err := server.RegisterService(service, "pulsevm")
	return map[string]http.Handler{
		"/rpc": server,
	}, err
}

func (vm *VM) HealthCheck(context.Context) (interface{}, error) {
	return nil, nil
}

func (vm *VM) SetPreference(ctx context.Context, blkID ids.ID) error {
	if vm.manager.SetPreference(blkID) {
		vm.Builder.ResetBlockTimer()
	}
	return nil
}

func (vm *VM) LastAccepted(context.Context) (ids.ID, error) {
	return vm.manager.LastAccepted(), nil
}

func (vm *VM) GetBlockIDAtHeight(ctx context.Context, height uint64) (ids.ID, error) {
	return vm.state.GetBlockIDAtHeight(height)
}

func (vm *VM) GetBlock(ctx context.Context, blkID ids.ID) (snowman.Block, error) {
	return vm.manager.GetBlock(blkID)
}

func (vm *VM) ParseBlock(ctx context.Context, blockBytes []byte) (snowman.Block, error) {
	// Note: blocks to be parsed are not verified, so we must used blocks.Codec
	// rather than blocks.GenesisCodec
	statelessBlk, err := block.Parse(block.Codec, blockBytes)
	if err != nil {
		return nil, err
	}
	return vm.manager.NewBlock(statelessBlk), nil
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
