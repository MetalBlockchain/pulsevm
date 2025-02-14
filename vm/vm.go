package vm

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/MetalBlockchain/metalgo/api/metrics"
	"github.com/MetalBlockchain/metalgo/database"
	"github.com/MetalBlockchain/metalgo/database/versiondb"
	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/snow"
	"github.com/MetalBlockchain/metalgo/snow/consensus/snowman"
	"github.com/MetalBlockchain/metalgo/snow/engine/common"
	"github.com/MetalBlockchain/metalgo/utils/json"
	"github.com/MetalBlockchain/metalgo/utils/timer/mockable"
	"github.com/MetalBlockchain/metalgo/version"
	"github.com/MetalBlockchain/metalgo/vms/txs/mempool"
	"github.com/MetalBlockchain/pulsevm/chain/block"
	"github.com/MetalBlockchain/pulsevm/chain/config"
	"github.com/MetalBlockchain/pulsevm/chain/genesis"
	"github.com/MetalBlockchain/pulsevm/chain/txs"
	txexecutor "github.com/MetalBlockchain/pulsevm/chain/txs/executor"
	txmempool "github.com/MetalBlockchain/pulsevm/chain/txs/mempool"
	"github.com/MetalBlockchain/pulsevm/network"
	"github.com/MetalBlockchain/pulsevm/state"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	blockbuilder "github.com/MetalBlockchain/pulsevm/chain/block/builder"
	blockexecutor "github.com/MetalBlockchain/pulsevm/chain/block/executor"

	snowmanblock "github.com/MetalBlockchain/metalgo/snow/engine/snowman/block"

	"github.com/gorilla/rpc/v2"
)

var _ snowmanblock.ChainVM = &VM{}

//var _ snowmanblock.BatchedChainVM = &VM{}

type VM struct {
	blockbuilder.Builder

	// Used to get time. Useful for faking time during tests.
	clock mockable.Clock

	registerer prometheus.Registerer

	ctx          *snow.Context
	genesisBytes []byte
	toEngine     chan<- common.Message

	baseDB database.Database
	db     *versiondb.Database

	// Block parser
	parser block.Parser

	txBackend *txexecutor.Backend

	state state.State

	// Set to true once this VM is marked as `Bootstrapped` by the engine
	bootstrapped bool

	// Cancelled on shutdown
	onShutdownCtx context.Context
	// Call [onShutdownCtxCancel] to cancel [onShutdownCtx] during Shutdown()
	onShutdownCtxCancel context.CancelFunc
	awaitShutdown       sync.WaitGroup

	chainManager  blockexecutor.Manager
	network       *network.Network
	networkConfig network.Config
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

	vm.registerer, err = metrics.MakeAndRegister(chainCtx.Metrics, "")
	if err != nil {
		return err
	}

	vm.ctx = chainCtx
	vm.genesisBytes = genesisBytes
	vm.toEngine = toEngine
	vm.baseDB = db
	vm.db = versiondb.New(db)
	vm.parser, err = block.NewParser()
	if err != nil {
		return err
	}

	if state, err := state.New(
		vm.db,
		vm.parser,
		genesisBytes,
		vm.registerer,
		execConfig,
	); err != nil {
		return err
	} else {
		vm.state = state
	}

	if err := vm.initGenesis(genesisBytes); err != nil {
		return err
	}

	mempool, err := txmempool.New("mempool", vm.registerer, toEngine)
	if err != nil {
		return fmt.Errorf("failed to create mempool: %w", err)
	}

	vm.txBackend = &txexecutor.Backend{
		Ctx:          vm.ctx,
		Codec:        vm.parser.Codec(),
		Bootstrapped: false,
	}
	vm.chainManager = blockexecutor.NewManager(
		mempool,
		vm.state,
		vm.txBackend,
		&vm.clock,
		vm.onAccept,
	)

	// Invariant: The context lock is not held when calling network.IssueTx.
	vm.networkConfig = network.DefaultConfig
	vm.network, err = network.New(
		vm.ctx.Log,
		vm.ctx.NodeID,
		vm.ctx.SubnetID,
		vm.ctx.ValidatorState,
		vm.parser,
		network.NewLockedTxVerifier(
			&vm.ctx.Lock,
			vm.chainManager,
		),
		mempool,
		appSender,
		vm.registerer,
		vm.networkConfig,
	)
	if err != nil {
		return fmt.Errorf("failed to initialize network: %w", err)
	}

	vm.Builder = blockbuilder.New(
		vm.txBackend,
		vm.chainManager,
		&vm.clock,
		mempool,
	)

	vm.onShutdownCtx, vm.onShutdownCtxCancel = context.WithCancel(context.Background())
	vm.awaitShutdown.Add(2)
	go func() {
		defer vm.awaitShutdown.Done()

		// Invariant: PushGossip must never grab the context lock.
		vm.network.PushGossip(vm.onShutdownCtx)
	}()
	go func() {
		defer vm.awaitShutdown.Done()

		// Invariant: PullGossip must never grab the context lock.
		vm.network.PullGossip(vm.onShutdownCtx)
	}()

	chainCtx.Log.Info("initialized")

	return vm.state.Commit()
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
	if vm.state == nil {
		return nil
	}

	vm.onShutdownCtxCancel()
	vm.awaitShutdown.Wait()

	return errors.Join(
		vm.state.Close(),
		vm.baseDB.Close(),
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

func (vm *VM) SetPreference(_ context.Context, blkID ids.ID) error {
	vm.chainManager.SetPreference(blkID)
	return nil
}

func (vm *VM) LastAccepted(context.Context) (ids.ID, error) {
	return vm.chainManager.LastAccepted(), nil
}

func (vm *VM) GetBlockIDAtHeight(ctx context.Context, height uint64) (ids.ID, error) {
	return vm.state.GetBlockIDAtHeight(height)
}

func (vm *VM) GetBlock(_ context.Context, blkID ids.ID) (snowman.Block, error) {
	return vm.chainManager.GetBlock(blkID)
}

func (vm *VM) ParseBlock(_ context.Context, blkBytes []byte) (snowman.Block, error) {
	blk, err := vm.parser.ParseBlock(blkBytes)
	if err != nil {
		return nil, err
	}
	return vm.chainManager.NewBlock(blk), nil
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
	version *version.Application,
) error {
	return vm.network.Connected(ctx, nodeID, version)
}

func (vm *VM) Disconnected(
	ctx context.Context,
	nodeID ids.NodeID,
) error {
	return vm.network.Disconnected(ctx, nodeID)
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
	vm.txBackend.Bootstrapped = false
	return nil
}

// onNormalOperationsStarted marks this VM as bootstrapped
func (vm *VM) onNormalOperationsStarted() error {
	vm.txBackend.Bootstrapped = true
	vm.bootstrapped = true
	return nil
}

func (vm *VM) issueTxFromRPC(tx *txs.Tx) (ids.ID, error) {
	txID := tx.ID()
	err := vm.network.IssueTxFromRPC(tx)
	if err != nil && !errors.Is(err, mempool.ErrDuplicateTx) {
		vm.ctx.Log.Debug("failed to add tx to mempool",
			zap.Stringer("txID", txID),
			zap.Error(err),
		)
		return txID, err
	}
	return txID, nil
}

// Invariant: onAccept is called when [tx] is being marked as accepted, but
// before its state changes are applied.
// Invariant: any error returned by onAccept should be considered fatal.
// TODO: Remove [onAccept] once the deprecated APIs this powers are removed.
func (vm *VM) onAccept(tx *txs.Tx) error {
	return nil
}

func (vm *VM) initGenesis(genesisBytes []byte) error {
	genesis, err := genesis.Parse(genesisBytes)
	if err != nil {
		return err
	}

	stateInitialized, err := vm.state.IsInitialized()
	if err != nil {
		return err
	}

	vm.ctx.Log.Info("initializing genesis state")

	if err := vm.state.Initialize(genesis.Timestamp); err != nil {
		return err
	}

	if !stateInitialized {
		return vm.state.SetInitialized()
	}

	return nil
}
