package executor

import (
	"errors"

	"github.com/MetalBlockchain/metalgo/chains/atomic"
	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/snow/consensus/snowman"
	"github.com/MetalBlockchain/metalgo/utils/set"
	"github.com/MetalBlockchain/metalgo/utils/timer/mockable"
	"github.com/MetalBlockchain/pulsevm/chain/block"
	"github.com/MetalBlockchain/pulsevm/chain/txs"
	"github.com/MetalBlockchain/pulsevm/chain/txs/executor"
	"github.com/MetalBlockchain/pulsevm/chain/txs/mempool"
	"github.com/MetalBlockchain/pulsevm/state"
)

var (
	_ Manager = (*manager)(nil)

	ErrChainNotSynced = errors.New("chain not synced")
)

type Manager interface {
	state.Versions

	// Returns the ID of the most recently accepted block.
	LastAccepted() ids.ID

	SetPreference(blkID ids.ID)
	Preferred() ids.ID

	GetBlock(blkID ids.ID) (snowman.Block, error)
	GetStatelessBlock(blkID ids.ID) (block.Block, error)
	NewBlock(block.Block) snowman.Block

	// VerifyTx verifies that the transaction can be issued based on the currently
	// preferred state. This should *not* be used to verify transactions in a block.
	VerifyTx(tx *txs.Tx) error
}

func NewManager(
	mempool mempool.Mempool,
	state state.State,
	backend *executor.Backend,
	clk *mockable.Clock,
	onAccept func(*txs.Tx) error,
) Manager {
	lastAccepted := state.GetLastAccepted()
	return &manager{
		backend:      backend,
		state:        state,
		mempool:      mempool,
		clk:          clk,
		onAccept:     onAccept,
		blkIDToState: map[ids.ID]*blockState{},
		lastAccepted: lastAccepted,
		preferred:    lastAccepted,
	}
}

type manager struct {
	backend *executor.Backend
	state   state.State
	mempool mempool.Mempool
	clk     *mockable.Clock
	// Invariant: onAccept is called when [tx] is being marked as accepted, but
	// before its state changes are applied.
	// Invariant: any error returned by onAccept should be considered fatal.
	onAccept func(*txs.Tx) error

	// blkIDToState is a map from a block's ID to the state of the block.
	// Blocks are put into this map when they are verified.
	// Blocks are removed from this map when they are decided.
	blkIDToState map[ids.ID]*blockState

	// lastAccepted is the ID of the last block that had Accept() called on it.
	lastAccepted ids.ID
	preferred    ids.ID
}

type blockState struct {
	statelessBlock block.Block
	onAcceptState  state.Diff
	importedInputs set.Set[ids.ID]
	atomicRequests map[ids.ID]*atomic.Requests
}

func (m *manager) GetBlock(blkID ids.ID) (snowman.Block, error) {
	blk, err := m.GetStatelessBlock(blkID)
	if err != nil {
		return nil, err
	}
	return m.NewBlock(blk), nil
}

func (m *manager) GetStatelessBlock(blkID ids.ID) (block.Block, error) {
	// See if the block is in memory.
	if blkState, ok := m.blkIDToState[blkID]; ok {
		return blkState.statelessBlock, nil
	}
	// The block isn't in memory. Check the database.
	return m.state.GetBlock(blkID)
}

func (m *manager) NewBlock(blk block.Block) snowman.Block {
	return &Block{
		Block:   blk,
		manager: m,
	}
}

func (m *manager) GetState(blkID ids.ID) (state.Chain, bool) {
	// If the block is in the map, it is processing.
	if state, ok := m.blkIDToState[blkID]; ok {
		return state.onAcceptState, true
	}
	return m.state, blkID == m.lastAccepted
}

func (m *manager) LastAccepted() ids.ID {
	return m.lastAccepted
}

func (m *manager) SetPreference(blockID ids.ID) {
	m.preferred = blockID
}

func (m *manager) Preferred() ids.ID {
	return m.preferred
}

func (m *manager) VerifyTx(tx *txs.Tx) error {
	if !m.backend.Bootstrapped {
		return ErrChainNotSynced
	}

	stateDiff, err := state.NewDiff(m.lastAccepted, m)
	if err != nil {
		return err
	}

	executor := &executor.Executor{
		State: stateDiff,
		Tx:    tx,
	}
	return tx.Unsigned.Visit(executor)
}
