package executor

import (
	"errors"

	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/snow/consensus/snowman"
	"github.com/MetalBlockchain/pulsevm/chain/block"
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

	SetPreference(blkID ids.ID) (updated bool)
	Preferred() ids.ID

	GetBlock(blkID ids.ID) (snowman.Block, error)
	GetStatelessBlock(blkID ids.ID) (block.Block, error)
	NewBlock(block.Block) snowman.Block
}

type manager struct {
	*backend
	acceptor block.Visitor
	rejector block.Visitor

	preferred         ids.ID
	txExecutorBackend *executor.Backend
}

func NewManager(
	mempool mempool.Mempool,
	s state.State,
	txExecutorBackend *executor.Backend,
) Manager {
	lastAccepted := s.GetLastAccepted()
	backend := &backend{
		Mempool:      mempool,
		lastAccepted: lastAccepted,
		state:        s,
		ctx:          txExecutorBackend.Ctx,
		blkIDToState: map[ids.ID]*blockState{},
	}

	return &manager{
		backend:           backend,
		preferred:         lastAccepted,
		txExecutorBackend: txExecutorBackend,
	}
}

func (m *manager) GetBlock(blkID ids.ID) (snowman.Block, error) {
	blk, err := m.backend.GetBlock(blkID)
	if err != nil {
		return nil, err
	}
	return m.NewBlock(blk), nil
}

func (m *manager) GetStatelessBlock(blkID ids.ID) (block.Block, error) {
	return m.backend.GetBlock(blkID)
}

func (m *manager) NewBlock(blk block.Block) snowman.Block {
	return &Block{
		manager: m,
		Block:   blk,
	}
}

func (m *manager) SetPreference(blkID ids.ID) bool {
	updated := m.preferred != blkID
	m.preferred = blkID
	return updated
}

func (m *manager) Preferred() ids.ID {
	return m.preferred
}
