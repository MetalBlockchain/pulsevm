package mempool

import (
	"github.com/MetalBlockchain/metalgo/snow/engine/common"
	"github.com/MetalBlockchain/pulsevm/chain/txs"
	txmempool "github.com/MetalBlockchain/pulsevm/mempool"
	"github.com/prometheus/client_golang/prometheus"
)

var _ Mempool = (*mempool)(nil)

type Mempool interface {
	txmempool.Mempool[*txs.Tx]

	// RequestBuildBlock notifies the consensus engine that a block should be
	// built if there is at least one transaction in the mempool.
	RequestBuildBlock()
}

type mempool struct {
	txmempool.Mempool[*txs.Tx]

	toEngine chan<- common.Message
}

func New(
	namespace string,
	registerer prometheus.Registerer,
	toEngine chan<- common.Message,
) (Mempool, error) {
	metrics, err := txmempool.NewMetrics(namespace, registerer)
	if err != nil {
		return nil, err
	}
	pool := txmempool.New[*txs.Tx](
		metrics,
	)
	return &mempool{
		Mempool:  pool,
		toEngine: toEngine,
	}, nil
}

func (m *mempool) RequestBuildBlock() {
	if m.Len() == 0 {
		return
	}

	select {
	case m.toEngine <- common.PendingTxs:
	default:
	}
}
