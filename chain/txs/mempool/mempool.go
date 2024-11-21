package mempool

import (
	"github.com/MetalBlockchain/metalgo/snow/engine/common"
	txmempool "github.com/MetalBlockchain/metalgo/vms/txs/mempool"
	"github.com/MetalBlockchain/pulsevm/chain/txs"
	"github.com/prometheus/client_golang/prometheus"
)

type Mempool interface {
	txmempool.Mempool[*txs.Tx]

	// RequestBuildBlock notifies the consensus engine that a block should be
	// built. If [emptyBlockPermitted] is true, the notification will be sent
	// regardless of whether there are no transactions in the mempool. If not,
	// a notification will only be sent if there is at least one transaction in
	// the mempool.
	RequestBuildBlock(emptyBlockPermitted bool)
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
	pool := txmempool.New[*txs.Tx](metrics)
	return &mempool{
		Mempool:  pool,
		toEngine: toEngine,
	}, nil
}

func (m *mempool) Add(tx *txs.Tx) error {
	return m.Mempool.Add(tx)
}

func (m *mempool) RequestBuildBlock(emptyBlockPermitted bool) {
	if !emptyBlockPermitted && m.Len() == 0 {
		return
	}

	select {
	case m.toEngine <- common.PendingTxs:
	default:
	}
}
