package metrics

import (
	"github.com/MetalBlockchain/pulsevm/chain/block"
	"github.com/prometheus/client_golang/prometheus"
)

const blkLabel = "blk"

var (
	_ block.Visitor = (*blockMetrics)(nil)

	blkLabels = []string{blkLabel}
)

type blockMetrics struct {
	txMetrics *txMetrics
	numBlocks *prometheus.CounterVec
}

func newBlockMetrics(registerer prometheus.Registerer) (*blockMetrics, error) {
	txMetrics, err := newTxMetrics(registerer)
	if err != nil {
		return nil, err
	}

	m := &blockMetrics{
		txMetrics: txMetrics,
		numBlocks: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "blks_accepted",
				Help: "number of blocks accepted",
			},
			blkLabels,
		),
	}
	return m, registerer.Register(m.numBlocks)
}

func (m *blockMetrics) StandardBlock(b *block.StandardBlock) error {
	m.numBlocks.With(prometheus.Labels{
		blkLabel: "standard",
	}).Inc()
	for _, tx := range b.Transactions {
		if err := tx.Unsigned.Visit(m.txMetrics); err != nil {
			return err
		}
	}
	return nil
}
