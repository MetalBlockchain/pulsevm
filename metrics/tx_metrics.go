package metrics

import (
	"github.com/MetalBlockchain/pulsevm/chain/txs"
	"github.com/prometheus/client_golang/prometheus"
)

const txLabel = "tx"

var (
	_ txs.Visitor = (*txMetrics)(nil)

	txLabels = []string{txLabel}
)

type txMetrics struct {
	numTxs *prometheus.CounterVec
}

func newTxMetrics(registerer prometheus.Registerer) (*txMetrics, error) {
	m := &txMetrics{
		numTxs: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "txs_accepted",
				Help: "number of transactions accepted",
			},
			txLabels,
		),
	}
	return m, registerer.Register(m.numTxs)
}

func (m *txMetrics) BaseTransaction(*txs.BaseTx) error {
	m.numTxs.With(prometheus.Labels{
		txLabel: "base",
	}).Inc()
	return nil
}
