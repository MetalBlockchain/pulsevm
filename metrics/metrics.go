package metrics

import (
	"github.com/MetalBlockchain/metalgo/utils/metric"
	"github.com/MetalBlockchain/metalgo/utils/wrappers"
	"github.com/MetalBlockchain/pulsevm/chain/block"
	"github.com/prometheus/client_golang/prometheus"
)

var _ Metrics = (*metrics)(nil)

type Block struct {
	Block block.Block
}

type Metrics interface {
	metric.APIInterceptor

	// Mark that the given block was accepted.
	MarkAccepted(Block) error
}

func New(registerer prometheus.Registerer) (Metrics, error) {
	blockMetrics, err := newBlockMetrics(registerer)
	m := &metrics{
		blockMetrics: blockMetrics,
	}

	errs := wrappers.Errs{Err: err}
	apiRequestMetrics, err := metric.NewAPIInterceptor(registerer)
	errs.Add(err)
	m.APIInterceptor = apiRequestMetrics

	return m, errs.Err
}

type metrics struct {
	metric.APIInterceptor

	blockMetrics *blockMetrics
}

func (m *metrics) MarkAccepted(b Block) error {
	return b.Block.Visit(m.blockMetrics)
}
