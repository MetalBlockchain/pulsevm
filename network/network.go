package network

import (
	"github.com/MetalBlockchain/metalgo/network/p2p/gossip"
	"github.com/MetalBlockchain/metalgo/utils/logging"
	"github.com/MetalBlockchain/pulsevm/chain/txs"
)

type Network struct {
	log logging.Logger

	txPushGossiper *gossip.PushGossiper[*txs.Tx]
}

func New(
	log logging.Logger,
	parser txs.Parser
) (*Network, error) {
	marshaller := &txParser{
		parser: parser,
	}
	txPushGossiper, err := gossip.NewPushGossiper[*txs.Tx](
		marshaller,
		gossipMempool,
		validators,
		txGossipClient,
		txGossipMetrics,
		gossip.BranchingFactor{
			StakePercentage: config.PushGossipPercentStake,
			Validators:      config.PushGossipNumValidators,
			Peers:           config.PushGossipNumPeers,
		},
		gossip.BranchingFactor{
			Validators: config.PushRegossipNumValidators,
			Peers:      config.PushRegossipNumPeers,
		},
		config.PushGossipDiscardedCacheSize,
		config.TargetGossipSize,
		config.PushGossipMaxRegossipFrequency,
	)
	if err != nil {
		return nil, err
	}

	return &Network{
		log:            log,
		txPushGossiper: txPushGossiper,
	}, nil
}

func (n *Network) IssueTxFromRPC(tx *txs.Tx) error {
	if err := n.mempool.Add(tx); err != nil {
		return err
	}
	n.txPushGossiper.Add(tx)
	return nil
}
