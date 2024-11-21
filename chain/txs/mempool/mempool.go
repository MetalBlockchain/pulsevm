package mempool

import (
	txmempool "github.com/MetalBlockchain/metalgo/vms/txs/mempool"
	"github.com/MetalBlockchain/pulsevm/chain/txs"
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
