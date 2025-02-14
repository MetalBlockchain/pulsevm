package network

import (
	"sync"

	"github.com/MetalBlockchain/pulsevm/chain/txs"
)

var _ TxVerifier = (*LockedTxVerifier)(nil)

type TxVerifier interface {
	// VerifyTx verifies that the transaction should be issued into the mempool.
	VerifyTx(tx *txs.Tx) error
}

type LockedTxVerifier struct {
	lock       sync.Locker
	txVerifier TxVerifier
}

func (l *LockedTxVerifier) VerifyTx(tx *txs.Tx) error {
	l.lock.Lock()
	defer l.lock.Unlock()

	return l.txVerifier.VerifyTx(tx)
}

func NewLockedTxVerifier(lock sync.Locker, txVerifier TxVerifier) *LockedTxVerifier {
	return &LockedTxVerifier{
		lock:       lock,
		txVerifier: txVerifier,
	}
}
