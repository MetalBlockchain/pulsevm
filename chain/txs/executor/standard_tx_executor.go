package executor

import "github.com/MetalBlockchain/pulsevm/chain/txs"

var (
	_ txs.Visitor = (*StandardTransactionExecutor)(nil)
)

type StandardTransactionExecutor struct {
}

func (s *StandardTransactionExecutor) BaseTransaction(*txs.BaseTx) error {
	panic("unimplemented")
}

func (s *StandardTransactionExecutor) CreateAccountTx(*txs.CreateAccountTx) error {
	panic("unimplemented")
}

func (s *StandardTransactionExecutor) CreateAssetTx(*txs.CreateAssetTx) error {
	panic("unimplemented")
}
