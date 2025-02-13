package txs

type Visitor interface {
	BaseTx(*BaseTx) error
}
