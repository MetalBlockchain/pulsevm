package txs

type Visitor interface {
	BaseTransaction(*BaseTx) error
	CreateAccountTx(*CreateAccountTx) error
	CreateAssetTx(*CreateAssetTx) error
}
