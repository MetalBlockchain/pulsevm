package txs

var (
	_ UnsignedTx = (*CreateAssetTx)(nil)
)

type CreateAccountTx struct {
	BaseTx
}

func (tx *CreateAccountTx) Visit(visitor Visitor) error {
	return visitor.CreateAccountTx(tx)
}
