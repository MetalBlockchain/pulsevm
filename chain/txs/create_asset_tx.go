package txs

var (
	_ UnsignedTx = (*CreateAssetTx)(nil)
)

type CreateAssetTx struct {
	BaseTx
}

func (tx *CreateAssetTx) Visit(visitor Visitor) error {
	return visitor.CreateAssetTx(tx)
}
