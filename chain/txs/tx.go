package txs

import (
	"fmt"

	"github.com/MetalBlockchain/metalgo/codec"
	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/network/p2p/gossip"
	"github.com/MetalBlockchain/metalgo/utils/hashing"
	"github.com/MetalBlockchain/metalgo/utils/set"
)

var (
	_ gossip.Gossipable = (*Tx)(nil)
)

// Tx is a signed transaction
type Tx struct {
	// The body of this transaction
	Unsigned UnsignedTx `serialize:"true" json:"unsignedTx"`

	TxID  ids.ID `json:"id"`
	bytes []byte
}

func (tx *Tx) SetBytes(unsignedBytes, signedBytes []byte) {
	tx.Unsigned.SetBytes(unsignedBytes)
	tx.bytes = signedBytes
	tx.TxID = hashing.ComputeHash256Array(signedBytes)
}

func (tx *Tx) Bytes() []byte {
	return tx.bytes
}

func (tx *Tx) Size() int {
	return len(tx.bytes)
}

func (tx *Tx) ID() ids.ID {
	return tx.TxID
}

func (tx *Tx) GossipID() ids.ID {
	return tx.TxID
}

func (tx *Tx) InputIDs() set.Set[ids.ID] {
	return make(set.Set[ids.ID])
}

func (tx *Tx) Initialize(c codec.Manager) error {
	signedBytes, err := c.Marshal(CodecVersion, tx)
	if err != nil {
		return fmt.Errorf("couldn't marshal ProposalTx: %w", err)
	}

	unsignedBytesLen, err := c.Size(CodecVersion, &tx.Unsigned)
	if err != nil {
		return fmt.Errorf("couldn't calculate UnsignedTx marshal length: %w", err)
	}

	unsignedBytes := signedBytes[:unsignedBytesLen]
	tx.SetBytes(unsignedBytes, signedBytes)
	return nil
}

// Parse signed tx starting from its byte representation.
// Note: We explicitly pass the codec in Parse since we may need to parse
// P-Chain genesis txs whose length exceed the max length of txs.Codec.
func Parse(c codec.Manager, signedBytes []byte) (*Tx, error) {
	tx := &Tx{}
	if _, err := c.Unmarshal(signedBytes, tx); err != nil {
		return nil, fmt.Errorf("couldn't parse tx: %w", err)
	}

	unsignedBytesLen, err := c.Size(CodecVersion, &tx.Unsigned)
	if err != nil {
		return nil, fmt.Errorf("couldn't calculate UnsignedTx marshal length: %w", err)
	}

	unsignedBytes := signedBytes[:unsignedBytesLen]
	tx.SetBytes(unsignedBytes, signedBytes)
	return tx, nil
}
