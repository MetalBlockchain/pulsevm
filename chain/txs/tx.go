package txs

import (
	"fmt"

	"github.com/MetalBlockchain/metalgo/codec"
	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/network/p2p/gossip"
	"github.com/MetalBlockchain/metalgo/utils/crypto/secp256k1"
	"github.com/MetalBlockchain/metalgo/utils/hashing"
)

var (
	_ gossip.Gossipable = (*Tx)(nil)
)

// Tx is a signed transaction
type Tx struct {
	// The body of this transaction
	Unsigned   UnsignedTx `serialize:"true" json:"unsignedTx"`
	TxID       ids.ID     `json:"id"`
	Signatures [][]byte   `serialize:"true" json:"signatures"`

	bytes []byte
	codec codec.Manager
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

func (tx *Tx) Initialize(c codec.Manager) error {
	tx.codec = c
	signedBytes, err := c.Marshal(CodecVersion, tx)
	if err != nil {
		return fmt.Errorf("problem creating transaction: %w", err)
	}

	unsignedBytesLen, err := c.Size(CodecVersion, &tx.Unsigned)
	if err != nil {
		return fmt.Errorf("couldn't calculate UnsignedTx marshal length: %w", err)
	}

	unsignedBytes := signedBytes[:unsignedBytesLen]
	tx.SetBytes(unsignedBytes, signedBytes)
	return nil
}

func (tx *Tx) Sign(privateKey secp256k1.PrivateKey) error {
	sig, err := privateKey.Sign(tx.Unsigned.Bytes())
	if err != nil {
		return fmt.Errorf("problem signing transaction: %w", err)
	}
	tx.Signatures = append(tx.Signatures, sig)
	signedBytes, err := tx.codec.Marshal(CodecVersion, tx)
	if err != nil {
		return fmt.Errorf("problem creating transaction: %w", err)
	}
	tx.bytes = signedBytes
	return nil
}
