package txs

import (
	"fmt"

	"github.com/MetalBlockchain/metalgo/codec"
	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/network/p2p/gossip"
	"github.com/MetalBlockchain/metalgo/utils/crypto/secp256k1"
	"github.com/MetalBlockchain/metalgo/utils/hashing"
	"github.com/MetalBlockchain/metalgo/utils/units"
	"github.com/MetalBlockchain/metalgo/utils/wrappers"
	"github.com/MetalBlockchain/pulsevm/chain/common"
)

var (
	_ gossip.Gossipable   = (*Tx)(nil)
	_ common.Serializable = (*Tx)(nil)
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

func (tx *Tx) Marshal(p *wrappers.Packer) ([]byte, error) {
	p.PackShort(tx.Unsigned.GetType())
	if _, err := tx.Unsigned.Marshal(p); err != nil {
		return nil, err
	}
	p.PackInt(uint32(len(tx.Signatures)))
	for _, sig := range tx.Signatures {
		p.PackFixedBytes(sig)
	}
	return p.Bytes, p.Err
}

func (tx *Tx) Unmarshal(p *wrappers.Packer) error {
	// Type ID
	typeID := p.UnpackShort()
	switch typeID {
	case BASE_TX:
		tx.Unsigned = &BaseTx{}
		if err := tx.Unsigned.Unmarshal(p); err != nil {
			return err
		}
		numSignatures := p.UnpackInt()
		tx.Signatures = make([][]byte, numSignatures)
		for i := range int(numSignatures) {
			tx.Signatures[i] = p.UnpackFixedBytes(secp256k1.SignatureLen)
		}
		return p.Err
	default:
		return fmt.Errorf("unknown tx type: %d", typeID)
	}
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

func (tx *Tx) Initialize() error {
	signedBytes, err := tx.Marshal(&wrappers.Packer{MaxSize: 256 * units.KiB})
	if err != nil {
		return fmt.Errorf("problem creating transaction: %w", err)
	}

	unsignedBytes, err := tx.Unsigned.Marshal(&wrappers.Packer{MaxSize: 256 * units.KiB})
	if err != nil {
		return fmt.Errorf("couldn't calculate UnsignedTx marshal length: %w", err)
	}

	tx.SetBytes(unsignedBytes, signedBytes)
	return nil
}

func (tx *Tx) Sign(privateKey *secp256k1.PrivateKey) error {
	sig, err := privateKey.Sign(tx.Unsigned.Bytes())
	if err != nil {
		return fmt.Errorf("problem signing transaction: %w", err)
	}
	tx.Signatures = append(tx.Signatures, sig)
	signedBytes, err := tx.Marshal(&wrappers.Packer{MaxSize: 256 * units.KiB})
	if err != nil {
		return fmt.Errorf("problem creating transaction: %w", err)
	}
	tx.bytes = signedBytes
	return nil
}
