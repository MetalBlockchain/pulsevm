package txs

import (
	"fmt"

	"github.com/MetalBlockchain/metalgo/utils/units"
	"github.com/MetalBlockchain/metalgo/utils/wrappers"
)

// CodecVersion is the current default codec version
const CodecVersion = 0

var _ Parser = (*parser)(nil)

type Parser interface {
	ParseTx(bytes []byte) (*Tx, error)
	ParseGenesisTx(bytes []byte) (*Tx, error)
}

type parser struct{}

func NewParser() (Parser, error) {
	return &parser{}, nil
}

func (p *parser) ParseTx(bytes []byte) (*Tx, error) {
	return parse(bytes)
}

func (p *parser) ParseGenesisTx(bytes []byte) (*Tx, error) {
	return parse(bytes)
}

func parse(signedBytes []byte) (*Tx, error) {
	tx := &Tx{}
	if err := tx.Unmarshal(&wrappers.Packer{
		Bytes: signedBytes,
	}); err != nil {
		return nil, err
	}

	unsignedBytes, err := tx.Unsigned.Marshal(&wrappers.Packer{MaxSize: 256 * units.KiB})
	if err != nil {
		return nil, fmt.Errorf("couldn't calculate UnsignedTx marshal length: %w", err)
	}

	tx.SetBytes(unsignedBytes, signedBytes)
	return tx, nil
}
