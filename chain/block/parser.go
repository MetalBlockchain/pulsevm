package block

import (
	"github.com/MetalBlockchain/metalgo/utils/wrappers"
	"github.com/MetalBlockchain/pulsevm/chain/txs"
)

// CodecVersion is the current default codec version
const CodecVersion = txs.CodecVersion

var _ Parser = (*parser)(nil)

type Parser interface {
	txs.Parser

	ParseBlock(bytes []byte) (Block, error)
	ParseGenesisBlock(bytes []byte) (Block, error)
}

type parser struct {
	txs.Parser
}

func NewParser() (Parser, error) {
	p, err := txs.NewParser()
	if err != nil {
		return nil, err
	}
	return &parser{
		Parser: p,
	}, err
}

func (p *parser) ParseBlock(bytes []byte) (Block, error) {
	return parse(bytes)
}

func (p *parser) ParseGenesisBlock(bytes []byte) (Block, error) {
	return parse(bytes)
}

func parse(bytes []byte) (Block, error) {
	var blk Block
	if err := blk.Unmarshal(&wrappers.Packer{
		Bytes: bytes,
	}); err != nil {
		return nil, err
	}
	return blk, blk.initialize(bytes)
}
