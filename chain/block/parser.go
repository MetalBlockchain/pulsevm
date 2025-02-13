package block

import (
	"errors"

	"github.com/MetalBlockchain/metalgo/codec"
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
	c := p.CodecRegistry()
	gc := p.GenesisCodecRegistry()

	err = errors.Join(
		c.RegisterType(&StandardBlock{}),
		gc.RegisterType(&StandardBlock{}),
	)
	return &parser{
		Parser: p,
	}, err
}

func (p *parser) ParseBlock(bytes []byte) (Block, error) {
	return parse(p.Codec(), bytes)
}

func (p *parser) ParseGenesisBlock(bytes []byte) (Block, error) {
	return parse(p.GenesisCodec(), bytes)
}

func parse(cm codec.Manager, bytes []byte) (Block, error) {
	var blk Block
	if _, err := cm.Unmarshal(bytes, &blk); err != nil {
		return nil, err
	}
	return blk, blk.initialize(bytes, cm)
}
