package api

import (
	"github.com/MetalBlockchain/metalgo/utils/formatting"
	avajson "github.com/MetalBlockchain/metalgo/utils/json"
)

type FormattedTx struct {
	Tx       string              `json:"tx"`
	Encoding formatting.Encoding `json:"encoding"`
}

type GetBlockByHeightArgs struct {
	Height   avajson.Uint64      `json:"height"`
	Encoding formatting.Encoding `json:"encoding"`
}
