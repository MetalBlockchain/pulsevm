package api

import (
	"encoding/json"

	"github.com/MetalBlockchain/metalgo/ids"
	"github.com/MetalBlockchain/metalgo/utils/formatting"
)

type EmptyReply struct{}

type IssueTxReply struct {
	TxID ids.ID `json:"txID"`
}

type PingReply struct {
	Success bool `serialize:"true" json:"success"`
}

type GetBlockResponse struct {
	Block json.RawMessage `json:"block"`
	// If GetBlockResponse.Encoding is formatting.Hex, GetBlockResponse.Block is
	// the string representation of the block under hex encoding.
	// If GetBlockResponse.Encoding is formatting.JSON, GetBlockResponse.Block
	// is the actual block returned as a JSON.
	Encoding formatting.Encoding `json:"encoding"`
}
