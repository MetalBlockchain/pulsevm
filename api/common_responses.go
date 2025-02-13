package api

import "github.com/MetalBlockchain/metalgo/ids"

type EmptyReply struct{}

type JSONTxID struct {
	TxID ids.ID `json:"txID"`
}
