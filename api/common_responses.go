package api

import "github.com/MetalBlockchain/metalgo/ids"

type EmptyReply struct{}

type IssueTxReply struct {
	TxID ids.ID `json:"txID"`
}

type PingReply struct {
	Success bool `serialize:"true" json:"success"`
}
