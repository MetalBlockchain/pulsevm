package api

import "github.com/MetalBlockchain/metalgo/utils/formatting"

type FormattedTx struct {
	Tx       string              `json:"tx"`
	Encoding formatting.Encoding `json:"encoding"`
}
