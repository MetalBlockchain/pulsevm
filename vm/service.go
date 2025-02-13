package vm

import (
	"fmt"
	"net/http"

	"github.com/MetalBlockchain/metalgo/utils/formatting"
	"github.com/MetalBlockchain/pulsevm/api"
	"github.com/MetalBlockchain/pulsevm/chain/txs"
	"go.uber.org/zap"
)

const (
	Endpoint = "/rpc"
)

type Service struct {
	vm *VM
}

type PingReply struct {
	Success bool `serialize:"true" json:"success"`
}

func (svc *Service) Ping(_ *http.Request, _ *struct{}, response *PingReply) (err error) {
	svc.vm.ctx.Log.Debug("API called", zap.String("service", "pulsevm"), zap.String("method", "ping"))

	response.Success = true

	return nil
}

func (svc *Service) IssueTx(_ *http.Request, args *api.FormattedTx, response *api.JSONTxID) (err error) {
	svc.vm.ctx.Log.Debug("API called", zap.String("service", "pulsevm"), zap.String("method", "issueTx"))

	txBytes, err := formatting.Decode(args.Encoding, args.Tx)
	if err != nil {
		return fmt.Errorf("problem decoding transaction: %w", err)
	}
	tx, err := txs.Parse(txs.Codec, txBytes)
	if err != nil {
		return fmt.Errorf("couldn't parse tx: %w", err)
	}
	if err := svc.vm.issueTxFromRPC(tx); err != nil {
		return fmt.Errorf("couldn't issue tx: %w", err)
	}

	response.TxID = tx.ID()

	return nil
}
