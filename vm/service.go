package vm

import (
	"fmt"
	"net/http"

	"github.com/MetalBlockchain/metalgo/utils/formatting"
	"github.com/MetalBlockchain/metalgo/utils/logging"
	"github.com/MetalBlockchain/pulsevm/api"
	"go.uber.org/zap"
)

const (
	Endpoint = "/rpc"
)

type Service struct {
	vm *VM
}

func (svc *Service) Ping(_ *http.Request, _ *struct{}, response *api.PingReply) (err error) {
	svc.vm.ctx.Log.Info("API called", zap.String("service", "pulsevm"), zap.String("method", "ping"))

	response.Success = true

	return nil
}

func (svc *Service) IssueTx(_ *http.Request, args *api.FormattedTx, response *api.IssueTxReply) (err error) {
	svc.vm.ctx.Log.Info("API called",
		zap.String("service", "pulsevm"),
		zap.String("method", "issueTx"),
		logging.UserString("tx", args.Tx),
	)

	txBytes, err := formatting.Decode(args.Encoding, args.Tx)
	if err != nil {
		return fmt.Errorf("problem decoding transaction: %w", err)
	}

	tx, err := svc.vm.parser.ParseTx(txBytes)
	if err != nil {
		svc.vm.ctx.Log.Debug("failed to parse tx",
			zap.Error(err),
		)
		return err
	}

	response.TxID, err = svc.vm.issueTxFromRPC(tx)

	return err
}
