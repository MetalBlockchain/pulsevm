package vm

import (
	"encoding/json"
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

func (s *Service) GetBlockByHeight(_ *http.Request, args *api.GetBlockByHeightArgs, reply *api.GetBlockResponse) error {
	s.vm.ctx.Log.Debug("API called",
		zap.String("service", "pulsevm"),
		zap.String("method", "getBlockByHeight"),
		zap.Uint64("height", uint64(args.Height)),
	)

	s.vm.ctx.Lock.Lock()
	defer s.vm.ctx.Lock.Unlock()

	reply.Encoding = args.Encoding
	blockID, err := s.vm.state.GetBlockIDAtHeight(uint64(args.Height))
	if err != nil {
		return fmt.Errorf("couldn't get block at height %d: %w", args.Height, err)
	}
	block, err := s.vm.chainManager.GetStatelessBlock(blockID)
	if err != nil {
		s.vm.ctx.Log.Error("couldn't get accepted block",
			zap.Stringer("blkID", blockID),
			zap.Error(err),
		)
		return fmt.Errorf("couldn't get block with id %s: %w", blockID, err)
	}

	var result any
	if args.Encoding == formatting.JSON {
		result = block
	} else {
		result, err = formatting.Encode(args.Encoding, block.Bytes())
		if err != nil {
			return fmt.Errorf("couldn't encode block %s as string: %w", blockID, err)
		}
	}

	reply.Block, err = json.Marshal(result)
	return err
}
