package vm

import (
	"net/http"
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

func (svc *Service) Ping(_ *http.Request, _ *struct{}, reply *PingReply) (err error) {
	reply.Success = true
	return nil
}
