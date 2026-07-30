package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// PulseVM exposes a JSON-RPC 2.0 API at the chain's handler prefix. Queries are
// issued directly from Go so that assertions live in the test rather than in
// the Rust fixture, which is limited to signing and submitting transactions.

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	// PulseVM puts the underlying cause here; the message alone is a generic
	// label like "internal_error".
	Data string `json:"data"`
}

func (e *rpcError) String() string {
	if e.Data != "" {
		return fmt.Sprintf("%d: %s: %s", e.Code, e.Message, e.Data)
	}
	return fmt.Sprintf("%d: %s", e.Code, e.Message)
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error"`
}

// RPCCall issues a JSON-RPC request against a chain endpoint and unmarshals the
// result into out.
func RPCCall(ctx context.Context, uri, method string, params any, out any) error {
	body, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: 1, Method: method, Params: params})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var decoded rpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return fmt.Errorf("decoding %s response: %w", method, err)
	}
	if decoded.Error != nil {
		return fmt.Errorf("%s: RPC error %s", method, decoded.Error)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(decoded.Result, out)
}

// CurrencyBalance returns the balance `account` holds of `symbol` in the token
// contract at `code`, e.g. "250.0000 PULSE". An account with no balance row
// yields an empty string rather than an error, matching the chain's behaviour
// of returning an empty list.
func CurrencyBalance(ctx context.Context, uri, code, account, symbol string) (string, error) {
	var balances []string
	err := RPCCall(ctx, uri, "pulsevm.getCurrencyBalance", map[string]any{
		"code":    code,
		"account": account,
		"symbol":  symbol,
	}, &balances)
	if err != nil {
		return "", err
	}
	if len(balances) == 0 {
		return "", nil
	}
	return balances[0], nil
}
