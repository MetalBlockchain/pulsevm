package engine

import (
	_ "embed"
	"testing"

	"github.com/stretchr/testify/assert"
)

//go:embed wasm_examples/00_fibonacci.wasm
var fibonacciWasm []byte

//go:embed wasm_examples/02_valid.wasm
var validWasm []byte

//go:embed wasm_examples/03_invalid_apply_params.wasm
var invalidApplyParamsWasm []byte

//go:embed wasm_examples/04_invalid_apply_response.wasm
var invalidApplyResponseWasm []byte

func TestWasmValidation(t *testing.T) {
	if err := ValidateWasm(fibonacciWasm); err != nil {
		assert.EqualErrorf(t, err, "wasm validation error: missing apply function", "unexpected error: %v", err)
	} else {
		t.Error("expected error, got nil")
	}

	err := ValidateWasm(validWasm)
	assert.NoError(t, err)

	if err := ValidateWasm(invalidApplyParamsWasm); err != nil {
		assert.EqualErrorf(t, err, "wasm validation error: apply function should have 3 parameters", "unexpected error: %v", err)
	} else {
		t.Error("expected error, got nil")
	}

	if err := ValidateWasm(invalidApplyResponseWasm); err != nil {
		assert.EqualErrorf(t, err, "wasm validation error: apply function should have no return value", "unexpected error: %v", err)
	} else {
		t.Error("expected error, got nil")
	}
}
