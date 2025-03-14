package engine

import (
	"context"
	"fmt"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

func ValidateWasm(wasmSource []byte) error {
	runtime := wazero.NewRuntime(context.TODO())
	defer runtime.Close(context.TODO())

	module, err := runtime.Instantiate(context.TODO(), wasmSource)
	if err != nil {
		return fmt.Errorf("failed to instantiate module: %w", err)
	}

	functions := module.ExportedFunctionDefinitions()
	applyFunction := functions["apply"]
	if applyFunction == nil {
		return fmt.Errorf("wasm validation error: missing apply function")
	}
	if len(applyFunction.ParamTypes()) != 3 {
		return fmt.Errorf("wasm validation error: apply function should have 3 parameters")
	}
	for _, paramType := range applyFunction.ParamTypes() {
		if paramType != api.ValueTypeI64 {
			return fmt.Errorf("wasm validation error: apply function parameters should be of type i64")
		}
	}
	if len(applyFunction.ResultTypes()) != 0 {
		return fmt.Errorf("wasm validation error: apply function should have no return value")
	}

	return nil
}
