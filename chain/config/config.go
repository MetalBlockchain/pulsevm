package config

import (
	"encoding/json"

	"github.com/MetalBlockchain/metalgo/utils/units"
)

var Default = Config{
	BlockCacheSize:   64 * units.MiB,
	TxCacheSize:      128 * units.MiB,
	BlockIDCacheSize: 8192,
}

type Config struct {
	BlockCacheSize   int `json:"block-cache-size"`
	TxCacheSize      int `json:"tx-cache-size"`
	BlockIDCacheSize int `json:"block-id-cache-size"`
}

func GetConfig(b []byte) (*Config, error) {
	ec := Default

	// An empty slice is invalid json, so handle that as a special case.
	if len(b) == 0 {
		return &ec, nil
	}

	return &ec, json.Unmarshal(b, &ec)
}
