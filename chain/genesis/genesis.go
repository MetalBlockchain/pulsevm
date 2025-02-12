package genesis

import (
	"encoding/json"
	"fmt"
	"time"
)

type Genesis struct {
	Timestamp time.Time `serialize:"true" json:"timestamp"`
}

func Parse(genesisBytes []byte) (*Genesis, error) {
	gen := &Genesis{}

	if err := json.Unmarshal(genesisBytes, gen); err != nil {
		return nil, fmt.Errorf("failed to parse the genesis file: %v", err)
	}

	return gen, nil
}
