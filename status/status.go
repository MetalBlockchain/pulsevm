package status

import (
	"errors"
	"fmt"

	"github.com/MetalBlockchain/metalgo/vms/components/verify"
)

// List of possible status values:
// - [Unknown] The transaction is not known
// - [Committed] The transaction was proposed and committed
// - [Aborted] The transaction was proposed and aborted
// - [Processing] The transaction was proposed and is currently in the preferred chain
// - [Dropped] The transaction was dropped due to failing verification
const (
	Unknown    Status = 0
	Committed  Status = 4
	Aborted    Status = 5
	Processing Status = 6
	Dropped    Status = 8
)

var (
	errUnknownStatus = errors.New("unknown status")

	_ verify.Verifiable = Status(0)
	_ fmt.Stringer      = Status(0)
)

type Status uint32

// Verify that this is a valid status.
func (s Status) Verify() error {
	switch s {
	case Unknown, Committed, Aborted, Processing, Dropped:
		return nil
	default:
		return errUnknownStatus
	}
}

func (s Status) String() string {
	switch s {
	case Unknown:
		return "Unknown"
	case Committed:
		return "Committed"
	case Aborted:
		return "Aborted"
	case Processing:
		return "Processing"
	case Dropped:
		return "Dropped"
	default:
		return "Invalid status"
	}
}
