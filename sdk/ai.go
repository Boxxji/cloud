package cloud

import (
	"context"

	tasksclient "github.com/hanzoai/tasks/pkg/sdk/client"
)

// Callbacks the ai module makes back into the host. Declared here, installed by
// apps/ — importing ai/object here would put ~1480 packages under every
// subsystem, and nothing here reads back from it.

type (
	BalanceReaderFunc func(ctx context.Context, subject, namespace, currency string) (int64, error)
	IngestDialerFunc  func(org string) (tasksclient.Client, error)
)

var (
	balanceReader BalanceReaderFunc
	ingestDialer  IngestDialerFunc
)

// nil means that subsystem isn't co-resident; apps/ leaves it uninstalled.
//
// There were FIVE of these, and the fifth was a writer rather than a snapshot: an
// exported SetRollingCapReader, written from outside this package so a separate
// rollingcap app could install the AI-spend cap. A writer across this edge cannot
// work, because the edge these globals sit on is a PROCESS. Every app is its own
// child, so a value written into this variable in one child is invisible in
// every other — and the only reader was the `ai` module's gate, in ai's child.
// The plan limits compose where that gate runs (apps/ai/limits.go) and need no writer.
func BalanceReader() BalanceReaderFunc { return balanceReader }

// SetBalanceReader installs the wallet read the AI gate weighs a call against. The host
// calls it once, when it wires the finance ledger.
func SetBalanceReader(f BalanceReaderFunc) { balanceReader = f }
func IngestDialer() IngestDialerFunc       { return ingestDialer }
