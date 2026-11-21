package meter

import "strings"

// name.go — what a metered unit reads as on a customer's bill.
//
// A debit records its UNIT in Usage.Model: the model an AI call hit, or the word a
// surface meters by ("session", "op", "desktop/visor"). The unit is the ledger's key
// and stays as written. This is the one place it becomes the words a customer reads,
// so every surface that shows spend — the usage rows, the spend breakdown — names a
// line the same way.
//
// A unit with no entry here is its own name. An AI model's id IS the product a
// customer chose ("zen5"), and a unit nobody has named yet reads as what it is rather
// than as a guess.

// names spells the words surfaces meter by.
var names = map[string]string{
	"session":         "Agent sessions",      // apps/agents: an hour of a running session
	"bot":             "Bots",                // apps/agents: an hour of a resident bot
	"op":              "Storage requests",    // apps/s3, apps/space: one data-plane operation
	"build":           "Builds",              // apps/platform: build minutes
	"compute":         "App compute",         // apps/platform: a live app's running hours
	"invoke":          "Function calls",      // apps/functions: one invocation
	"gbsec":           "Function compute",    // apps/functions: GB-seconds
	"dataset":         "Datasets",            // apps/dataset
	"domain.register": "Domain registration", // apps/domain
}

// sandboxes spells the classes apps/sandbox leases. A lease is billed as
// "<class>/<runtime>", its hours as "sandbox/<class>" and its disk as
// "sandbox/<class>/disk". The runtime says where the pod ran, which a bill does not.
var sandboxes = map[string]string{
	"exec":    "Code sandbox",
	"dev":     "Dev sandbox",
	"desktop": "Desktop sandbox",
	"browser": "Browser sandbox",
	"android": "Android sandbox",
}

// UnitName is what unit reads as on a bill.
func UnitName(unit string) string {
	unit = strings.TrimSpace(unit)
	if n, ok := names[unit]; ok {
		return n
	}
	parts := strings.Split(unit, "/")
	switch {
	case len(parts) == 2 && parts[0] == "sandbox" && sandboxes[parts[1]] != "":
		return sandboxes[parts[1]] + " hours"
	case len(parts) == 3 && parts[0] == "sandbox" && parts[2] == "disk" && sandboxes[parts[1]] != "":
		return sandboxes[parts[1]] + " disk"
	case len(parts) == 2 && sandboxes[parts[0]] != "":
		return sandboxes[parts[0]]
	}
	return unit
}
