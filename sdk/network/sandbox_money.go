package network

import (
	"fmt"
	"slices"
	"strings"
)

// A SANDBOX NETWORK HOLDS NO PRODUCTION PAYMENT MATERIAL, and refuses to boot
// holding any.
//
// SandboxOnly forces the sandbox books and refuses the posture switch, and
// commerce's ceiling keeps every org in test. Neither can take back a
// credential the pod was handed: a production Square token in the environment
// of a testnet or devnet is a real merchant account one code path away from a
// charge. So the environment itself is checked before anything serves, and the
// answer names every offending variable, never its value.
//
// Off mainnet it requires:
//   - none of the production Square names (SQUARE_ACCESS_TOKEN,
//     SQUARE_APPLICATION_ID, SQUARE_LOCATION_ID, or commerce's
//     SQUARE_PRODUCTION_* spellings) to carry a value;
//   - no variable to carry a live payment key (sk_live_, rk_live_);
//   - no Square name outside the SQUARE_SANDBOX_* set to carry an access
//     token (EAAA…);
//   - SQUARE_SANDBOX_APPLICATION_ID, when set, to be a sandbox application
//     (sandbox-…);
//   - SQUARE_ENVIRONMENT to be sandbox.
//
// On mainnet it requires nothing: production money is what mainnet is for.
func SandboxMoney(n Network, env []string) error {
	if n == Mainnet {
		return nil
	}
	var bad []string
	square := ""
	paypalEnv := ""
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		v = strings.TrimSpace(v)
		if k == "SQUARE_ENVIRONMENT" {
			square = strings.ToLower(v)
		}
		if k == "PAYPAL_ENVIRONMENT" {
			paypalEnv = strings.ToLower(v)
		}
		if v == "" {
			continue
		}
		switch {
		case slices.Contains(liveSquare, k):
			bad = append(bad, k+" (a production Square name)")
		case slices.Contains(livePayPal, k):
			bad = append(bad, k+" (a production PayPal name)")
		case strings.HasPrefix(v, "sk_live_") || strings.HasPrefix(v, "rk_live_"):
			bad = append(bad, k+" (a live payment key)")
		case strings.HasPrefix(k, "SQUARE_") && !strings.HasPrefix(k, "SQUARE_SANDBOX_") && strings.HasPrefix(v, "EAAA"):
			bad = append(bad, k+" (a Square access token outside the SQUARE_SANDBOX_ names)")
		case k == "SQUARE_SANDBOX_APPLICATION_ID" && !strings.HasPrefix(v, "sandbox-"):
			bad = append(bad, k+" (not a sandbox application: want sandbox-…)")
		}
	}
	if square != "sandbox" {
		bad = append(bad, "SQUARE_ENVIRONMENT (want sandbox)")
	}
	if paypalEnv != "" && paypalEnv != "sandbox" && paypalEnv != "test" {
		bad = append(bad, "PAYPAL_ENVIRONMENT (want sandbox)")
	}
	if len(bad) == 0 {
		return nil
	}
	slices.Sort(bad)
	return fmt.Errorf("%s is a sandbox network and its environment holds production payment material: %s", n, strings.Join(bad, ", "))
}

// liveSquare is every name a production Square credential is read under: the
// deployment's own (commerce thirdparty/square) and commerce's KMS spellings.
var liveSquare = []string{
	"SQUARE_ACCESS_TOKEN",
	"SQUARE_APPLICATION_ID",
	"SQUARE_LOCATION_ID",
	"SQUARE_PRODUCTION_ACCESS_TOKEN",
	"SQUARE_PRODUCTION_APPLICATION_ID",
	"SQUARE_PRODUCTION_LOCATION_ID",
}

// livePayPal is every name a production PayPal credential is read under.
var livePayPal = []string{
	"PAYPAL_CLIENT_ID",
	"PAYPAL_CLIENT_SECRET",
	"PAYPAL_APPLICATION_ID",
	"PAYPAL_WEBHOOK_ID",
	"PAYPAL_LIVE_CLIENT_ID",
	"PAYPAL_LIVE_CLIENT_SECRET",
	"PAYPAL_LIVE_APPLICATION_ID",
	"PAYPAL_LIVE_WEBHOOK_ID",
}
