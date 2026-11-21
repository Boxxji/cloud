package network

import (
	"strings"
	"testing"
)

// sandboxEnv is what a sandbox network's values file declares: Square's
// sandbox and nothing of production's.
func sandboxEnv(extra ...string) []string {
	return append([]string{
		"SQUARE_ENVIRONMENT=sandbox",
		"SQUARE_SANDBOX_ACCESS_TOKEN=EAAAl-sandbox-token",
		"SQUARE_SANDBOX_APPLICATION_ID=sandbox-sq0idb-APP",
		"SQUARE_SANDBOX_LOCATION_ID=LSANDBOX",
		"SQUARE_WEBHOOK_SIGNATURE_KEY=whsig",
		"CLOUD_NETWORK=devnet",
	}, extra...)
}

// The sandbox shape boots on both sandbox networks.
func TestSandboxMoneyAdmitsTheSandboxShape(t *testing.T) {
	for _, n := range []Network{Testnet, Devnet} {
		if err := SandboxMoney(n, sandboxEnv()); err != nil {
			t.Fatalf("%s refused its own sandbox values: %v", n, err)
		}
		if err := SandboxMoney(n, sandboxEnv(
			"PAYPAL_ENVIRONMENT=sandbox",
			"PAYPAL_SANDBOX_CLIENT_ID=ASLZ-sandbox",
			"PAYPAL_SANDBOX_CLIENT_SECRET=EImN-sandbox",
			"PAYPAL_SANDBOX_WEBHOOK_ID=9T362023MY7177815",
		)); err != nil {
			t.Fatalf("%s refused its own PayPal sandbox values: %v", n, err)
		}
	}
}

// Each piece of production payment material, alone, stops a sandbox network,
// and the refusal names the variable and never its value.
func TestSandboxMoneyRefusesProductionMaterial(t *testing.T) {
	cases := []struct {
		name string
		env  []string
		want string
	}{
		{"production token", sandboxEnv("SQUARE_ACCESS_TOKEN=EAAAprod-hostile"), "SQUARE_ACCESS_TOKEN"},
		{"production application", sandboxEnv("SQUARE_APPLICATION_ID=sq0idp-hostile"), "SQUARE_APPLICATION_ID"},
		{"production location", sandboxEnv("SQUARE_LOCATION_ID=LPROD-hostile"), "SQUARE_LOCATION_ID"},
		{"commerce's production spelling", sandboxEnv("SQUARE_PRODUCTION_ACCESS_TOKEN=EAAAprod-hostile"), "SQUARE_PRODUCTION_ACCESS_TOKEN"},
		{"live payment key anywhere", sandboxEnv("STRIPE_SECRET_KEY=sk_live_hostile"), "STRIPE_SECRET_KEY"},
		{"restricted live key", sandboxEnv("PAYMENTS_KEY=rk_live_hostile"), "PAYMENTS_KEY"},
		{"access token under another Square name", sandboxEnv("SQUARE_TOKEN=EAAAprod-hostile"), "SQUARE_TOKEN"},
		{"production application under the sandbox name", []string{"SQUARE_ENVIRONMENT=sandbox", "SQUARE_SANDBOX_APPLICATION_ID=sq0idp-hostile"}, "SQUARE_SANDBOX_APPLICATION_ID"},
		{"production environment", []string{"SQUARE_ENVIRONMENT=production"}, "SQUARE_ENVIRONMENT"},
		{"no environment declared", []string{"SQUARE_SANDBOX_APPLICATION_ID=sandbox-sq0idb-APP"}, "SQUARE_ENVIRONMENT"},
		{"paypal live client id", sandboxEnv("PAYPAL_CLIENT_ID=BAAprod-hostile"), "PAYPAL_CLIENT_ID"},
		{"paypal live client secret", sandboxEnv("PAYPAL_CLIENT_SECRET=EKprod-hostile"), "PAYPAL_CLIENT_SECRET"},
		{"paypal explicit live client id", sandboxEnv("PAYPAL_LIVE_CLIENT_ID=BAAprod-hostile"), "PAYPAL_LIVE_CLIENT_ID"},
		{"paypal production environment", sandboxEnv("PAYPAL_ENVIRONMENT=live"), "PAYPAL_ENVIRONMENT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := SandboxMoney(Devnet, tc.env)
			if err == nil {
				t.Fatal("a sandbox network booted holding production payment material")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refusal %q does not name %s", err, tc.want)
			}
			if strings.Contains(err.Error(), "hostile") {
				t.Fatalf("refusal %q prints a value", err)
			}
		})
	}
}

// Every offending variable is named in one refusal, not the first only.
func TestSandboxMoneyNamesEveryOffender(t *testing.T) {
	err := SandboxMoney(Testnet, []string{"SQUARE_ENVIRONMENT=production", "SQUARE_ACCESS_TOKEN=EAAAx", "SQUARE_LOCATION_ID=L"})
	if err == nil {
		t.Fatal("refused nothing")
	}
	for _, name := range []string{"SQUARE_ENVIRONMENT", "SQUARE_ACCESS_TOKEN", "SQUARE_LOCATION_ID"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("refusal %q omits %s", err, name)
		}
	}
}

// An empty production name is not material: a values file may list a name
// whose Secret key is unset.
func TestSandboxMoneyIgnoresEmptyNames(t *testing.T) {
	if err := SandboxMoney(Devnet, sandboxEnv("SQUARE_ACCESS_TOKEN=", "SQUARE_LOCATION_ID=  ")); err != nil {
		t.Fatalf("empty production names refused: %v", err)
	}
}

// Mainnet holds production money by definition, and the check is not run.
func TestSandboxMoneyLeavesMainnetAlone(t *testing.T) {
	env := []string{"SQUARE_ENVIRONMENT=production", "SQUARE_ACCESS_TOKEN=EAAAprod", "SQUARE_APPLICATION_ID=sq0idp-APP", "SQUARE_LOCATION_ID=L"}
	if err := SandboxMoney(Mainnet, env); err != nil {
		t.Fatalf("mainnet refused its own production values: %v", err)
	}
	if err := SandboxMoney(Mainnet, nil); err != nil {
		t.Fatalf("mainnet with no payment env refused: %v", err)
	}
}
