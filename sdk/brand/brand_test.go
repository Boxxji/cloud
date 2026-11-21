package brand

import (
	"net/url"
	"slices"
	"strings"
	"testing"
)

// TestOneIssuerRuleForBothHosts pins the disagreement Issuer was extracted to end.
//
// A pinned issuer with a trailing slash was trimmed by package cloud and NOT by the
// light host, which had spelled the rule again inline because it is built not to
// link package cloud. An OIDC issuer is compared as a literal string, so those are
// two different issuers: a token stamped by one fails validation against the other.
func TestOneIssuerRuleForBothHosts(t *testing.T) {
	for _, tc := range []struct{ pinned, id, want string }{
		{"https://hanzo.id/", "hanzo", "https://hanzo.id"},    // the trailing slash is the bug
		{"  https://hanzo.id  ", "hanzo", "https://hanzo.id"}, // and so is the whitespace
		{"https://iam.example/", "lux", "https://iam.example"},
		{"", "hanzo", IssuerFor("hanzo")}, // unpinned falls to the brand's own
		{"   ", "lux", IssuerFor("lux")},  // blank is unpinned, not a pin of ""
	} {
		if got := Issuer(tc.pinned, tc.id); got != tc.want {
			t.Errorf("Issuer(%q, %q) = %q, want %q", tc.pinned, tc.id, got, tc.want)
		}
	}

	// It never answers empty. An empty issuer flows to IAMBase(), which the sk- API
	// key resolver dials, and an empty base reads as "unresolved key" — every API-key
	// request on the fleet authenticating as nobody, with no error and no log line.
	if got := Issuer("", "no-such-brand"); got == "" {
		t.Error("Issuer answered empty for an unknown brand; every API-key request would authenticate as nobody")
	}
}

// A framer is an ORIGIN the registry names: https, a host, nothing after it, and
// never a wildcard — an apex whose subdomains are customer sites (hanzo.app)
// cannot be admitted by a pattern without admitting every customer.
func TestEveryFramerIsANamedOrigin(t *testing.T) {
	all := Framers()
	if len(all) == 0 {
		t.Fatal("no brand names a surface that frames our pages")
	}
	for _, f := range all {
		u, err := url.Parse(f)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			t.Errorf("framer %q is not an https origin", f)
		}
		if strings.Contains(f, "*") {
			t.Errorf("framer %q is a wildcard", f)
		}
	}
	if !slices.IsSorted(all) || len(slices.Compact(slices.Clone(all))) != len(all) {
		t.Errorf("Framers() = %v, want each once, sorted", all)
	}
}

// Every host the Bots app is served at frames a bot's computer (apps/sandbox
// page.go reads Framers for the screen and terminal pages). hanzo.bot was missing,
// and its computer answered "refused to connect".
func TestEveryBotsHostFramesAComputer(t *testing.T) {
	all := Framers()
	for _, host := range []string{"https://hanzo.ai", "https://hanzo.app", "https://hanzo.bot", "https://bot.hanzo.ai", "https://hanzo.team"} {
		if !slices.Contains(all, host) {
			t.Errorf("%s draws the Bots app but may not frame a bot's computer", host)
		}
	}
}

// A return is a named PAGE: an OAuth callback 302s to it carrying a grant, so a
// pattern, a customer's subdomain, or another brand's host would hand that grant
// to someone else.
func TestEveryReturnIsANamedPageOfItsBrand(t *testing.T) {
	for _, want := range []string{"https://hanzo.app/?at=-/settings/integrations", "https://hanzo.app/?at=-/sync", "https://hanzo.app/dev/projects", "https://hanzo.app/dev/sync", "https://hanzo.ai/?at=-/settings/integrations", "https://hanzo.ai/?at=-/sync", "https://hanzo.ai/dev/projects", "https://hanzo.ai/dev/sync", "https://console.hanzo.ai/connectors", "https://platform.hanzo.ai/connectors", "https://social.hanzo.ai/accounts"} {
		if !slices.Contains(For("hanzo").Returns, want) {
			t.Errorf("hanzo Returns = %v, missing %s", For("hanzo").Returns, want)
		}
	}
	for _, id := range []string{"hanzo", "lux", "zoo", "pars", "bootnode"} {
		for _, r := range For(id).Returns {
			u, err := url.Parse(r)
			if err != nil || u.Scheme != "https" || u.Host == "" || u.Port() != "" || u.User != nil || u.Fragment != "" || !strings.HasPrefix(u.Path, "/") {
				t.Errorf("%s return %q is not an https page", id, r)
				continue
			}
			if q := u.Query(); len(q) > 1 || (len(q) == 1 && len(q["at"]) != 1) {
				t.Errorf("%s return %q carries a query other than at", id, r)
			}
			if strings.Contains(r, "*") || Published(u.Hostname()) {
				t.Errorf("%s return %q admits a customer's site", id, r)
			}
			if got := ForHost(u.Hostname()); got != id {
				t.Errorf("%s return %q is %s's host", id, r, got)
			}
		}
	}
}

func TestOwnedAndPublished(t *testing.T) {
	for host, want := range map[string]struct{ owned, published bool }{
		"hanzo.ai":          {true, false},
		"cal.hanzo.ai":      {true, false},
		"hanzo.team":        {true, false},
		"www.hanzo.chat":    {true, false},
		"hanzoskills.com":   {true, false},
		"hanzo.app":         {true, false},
		"intel.hanzo.app":   {true, false},
		"acme.hanzo.app":    {false, true},
		"a.b.hanzo.app":     {false, true},
		"lux.exchange":      {true, false},
		"evilhanzo.ai":      {false, false},
		"hanzo.ai.evil.com": {false, false},
		"acme.com":          {false, false},
	} {
		if got := Owned(host); got != want.owned {
			t.Errorf("Owned(%q) = %v, want %v", host, got, want.owned)
		}
		if got := Published(host); got != want.published {
			t.Errorf("Published(%q) = %v, want %v", host, got, want.published)
		}
	}
}

// An agent that lands on a surface is told the manifest of THAT surface's brand,
// and a host no brand claims, or a customer's site, is told nothing: a Lux page
// that names Hanzo's manifest is the cross-showing the registry exists to stop.
func TestAgentNamesOnlyItsOwnBrand(t *testing.T) {
	for host, want := range map[string]string{
		"api.hanzo.ai":        "https://hanzoskills.com/hanzo.md",
		"API.Hanzo.AI:443":    "https://hanzoskills.com/hanzo.md",
		"console.hanzo.ai":    "https://hanzoskills.com/hanzo.md",
		"hanzo.app":           "https://hanzoskills.com/hanzo.md",
		"api.lux.network":     "https://lux.network/llms.txt",
		"console.lux.cloud":   "https://lux.network/llms.txt",
		"api.zoo.ngo":         "https://zoo.ngo/llms.txt",
		"console.zoo.cloud":   "https://zoo.ngo/llms.txt",
		"api.pars.network":    "", // a brand that publishes no manifest
		"acme.hanzo.app":      "", // a customer's site
		"Acme.Hanzo.App:443":  "", // the same site, however it is spelled
		"acme.hanzo.app.":     "",
		"karma.style":         "", // nobody's brand
		"cloud":               "", // an in-cluster name
		"":                    "",
		"hanzo.ai.evil.com":   "",
		"api.lux.network.":    "https://lux.network/llms.txt",
		"evilhanzo.ai":        "",
		"intel.hanzo.app":     "https://hanzoskills.com/hanzo.md", // a first-party Site inside the namespace
		"api.zoo.ngo:8443":    "https://zoo.ngo/llms.txt",
		"api.bootno.de":       "",
		"console.lux.network": "https://lux.network/llms.txt",
	} {
		b, ok := Agent(host)
		if b.Agent != want || ok != (want != "") {
			t.Errorf("Agent(%q) = %q %v, want %q", host, b.Agent, ok, want)
		}
	}
	if !For("hanzo").Wallet || For("lux").Wallet || For("zoo").Wallet {
		t.Error("only hanzo's IAM is stated to open an account for a first-seen wallet")
	}
}

// Origin is the origin a client reached at its own Host: https for every public
// name, whatever plain-HTTP hop the answer was rendered behind; http only for this
// machine's names. The port stays as sent.
func TestOrigin(t *testing.T) {
	for host, want := range map[string]string{
		"api.hanzo.ai":         "https://api.hanzo.ai",
		"api.lux.network:8443": "https://api.lux.network:8443",
		"red-probe.example":    "https://red-probe.example",
		"localhost:8000":       "http://localhost:8000",
		"cloud":                "http://cloud",
		"cloud:8000":           "http://cloud:8000",
		"127.0.0.1:8000":       "http://127.0.0.1:8000",
		"10.0.0.7":             "http://10.0.0.7",
		"[::1]:8000":           "http://[::1]:8000",
		"[2606:4700::1]":       "https://[2606:4700::1]",
		"cloud.local":          "http://cloud.local",
		"app.localhost":        "http://app.localhost",
	} {
		if got := Origin(host); got != want {
			t.Errorf("Origin(%q) = %q, want %q", host, got, want)
		}
	}
}

// A person is sent to their own brand's pages: Hanzo takes credit at its
// checkout's amount step (the page every Add credits in its apps opens) and names
// its console as platform.hanzo.ai, whichever Hanzo host was asked; Lux and Zoo have
// no checkout and keep their consoles; a brand with neither is sent nowhere.
func TestAPersonIsSentToTheirBrandsPages(t *testing.T) {
	for _, tc := range []struct{ host, credit, keys string }{
		{"api.hanzo.ai", "https://hanzo.ai/pay/amount/card", "https://platform.hanzo.ai/api-keys"},
		{"console.hanzo.ai", "https://hanzo.ai/pay/amount/card", "https://platform.hanzo.ai/api-keys"},
		{"hanzo.team", "https://hanzo.ai/pay/amount/card", "https://platform.hanzo.ai/api-keys"},
		{"api.lux.cloud", "", "https://console.lux.cloud/api-keys"},
		{"api.zoo.cloud:443", "", "https://console.zoo.cloud/api-keys"},
		{"api.pars.network", "", ""},
		{"api.bootno.de", "", ""},
	} {
		if got := AddCredit(tc.host); got != tc.credit {
			t.Errorf("AddCredit(%q) = %q, want %q", tc.host, got, tc.credit)
		}
		if got := ConsolePage(tc.host, "/api-keys"); got != tc.keys {
			t.Errorf("ConsolePage(%q, /api-keys) = %q, want %q", tc.host, got, tc.keys)
		}
	}
}
