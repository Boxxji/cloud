// SPDX-License-Identifier: Apache-2.0 OR MIT

package x402

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luxfi/crypto"
	luxlog "github.com/luxfi/log"
	"github.com/zap-proto/zip"

	protocol "github.com/hanzoai/commerce/payment/x402"
)

// The token, payee and key below are test values with no meaning.
const (
	token = "0x00000000000000000000000000000000000a11c3"
	payee = "0x7e57000000000000000000000000000000000001"
	// the eth-account documentation key
	keyHex = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
)

func asset() protocol.Asset {
	return protocol.Asset{Network: "eip155:84532", Address: token, Name: "Test Dollar", Version: "2", Decimals: 6, PayTo: payee, MaxTimeoutSeconds: 60}
}

// ledger is a facilitator that settles a nonce once.
type ledger struct {
	mu      sync.Mutex
	settled int
	spent   map[string]bool
}

func (l *ledger) Verify(_ context.Context, p protocol.PaymentPayload, _ protocol.PaymentRequirements) (protocol.VerifyResponse, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.spent[p.Payload.Authorization.Nonce] {
		return protocol.VerifyResponse{InvalidReason: protocol.ReasonInvalidTransaction}, nil
	}
	return protocol.VerifyResponse{IsValid: true, Payer: p.Payload.Authorization.From}, nil
}

func (l *ledger) Settle(_ context.Context, p protocol.PaymentPayload, o protocol.PaymentRequirements) (protocol.SettlementResponse, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.spent == nil {
		l.spent = map[string]bool{}
	}
	l.spent[p.Payload.Authorization.Nonce] = true
	l.settled++
	return protocol.SettlementResponse{Success: true, Payer: p.Payload.Authorization.From, Transaction: "tx", Network: o.Network, Amount: o.Amount}, nil
}

func key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := crypto.HexToECDSA(keyHex)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mount(t *testing.T, prices map[string]protocol.Price) (*zip.App, *ledger, *int) {
	t.Helper()
	l := &ledger{}
	app := zip.New(zip.Config{})
	if err := Mount(app, luxlog.New("test"), Config{Assets: []protocol.Asset{asset()}, Prices: prices, Facilitator: l}); err != nil {
		t.Fatal(err)
	}
	ran := new(int)
	app.Raw(http.MethodGet, "/v1/data", func(c *zip.Ctx) error { *ran++; return c.JSON(200, map[string]string{"data": "premium"}) })
	app.Raw(http.MethodGet, "/v1/run/a/b", func(c *zip.Ctx) error { *ran++; return c.JSON(200, map[string]string{"ran": "yes"}) })
	app.Raw(http.MethodGet, "/v1/free", func(c *zip.Ctx) error { return c.JSON(200, map[string]string{"free": "yes"}) })
	return app, l, ran
}

func do(t *testing.T, app *zip.App, method, path string, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := app.Test(req, zip.TestConfig{Timeout: 10 * time.Second, FailOnTimeout: true})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

// pay signs the challenge a priced path answers, as a client does.
func pay(t *testing.T, app *zip.App, path string) map[string]string {
	t.Helper()
	resp, _ := do(t, app, http.MethodGet, path, nil)
	var pr protocol.PaymentRequired
	if err := protocol.DecodeHeader(resp.Header.Get(protocol.HeaderPaymentRequired), &pr); err != nil {
		t.Fatalf("%s carried no challenge: %v", path, err)
	}
	s := protocol.Signer{Key: key(t), Allow: func(protocol.ResourceInfo, protocol.PaymentRequirements) bool { return true }}
	p, err := s.Pay(context.Background(), pr)
	if err != nil {
		t.Fatal(err)
	}
	h, err := protocol.EncodeHeader(p)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{protocol.HeaderPaymentSignature: h}
}

var prices = map[string]protocol.Price{
	"GET /v1/data":  {Amount: "0.01", Description: "data"},
	"GET /v1/run/*": {Amount: "0.25"},
}

func TestAPricedRouteIsChallengedThenServedAndSettled(t *testing.T) {
	app, l, ran := mount(t, prices)
	resp, body := do(t, app, http.MethodGet, "/v1/data", nil)
	if resp.StatusCode != 402 || *ran != 0 || strings.Contains(body, "premium") {
		t.Fatalf("unpaid: %d ran %d", resp.StatusCode, *ran)
	}
	var pr protocol.PaymentRequired
	if err := protocol.DecodeHeader(resp.Header.Get(protocol.HeaderPaymentRequired), &pr); err != nil || pr.Accepts[0].Amount != "10000" || pr.Accepts[0].PayTo != payee {
		t.Fatalf("challenge %v %+v", err, pr)
	}
	resp, body = do(t, app, http.MethodGet, "/v1/data", pay(t, app, "/v1/data"))
	if resp.StatusCode != 200 || !strings.Contains(body, "premium") || l.settled != 1 || resp.Header.Get(protocol.HeaderPaymentResponse) == "" {
		t.Fatalf("paid: %d %s settled %d", resp.StatusCode, body, l.settled)
	}
}

func TestAPrefixPricesEverythingUnderIt(t *testing.T) {
	app, l, _ := mount(t, prices)
	resp, _ := do(t, app, http.MethodGet, "/v1/run/a/b", nil)
	var pr protocol.PaymentRequired
	if err := protocol.DecodeHeader(resp.Header.Get(protocol.HeaderPaymentRequired), &pr); resp.StatusCode != 402 || err != nil || pr.Accepts[0].Amount != "250000" {
		t.Fatalf("prefix: %d %v", resp.StatusCode, err)
	}
	if resp, _ := do(t, app, http.MethodGet, "/v1/run/a/b", pay(t, app, "/v1/run/a/b")); resp.StatusCode != 200 || l.settled != 1 {
		t.Fatalf("paid prefix: %d", resp.StatusCode)
	}
}

// The router answers /V1/Data/ with the handler of /v1/data; a paywall keyed on the
// literal path would be bypassed by the other spelling, and HEAD reaches GET handlers.
func TestNoSpellingOfAPricedPathIsFree(t *testing.T) {
	app, _, ran := mount(t, prices)
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/V1/Data"}, {http.MethodGet, "/v1/data/"}, {http.MethodGet, "//v1//data"},
		{http.MethodGet, "/v1/x/../data"}, {http.MethodHead, "/v1/data"}, {http.MethodGet, "/v1/RUN/a/b"},
	} {
		if resp, body := do(t, app, c.method, c.path, nil); resp.StatusCode == 200 && strings.Contains(body, "premium") || *ran != 0 {
			t.Errorf("%s %s served unpaid (status %d, ran %d)", c.method, c.path, resp.StatusCode, *ran)
		}
	}
}

func TestUnpricedRoutesAreUntouched(t *testing.T) {
	app, l, _ := mount(t, prices)
	resp, body := do(t, app, http.MethodGet, "/v1/free", nil)
	if resp.StatusCode != 200 || !strings.Contains(body, "yes") || l.settled != 0 {
		t.Fatalf("%d", resp.StatusCode)
	}
}

func TestThePriceTableIsListed(t *testing.T) {
	app, _, _ := mount(t, prices)
	resp, body := do(t, app, http.MethodGet, "/v1/x402/prices", nil)
	var out struct {
		X402Version int            `json:"x402Version"`
		Prices      []protocol.Row `json:"prices"`
	}
	if resp.StatusCode != 200 || json.Unmarshal([]byte(body), &out) != nil || out.X402Version != 2 || len(out.Prices) != 2 {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if out.Prices[0].Resource != "GET /v1/data" || out.Prices[0].Price != "0.01" {
		t.Fatalf("%+v", out.Prices)
	}
}

func TestLoadIsStrict(t *testing.T) {
	good := `{"facilitator":"https://f.test","assets":[{"network":"eip155:84532","address":"` + token + `","name":"Test Dollar","version":"2","decimals":6,"payTo":"` + payee + `","maxTimeoutSeconds":60}],"prices":{"GET /v1/data":{"amount":"0.01"}}}`
	cfg, err := Load(strings.NewReader(good))
	if err != nil || len(cfg.Assets) != 1 || cfg.Prices["GET /v1/data"].Amount != "0.01" || cfg.Facilitator == nil {
		t.Fatalf("%v %+v", err, cfg)
	}
	for name, in := range map[string]string{
		"unknown field":  strings.Replace(good, `"prices"`, `"price"`, 1),
		"no facilitator": strings.Replace(good, `https://f.test`, ``, 1),
		"not http":       strings.Replace(good, `https://f.test`, `ftp://f.test`, 1),
		"trailing":       good + `{}`,
		"not json":       `nope`,
	} {
		if _, err := Load(strings.NewReader(in)); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}

func TestMountRefusesWhatItCannotPrice(t *testing.T) {
	ok := Config{Assets: []protocol.Asset{asset()}, Prices: prices, Facilitator: &ledger{}}
	bad := map[string]func(*Config){
		"no facilitator": func(c *Config) { c.Facilitator = nil },
		"no prices":      func(c *Config) { c.Prices = nil },
		"no assets":      func(c *Config) { c.Assets = nil },
		"bad asset":      func(c *Config) { c.Assets = []protocol.Asset{{}} },
		"no method":      func(c *Config) { c.Prices = map[string]protocol.Price{"/v1/data": {Amount: "1"}} },
		"lower method":   func(c *Config) { c.Prices = map[string]protocol.Price{"get /v1/data": {Amount: "1"}} },
		"no slash":       func(c *Config) { c.Prices = map[string]protocol.Price{"GET v1": {Amount: "1"}} },
		"bad amount":     func(c *Config) { c.Prices = map[string]protocol.Price{"GET /v1/data": {Amount: "0"}} },
	}
	for name, f := range bad {
		c := ok
		f(&c)
		if err := Mount(zip.New(zip.Config{}), luxlog.New("test"), c); err == nil {
			t.Errorf("%s: mounted", name)
		}
	}
	if err := Mount(nil, luxlog.New("test"), ok); err == nil {
		t.Error("nil app mounted")
	}
}
