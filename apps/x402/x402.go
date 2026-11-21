// SPDX-License-Identifier: Apache-2.0 OR MIT

// Package x402 charges per request over HTTP 402 for the routes an operator prices.
//
// It is the x402 version 2 mechanism of github.com/hanzoai/commerce/payment/x402
// mounted on the router: a priced request without a payment is answered 402 with
// the terms, one with a payment is verified before the route runs, and the payment
// settles once the route has answered with a success. Nothing is priced until the
// operator says so: there is no default token, payee, network or price, and a
// deployment with no configuration mounts nothing and serves every route as it did.
//
// The operator gives three things (Config): the assets a payer may pay in, the
// price of each route, and the facilitator that verifies and settles. Load reads
// them from a JSON file.
//
//	{
//	  "facilitator": "https://facilitator.example",
//	  "assets": [{"network":"eip155:8453","address":"0x…","name":"…","version":"2",
//	              "decimals":6,"payTo":"0x…","maxTimeoutSeconds":60}],
//	  "prices": {"GET /v1/data": {"amount":"0.01"}, "POST /v1/run/*": {"amount":"0.25"}}
//	}
//
// A price key is a method and a path. A path ending in /* prices everything under
// that prefix, and the longest match wins. Paths match the way the router does, not
// literally: case is folded, a trailing slash and "." or ".." segments are ignored,
// so /V1/Data/ cannot reach the handler of /v1/data without paying for it. A HEAD
// request is priced as GET.
//
// Prices are charged for a route's success: a handler that returns an error or
// answers 4xx or 5xx settles nothing. Routes that fail by rendering an error and
// returning nil are still seen by their status, but a priced route should be a typed
// op, whose failures are returned errors.
//
// Surface (typed op, /v1 only):
//
//	GET /v1/x402/prices   every priced route and the exact terms for paying it
package x402

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	luxlog "github.com/luxfi/log"
	"github.com/zap-proto/zip"

	protocol "github.com/hanzoai/commerce/payment/x402"
)

//go:generate go run github.com/zap-proto/zip/cmd/zipdoc

// Config is what an operator gives the rail. Nothing in it has a default.
type Config struct {
	// Assets are the ways a payer may pay: a token on a network, the payee, the
	// token's EIP-712 domain and decimals. Every price is quoted in each of them.
	Assets []protocol.Asset
	// Prices maps a method and path ("GET /v1/data", or "POST /v1/run/*" for a
	// prefix) to its price in whole units of every asset.
	Prices map[string]protocol.Price
	// Facilitator verifies and settles payments. A host that settles on its own
	// books passes its own; Load builds one that speaks to a facilitator by URL.
	Facilitator protocol.Facilitator
}

// file is the JSON an operator writes.
type file struct {
	Facilitator string                    `json:"facilitator"`
	Assets      []protocol.Asset          `json:"assets"`
	Prices      map[string]protocol.Price `json:"prices"`
}

// Load reads an operator's JSON configuration. A field it does not know is an error:
// a misspelled key must not leave a route unpriced. The facilitator is reached at
// the URL named, without credentials; a facilitator that needs them is wired by the
// host with its own Config.Facilitator.
func Load(r io.Reader) (Config, error) {
	var f file
	dec := json.NewDecoder(io.LimitReader(r, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return Config{}, fmt.Errorf("x402: config: %w", err)
	}
	if dec.More() {
		return Config{}, errors.New("x402: config: trailing data after the document")
	}
	if !strings.HasPrefix(f.Facilitator, "https://") && !strings.HasPrefix(f.Facilitator, "http://") {
		return Config{}, errors.New("x402: config: facilitator must be an http(s) URL")
	}
	return Config{Assets: f.Assets, Prices: f.Prices, Facilitator: protocol.Remote{URL: f.Facilitator}}, nil
}

// Mount charges for the configured routes. It must be mounted before the routes it
// prices: the payment check wraps the handlers registered after it. An invalid
// configuration is an error, so a deployment never starts with a price it did not
// understand.
func Mount(app *zip.App, log luxlog.Logger, cfg Config) error {
	if app == nil {
		return errors.New("x402: nil app")
	}
	if cfg.Facilitator == nil {
		return errors.New("x402: no facilitator")
	}
	if len(cfg.Prices) == 0 {
		return errors.New("x402: no prices: nothing to charge for")
	}
	table, err := protocol.NewTable(cfg.Assets...)
	if err != nil {
		return err
	}
	for key, price := range cfg.Prices {
		method, p, ok := strings.Cut(key, " ")
		if !ok || !strings.HasPrefix(p, "/") || method != strings.ToUpper(method) || method == "" {
			return fmt.Errorf("x402: price key %q is not a method and a path, like \"GET /v1/data\"", key)
		}
		if err := table.Set(method+" "+canonical(p), price); err != nil {
			return err
		}
	}
	gate := &protocol.Gate{Table: table, Facilitator: cfg.Facilitator}
	app.Use(protocol.Paywall(gate, pricedKey(table)))
	app.Group("/v1/x402").Get("/prices", ops{table: table}.prices)
	log.Info("x402 mounted", "priced", len(cfg.Prices), "assets", len(cfg.Assets))
	return nil
}

// canonical is a path as the router reads it: lower case, cleaned of repeated
// slashes, "." and ".." segments and a trailing slash.
func canonical(p string) string { return strings.ToLower(path.Clean("/" + p)) }

// pricedKey names the table entry that prices a request: the exact method and
// canonical path, else the longest "/*" prefix that contains it, else the empty key,
// which is not priced.
func pricedKey(t *protocol.Table) func(method, p string) string {
	return func(method, p string) string {
		p = canonical(p)
		if exact := method + " " + p; t.Priced(exact) {
			return exact
		}
		for p != "/" {
			p = path.Dir(p)
			prefix := p
			if prefix != "/" {
				prefix += "/"
			}
			if key := method + " " + prefix + "*"; t.Priced(key) {
				return key
			}
		}
		return ""
	}
}

// ops binds the typed ops. A typed handler takes no service parameter, so the table
// arrives as a receiver.
type ops struct{ table *protocol.Table }

// noIn is the input of an op that takes nothing.
type noIn struct{}

// priceTable is every priced route.
type priceTable struct {
	// X402Version is the protocol version the terms are stated in.
	X402Version int `json:"x402Version"`
	// Prices is one row per priced route, ordered by key; never null.
	Prices []protocol.Row `json:"prices"`
}

// prices lists every priced route with the exact terms for paying it, so a client
// can sign before it is refused: the price in whole units, and for each asset the
// network, token, payee, amount in atomic units and the token's signing domain. A
// payment is made on the route itself, in the PAYMENT-SIGNATURE header, and the
// receipt comes back in PAYMENT-RESPONSE; nothing is paid here. It needs no
// credential, so a client can price a route before it has an account.
func (o ops) prices(_ context.Context, _ *noIn) (*priceTable, error) {
	return &priceTable{X402Version: protocol.Version, Prices: o.table.Listing()}, nil
}
